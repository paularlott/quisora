package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// The public endpoints of a tenant's SSH certificate authority (docs/design/ssh-ca.md), under
// /o/<org>/ssh/<tenant> where <tenant> is the tenant's id or name: the discovery document the CLI starts from, the
// CA keys and revocation list servers fetch, and the endpoint that signs a user certificate for an access token.
// A tenant that is unknown, or never had SSH, answers 404 everywhere. One whose SSH is off answers 404 to signing, and
// still serves its discovery document (which says "enabled": false), CA keys and revocation list, which then revokes
// every certificate: turning SSH off reaches the servers that fetch them. The public documents carry an ETag (a request
// with If-None-Match that names it is answered 304) and are limited per address and tenant (web.SSHFetchUnitsPerIP).

const (
	sshSignsPerUser = web.SSHSignsPerUser // certificates signed per user and minute (counted with the account page's)
	sshSignsPerIP   = web.SSHSignsPerIP   // certificates signed per address and minute

	// maxSSHSignBody bounds a sign request: a public key line and a few principals are far smaller.
	maxSSHSignBody = 16 << 10
	// maxSSHTTL stops a ttl in seconds overflowing a duration; the service refuses what is above the tenant's own limit.
	maxSSHTTL = 10 * 365 * 24 * 3600
)

// sshDiscovery is the document at /o/<org>/ssh/<tenant>.
type sshDiscovery struct {
	Issuer                      string   `json:"issuer"`
	Org                         string   `json:"org"`
	Tenant                      string   `json:"tenant"`
	TenantID                    string   `json:"tenant_id"`
	Enabled                     bool     `json:"enabled"` // false: SSH is turned off, no certificate is signed and the revocation list revokes all
	ClientID                    string   `json:"client_id"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	SignEndpoint                string   `json:"sign_endpoint"`
	UserCAEndpoint              string   `json:"user_ca_endpoint"`
	KnownHostsEndpoint          string   `json:"known_hosts_endpoint"`
	KRLEndpoint                 string   `json:"krl_endpoint"`
	HostSignEndpoint            string   `json:"host_sign_endpoint"`
	CertTTL                     int      `json:"cert_ttl"`
	MaxAuthAge                  int      `json:"max_auth_age"`
	HostCerts                   bool     `json:"host_certs"`
	HostPatterns                []string `json:"host_patterns"`
	ACRValues                   string   `json:"acr_values"`
}

// sshSignRequest is the body of the sign endpoint.
type sshSignRequest struct {
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals"`
	TTL        int64    `json:"ttl"` // seconds; 0: the tenant's CertTTL
}

// sshSignResponse is the certificate made.
type sshSignResponse struct {
	Certificate string   `json:"certificate"`
	Serial      string   `json:"serial"` // decimal: 64 bits do not fit a JSON number everywhere
	KeyID       string   `json:"key_id"`
	Principals  []string `json:"principals"`
	ValidAfter  string   `json:"valid_after"`
	ValidBefore string   `json:"valid_before"`
}

// sshTenant finds the tenant the path names for signing, answering 404 (unknown, or SSH off) or 503 itself, and says
// whether it did not.
func (p *Provider) sshTenant(w http.ResponseWriter, r *http.Request) (*model.Tenant, *model.Org, bool) {
	return p.sshLookup(w, r, p.svc.SSHTenantByRef)
}

// sshPublished finds the tenant the path names for the public documents, which a tenant with SSH off serves too, and
// counts the request against the limit of its address for that tenant (429): by the tenant's id, so naming it by id or
// by name is one budget, and the paths that name no tenant share one more. The tenant is read before the request is
// counted (one read, as a 404 costs): a made-up name gets no counter of its own.
func (p *Provider) sshPublished(w http.ResponseWriter, r *http.Request) (*model.Tenant, *model.Org, bool) {
	org := web.Org(r)
	t, err := p.svc.SSHTenantPublished(r.Context(), org.ID, r.PathValue("tenant"))
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		writeOAuthError(w, serverError(unavailable(err)))
		return nil, nil, false
	}
	id := ""
	if t != nil {
		id = t.ID
	}
	within, err := p.s.SSHFetchAllowed(r.Context(), r, id)
	switch {
	case err != nil:
		writeOAuthError(w, serverError(unavailable(err)))
		return nil, nil, false
	case !within:
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", retry: true})
		return nil, nil, false
	case t == nil:
		web.WriteJSON(w, http.StatusNotFound, web.ErrorBody{Error: "Not found."})
		return nil, nil, false
	}
	return t, org, true
}

func (p *Provider) sshLookup(w http.ResponseWriter, r *http.Request, find func(context.Context, string, string) (*model.Tenant, error)) (*model.Tenant, *model.Org, bool) {
	org := web.Org(r)
	t, err := find(r.Context(), org.ID, r.PathValue("tenant"))
	switch {
	case errors.Is(err, service.ErrNotFound):
		web.WriteJSON(w, http.StatusNotFound, web.ErrorBody{Error: "Not found."})
		return nil, nil, false
	case err != nil:
		writeOAuthError(w, serverError(unavailable(err)))
		return nil, nil, false
	}
	return t, org, true
}

// Cache-Control of the public GET answers: anyone may keep the discovery document for a minute; the CA keys and the
// revocation list are revalidated every time (their ETags), so a cache never holds back a revocation, nor serves an
// old ca.pub beside a new list after a rotation.
const (
	sshCachePublic     = "public, max-age=60"
	sshCacheRevalidate = "no-cache"
)

// sshServe answers a public GET for tenant t with body, whose ETag is tag: 304 when the request's If-None-Match names
// the tag (or is *), else the body, counting the rest of what a document sent costs against the address's limit.
func (p *Provider) sshServe(w http.ResponseWriter, r *http.Request, t *model.Tenant, contentType, cacheControl string, body []byte, tag string) {
	h := w.Header()
	h.Set("ETag", tag)
	h.Set("Cache-Control", cacheControl)
	if etagMatches(r.Header.Get("If-None-Match"), tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	p.s.SSHFetchServed(r.Context(), r, t.ID)
	h.Set("Content-Type", contentType)
	_, _ = w.Write(body)
}

// sshTag is the ETag of a document: a hash of it.
func sshTag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// etagMatches reports whether an If-None-Match header names tag, or is *: the weak comparison of RFC 9110 §13.1.2
// (a W/ prefix is ignored).
func etagMatches(header, tag string) bool {
	if header == "" {
		return false
	}
	for _, t := range strings.Split(header, ",") {
		if t = strings.TrimSpace(t); t == "*" || strings.TrimPrefix(t, "W/") == tag {
			return true
		}
	}
	return false
}

// handleSSHDiscovery is GET /o/<org>/ssh/<tenant>: where everything of the tenant's SSH is, and its terms.
func (p *Provider) handleSSHDiscovery(w http.ResponseWriter, r *http.Request) {
	t, org, ok := p.sshPublished(w, r)
	if !ok {
		return
	}
	e := p.cfg.OrgEndpoints(org.ID)
	base := e.Issuer + "/ssh/" + t.ID
	d := sshDiscovery{
		Issuer: e.Issuer, Org: org.Name, Tenant: t.Name, TenantID: t.ID, Enabled: t.SSH.Enabled, ClientID: t.SSH.ClientID,
		AuthorizationEndpoint: e.Authorization, TokenEndpoint: e.Token, DeviceAuthorizationEndpoint: e.DeviceAuthorization,
		SignEndpoint: base + "/sign", UserCAEndpoint: base + "/ca.pub", KnownHostsEndpoint: base + "/known_hosts", KRLEndpoint: base + "/krl",
		HostSignEndpoint: p.cfg.Server.PublicURL + "/api/orgs/" + org.ID + "/tenants/" + t.ID + "/ssh/host-certificates",
		CertTTL:          t.SSH.CertTTL, MaxAuthAge: t.SSH.MaxAuthAge, HostCerts: t.SSH.HostCerts,
		HostPatterns: append([]string{}, t.SSH.HostPatterns...), ACRValues: acrMFA,
	}
	b, _ := json.Marshal(d)
	p.sshServe(w, r, t, "application/json; charset=utf-8", sshCachePublic, b, sshTag(b))
}

// sshKeyLines writes one line per published CA key of the tenant for purpose: prefix (of the tenant), the key and the
// comment quisora:<org>/<tenant>:<purpose>:<key id>.
func (p *Provider) sshKeyLines(w http.ResponseWriter, r *http.Request, purpose string, prefix func(*model.Tenant) string) {
	t, org, ok := p.sshPublished(w, r)
	if !ok {
		return
	}
	var b strings.Builder
	// A tenant that does not sign host certificates publishes no host CA keys, whatever it signed once.
	if purpose == model.SSHPurposeUser || t.SSH.HostCerts {
		keys, err := p.svc.SSHKeysOf(r.Context(), t, purpose)
		if err != nil {
			writeOAuthError(w, serverError(unavailable(err)))
			return
		}
		for _, k := range keys {
			if prefix != nil {
				b.WriteString(prefix(t))
			}
			b.WriteString(strings.TrimSpace(k.PublicKey))
			b.WriteString(" quisora:" + org.Name + "/" + t.Name + ":" + purpose + ":" + k.ID + "\n")
		}
	}
	body := []byte(b.String())
	p.sshServe(w, r, t, "text/plain; charset=utf-8", sshCacheRevalidate, body, sshTag(body))
}

// handleSSHUserCA is GET /o/<org>/ssh/<tenant>/ca.pub: the user CA keys in authorized_keys form, for sshd's
// TrustedUserCAKeys.
func (p *Provider) handleSSHUserCA(w http.ResponseWriter, r *http.Request) {
	p.sshKeyLines(w, r, model.SSHPurposeUser, nil)
}

// handleSSHKnownHosts is GET /o/<org>/ssh/<tenant>/known_hosts: the host CA keys as @cert-authority lines for the host
// patterns of the tenant, for a client's known_hosts. Empty unless host certificates are on.
func (p *Provider) handleSSHKnownHosts(w http.ResponseWriter, r *http.Request) {
	p.sshKeyLines(w, r, model.SSHPurposeHost, func(t *model.Tenant) string {
		return "@cert-authority " + strings.Join(t.SSH.HostPatterns, ",") + " "
	})
}

// handleSSHKRL is GET /o/<org>/ssh/<tenant>/krl: the key revocation list, for sshd's RevokedKeys. Its ETag says what it
// revokes (not when it was made), so a server that has the list gets 304 until a revocation changes it. A list that
// cannot be made is logged as an error: it is a 503, and the servers keep their old list meanwhile.
func (p *Provider) handleSSHKRL(w http.ResponseWriter, r *http.Request) {
	t, org, ok := p.sshPublished(w, r)
	if !ok {
		return
	}
	krl, tag, err := p.svc.SSHKRLTagged(r.Context(), t.ID)
	switch {
	case errors.Is(err, service.ErrNotFound): // the tenant was changed since it was read
		web.WriteJSON(w, http.StatusNotFound, web.ErrorBody{Error: "Not found."})
		return
	case err != nil:
		p.log.Error("oidc: making an SSH revocation list", "org", org.ID, "tenant", t.ID, "error", err)
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	p.sshServe(w, r, t, "application/octet-stream", sshCacheRevalidate, krl, tag)
}

// sshError is an error answer of the sign endpoint, in the token endpoint's shape.
func sshError(w http.ResponseWriter, status int, code, desc string) {
	writeOAuthError(w, &oauthError{status: status, code: code, desc: desc})
}

// handleSSHSign is POST /o/<org>/ssh/<tenant>/sign: a user certificate for the public key in the body, for the user of
// the access token (the bearer or DPoP token of the tenant's SSH application, from a sign-in with a second factor).
// Everything the certificate depends on is decided by Service.SignUserSSH; this is the HTTP shape of it, and the rate
// limits.
func (p *Provider) handleSSHSign(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	t, org, ok := p.sshTenant(w, r)
	if !ok {
		return
	}
	// The caller: authenticated as userinfo does, so a DPoP-bound token works and an undecidable one is not refused.
	tok, scheme, ok := bearer(r)
	if !ok {
		bearerError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if tok == "" {
		bearerError(w, http.StatusUnauthorized, "")
		return
	}
	cl, err := p.VerifyRequestToken(r, scheme, tok)
	switch {
	case errors.Is(err, ErrDPoPProof):
		p.dpopChallenge(w, http.StatusUnauthorized, "invalid_dpop_proof")
		return
	case service.IsUnavailable(err):
		bearerUnavailable(w, err)
		return
	case err != nil && scheme == "DPoP":
		p.dpopChallenge(w, http.StatusUnauthorized, "invalid_token")
		return
	case err != nil || cl.Sub == cl.ClientID: // a client's own token (client credentials) is nobody's sign-in
		bearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	u, err := p.user(r.Context(), cl.Sub)
	switch {
	case err != nil && !gone(err):
		bearerUnavailable(w, err)
		return
	case err != nil || u.OrgID != org.ID || cl.GID == "": // (every token of a sign-in has its grant)
		bearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	// The certificate stands on the token's grant: it takes the grant's session epoch and sign-out stamp, never the
	// current ones, so it is revoked with what the grant's sign-in loses (VerifyRequestToken found the grant alive).
	grant, err := p.grantStateOf(r.Context(), cl.GID, u)
	switch {
	case err != nil:
		bearerUnavailable(w, err)
		return
	case !grant.alive:
		bearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	// Counted before anything is signed, so what is refused counts too; the account page spends the same budget.
	ctx := r.Context()
	within, err := p.s.SSHSignAllowed(ctx, r, u.ID)
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if !within {
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", retry: true})
		return
	}

	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		sshError(w, http.StatusBadRequest, "invalid_request", "send the request as application/json")
		return
	}
	var in sshSignRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSSHSignBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			sshError(w, http.StatusRequestEntityTooLarge, "invalid_request", "the request is too large")
			return
		}
		sshError(w, http.StatusBadRequest, "invalid_request", "the request body must be JSON: {\"public_key\": …, \"principals\": […], \"ttl\": seconds}")
		return
	}
	if in.TTL < 0 {
		sshError(w, http.StatusBadRequest, "invalid_request", "ttl is a number of seconds")
		return
	}

	issued, err := p.svc.SignUserSSH(ctx, service.SSHUserRequest{
		Actor: service.ActorForUser(u, web.ClientIP(r)), User: u, TenantID: t.ID, ClientID: cl.ClientID,
		PublicKey: in.PublicKey, Principals: in.Principals, TTL: time.Duration(min(in.TTL, maxSSHTTL)) * time.Second,
		// the grant's amr, as Quisora verified the sign-in: the token's amr also has what an upstream provider said
		AMR: grant.amr, AuthTime: time.Unix(int64(cl.AuthTime), 0), Via: "cli", SessionEpoch: grant.epoch, Stamp: grant.stamp,
	})
	var refusal *service.SSHRefusal
	var field *service.FieldError
	switch {
	case errors.As(err, &refusal):
		sshError(w, http.StatusForbidden, "access_denied", refusal.Msg)
		return
	case errors.As(err, &field):
		sshError(w, http.StatusBadRequest, "invalid_request", field.Field+": "+field.Msg)
		return
	case errors.Is(err, service.ErrForbidden):
		sshError(w, http.StatusForbidden, "access_denied", "this account cannot get a certificate")
		return
	case errors.Is(err, service.ErrNotFound):
		web.WriteJSON(w, http.StatusNotFound, web.ErrorBody{Error: "Not found."})
		return
	case err != nil:
		p.log.Error("oidc: signing an SSH certificate", "org", org.ID, "tenant", t.ID, "user", u.ID, "error", err)
		writeOAuthError(w, serverError(err))
		return
	}
	c := issued.Cert
	b, _ := json.Marshal(sshSignResponse{
		Certificate: issued.Certificate, Serial: strconv.FormatUint(c.Serial, 10), KeyID: c.KeyID, Principals: c.Principals,
		ValidAfter: c.ValidAfter.UTC().Format(time.RFC3339), ValidBefore: c.ValidBefore.UTC().Format(time.RFC3339),
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(b)
}
