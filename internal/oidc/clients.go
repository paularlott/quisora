package oidc

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientEntry is a cached client with its registered public keys parsed.
type clientEntry struct {
	c    *model.Client
	keys []pubKey // from client.JWKS
}

type pubKey struct {
	kid string
	alg string
	pub crypto.PublicKey
}

func parseKeys(jwks []JWK) []pubKey {
	var out []pubKey
	for _, j := range jwks {
		if j.Use == "enc" {
			continue
		}
		pub, err := j.PublicKey()
		if err != nil {
			continue
		}
		alg := j.KeyAlg()
		switch {
		case j.Alg == AlgPS256 && alg == AlgRS256:
			alg = AlgPS256 // an RSA key declared for PSS
		case j.Alg != "" && j.Alg != alg:
			continue
		case j.Alg == "" && alg == AlgRS256:
			out = append(out, pubKey{kid: j.Kid, alg: AlgPS256, pub: pub}) // an RSA key without alg: either scheme
		}
		out = append(out, pubKey{kid: j.Kid, alg: alg, pub: pub})
	}
	return out
}

// client returns the (cached) client the application of organization orgID names by client_id. A client of another
// organization is unknown, exactly as one that does not exist: nothing tells that it is somewhere else.
func (p *Provider) client(ctx context.Context, orgID, id string) (*clientEntry, error) {
	if len(id) == 0 || len(id) > service.MaxMetadataURL {
		return nil, store.ErrNotFound
	}
	e, err := p.loadClient(ctx, model.ClientRecordID(orgID, id))
	if err != nil {
		return nil, err
	}
	// The record's id is the client_id too, except for a metadata-document application's (its digest): that one is
	// named by its URL, never by its record id.
	if e.c.OrgID != orgID || e.c.ClientID() != id {
		return nil, store.ErrNotFound
	}
	return p.standing(ctx, e)
}

// recordClient returns the (cached) client of a record id: how grants, sessions and flows name the clients they were
// made for (model.Client.ID).
func (p *Provider) recordClient(ctx context.Context, id string) (*clientEntry, error) {
	e, err := p.loadClient(ctx, id)
	if err != nil {
		return nil, err
	}
	return p.standing(ctx, e)
}

// loadClient reads a client's record through the cache.
func (p *Provider) loadClient(ctx context.Context, id string) (*clientEntry, error) {
	if e, ok := p.clients.get(id); ok {
		return e, nil
	}
	tok := p.clients.token(id)
	c, err := p.svc.Clients.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	e := &clientEntry{c: c}
	if c.JWKS != "" {
		if jwks, err := ParseJWKS([]byte(c.JWKS)); err == nil {
			e.keys = parseKeys(jwks)
		}
	}
	p.clients.putIf(id, e, tok)
	return e, nil
}

// standing returns e if its application still stands on its organization: one of a deleted organization is unknown (the
// orphan sweep removes its record later).
func (p *Provider) standing(ctx context.Context, e *clientEntry) (*clientEntry, error) {
	if _, err := p.org(ctx, e.c.OrgID); err != nil {
		if gone(err) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return e, nil
}

// ---------------------------------------------------------------------------------------------------------------
// OAuth errors

type oauthError struct {
	status int
	code   string
	desc   string
	realm  bool   // add WWW-Authenticate: Basic
	retry  bool   // add Retry-After (rate limited)
	nonce  string // add DPoP-Nonce (use_dpop_nonce)
}

func (e *oauthError) Error() string { return e.code + ": " + e.desc }

func oerr(code, desc string) *oauthError {
	return &oauthError{status: http.StatusBadRequest, code: code, desc: desc}
}

func errInvalidClient(desc string) *oauthError {
	return &oauthError{status: http.StatusUnauthorized, code: "invalid_client", desc: desc, realm: true}
}

func setNoStore(w http.ResponseWriter) {
	h := w.Header()
	h["Cache-Control"], h["Pragma"] = noStore, noCache // shared read-only slices (cap 1): no allocation
}

var (
	noStore = []string{"no-store"}[:1:1]
	noCache = []string{"no-cache"}[:1:1]
)

// writeOAuthError writes an RFC 6749 §5.2 error response.
func writeOAuthError(w http.ResponseWriter, e *oauthError) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if e.realm {
		w.Header().Set("WWW-Authenticate", `Basic realm="quisora", charset="UTF-8"`)
	}
	if e.retry {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter/time.Second)))
	}
	if e.nonce != "" {
		w.Header().Set("DPoP-Nonce", e.nonce)
	}
	w.WriteHeader(e.status)
	o := newObj(96)
	o.str("error", e.code)
	o.strIf("error_description", e.desc)
	_, _ = w.Write(o.bytes())
}

// ---------------------------------------------------------------------------------------------------------------
// Client authentication

// authenticateClient authenticates the caller of a back-channel endpoint (token, introspect, revoke) with
// client_secret_basic, client_secret_post or private_key_jwt. There is no "none" method.
// clientAuthFailuresPerMin bounds failed client authentications per client id and IP address and minute (token,
// introspection and revocation endpoints together): secrets cannot be guessed anyway, but a flood of attempts (and
// of private_key_jwt signature checks) costs work. Keyed by client as well as address, so one client's failures do
// not lock out the others behind a shared address (a load balancer without trust_proxy). Only a failure counts; past
// the limit every attempt from that client and address is refused for the rest of the minute, the right secret too
// (see authenticateClient).
const clientAuthFailuresPerMin = 30

// clientAuthFailuresPerIPMin bounds failures per IP address and minute whatever client ids are sent: the per-client
// budget alone resets for every made-up id, and each unknown id costs a store read. Ten clients' worth, so a shared
// address is only refused when it is plainly guessing.
const clientAuthFailuresPerIPMin = 10 * clientAuthFailuresPerMin

// authenticateClient is checkClient with a ceiling on failures.
func (p *Provider) authenticateClient(r *http.Request, allowPublic bool) (*clientEntry, *oauthError) {
	ip := web.RateKeyIP(r)
	key := "client-auth|" + authClientID(r) + "|" + ip
	ipKey := "client-auth-ip|" + ip
	limited := &oauthError{status: http.StatusTooManyRequests, code: "invalid_client",
		desc: "too many failed client authentications; try again in a minute", retry: true}
	// A counter that cannot be read or updated refuses the request (a limit never fails open) but answers "try again"
	// (503) rather than "too many failures": nothing tripped, and the valid client must retry, not back off a minute.
	// Over the limit, every attempt from this client and address is refused, the right secret included, before
	// anything is checked: guessing cannot go on, and a correct guess among the refused ones teaches nothing.
	n, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, key, 0, time.Minute)
	if err != nil {
		return nil, serverError(unavailable(err))
	}
	if n >= clientAuthFailuresPerMin {
		return nil, limited
	}
	n, err = p.s.Eph.Incr(r.Context(), nsRateOIDC, ipKey, 0, time.Minute)
	if err != nil {
		return nil, serverError(unavailable(err))
	}
	if n >= clientAuthFailuresPerIPMin {
		return nil, limited
	}
	ce, e := p.checkClient(r, allowPublic)
	if e == nil || e.code != "invalid_client" {
		return ce, e
	}
	// The authentication has already failed: if counting the failure fails too, the caller still gets that
	// failure (invalid_client), not a limit it has not reached.
	n, err = p.s.Eph.Incr(r.Context(), nsRateOIDC, ipKey, 1, time.Minute)
	if err != nil {
		return ce, e
	}
	if n > clientAuthFailuresPerIPMin {
		return nil, limited
	}
	n, err = p.s.Eph.Incr(r.Context(), nsRateOIDC, key, 1, time.Minute)
	if err != nil {
		return ce, e
	}
	if n == clientAuthFailuresPerMin {
		// The failure that reaches the limit: once per client, address and minute. Only for a client that exists
		// (an unknown id has no organization to record it in, and anyone can make up any number of them).
		if c, cerr := p.client(r.Context(), web.Org(r).ID, authClientID(r)); cerr == nil {
			p.auditClient(r.Context(), c.c, "", "oauth.client_auth.limited", map[string]string{
				"failures_per_minute": strconv.Itoa(clientAuthFailuresPerMin)})
		}
	}
	if n > clientAuthFailuresPerMin {
		return nil, limited
	}
	return ce, e
}

// authClientID is the client id a request authenticates as, resolved the way checkClient resolves it, for keying the
// failure limit: the Basic user name form-urldecoded (else "%61bc" and "abc" would be separate budgets for guessing
// one client), else client_id, else the issuer of a client assertion (client_id is optional with private_key_jwt,
// RFC 7523 §3; without this such clients would share the empty-id budget that unauthenticated junk drains). Nothing
// is verified here: naming a client only spends that client's budget from this address, whoever does it.
func authClientID(r *http.Request) string {
	id, _, ok := r.BasicAuth()
	if ok {
		if u, err := url.QueryUnescape(id); err == nil {
			id = u
		}
	}
	if id == "" {
		id = r.PostForm.Get("client_id")
	}
	if id == "" {
		if a := r.PostForm.Get("client_assertion"); a != "" {
			if pj, err := ParseJWT(a); err == nil {
				var cl struct {
					Iss string `json:"iss"`
				}
				if json.Unmarshal(pj.Payload, &cl) == nil {
					id = cl.Iss
				}
			}
		}
	}
	if len(id) > 128 {
		id = id[:128]
	}
	return id
}

func (p *Provider) checkClient(r *http.Request, allowPublic bool) (*clientEntry, *oauthError) {
	form := r.PostForm
	var id, secret, used string
	haveSecret := false
	methods := 0
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, cred, _ := strings.Cut(h, " ")
		if !strings.EqualFold(scheme, "Basic") {
			return nil, errInvalidClient("unsupported authorization scheme")
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
		if err != nil {
			return nil, errInvalidClient("malformed Basic credentials")
		}
		u, pw, ok := strings.Cut(string(raw), ":")
		if !ok {
			return nil, errInvalidClient("malformed Basic credentials")
		}
		// RFC 6749 §2.3.1: both parts are form-urlencoded before Base64.
		if id, err = url.QueryUnescape(u); err != nil {
			return nil, errInvalidClient("malformed Basic credentials")
		}
		if secret, err = url.QueryUnescape(pw); err != nil {
			return nil, errInvalidClient("malformed Basic credentials")
		}
		haveSecret, used = true, model.AuthMethodSecretBasic
		methods++
		if v := form.Get("client_id"); v != "" && v != id {
			return nil, errInvalidClient("client_id mismatch")
		}
	}
	if v := form.Get("client_secret"); v != "" {
		if methods > 0 {
			return nil, oerr("invalid_request", "use exactly one client authentication method")
		}
		id, secret, haveSecret, used = form.Get("client_id"), v, true, model.AuthMethodSecretPost
		methods++
	}
	assertion := form.Get("client_assertion")
	if assertion != "" {
		if methods > 0 || form.Get("client_assertion_type") != assertionType {
			return nil, oerr("invalid_request", "use exactly one client authentication method")
		}
		methods++
	}
	ctx := r.Context()
	org := web.Org(r)
	if methods == 0 {
		// Public clients identify themselves by client_id alone; a confidential client never falls back to this.
		if allowPublic {
			if cid := form.Get("client_id"); cid != "" {
				if e, err := p.client(ctx, org.ID, cid); err == nil && e.c.Enabled && e.c.Public() {
					return e, nil
				}
			}
		}
		return nil, errInvalidClient("client authentication required")
	}
	if assertion != "" {
		return p.authAssertion(ctx, org.ID, form.Get("client_id"), assertion, p.requestURL(r))
	}
	e, err := p.client(ctx, org.ID, id)
	if err != nil && !gone(err) { // the client could not be read (the store refused or failed): not "invalid"
		return nil, serverError(unavailable(err))
	}
	if err != nil || !e.c.Enabled {
		return nil, errInvalidClient("unknown client or wrong credentials")
	}
	// The client authenticates the way it was registered to (token_endpoint_auth_method), nothing else.
	if !haveSecret || used != e.c.AuthMethod || secret == "" || !service.VerifyClientSecret(e.c, secret) {
		return nil, errInvalidClient("unknown client or wrong credentials")
	}
	return e, nil
}

// authAssertion verifies an RFC 7523 private_key_jwt client assertion of a client of organization orgID, presented at
// endpoint (the URL of the endpoint called: the token, PAR, introspection or revocation endpoint).
func (p *Provider) authAssertion(ctx context.Context, orgID, formClientID, assertion, endpoint string) (*clientEntry, *oauthError) {
	bad := errInvalidClient("invalid client assertion")
	pj, err := ParseJWT(assertion)
	if err != nil {
		return nil, bad
	}
	var cl Claims
	if err := json.Unmarshal(pj.Payload, &cl); err != nil || cl.Iss == "" || cl.Iss != cl.Sub {
		return nil, bad
	}
	if formClientID != "" && formClientID != cl.Iss {
		return nil, bad
	}
	e, err := p.client(ctx, orgID, cl.Iss)
	if err != nil && !gone(err) {
		return nil, serverError(unavailable(err))
	}
	if err != nil || !e.c.Enabled || e.c.AuthMethod != model.AuthMethodPrivateJWT {
		return nil, bad
	}
	if !p.verifyWithClientKeys(ctx, e, pj) {
		return nil, bad
	}
	// FAPI 2.0 §5.3.2.1: the issuer alone, as a string, is the audience (an assertion made for another server's
	// token endpoint cannot be replayed here), and RS256 is not allowed.
	if e.c.FAPI && (pj.Header.Alg == AlgRS256 || !audIsIssuer(pj.Payload, p.issuer(orgID))) {
		return nil, errInvalidClient("a FAPI 2.0 client's assertion needs aud set to the issuer alone, and an algorithm other than RS256")
	}
	now := time.Now()
	exp := time.Unix(int64(cl.Exp), 0)
	if cl.Exp == 0 || now.After(exp.Add(leeway)) || exp.After(now.Add(5*time.Minute+leeway)) {
		return nil, errInvalidClient("assertion expired or valid for too long")
	}
	if cl.Iat != 0 && time.Unix(int64(cl.Iat), 0).After(now.Add(leeway)) ||
		cl.Nbf != 0 && time.Unix(int64(cl.Nbf), 0).After(now.Add(leeway)) {
		return nil, errInvalidClient("assertion not yet valid")
	}
	// RFC 7523 §3: the audience identifies this server (here, the organization): its issuer, its token endpoint (the
	// usual choice), or the endpoint the assertion is presented at (RFC 9126 §2 for PAR; libraries do the same for introspection and
	// revocation).
	if !cl.Aud.Has(p.tokenURL(orgID)) && !cl.Aud.Has(p.issuer(orgID)) && !cl.Aud.Has(endpoint) {
		return nil, errInvalidClient("assertion audience must be the issuer, the token endpoint or the endpoint called")
	}
	if cl.Jti == "" || len(cl.Jti) > 256 {
		return nil, errInvalidClient("assertion needs a jti")
	}
	first, err := p.svc.UseOnce(ctx, "jti|"+e.c.ID+"|"+cl.Jti, time.Now().Add(max(time.Until(exp), 0)+2*leeway))
	if err != nil {
		return nil, &oauthError{status: http.StatusServiceUnavailable, code: "temporarily_unavailable"}
	}
	if !first {
		return nil, errInvalidClient("assertion already used")
	}
	return e, nil
}

// audIsIssuer reports whether the aud claim of payload is the string iss (not an array holding it).
func audIsIssuer(payload []byte, iss string) bool {
	var cl struct {
		Aud json.RawMessage `json:"aud"`
	}
	var aud string
	return json.Unmarshal(payload, &cl) == nil && len(cl.Aud) > 0 && cl.Aud[0] == '"' &&
		json.Unmarshal(cl.Aud, &aud) == nil && aud == iss
}

// verifyWithClientKeys verifies pj against the client's registered keys (inline JWKS first, then jwks_uri).
func (p *Provider) verifyWithClientKeys(ctx context.Context, e *clientEntry, pj *Parsed) bool {
	try := func(keys []pubKey) (matched, ok bool) {
		for _, k := range keys {
			if k.alg != pj.Header.Alg || (pj.Header.Kid != "" && k.kid != "" && k.kid != pj.Header.Kid) {
				continue
			}
			matched = true
			if pj.Verify(k.pub) == nil {
				return true, true
			}
		}
		return matched, false
	}
	if _, ok := try(e.keys); ok {
		return true
	}
	if e.c.JWKSURI == "" {
		return false
	}
	keys := p.remoteKeys(ctx, e.c.JWKSURI, false)
	matched, ok := try(keys)
	if ok {
		return true
	}
	// A key rotation at the client shows up as a kid we have not seen: refetch (rate limited). A bad signature
	// from a known kid (or, without a kid, from a key of the right algorithm) never triggers outbound traffic.
	if pj.Header.Kid != "" {
		for _, k := range keys {
			if k.kid == pj.Header.Kid {
				return false
			}
		}
	} else if matched {
		return false
	}
	_, ok = try(p.remoteKeys(ctx, e.c.JWKSURI, true))
	return ok
}

// ---------------------------------------------------------------------------------------------------------------
// Remote JWKS (jwks_uri) with a small cache

type remoteJWKS struct {
	keys     []pubKey
	fetched  time.Time
	forced   time.Time
	retryAt  time.Time // no fetch before this after a failure (exponential backoff)
	fails    int
	fetching chan struct{} // closed when the fetch under way ends: callers meanwhile wait for it, not fetch too
}

const (
	jwksTTL      = 10 * time.Minute
	jwksMaxBytes = 64 << 10
)

// Variables so tests can shorten them. Failed fetches back off jwksForceEvery * 2^(fails-1), capped at jwksBackoffMax.
var (
	jwksForceEvery = 30 * time.Second
	jwksBackoffMax = 10 * time.Minute
)

func (p *Provider) remoteKeys(ctx context.Context, uri string, force bool) []pubKey {
	p.jwksMu.Lock()
	rj := p.remoteKey[uri]
	now := time.Now()
	if rj != nil && ((!force && now.Sub(rj.fetched) < jwksTTL) || (force && now.Sub(rj.forced) < jwksForceEvery)) {
		keys := rj.keys
		p.jwksMu.Unlock()
		return keys
	}
	if rj != nil && now.Before(rj.retryAt) { // backing off after a failed fetch
		keys := rj.keys
		p.jwksMu.Unlock()
		return keys
	}
	if rj == nil {
		if len(p.remoteKey) > 5000 {
			clear(p.remoteKey)
		}
		rj = &remoteJWKS{}
		p.remoteKey[uri] = rj
	}
	cached := func() []pubKey {
		p.jwksMu.Lock()
		defer p.jwksMu.Unlock()
		return rj.keys
	}
	if wait := rj.fetching; wait != nil { // another request is fetching these keys: its answer is this one's too
		p.jwksMu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
		}
		return cached()
	}
	rj.forced = now
	done := make(chan struct{})
	rj.fetching = done
	p.jwksMu.Unlock()
	defer func() {
		p.jwksMu.Lock()
		rj.fetching = nil
		p.jwksMu.Unlock()
		close(done)
	}()
	fail := func() {
		p.jwksMu.Lock()
		rj.fails++
		d := jwksBackoffMax
		if rj.fails < 32 {
			d = min(jwksForceEvery<<(rj.fails-1), jwksBackoffMax)
		}
		rj.retryAt = time.Now().Add(d)
		p.jwksMu.Unlock()
	}
	body, err := p.fetch(ctx, uri, jwksMaxBytes)
	if err != nil {
		p.log.Warn("oidc: fetching client jwks", "uri", uri, "error", err)
		fail()
		return cached()
	}
	jwks, err := ParseJWKS(body)
	if err != nil {
		p.log.Warn("oidc: parsing client jwks", "uri", uri, "error", err)
		fail()
		return cached()
	}
	keys := parseKeys(jwks)
	p.jwksMu.Lock()
	rj.keys, rj.fetched, rj.fails, rj.retryAt = keys, time.Now(), 0, time.Time{}
	p.jwksMu.Unlock()
	return keys
}

func (p *Provider) fetch(ctx context.Context, uri string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("response too large")
	}
	return b, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Outbound HTTP with an SSRF guard

func (p *Provider) safeClient() *http.Client {
	return secure.OutboundClient(p.cfg.OutboundReach, p.roots, p.log)
}
