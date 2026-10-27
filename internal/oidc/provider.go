// Package oidc is the OAuth 2.0 / OpenID Connect provider: signing keys, a small JWT implementation, the
// authorization, token, userinfo, introspection, revocation and logout endpoints, and back-channel logout.
//
// Wiring: p := oidc.New(srv); srv.Use(p). The cluster layer calls Invalidate / InvalidateClient / InvalidateUser /
// InvalidateOrg when the corresponding records change, and the elected leader calls EnsureKeys periodically.
package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/evictgen"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/queue"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// Ephemeral namespaces.
const (
	nsFlow     = "oauth.flow"
	nsCode     = "oauth.code"
	nsUsed     = "oauth.used"     // code id -> grant id, to revoke on replay
	nsReplayed = "oauth.replayed" // code id presented again: a redemption still under way revokes what it makes
	nsRateOIDC = "oauth.rate"     // failed client authentications per IP
	nsLogout   = "oauth.logout"
	flowTTL    = 20 * time.Minute
	usedTTL    = time.Hour
	// cacheTTL bounds every cache of stored data here (clients, users, organizations, tenants, groups, the public
	// clients' origins, the signing keys): a change made elsewhere counts here within it, whatever the store; a change
	// this node hears of (cache eviction hooks) counts at once.
	cacheTTL  = 5 * time.Second
	grantTTL  = 3 * time.Second // grant-alive checks for introspection / userinfo
	leeway    = 30 * time.Second
	maxScopes = 64
)

// Provider is the OIDC provider module.
type Provider struct {
	s   *web.Server
	svc *service.Service
	cfg *config.Config
	log logger.Logger

	verified verifiedCache // access tokens whose signature has been checked (verifycache.go)

	// HTTP fetches client JWKS documents and delivers back-channel logout tokens. The default refuses connections to
	// loopback, private and link-local addresses but those server.allowed_networks and server.allow_private_networks
	// allow (SSRF guard: config.OutboundReach, read at each connection). Tests replace it.
	HTTP  *http.Client
	roots *x509.CertPool // system roots plus server.extra_ca_file (nil: system roots)

	keySet        atomic.Pointer[keySet]
	keyMu         sync.Mutex
	genMu         sync.Mutex // guards keyGen with keySet: a load that began before an Invalidate never installs its result
	keyGen        uint64     // bumped by Invalidate
	lastKIDReload atomic.Int64
	jwksCache     atomic.Pointer[jwksSnapshot]

	clients *ttlCache[*clientEntry]
	origins *ttlCache[*originSet] // by organization id: the origins of its public clients (cors.go)
	users   *ttlCache[*model.User]
	orgs    *ttlCache[*model.Org]
	tenants *ttlCache[*model.Tenant]
	grants  *ttlCache[grantState]
	groups  *ttlCache[groupEntry]
	memGen  sync.Map // org id -> *atomic.Uint64, bumped by InvalidateMembership
	memAll  atomic.Uint64

	jwksMu    sync.Mutex
	remoteKey map[string]*remoteJWKS

	bcWG      sync.WaitGroup            // back-channel logouts queued or being sent
	bcQueue   chan bcTarget             // waiting to be sent (bcQueueMax)
	bcMu      sync.Mutex                // guards bcWorkers
	bcWorkers int                       // senders running (at most bcWorkersMax; none while nothing waits)
	bcRetry   *queue.Queue[LogoutRetry] // failed logouts waiting to be tried again (OpenLogoutQueue; nil: none)

}

// New builds the provider for server s. Register mounts its routes.
func New(s *web.Server) *Provider {
	p := &Provider{s: s, svc: s.Svc, cfg: s.Cfg, log: s.Log,
		clients: newTTLCache[*clientEntry](cacheTTL, 50_000), origins: newTTLCache[*originSet](cacheTTL, 20_000), users: newTTLCache[*model.User](cacheTTL, 200_000),
		orgs: newTTLCache[*model.Org](cacheTTL, 20_000), tenants: newTTLCache[*model.Tenant](cacheTTL, 20_000), grants: newTTLCache[grantState](grantTTL, 200_000), groups: newTTLCache[groupEntry](cacheTTL, 200_000),
		remoteKey: map[string]*remoteJWKS{}, bcQueue: make(chan bcTarget, bcQueueMax)}
	p.roots, _ = secure.RootPool(s.Cfg.Server.ExtraCAFile) // checked by config.Validate
	p.HTTP = p.safeClient()
	return p
}

// InvalidateClient evicts a cached client ("" = all).
func (p *Provider) InvalidateClient(id string) {
	p.origins.clear() // a record id does not say whose organization's origins changed
	if id == "" {
		p.clients.clear()
		return
	}
	p.clients.del(id)
}

// InvalidateUser evicts a cached user.
func (p *Provider) InvalidateUser(id string) { p.users.del(id) }

// InvalidateOrg evicts a cached organization.
func (p *Provider) InvalidateOrg(id string) { p.orgs.del(id) }

// InvalidateTenant evicts a cached tenant.
func (p *Provider) InvalidateTenant(id string) { p.tenants.del(id) }

// InvalidateGrant evicts the cached "grant exists" answer for a grant.
func (p *Provider) InvalidateGrant(id string) { p.grants.del(id) }

type groupEntry struct {
	ids   []string
	names []string
	tags  []string // union of the tags of the user's groups, sorted
	gen   uint64
}

func (p *Provider) membershipGen(orgID string) uint64 {
	g := p.memAll.Load()
	if v, ok := p.memGen.Load(orgID); ok {
		g += v.(*atomic.Uint64).Load()
	}
	return g
}

// InvalidateMembership drops every cached group list of an organization (call when a group or member record
// changes; "" drops them all). Without it a changed membership appears in new tokens within the cache TTL (5 s).
func (p *Provider) InvalidateMembership(orgID string) {
	if orgID == "" {
		p.memAll.Add(1)
		return
	}
	v, _ := p.memGen.LoadOrStore(orgID, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
}

// Wait blocks until the back-channel logouts queued or being sent are done (tests, shutdown), for at most
// bcShutdownWait: a shutdown is not held up for long by relying parties that do not answer.
func (p *Provider) Wait() {
	done := make(chan struct{})
	go func() { p.bcWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(bcShutdownWait):
		p.log.Warn("oidc: back-channel logouts still queued at shutdown were not sent", "queued", len(p.bcQueue))
	}
}

// Register mounts the routes.
func (p *Provider) Register(s *web.Server) {
	if p.s == nil {
		p.s, p.svc, p.cfg, p.log = s, s.Svc, s.Cfg, s.Log
	}
	// Every ended session (sign-out, revoke, password reset, disabled or deleted user) notifies its relying parties.
	p.svc.OnSessionsEnding = func(ctx context.Context, userID string, sessionIDs []string) {
		if sessionIDs == nil {
			p.BackchannelLogoutUser(ctx, userID)
		} else {
			p.BackchannelLogout(ctx, sessionIDs...)
		}
	}
	// So does a user removing one application's access from their account.
	p.svc.OnAppAccessEnding = p.BackchannelLogoutClient
	// A store that refuses now (still starting, say) leaves the keys to the housekeeping leader's rotation and to the
	// first token signed.
	if err := p.EnsureKeys(context.Background()); errors.Is(err, store.ErrUnavailable) {
		p.log.Warn("oidc: signing keys not checked at start-up: the store refused; they are checked again later", "error", err)
	} else if err != nil {
		p.log.Error("oidc: ensuring signing keys", "error", err)
	}
	// Every endpoint is the organization's own, under /o/{org}/ (an id or a name: web.Org), with the organization's
	// issuer (issuer). The preflights of the metadata and the keys name no organization's data, so they need not
	// look one up; those that allow the origins of a public client do (handleCORSPreflight).
	m := s.Mux
	endpoint := func(method, path string, h http.Handler) { m.Handle(method+" /o/{org}"+path, s.InOrg(h)) }
	fn := func(method, path string, f http.HandlerFunc) { endpoint(method, path, f) }
	preflight := func(path string, h http.HandlerFunc) { m.HandleFunc("OPTIONS /o/{org}"+path, h) }

	// The metadata documents (RFC 8414, OpenID Connect Discovery) are served at the organization's id form only, as
	// the issuer in them is the address they were fetched from; they are also served the way RFC 8414 §3.1 inserts
	// the well-known segment between the host and the issuer's path, which is how MCP clients find them.
	for _, doc := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		for _, form := range []struct{ before, after string }{{"", doc}, {doc, ""}} {
			path := form.before + "/o/{org}" + form.after
			m.Handle("GET "+path, s.InOrg(p.handleDiscovery(form.before, form.after)))
			m.HandleFunc("OPTIONS "+path, handlePreflight)
		}
	}
	fn("GET", "/oauth/jwks", p.handleJWKS)
	preflight("/oauth/jwks", handlePreflight)

	fn("GET", "/oauth/authorize", p.handleAuthorize)
	fn("POST", "/oauth/authorize", p.handleAuthorize)
	fn("GET", "/oauth/authorize/resume", p.handleResume)
	fn("GET", "/oauth/authorize/cancel", p.handleCancel)
	endpoint("GET", "/oauth/consent", s.RequirePage(p.handleConsentPage))
	endpoint("POST", "/api-internal/oauth/consent", s.RequireAPI(p.handleConsent))

	fn("POST", "/oauth/device_authorization", p.handleDeviceAuthorization)
	fn("OPTIONS", "/oauth/device_authorization", p.handleCORSPreflight)
	fn("GET", "/device", p.handleDevicePage)
	fn("POST", "/oauth/par", p.handlePAR)
	fn("OPTIONS", "/oauth/par", p.handleCORSPreflight)
	fn("POST", "/oauth/token", p.handleToken)
	fn("OPTIONS", "/oauth/token", p.handleCORSPreflight)
	fn("OPTIONS", "/oauth/revoke", p.handleCORSPreflight)
	fn("OPTIONS", "/oauth/userinfo", p.handleCORSPreflight)
	fn("GET", "/oauth/userinfo", p.handleUserinfo)
	fn("POST", "/oauth/userinfo", p.handleUserinfo)
	fn("POST", "/oauth/introspect", p.handleIntrospect)
	fn("POST", "/oauth/revoke", p.handleRevoke)
	fn("POST", "/oauth/register", p.handleRegister)

	fn("GET", "/oauth/logout", p.handleLogout)
	fn("POST", "/oauth/logout", p.handleLogout)
	endpoint("POST", "/oauth/logout/confirm", s.WithSession(http.HandlerFunc(p.handleLogoutConfirm)))
}

// ---------------------------------------------------------------------------------------------------------------
// Cached lookups

func (p *Provider) user(ctx context.Context, id string) (*model.User, error) {
	if u, ok := p.users.get(id); ok {
		return u, nil
	}
	tok := p.users.token(id)
	u, err := p.svc.Users.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	p.users.putIf(id, u, tok)
	return u, nil
}

func (p *Provider) org(ctx context.Context, id string) (*model.Org, error) {
	if o, ok := p.orgs.get(id); ok {
		return o, nil
	}
	tok := p.orgs.token(id)
	o, err := p.svc.Orgs.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	p.orgs.putIf(id, o, tok)
	return o, nil
}

// clientTenant is service.ClientTenant through a short cache (a tenant is read on every token request).
func (p *Provider) clientTenant(ctx context.Context, c *model.Client) (*model.Tenant, error) {
	if t, ok := p.tenants.get(c.TenantID); ok && t.OrgID == c.OrgID {
		return t, nil
	}
	tok := p.tenants.token(c.TenantID)
	t, err := p.svc.ClientTenant(ctx, c)
	if err != nil {
		return nil, err
	}
	if t.ID == c.TenantID {
		p.tenants.putIf(t.ID, t, tok)
	}
	return t, nil
}

// grantAlive reports whether a refresh grant still exists (not revoked, not expired). An error means it could not
// be read (the grant, or the sign-out counters its stamp is compared with): the caller answers 503, never "alive"
// on a guess nor "ended" for a token that may well be good. Only an answer is cached: a failed read is asked again.
func (p *Provider) grantAlive(ctx context.Context, id string, u *model.User) (bool, error) {
	st, ok := p.grants.get(id)
	if !ok {
		tok := p.grants.token(id)
		g, err := p.svc.Grants.Get(ctx, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return false, unavailable(err)
		}
		if err == nil {
			st = grantState{alive: true, org: g.OrgID, stamp: g.Stamp, epoch: g.Epoch}
		}
		p.grants.putIf(id, st, tok)
	}
	if !st.alive || !u.SessionHolds(st.epoch) { // (a grant of an ended session epoch: model.User.SessionEpoch)
		return false, nil
	}
	// The stamp is compared on every use, cached or not: an emergency sign-out ends the grant's tokens at once.
	want, err := p.svc.SessionStamp(ctx, st.org)
	if err != nil {
		return false, unavailable(err)
	}
	return st.stamp.Current(want), nil
}

// grantState is what the grant cache knows of a grant: whether it exists (not revoked), and its organization and
// sign-out stamp.
type grantState struct {
	alive bool
	org   string
	stamp model.SignOutStamp
	epoch uint64 // the session epoch it was granted in
}

// ---------------------------------------------------------------------------------------------------------------
// TTL cache

type ttlItem[T any] struct {
	v   T
	exp int64 // unix nanos
}

// ttlCache keeps entries for ttl in two generations: puts go to m, and once a ttl period (or when m holds max) m
// becomes old and the old one is dropped. Everything in old is at least that old, so what is expired goes without a
// sweep (a sweep would hold the lock, and every reader, for the whole map), and the cache holds at most 2×max.
type ttlCache[T any] struct {
	mu      sync.RWMutex
	m, old  map[string]ttlItem[T]
	ttl     time.Duration
	max     int
	rotated int64 // unix nanos when m was started (mu)
	gens    evictgen.Gens
}

func newTTLCache[T any](ttl time.Duration, max int) *ttlCache[T] {
	return &ttlCache[T]{m: map[string]ttlItem[T]{}, ttl: ttl, max: max, rotated: time.Now().UnixNano()}
}

func (c *ttlCache[T]) get(k string) (v T, ok bool) {
	c.mu.RLock()
	it, found := c.m[k]
	if !found {
		it, found = c.old[k]
	}
	c.mu.RUnlock()
	if !found || time.Now().UnixNano() > it.exp {
		return v, false
	}
	return it.v, true
}

// token is taken before the store is read for a miss of k; putIf puts the copy read only if k was not deleted (or the
// cache cleared) since, so a fill that began before an eviction cannot store the copy that eviction was for.
func (c *ttlCache[T]) token(k string) uint64 { return c.gens.Token(k) }

func (c *ttlCache[T]) putIf(k string, v T, tok uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gens.Valid(k, tok) {
		c.putLocked(k, v)
	}
}

// put stores v whatever happened meanwhile: for a value known to be current (a grant just revoked).
func (c *ttlCache[T]) put(k string, v T) {
	c.mu.Lock()
	c.putLocked(k, v)
	c.mu.Unlock()
}

func (c *ttlCache[T]) putLocked(k string, v T) {
	now := time.Now().UnixNano()
	if len(c.m) >= c.max || now-c.rotated > int64(c.ttl) {
		c.old, c.m, c.rotated = c.m, make(map[string]ttlItem[T], len(c.m)), now
	}
	delete(c.old, k) // the new value is the only one
	c.m[k] = ttlItem[T]{v: v, exp: now + int64(c.ttl)}
}

func (c *ttlCache[T]) del(k string) {
	c.mu.Lock()
	c.gens.Bump(k)
	delete(c.m, k)
	delete(c.old, k)
	c.mu.Unlock()
}

func (c *ttlCache[T]) clear() {
	c.mu.Lock()
	c.gens.BumpAll()
	clear(c.m)
	c.old = nil
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------------------------------------------
// Discovery and JWKS

// issuer is the issuer of organization orgID (Config.OrgIssuer): its tokens carry it as iss, and every endpoint of it is
// under it. A token of one organization is not another's: each checks the issuer of its own.
func (p *Provider) issuer(orgID string) string { return p.cfg.OrgIssuer(orgID) }

// issuerOrg is the id of the organization whose issuer iss is, and false for any other string.
func (p *Provider) issuerOrg(iss string) (string, bool) {
	id, ok := strings.CutPrefix(iss, p.cfg.OrgIssuer(""))
	return id, ok && model.IsID(id)
}

// requestURL is the absolute URL a request was made to (the DPoP proofs and client assertions of the request name it).
func (p *Provider) requestURL(r *http.Request) string { return p.cfg.Server.PublicURL + r.URL.Path }

// tokenURL is the token endpoint of organization orgID.
func (p *Provider) tokenURL(orgID string) string { return p.cfg.OrgEndpoints(orgID).Token }

// buildDiscovery is the metadata document of organization orgID: its issuer and the endpoints under it
// (Config.OrgEndpoints, which the console shows too).
func (p *Provider) buildDiscovery(orgID string) []byte {
	e := p.cfg.OrgEndpoints(orgID)
	d := map[string]any{
		"issuer":                                e.Issuer,
		"authorization_endpoint":                e.Authorization,
		"token_endpoint":                        e.Token,
		"userinfo_endpoint":                     e.UserInfo,
		"jwks_uri":                              e.JWKS,
		"introspection_endpoint":                e.Introspection,
		"registration_endpoint":                 e.Registration,
		"revocation_endpoint":                   e.Revocation,
		"end_session_endpoint":                  e.EndSession,
		"pushed_authorization_request_endpoint": e.PAR,
		"device_authorization_endpoint":         e.DeviceAuthorization,
		"require_pushed_authorization_requests": false, // per client (require_pushed_authorization_requests)
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query", "form_post"},
		"grant_types_supported": []string{"authorization_code", "refresh_token", "client_credentials",
			service.GrantTokenExchange, service.GrantDeviceCode},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": allAlgs,
		"token_endpoint_auth_methods_supported": []string{model.AuthMethodSecretPost, model.AuthMethodSecretBasic,
			model.AuthMethodPrivateJWT, model.AuthMethodNone},
		"token_endpoint_auth_signing_alg_values_supported":         allAlgs,
		"introspection_endpoint_auth_methods_supported":            []string{model.AuthMethodSecretPost, model.AuthMethodSecretBasic, model.AuthMethodPrivateJWT},
		"introspection_endpoint_auth_signing_alg_values_supported": allAlgs,
		// public clients revoke their own tokens (RFC 7009 §2.1); introspection is for confidential clients only
		"revocation_endpoint_auth_methods_supported": []string{model.AuthMethodSecretPost, model.AuthMethodSecretBasic, model.AuthMethodPrivateJWT,
			model.AuthMethodNone},
		"revocation_endpoint_auth_signing_alg_values_supported": allAlgs,
		"code_challenge_methods_supported":                      []string{"S256"},
		"dpop_signing_alg_values_supported":                     dpopAlgs,
		// a client_id may be the https URL of the client's metadata document (MCP's Client ID Metadata Documents)
		"client_id_metadata_document_supported": true,
		"scopes_supported": []string{"openid", "profile", "email", "phone", "groups", "org", "enterprise", "offline_access",
			service.ScopeSCIM}, // scim: client credentials tokens of SCIM provisioning clients
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid", "org",
			"org_name", "tenant", "tenant_name", "role", "email", "email_verified", "name", "preferred_username", "given_name", "family_name",
			"locale", "zoneinfo", "updated_at", "phone_number", "phone_number_verified", "groups", "tags", "roles", "enterprise"},
		"prompt_values_supported":                        []string{"none", "login", "consent", "select_account"},
		"claim_types_supported":                          []string{"normal"},
		"claims_parameter_supported":                     true,
		"acr_values_supported":                           []string{acrBasic, acrMFA},
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false, // only the request_uri of a pushed request
		"authorization_response_iss_parameter_supported": true,
		"backchannel_logout_supported":                   true,
		"backchannel_logout_session_supported":           true,
		"frontchannel_logout_supported":                  false,
	}
	b, _ := json.Marshal(d)
	return b
}

func setCORS(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Max-Age", "86400")
}

func handlePreflight(w http.ResponseWriter, _ *http.Request) {
	setCORS(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleDiscovery serves the metadata document of the organization at /o/<org> with before in front of it and after
// behind it ("" and the well-known path, or the other way round: RFC 8414 §3.1). A document is only served where the
// issuer in it is the address: a request that names the organization by its name is sent to the id form.
func (p *Provider) handleDiscovery(before, after string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		org := web.Org(r)
		if r.PathValue("org") != org.ID {
			target := before + web.OrgPath(org.ID, after)
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(p.buildDiscovery(org.ID))
	}
}

func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	b, err := p.jwksJSON(r.Context())
	if err != nil {
		web.WriteJSON(w, http.StatusServiceUnavailable, web.ErrorBody{Error: "keys unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

// ---------------------------------------------------------------------------------------------------------------
// Small helpers shared by the endpoints

func splitScope(s string) []string {
	f := strings.Fields(s)
	if len(f) > maxScopes {
		return f[:maxScopes]
	}
	return f
}

// subset reports whether every element of sub is in super.
func subset(sub, super []string) bool {
	for _, s := range sub {
		if !slices.Contains(super, s) {
			return false
		}
	}
	return true
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
