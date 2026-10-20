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
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// Ephemeral namespaces.
const (
	nsFlow     = "oauth.flow"
	nsCode     = "oauth.code"
	nsUsed     = "oauth.used" // code id -> grant id, to revoke on replay
	nsRateOIDC = "oauth.rate" // failed client authentications per IP
	nsJTI      = "jti"
	nsLogout   = "oauth.logout"
	flowTTL    = 20 * time.Minute
	usedTTL    = time.Hour
	cacheTTL   = 30 * time.Second // clients; hooks evict sooner
	shortTTL   = 5 * time.Second  // users, orgs
	grantTTL   = 3 * time.Second  // grant-alive checks for introspection / userinfo
	leeway     = 30 * time.Second
	maxScopes  = 64
)

// Provider is the OIDC provider module.
type Provider struct {
	s   *web.Server
	svc *service.Service
	cfg *config.Config
	log logger.Logger

	verified verifiedCache // access tokens whose signature has been checked (verifycache.go)

	// HTTP fetches client JWKS documents and delivers back-channel logout tokens. The default refuses connections to
	// loopback, private and link-local addresses unless AllowPrivateNetworks is set (SSRF guard). Tests replace it.
	HTTP *http.Client
	// AllowPrivateNetworks lets the default HTTP client reach RFC 1918 / loopback hosts (internal relying parties).
	AllowPrivateNetworks bool
	roots                *x509.CertPool // system roots plus server.extra_ca_file (nil: system roots)

	keySet        atomic.Pointer[keySet]
	keyMu         sync.Mutex
	lastKIDReload atomic.Int64
	jwksCache     atomic.Pointer[jwksSnapshot]
	shortKeys     atomic.Bool // ShortCaches: re-read signing keys every few seconds
	origins       atomic.Pointer[originSet]
	shortOrigins  atomic.Bool // origins are re-read after shortTTL, not a minute (ShortCaches)

	clients *ttlCache[*clientEntry]
	users   *ttlCache[*model.User]
	orgs    *ttlCache[*model.Org]
	tenants *ttlCache[*model.Tenant]
	grants  *ttlCache[bool]
	groups  *ttlCache[groupEntry]
	memGen  sync.Map // org id -> *atomic.Uint64, bumped by InvalidateMembership
	memAll  atomic.Uint64

	jwksMu    sync.Mutex
	remoteKey map[string]*remoteJWKS

	bcWG  sync.WaitGroup
	bcSem chan struct{}

	discovery []byte
	issuer    string
	tokenURL  string
}

// New builds the provider for server s. Register mounts its routes.
func New(s *web.Server) *Provider {
	p := &Provider{s: s, svc: s.Svc, cfg: s.Cfg, log: s.Log, issuer: s.Cfg.Issuer(),
		clients: newTTLCache[*clientEntry](cacheTTL, 50_000), users: newTTLCache[*model.User](shortTTL, 200_000),
		orgs: newTTLCache[*model.Org](shortTTL, 20_000), tenants: newTTLCache[*model.Tenant](shortTTL, 20_000), grants: newTTLCache[bool](grantTTL, 200_000), groups: newTTLCache[groupEntry](shortTTL, 200_000),
		remoteKey: map[string]*remoteJWKS{}, bcSem: make(chan struct{}, 32)}
	p.tokenURL = p.issuer + "/oauth/token"
	p.roots, _ = secure.RootPool(s.Cfg.Server.ExtraCAFile) // checked by config.Validate
	p.HTTP = p.safeClient()
	p.discovery = p.buildDiscovery()
	return p
}

// ShortCaches bounds the client and CORS origin caches like the user and organization caches (5s). Nodes that share a database
// without gossip call it: they are never told about another node's changes, so a cache entry's age is the only
// bound on how long a disabled client or a rotated secret keeps working there.
func (p *Provider) ShortCaches() {
	p.clients.mu.Lock()
	p.clients.ttl = shortTTL
	p.clients.mu.Unlock()
	p.shortKeys.Store(true) // a key rotated by another node is published (and used) here within seconds
	p.shortOrigins.Store(true)
}

// InvalidateClient evicts a cached client ("" = all).
func (p *Provider) InvalidateClient(id string) {
	p.origins.Store(nil)
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

// Wait blocks until in-flight back-channel logout deliveries finish (shutdown, tests).
func (p *Provider) Wait() { p.bcWG.Wait() }

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
	// A node that may not change replicated data now (catching up after a start, a new node copying the cluster's
	// data) leaves keys to the housekeeping leader: a key it made from its own, possibly incomplete, view would be
	// one more for every node.
	if p.svc.CanWrite() {
		if err := p.EnsureKeys(context.Background()); err != nil {
			p.log.Error("oidc: ensuring signing keys", "error", err)
		}
	}
	m := s.Mux
	m.HandleFunc("GET /.well-known/openid-configuration", p.handleDiscovery)
	m.HandleFunc("GET /.well-known/oauth-authorization-server", p.handleDiscovery)
	m.HandleFunc("OPTIONS /.well-known/openid-configuration", handlePreflight)
	m.HandleFunc("OPTIONS /.well-known/oauth-authorization-server", handlePreflight)
	m.HandleFunc("GET /oauth/jwks", p.handleJWKS)
	m.HandleFunc("OPTIONS /oauth/jwks", handlePreflight)

	m.HandleFunc("GET /oauth/authorize", p.handleAuthorize)
	m.HandleFunc("POST /oauth/authorize", p.handleAuthorize)
	m.HandleFunc("GET /oauth/authorize/resume", p.handleResume)
	m.Handle("GET /oauth/consent", s.RequirePage(p.handleConsentPage))
	m.Handle("POST /api/oauth/consent", s.RequireAPI(p.handleConsent))

	m.HandleFunc("POST /oauth/token", p.handleToken)
	m.HandleFunc("OPTIONS /oauth/token", p.handleCORSPreflight)
	m.HandleFunc("OPTIONS /oauth/revoke", p.handleCORSPreflight)
	m.HandleFunc("OPTIONS /oauth/userinfo", p.handleCORSPreflight)
	m.HandleFunc("GET /oauth/userinfo", p.handleUserinfo)
	m.HandleFunc("POST /oauth/userinfo", p.handleUserinfo)
	m.HandleFunc("POST /oauth/introspect", p.handleIntrospect)
	m.HandleFunc("POST /oauth/revoke", p.handleRevoke)

	m.HandleFunc("GET /oauth/logout", p.handleLogout)
	m.HandleFunc("POST /oauth/logout", p.handleLogout)
	m.Handle("POST /oauth/logout/confirm", s.WithSession(http.HandlerFunc(p.handleLogoutConfirm)))
}

// ---------------------------------------------------------------------------------------------------------------
// Cached lookups

func (p *Provider) user(ctx context.Context, id string) (*model.User, error) {
	if u, ok := p.users.get(id); ok {
		return u, nil
	}
	u, err := p.svc.Users.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	p.users.put(id, u)
	return u, nil
}

func (p *Provider) org(ctx context.Context, id string) (*model.Org, error) {
	if o, ok := p.orgs.get(id); ok {
		return o, nil
	}
	o, err := p.svc.Orgs.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	p.orgs.put(id, o)
	return o, nil
}

// clientTenant is service.ClientTenant through a short cache (a tenant is read on every token request).
func (p *Provider) clientTenant(ctx context.Context, c *model.Client) (*model.Tenant, error) {
	if t, ok := p.tenants.get(c.TenantID); ok && t.OrgID == c.OrgID {
		return t, nil
	}
	t, err := p.svc.ClientTenant(ctx, c)
	if err != nil {
		return nil, err
	}
	p.tenants.put(t.ID, t)
	return t, nil
}

// grantAlive reports whether a refresh grant still exists (not revoked, not expired).
func (p *Provider) grantAlive(ctx context.Context, id string) bool {
	if v, ok := p.grants.get(id); ok {
		return v
	}
	g, err := p.svc.Grants.Get(ctx, id)
	alive := err == nil && !g.Revoked
	if err == nil || errors.Is(err, store.ErrNotFound) {
		p.grants.put(id, alive)
	}
	return alive
}

// ---------------------------------------------------------------------------------------------------------------
// TTL cache

type ttlItem[T any] struct {
	v   T
	exp int64 // unix nanos
}

type ttlCache[T any] struct {
	mu  sync.RWMutex
	m   map[string]ttlItem[T]
	ttl time.Duration
	max int
}

func newTTLCache[T any](ttl time.Duration, max int) *ttlCache[T] {
	return &ttlCache[T]{m: map[string]ttlItem[T]{}, ttl: ttl, max: max}
}

func (c *ttlCache[T]) get(k string) (v T, ok bool) {
	c.mu.RLock()
	it, found := c.m[k]
	c.mu.RUnlock()
	if !found || time.Now().UnixNano() > it.exp {
		return v, false
	}
	return it.v, true
}

func (c *ttlCache[T]) put(k string, v T) {
	c.mu.Lock()
	if len(c.m) >= c.max {
		now := time.Now().UnixNano()
		for key, it := range c.m {
			if now > it.exp {
				delete(c.m, key)
			}
		}
		if len(c.m) >= c.max { // still full of live entries: start over rather than grow without bound
			clear(c.m)
		}
	}
	c.m[k] = ttlItem[T]{v: v, exp: time.Now().Add(c.ttl).UnixNano()}
	c.mu.Unlock()
}

func (c *ttlCache[T]) del(k string) {
	c.mu.Lock()
	delete(c.m, k)
	c.mu.Unlock()
}

func (c *ttlCache[T]) clear() {
	c.mu.Lock()
	clear(c.m)
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------------------------------------------
// Discovery and JWKS

func (p *Provider) buildDiscovery() []byte {
	iss := p.issuer
	d := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth/authorize",
		"token_endpoint":                        iss + "/oauth/token",
		"userinfo_endpoint":                     iss + "/oauth/userinfo",
		"jwks_uri":                              iss + "/oauth/jwks",
		"introspection_endpoint":                iss + "/oauth/introspect",
		"revocation_endpoint":                   iss + "/oauth/revoke",
		"end_session_endpoint":                  iss + "/oauth/logout",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{AlgES256, AlgEdDSA, AlgRS256},
		"token_endpoint_auth_methods_supported": []string{model.AuthMethodSecretPost, model.AuthMethodSecretBasic,
			model.AuthMethodPrivateJWT, model.AuthMethodNone},
		"token_endpoint_auth_signing_alg_values_supported":         []string{AlgES256, AlgEdDSA, AlgRS256},
		"introspection_endpoint_auth_methods_supported":            []string{model.AuthMethodSecretPost, model.AuthMethodSecretBasic, model.AuthMethodPrivateJWT},
		"introspection_endpoint_auth_signing_alg_values_supported": []string{AlgES256, AlgEdDSA, AlgRS256},
		// public clients revoke their own tokens (RFC 7009 §2.1); introspection is for confidential clients only
		"revocation_endpoint_auth_methods_supported": []string{model.AuthMethodSecretPost, model.AuthMethodSecretBasic, model.AuthMethodPrivateJWT,
			model.AuthMethodNone},
		"revocation_endpoint_auth_signing_alg_values_supported": []string{AlgES256, AlgEdDSA, AlgRS256},
		"code_challenge_methods_supported":                      []string{"S256"},
		"scopes_supported":                                      []string{"openid", "profile", "email", "phone", "groups", "org", "enterprise", "offline_access"},
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid", "org",
			"org_name", "tenant", "tenant_name", "role", "email", "email_verified", "name", "preferred_username", "given_name", "family_name",
			"locale", "zoneinfo", "updated_at", "phone_number", "phone_number_verified", "groups", "tags", "roles", "enterprise"},
		"prompt_values_supported":                        []string{"none", "login", "consent", "select_account"},
		"claim_types_supported":                          []string{"normal"},
		"claims_parameter_supported":                     true,
		"acr_values_supported":                           []string{acrBasic, acrMFA},
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
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

func (p *Provider) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(p.discovery)
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
