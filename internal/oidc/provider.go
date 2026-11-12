// Package oidc is the OAuth 2.0 / OpenID Connect provider: signing keys, a small JWT implementation, the
// authorization, token, userinfo, introspection, revocation and logout endpoints, and back-channel logout.
//
// Wiring: p := oidc.New(srv); srv.Use(p). The cluster layer calls Invalidate / InvalidateClient / InvalidateUser /
// InvalidateTenant / InvalidateGrant / InvalidateMembership when the corresponding records change (organizations are
// the service's: service.Service.InvalidateOrgs), and the elected leader calls EnsureKeys periodically.
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
	"github.com/paularlott/quisora/internal/queue"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/ttlcache"
	"github.com/paularlott/quisora/internal/web"
)

// Ephemeral namespaces.
const (
	nsFlow     = "oauth.flow"
	nsCode     = "oauth.code"
	nsUsed     = "oauth.used"     // client and code id (replayKey) -> organization, user and grant id (NUL-separated), to revoke on replay
	nsReplayed = "oauth.replayed" // client and code id (replayKey) presented again: a redemption still under way revokes what it makes
	nsRateOIDC = "oauth.rate"     // failed client authentications per IP
	nsHeld     = "oauth.held"     // flows each client address holds (holdFlow)
	nsLogout   = "oauth.logout"
	flowTTL    = 20 * time.Minute
	usedTTL    = time.Hour
	// replayMarkTTL keeps the mark of a code presented after it was taken (nsReplayed) for as long as the redemption
	// that took it can still be running: that redemption looks for the mark once it has made its grant. A request
	// runs within the server's write timeout (60 s), so five minutes is ample. Anyone can present an unknown code, so
	// the mark is kept no longer than that, not usedTTL.
	replayMarkTTL = 5 * time.Minute
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

	clients *ttlcache.Cache[*clientEntry]
	origins *ttlcache.Cache[*originSet] // by organization id: the origins of its public clients (cors.go)
	users   *ttlcache.Cache[*model.User]
	tenants *ttlcache.Cache[*model.Tenant]
	grants  *ttlcache.Cache[grantState]
	groups  *ttlcache.Cache[groupEntry]
	memGen  sync.Map // org id -> *atomic.Uint64, bumped by InvalidateMembership
	memAll  atomic.Uint64

	// grantRoom is, by user, how many more of the user's grants this node makes before it counts them again, and
	// grantCounting the users whose grants are being counted (noteGrant).
	grantRoom     *ttlcache.Cache[*atomic.Int64]
	grantCounting sync.Map

	// originsLoads are the reads of an organization's origins under way, by organization id: a miss waits for the one
	// under way rather than reading every public client of the organization again (cors.go).
	originsMu    sync.Mutex
	originsLoads map[string]*originsLoad

	jwksMu    sync.Mutex
	remoteKey map[string]*remoteJWKS

	bcWG      sync.WaitGroup            // back-channel logouts queued, being sent or being moved to the retry queue
	bcMu      sync.Mutex                // guards the fields below up to bcRetry
	bcOrgs    map[string]*bcOrg         // organizations with logouts queued or being sent, by id
	bcTurn    []*bcOrg                  // those with logouts queued, in the order the senders serve them
	bcQueued  int                       // logouts waiting to be sent, of all (at most bcQueueMax)
	bcWorkers int                       // senders running (at most bcWorkersMax; none while nothing waits)
	bcRetry   *queue.Queue[LogoutRetry] // failed logouts waiting to be tried again (OpenLogoutQueue; nil: none)

}

// New builds the provider for server s. Register mounts its routes.
func New(s *web.Server) *Provider {
	p := &Provider{s: s, svc: s.Svc, cfg: s.Cfg, log: s.Log,
		clients: ttlcache.New[*clientEntry](cacheTTL, 50_000), origins: ttlcache.New[*originSet](cacheTTL, 20_000), users: ttlcache.New[*model.User](cacheTTL, 200_000),
		tenants: ttlcache.New[*model.Tenant](cacheTTL, 20_000), grants: ttlcache.New[grantState](grantTTL, 200_000), groups: ttlcache.New[groupEntry](cacheTTL, 200_000),
		grantRoom: ttlcache.New[*atomic.Int64](grantRoomTTL, 100_000),
		remoteKey: map[string]*remoteJWKS{}, bcOrgs: map[string]*bcOrg{}, originsLoads: map[string]*originsLoad{}}
	p.roots, _ = secure.RootPool(s.Cfg.Server.ExtraCAFile) // checked by config.Validate
	p.HTTP = p.safeClient()
	return p
}

// InvalidateClient evicts a cached client ("" = all) and every organization's origins, as a record id does not say
// whose organization's changed: InvalidateClientIn, when the organization is known.
func (p *Provider) InvalidateClient(id string) { p.InvalidateClientIn("", id) }

// InvalidateClientIn evicts a cached client ("" = all) of organization orgID and that organization's origins ("": every
// organization's, for a change that does not say whose it was, a deletion's). Only the organization whose client
// changed reads its origins again: registrations at one organization (unauthenticated) must not make every
// organization's next CORS request read all its public clients.
func (p *Provider) InvalidateClientIn(orgID, id string) {
	if orgID == "" {
		p.origins.Clear()
	} else {
		p.origins.Del(orgID)
	}
	if id == "" {
		p.clients.Clear()
		return
	}
	p.clients.Del(id)
}

// InvalidateUser evicts a cached user.
func (p *Provider) InvalidateUser(id string) { p.users.Del(id) }

// InvalidateTenant evicts a cached tenant.
func (p *Provider) InvalidateTenant(id string) { p.tenants.Del(id) }

// InvalidateGrant evicts the cached "grant exists" answer for a grant.
func (p *Provider) InvalidateGrant(id string) { p.grants.Del(id) }

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

// ForgetMembership drops the bookkeeping kept for an organization that was deleted, which InvalidateMembership
// would otherwise keep for as long as the process runs. Removing the counter alone would lower the generation
// of the organization's cached lists to one they may have been stamped with before, so the global generation is
// raised past it, dropping every list (an organization is deleted rarely).
func (p *Provider) ForgetMembership(orgID string) {
	n := uint64(1)
	if v, ok := p.memGen.LoadAndDelete(orgID); ok {
		n += v.(*atomic.Uint64).Load() // the global generation takes over what the counter contributed, and one more
	}
	p.memAll.Add(n)
}

// Wait blocks until the back-channel logouts queued or being sent are done (tests, shutdown), for a bounded time: a
// shutdown is not held up for long by relying parties that do not answer. After bcShutdownWait the logouts still
// queued in memory go to the retry queue, which sends them after the restart, and those being sent have as long
// again to end (each within its timeout; one that fails goes to the retry queue too). Call it before the retry queue
// closes.
func (p *Provider) Wait() {
	done := make(chan struct{})
	go func() { p.bcWG.Wait(); close(done) }()
	select {
	case <-done:
		return
	case <-time.After(bcShutdownWait):
	}
	if left := p.unqueue(); len(left) > 0 {
		p.bcWG.Add(1) // ended by spill
		p.spill(left, "oidc: back-channel logouts still queued at shutdown: sent from the retry queue after the"+
			" restart, or not at all if that is full")
		p.bcWG.Add(-len(left)) // no longer queued here
	}
	select {
	case <-done:
	case <-time.After(bcShutdownWait):
		p.log.Warn("oidc: back-channel logouts still being sent at shutdown: those that fail are not retried")
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

	// A tenant's SSH certificate authority: what servers and the CLI fetch, and the signing of user certificates.
	fn("GET", "/ssh/{tenant}", p.handleSSHDiscovery)
	fn("GET", "/ssh/{tenant}/ca.pub", p.handleSSHUserCA)
	fn("GET", "/ssh/{tenant}/known_hosts", p.handleSSHKnownHosts)
	fn("GET", "/ssh/{tenant}/krl", p.handleSSHKRL)
	fn("POST", "/ssh/{tenant}/sign", p.handleSSHSign)

	fn("GET", "/oauth/logout", p.handleLogout)
	fn("POST", "/oauth/logout", p.handleLogout)
	endpoint("POST", "/oauth/logout/confirm", s.WithSession(http.HandlerFunc(p.handleLogoutConfirm)))
}

// ---------------------------------------------------------------------------------------------------------------
// Cached lookups

func (p *Provider) user(ctx context.Context, id string) (*model.User, error) {
	if u, ok := p.users.Get(id); ok {
		return u, nil
	}
	tok := p.users.Token(id)
	u, err := p.svc.Users.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	p.users.PutIf(id, u, tok)
	return u, nil
}

// clientTenant is service.ClientTenant through a short cache (a tenant is read on every token request).
func (p *Provider) clientTenant(ctx context.Context, c *model.Client) (*model.Tenant, error) {
	if t, ok := p.tenants.Get(c.TenantID); ok && t.OrgID == c.OrgID {
		return t, nil
	}
	tok := p.tenants.Token(c.TenantID)
	t, err := p.svc.ClientTenant(ctx, c)
	if err != nil {
		return nil, err
	}
	if t.ID == c.TenantID {
		p.tenants.PutIf(t.ID, t, tok)
	}
	return t, nil
}

// grantAlive reports whether a refresh grant still exists (not revoked, not expired). An error means it could not
// be read (the grant, or the sign-out counters its stamp is compared with): the caller answers 503, never "alive"
// on a guess nor "ended" for a token that may well be good. Only an answer is cached: a failed read is asked again.
func (p *Provider) grantAlive(ctx context.Context, id string, u *model.User) (bool, error) {
	st, err := p.grantStateOf(ctx, id, u)
	if err != nil {
		return false, err
	}
	if !st.alive || !u.SessionHolds(st.epoch) { // (a grant of an ended session epoch: model.User.SessionEpoch)
		return false, nil
	}
	// a guest's grant stands on the accounts its sign-in came from (model.Grant.Sources), read through the user cache
	if ok, err := p.svc.SourcesHold(ctx, st.sources, p.user); err != nil || !ok {
		return false, unavailable(err)
	}
	// The stamp is compared on every use, cached or not: an emergency sign-out ends the grant's tokens at once.
	want, err := p.svc.SessionStamp(ctx, st.org)
	if err != nil {
		return false, unavailable(err)
	}
	return st.stamp.Current(want), nil
}

// grantStateOf returns what is known of grant id of user u: from the grant cache, else read (and cached).
func (p *Provider) grantStateOf(ctx context.Context, id string, u *model.User) (grantState, error) {
	st, ok := p.grants.Get(id)
	if !ok {
		tok := p.grants.Token(id)
		g, err := p.svc.Grants.GetIn(ctx, u.OrgID, id) // a grant is in its user's organization's partition
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return grantState{}, unavailable(err)
		}
		if err == nil {
			st = grantState{alive: true, org: g.OrgID, stamp: g.Stamp, epoch: g.Epoch, amr: g.AMR, upstreamAMR: g.UpstreamAMR, upstream: g.Upstream, idp: g.IdP,
				sources: g.Sources}
		}
		p.grants.PutIf(id, st, tok)
	}
	return st, nil
}

// grantState is what the grant cache knows of a grant: whether it exists (not revoked), and its organization and
// sign-out stamp.
type grantState struct {
	alive bool
	org   string
	stamp model.SignOutStamp
	epoch uint64 // the session epoch it was granted in
	// amr is the grant's sign-in as Quisora verified it, what decisions read (a token's amr claim also carries what
	// the upstream provider said, upstreamAMR: model.TokenAMR)
	amr, upstreamAMR []string
	upstream         *model.UpstreamAccount // the account at the upstream provider (Grant.Upstream)
	idp              string                 // that provider's type (Grant.IdP)
	sources          []model.GuestSource    // the accounts a guest's grant stands on (Grant.Sources)
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
		"scopes_supported": []string{"openid", "profile", "email", "phone", "groups", "org", "roles", "enterprise", "idp", "offline_access",
			service.ScopeSCIM}, // scim: client credentials tokens of SCIM provisioning clients
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "idp", "sid", "org",
			"org_name", "tenant", "tenant_name", "org_role", "email", "email_verified", "name", "preferred_username", "given_name", "family_name",
			"locale", "zoneinfo", "updated_at", "phone_number", "phone_number_verified", "groups", "tags", "roles", "enterprise",
			"idp_sub", "idp_tenant", "idp_login"},
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
	if !p.cfg.Server.DisablePictures {
		d["claims_supported"] = append(d["claims_supported"].([]string), "picture")
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
