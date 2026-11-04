package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// flow is a validated authorization request waiting for sign-in / consent (ephemeral, ns "oauth.flow").
type flow struct {
	Org         string   `json:"o"` // the organization it was made in: only its endpoints carry it on
	ClientID    string   `json:"c"` // as the application sent it (model.Client.ClientID)
	RedirectURI string   `json:"r"`
	Scopes      []string `json:"sc"`
	State       string   `json:"st,omitempty"`
	Nonce       string   `json:"n,omitempty"`
	Challenge   string   `json:"cc"`
	Prompt      []string `json:"p,omitempty"`
	MaxAge      int      `json:"ma"` // -1 = not requested
	LoginHint   string   `json:"lh,omitempty"`
	Mode        string   `json:"m"` // query | form_post
	Resources   []string `json:"res,omitempty"`
	ADTypes     []string `json:"adt,omitempty"` // authorization details types asked for (authdetails.go)
	Created     int64    `json:"t"`             // unix nanos
	Logins      int      `json:"lg,omitempty"`
	Decision    string   `json:"d,omitempty"` // "allow" or "deny"
	DecidedBy   string   `json:"db,omitempty"`
	Tenant      string   `json:"tn,omitempty"`  // name of the client's tenant (hand-off to sign-in)
	Bind        []byte   `json:"b,omitempty"`   // SHA-256 of the secret held in the starting browser's flow cookie
	ClaimsUI    []string `json:"cu,omitempty"`  // claims requested individually for userinfo (claims.go)
	ClaimsID    []string `json:"ci,omitempty"`  // ... and for the ID token
	MFA         bool     `json:"mfa,omitempty"` // acr values that ask for a second factor
	DPoPJKT     string   `json:"jkt,omitempty"` // dpop_jkt: the DPoP key the code must be redeemed with
	Pushed      string   `json:"pu,omitempty"`  // the pushed request (par.go) the flow came from, used up when decided
	// Device is the device_code of the device sign-in (device.go) the flow approves: it ends in the browser, with
	// the device told, instead of at a redirect URI.
	Device string `json:"dv,omitempty"`
}

// consent is what the request asks the user to allow (consentScopes).
func (f *flow) consent() []string { return consentScopes(f.Scopes, f.ClaimsUI, f.ClaimsID) }

// resumePath is where the browser continues flow id of organization orgID after signing in.
func resumePath(orgID, id string) string {
	return web.OrgPath(orgID, "/oauth/authorize/resume?flow="+url.QueryEscape(id))
}

// Flow binding. /o/<org>/oauth/authorize gives the browser a random secret in a cookie and stores only its SHA-256 in the
// flow; resume and consent require the cookie to match, so a flow id planted in a victim's browser (flow fixation)
// cannot be completed there, nor can a stolen id be resumed from another browser. Each flow has its own cookie,
// `__Host-quisora_flow_<first 8 hex of SHA-256(flow id)>`, so several flows can run concurrently in one browser; they
// expire with the flow (Max-Age = flowTTL) and are removed when the flow completes.
const flowCookiePrefix = "__Host-quisora_flow_"

func flowCookieName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return flowCookiePrefix + hex.EncodeToString(sum[:4])
}

func newFlowSecret() (secret string, bind []byte) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(secret))
	return secret, sum[:]
}

func setFlowCookie(w http.ResponseWriter, id, secret string) {
	http.SetCookie(w, &http.Cookie{Name: flowCookieName(id), Value: secret, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(flowTTL / time.Second)})
}

func clearFlowCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{Name: flowCookieName(id), Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// flowBound reports whether the request carries the cookie of the browser that started flow f.
func flowBound(r *http.Request, id string, f *flow) bool {
	ck, err := r.Cookie(flowCookieName(id))
	if err != nil || len(f.Bind) != sha256.Size {
		return false
	}
	sum := sha256.Sum256([]byte(ck.Value))
	return subtle.ConstantTimeCompare(sum[:], f.Bind) == 1
}

func (p *Provider) wrongBrowser(w http.ResponseWriter, r *http.Request) {
	p.message(w, r, http.StatusForbidden, "Wrong browser", "This sign-in request was started in another browser",
		"Return to the application you were using and start the sign-in again in this browser.")
}

const maxLoginRedirects = 6

// fapiCodeTTL bounds the authorization codes of FAPI 2.0 clients (§5.3.2.1: at most 60 seconds).
const fapiCodeTTL = time.Minute

// codeTTL is how long an authorization code for c lasts.
func (p *Provider) codeTTL(c *model.Client) time.Duration {
	if c.FAPI {
		return min(p.cfg.Tokens.Code(), fapiCodeTTL)
	}
	return p.cfg.Tokens.Code()
}

func (f *flow) has(prompt string) bool { return slices.Contains(f.Prompt, prompt) }

func (p *Provider) saveFlow(ctx context.Context, id string, f *flow) {
	b, _ := json.Marshal(f)
	_ = p.s.Eph.Set(ctx, nsFlow, id, b, flowTTL)
}

// ---------------------------------------------------------------------------------------------------------------
// Pages

// MessageData feeds pages/oauth-message.html.
type MessageData struct {
	Heading string
	Body    string
}

// PostData feeds pages/oauth-post.html (response_mode=form_post).
type PostData struct {
	Action string
	Fields []PostField
}

// PostField is one hidden input of the form_post response.
type PostField struct{ Name, Value string }

// ConsentData feeds pages/consent.html.
type ConsentData struct {
	Flow       string
	ClientName string
	Scopes     []ScopeInfo
	Resources  []string // the APIs (resource indicators) the tokens will be for
	Username   string
	Tenant     string // tenant display name
	ReturnURL  string // the application's address, offered when the request can no longer be decided (returnURL)
	// SelfRegistered: the application registered itself (nobody in the organization set it up); RedirectHost is
	// where it sends the result, so the user can tell a look-alike name from the real thing.
	SelfRegistered bool
	// Remembered: allowing it is remembered (service.RemembersConsent), so the page says it will not ask again.
	Remembered   bool
	RedirectHost string
	// UserCode: the flow approves a device sign-in (device.go) showing this code.
	UserCode string
}

// returnURL is the home of the web application behind a validated redirect URI: its scheme and host. It is empty for
// native apps (a custom scheme, or a loopback IP whose port changes with every request), which have no page to go back
// to. The redirect URI was matched against the client's registered ones, so the link cannot point anywhere else.
func returnURL(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/"
}

// ScopeInfo describes a requested scope to the user.
type ScopeInfo struct{ Name, Description string }

// LogoutData feeds pages/oauth-logout.html.
type LogoutData struct {
	ID       string
	Username string
	Client   string
}

func (p *Provider) message(w http.ResponseWriter, r *http.Request, status int, title, heading, body string) {
	p.s.Render.Render(w, status, "oauth-message", p.s.Page(w, r, title, "", MessageData{Heading: heading, Body: body}))
}

// invalidRequestURI is the page for a request_uri that cannot be used and whose request cannot be answered at the
// client (expired, unknown, or pushed by another client: nothing in it can be trusted for this one).
func (p *Provider) invalidRequestURI(w http.ResponseWriter, r *http.Request) {
	p.message(w, r, http.StatusBadRequest, "Invalid request", "This sign-in request is not valid",
		"It has expired, or it was made for another application. Return to the application you were using and start again.")
}

func (p *Provider) expired(w http.ResponseWriter, r *http.Request) {
	p.message(w, r, http.StatusBadRequest, "Request expired", "This request has expired",
		"Return to the application you were using and start again.")
}

// ---------------------------------------------------------------------------------------------------------------
// Request validation

func isLoopbackHost(h string) bool { return h == "127.0.0.1" || h == "::1" || h == "localhost" }

// redirectMatches implements exact matching (RFC 6749 §3.1.2.3) plus the loopback port flexibility of RFC 8252 §7.3:
// an http redirect URI on localhost, 127.0.0.1 or [::1] matches whatever port a native app listens on (the host, path
// and query must be the ones registered). Desktop clients, MCP clients among them, commonly register localhost.
func redirectMatches(registered []string, uri string) bool {
	if uri == "" || len(uri) > 2048 {
		return false
	}
	if slices.Contains(registered, uri) {
		return true
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || u.Fragment != "" || u.User != nil || !isLoopbackHost(u.Hostname()) {
		return false
	}
	for _, reg := range registered {
		ru, err := url.Parse(reg)
		if err == nil && ru.Scheme == "http" && ru.Hostname() == u.Hostname() && ru.Path == u.Path &&
			ru.RawQuery == u.RawQuery && ru.User == nil {
			return true
		}
	}
	return false
}

// parseResources validates RFC 8707 resource indicators.
func parseResources(vals []string) ([]string, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	if len(vals) > 10 {
		return nil, errors.New("too many resource parameters")
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		u, err := url.Parse(v)
		// RFC 8707 §2: an absolute URI without a fragment: https://api.example/ or a URN such as urn:example:api
		if err != nil || !u.IsAbs() || u.Fragment != "" || (u.Host == "" && u.Opaque == "") || len(v) > 512 {
			return nil, errors.New("resource must be an absolute URI without a fragment")
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

// repeated returns the first parameter of v given more than once (RFC 6749 §3.1, §3.2: parameters must not be
// repeated), "" when none is; "resource" may repeat (RFC 8707).
func repeated(v url.Values) string {
	for k, vs := range v {
		if len(vs) > 1 && k != "resource" {
			return k
		}
	}
	return ""
}

// authorizePerIPMin bounds the authorization requests per IP address and minute (one that starts a sign-in flow holds
// about 1-2 KB for up to flowTTL). Far above what people signing in behind one address make; behind a proxy, set
// server.trust_proxy, or every user shares the proxy's address and its budget.
const authorizePerIPMin = 300

func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Counted first, whatever the request: one that names no real client still costs a store read, and one that does
	// holds a flow in memory for flowTTL. Nothing is known yet to redirect to, so a refusal is a page.
	n, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, "authorize|"+web.RateKeyIP(r), 1, time.Minute)
	if err != nil {
		// The counter cannot be used, so the request is refused, but as "try again", not as the limit it has not hit.
		w.Header().Set("Retry-After", "5")
		p.message(w, r, http.StatusServiceUnavailable, "Unavailable", "Please try again",
			"This request cannot be completed at the moment. Try again in a moment.")
		return
	}
	if n > authorizePerIPMin {
		w.Header().Set("Retry-After", "60")
		p.message(w, r, http.StatusTooManyRequests, "Too many requests", "Too many sign-in requests",
			"Too many sign-in requests came from your network. Wait a minute, then try again.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		p.message(w, r, http.StatusBadRequest, "Invalid request", "This request could not be read", "")
		return
	}
	q := r.Form
	dup := repeated(q)
	if dup == "client_id" || dup == "redirect_uri" || dup == "request_uri" { // which application, or where to: nothing to trust
		p.message(w, r, http.StatusBadRequest, "Invalid request", "This request could not be read", "")
		return
	}
	org := web.Org(r)
	// A pushed request (RFC 9126): its parameters are the ones the client pushed, whatever else the URL carries.
	pushed := strings.HasPrefix(q.Get("request_uri"), parURNPrefix)
	var pushedID string
	pushedUsed := false
	if pushed {
		pq, id, used, err := p.loadPushed(r.Context(), org.ID, q.Get("client_id"), q.Get("request_uri"))
		if errors.Is(err, errPushed) {
			p.invalidRequestURI(w, r)
			return
		}
		if err != nil { // the store could not say whether it was used: not an invalid request_uri
			p.message(w, r, http.StatusServiceUnavailable, "Unavailable", "Please try again",
				"This request cannot be completed at the moment. Try again in a moment.")
			return
		}
		q, dup, pushedID, pushedUsed = pq, repeated(pq), id, used
	}
	// A metadata document is read only for a resource whose tenant accepts self-registered applications: requests
	// naming documents for anything else never make this server fetch anything.
	if metadataURL(q.Get("client_id")) {
		if res, err := parseResources(q["resource"]); err != nil || len(res) == 0 {
			ce, _ := p.client(r.Context(), org.ID, q.Get("client_id"))
			if ce == nil || ce.c.SelfRegistered {
				p.message(w, r, http.StatusBadRequest, "Unknown application", "This application is not recognised",
					"The link you followed is not valid. Return to the application and try again.")
				return
			}
		} else if _, err := p.svc.TenantForResources(r.Context(), org.ID, res); err != nil {
			p.message(w, r, http.StatusBadRequest, "Unknown application", "This application is not recognised",
				"The link you followed is not valid. Return to the application and try again.")
			return
		}
	}
	ce, err := p.appClient(r.Context(), r, org.ID, q.Get("client_id"))
	if err != nil && !gone(err) { // the application or its organization cannot be read now: not an unknown one
		p.message(w, r, http.StatusServiceUnavailable, "Unavailable", "Please try again",
			"This request cannot be completed at the moment. Try again in a moment.")
		return
	}
	if err != nil || !ce.c.Enabled {
		p.message(w, r, http.StatusBadRequest, "Unknown application", "This application is not recognised",
			"The link you followed is not valid. Return to the application and try again.")
		return
	}
	c := ce.c
	redirectURI := q.Get("redirect_uri")
	if !redirectMatches(c.RedirectURIs, redirectURI) {
		p.message(w, r, http.StatusBadRequest, "Invalid redirect", "This request cannot be completed",
			"The application's redirect address is not registered. Contact the application's administrator.")
		return
	}
	// From here on errors go back to the client.
	f := &flow{Org: org.ID, ClientID: c.ClientID(), RedirectURI: redirectURI, MaxAge: -1, Mode: "query", Created: time.Now().UnixNano()}
	f.State = q.Get("state")
	if len(f.State) > 2048 || dup == "state" {
		f.State = ""
		p.redirectError(w, r, f, "invalid_request", "state is too long or repeated")
		return
	}
	if dup != "" {
		p.redirectError(w, r, f, "invalid_request", dup+" is repeated")
		return
	}
	if pushedUsed { // its redirect URI and state were checked when it was pushed
		if q.Get("response_mode") == "form_post" {
			f.Mode = "form_post"
		}
		p.redirectError(w, r, f, "invalid_request_uri", "the request_uri was already used")
		return
	}
	f.Pushed = pushedID
	if c.RequirePAR && !pushed {
		p.redirectError(w, r, f, "invalid_request", "this client must push its authorization requests (RFC 9126)")
		return
	}
	checked, e := p.checkAuthz(r.Context(), q, c, f)
	if e != nil {
		// Not an audit event: nobody has signed in, and anyone who knows the client ID can cause one. Mostly the
		// application asking for what its settings do not allow, which only its administrator can fix.
		metrics.AuthorizeRefused.Inc(e.code)
		p.log.Warn("oidc: authorization request refused", "org", org.ID, "client_id", c.ClientID(), "client", c.Name,
			"error", e.code, "description", e.desc)
		p.redirectError(w, r, f, e.code, e.desc)
		return
	}
	c = checked
	secret, bind := newFlowSecret()
	f.Bind = bind
	b, _ := json.Marshal(f)
	id, err := p.s.Eph.New(r.Context(), nsFlow, b, flowTTL)
	if err != nil {
		p.redirectError(w, r, f, "server_error", "temporarily unavailable")
		return
	}
	setFlowCookie(w, id, secret)
	p.proceed(w, r, id, f, c)
}

// checkAuthz validates the parameters of an authorization request q for client c (its redirect URI already matched)
// into f, the same way for /o/<org>/oauth/authorize and for a pushed request (par.go). It returns the client that governs the
// request: c, or for a self-registered application its view in the tenant owning the requested resources.
func (p *Provider) checkAuthz(ctx context.Context, q url.Values, c *model.Client, f *flow) (*model.Client, *oauthError) {
	switch m := q.Get("response_mode"); m {
	case "", "query":
	case "form_post":
		f.Mode = "form_post"
	default:
		return nil, oerr("invalid_request", "unsupported response_mode")
	}
	if q.Get("request") != "" {
		return nil, oerr("request_not_supported", "request objects are not supported")
	}
	if q.Get("request_uri") != "" {
		return nil, oerr("request_uri_not_supported", "request_uri is only supported for pushed authorization requests")
	}
	if q.Get("response_type") != "code" {
		return nil, oerr("unsupported_response_type", "only response_type=code is supported")
	}
	if !slices.Contains(c.GrantTypes, "authorization_code") {
		return nil, oerr("unauthorized_client", "the client may not use the authorization code grant")
	}
	f.Challenge = q.Get("code_challenge")
	switch {
	case f.Challenge == "" && q.Get("code_challenge_method") == "" && !c.RequirePKCE():
		// a confidential client that may omit PKCE (require_pkce off); its code then needs no verifier
	case !validChallenge(f.Challenge) || q.Get("code_challenge_method") != "S256":
		return nil, oerr("invalid_request", "PKCE is required: send code_challenge and code_challenge_method=S256")
	}
	f.Scopes = dedupe(splitScope(q.Get("scope")))
	if len(f.Scopes) == 0 {
		f.Scopes = slices.Clone(c.Scopes)
	}
	if !subset(f.Scopes, c.Scopes) {
		return nil, oerr("invalid_scope", "the requested scope is not available to this client")
	}
	f.Nonce = q.Get("nonce")
	if len(f.Nonce) > 1024 {
		return nil, oerr("invalid_request", "nonce is too long")
	}
	f.Prompt = strings.Fields(q.Get("prompt"))
	for _, v := range f.Prompt {
		if v != "none" && v != "login" && v != "consent" && v != "select_account" {
			return nil, oerr("invalid_request", "unsupported prompt value")
		}
	}
	if f.has("none") && len(f.Prompt) > 1 {
		return nil, oerr("invalid_request", "prompt=none cannot be combined with other values")
	}
	if v := q.Get("max_age"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, oerr("invalid_request", "max_age must be a non-negative integer")
		}
		f.MaxAge = n
	}
	if f.LoginHint = q.Get("login_hint"); len(f.LoginHint) > 256 {
		f.LoginHint = ""
	}
	res, err := parseResources(q["resource"])
	if err != nil {
		return nil, oerr("invalid_target", err.Error())
	}
	if c.SelfRegistered {
		// a self-registered application is governed by the tenant that owns the resources it asks for
		if len(res) == 0 {
			return nil, oerr("invalid_target", "a self-registered application must name the resource it wants access to (RFC 8707)")
		}
		inT, _, err := p.forResources(ctx, c, res)
		if err != nil {
			return nil, oerr("invalid_target", "the resource does not accept self-registered applications")
		}
		c = inT
		if q.Get("scope") == "" {
			f.Scopes = slices.Clone(c.Scopes)
		}
	}
	if !subset(res, c.Resources) {
		return nil, oerr("invalid_target", "the resource is not registered for this client")
	}
	f.Resources = res
	ad, e := parseAuthDetailsParam(q.Get("authorization_details"), c)
	if e != nil {
		return nil, e
	}
	f.ADTypes = ad
	cp, err := parseClaimsParam(q.Get("claims"), c.Scopes)
	if err != nil {
		return nil, oerr("invalid_request", err.Error())
	}
	f.ClaimsUI, f.ClaimsID = cp.UserInfo, cp.IDToken
	// Essential with values: one of them must be met. Essential without values only asks that an acr be returned
	// (OIDC Core 5.5.1.1), which it always is.
	if cp.ACREssential && len(cp.ACR) > 0 && !knowsACR(cp.ACR) {
		return nil, oerr("unmet_authentication_requirements", "none of the essential acr values can be satisfied (supported: "+
			acrBasic+", "+acrMFA+")")
	}
	f.MFA = demandsMFA(append(slices.Clone(cp.ACR), strings.Fields(q.Get("acr_values"))...))
	if f.DPoPJKT = q.Get("dpop_jkt"); f.DPoPJKT != "" && !validJKT(f.DPoPJKT) {
		return nil, oerr("invalid_request", "dpop_jkt must be a SHA-256 JWK thumbprint")
	}
	return c, nil
}

func (p *Provider) handleResume(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("flow")
	raw, err := p.s.Eph.Get(r.Context(), nsFlow, id)
	if err != nil {
		p.expired(w, r)
		return
	}
	var f flow
	if json.Unmarshal(raw, &f) != nil {
		p.expired(w, r)
		return
	}
	if f.Org != web.Org(r).ID {
		p.expired(w, r) // another organization's flow is none of this one's
		return
	}
	if !flowBound(r, id, &f) {
		p.wrongBrowser(w, r)
		return
	}
	ce, err := p.appClient(r.Context(), r, f.Org, f.ClientID)
	if err != nil || !ce.c.Enabled {
		p.expired(w, r)
		return
	}
	c, _, err := p.forResources(r.Context(), ce.c, f.Resources)
	if err != nil {
		p.expired(w, r) // the tenant no longer accepts the self-registered application
		return
	}
	p.proceed(w, r, id, &f, c)
}

// handleCancel is the sign-in page's Cancel: the user declines the request, and the application gets access_denied
// (OIDC Core §3.1.2.6). Only the browser that started the flow can cancel it.
func (p *Provider) handleCancel(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("flow")
	raw, err := p.s.Eph.Get(r.Context(), nsFlow, id)
	var f flow
	if err != nil || json.Unmarshal(raw, &f) != nil || f.Org != web.Org(r).ID {
		p.expired(w, r)
		return
	}
	if !flowBound(r, id, &f) {
		p.wrongBrowser(w, r)
		return
	}
	_ = p.s.Eph.Delete(r.Context(), nsFlow, id)
	clearFlowCookie(w, id)
	if f.Pushed != "" {
		p.usePushed(r.Context(), f.Pushed)
	}
	p.redirectError(w, r, &f, "access_denied", "the user cancelled the sign-in")
}

// ---------------------------------------------------------------------------------------------------------------
// Flow engine

// proceed decides what the browser needs next: sign in, re-authenticate, consent, or an authorization code.
func (p *Provider) proceed(w http.ResponseWriter, r *http.Request, id string, f *flow, c *model.Client) {
	ctx := r.Context()
	// A session the store could not check is not "signed out": prompt=none would answer login_required for a user who
	// is signed in, and any other request would send them to sign in again over a session that may well exist.
	sess, user, err := p.s.Sessions.Check(r)
	if err != nil {
		p.redirectError(w, r, f, "temporarily_unavailable", "the session could not be checked right now")
		return
	}
	none := f.has("none")
	tenant, terr := p.clientTenant(ctx, c)
	if terr != nil {
		p.message(w, r, http.StatusBadRequest, "Unavailable", "This application is not available", "")
		return
	}
	f.Tenant = tenant.Name

	signIn := func(reauth bool) {
		if none {
			p.redirectError(w, r, f, "login_required", "the user is not signed in")
			return
		}
		if f.Logins++; f.Logins > maxLoginRedirects {
			p.message(w, r, http.StatusForbidden, "Sign-in not possible", "We could not sign you in for this application",
				"The sign-in requirements for this application could not be met. Contact your administrator.")
			_ = p.s.Eph.Delete(ctx, nsFlow, id)
			return
		}
		p.saveFlow(ctx, id, f)
		target := web.OrgPath(c.OrgID, "/login") + "?tenant=" + url.QueryEscape(tenant.Name) +
			"&next=" + url.QueryEscape(resumePath(c.OrgID, id))
		if reauth {
			target += "&reauth=1"
		}
		if f.LoginHint != "" {
			target += "&login_hint=" + url.QueryEscape(f.LoginHint)
		}
		http.Redirect(w, r, target, http.StatusFound)
	}

	if sess == nil {
		signIn(false)
		return
	}
	org, err := p.svc.Org(ctx, user.OrgID)
	if err != nil {
		p.message(w, r, http.StatusBadRequest, "Unavailable", "Your organization is not available", "")
		return
	}
	// An authentication that happened after this request started always satisfies prompt=login and max_age.
	fresh := sess.AuthTime.UnixNano() > f.Created
	reauth := false
	if (f.has("login") || f.has("select_account")) && !fresh {
		reauth = true
	}
	if f.MaxAge >= 0 && !fresh && time.Since(sess.AuthTime) > time.Duration(f.MaxAge)*time.Second {
		reauth = true
	}
	eff, err := p.svc.EffectiveSignIn(ctx, org, tenant)
	if err != nil {
		p.redirectError(w, r, f, "server_error", "temporarily unavailable")
		return
	}
	if (eff.RequireMFA || f.MFA) && !MFASatisfied(sess.AMR) {
		reauth = true
	}
	if !methodAllowed(eff, sess) {
		reauth = true
	}
	if reauth {
		signIn(true)
		return
	}
	// A members-only tenant: the user (directly or through a group) needs live access that covers this client.
	app, err := p.appAccess(ctx, c, tenant, user)
	if err != nil {
		p.redirectError(w, r, f, "server_error", "temporarily unavailable")
		return
	}
	if !app.Allowed {
		_ = p.s.Eph.Delete(ctx, nsFlow, id)
		clearFlowCookie(w, id)
		if f.Device != "" {
			p.decideDevice(ctx, f, false, nil, nil, "")
		}
		if none {
			p.redirectError(w, r, f, "access_denied", errNoAccess.Error())
			return
		}
		p.message(w, r, http.StatusForbidden, "No access", "You do not have access to "+c.Name,
			"You are signed in as "+user.Email+". Ask your administrator to give you access to this application.")
		return
	}

	// A device sign-in for a manager or above, where the application does not allow it: refused, and the device told.
	if f.Device != "" && user.Role.Privileged() && !c.DevicePrivileged {
		_ = p.s.Eph.Delete(ctx, nsFlow, id)
		clearFlowCookie(w, id)
		p.decideDevice(ctx, f, false, nil, nil, "")
		p.message(w, r, http.StatusForbidden, "Not allowed", "Managers and administrators cannot sign in on devices with "+c.Name,
			"You are signed in as "+user.Email+". Your device was not signed in. Ask your administrator if you need this.")
		return
	}

	if f.Decision != "" && f.DecidedBy == user.ID {
		if f.Decision == "deny" {
			_ = p.s.Eph.Delete(ctx, nsFlow, id)
			clearFlowCookie(w, id)
			if f.Pushed != "" {
				p.usePushed(ctx, f.Pushed)
			}
			p.redirectError(w, r, f, "access_denied", "the user denied the request")
			return
		}
	} else if !c.FirstParty || f.Device != "" {
		// A device sign-in is always confirmed: the code may have come from someone else.
		consented := false
		if !f.has("consent") && !c.Public() && f.Device == "" {
			consented = p.hasConsent(ctx, user.ID, c, f.consent(), f.Resources)
		}
		if !consented {
			if none {
				p.redirectError(w, r, f, "consent_required", "the user has not consented")
				return
			}
			p.saveFlow(ctx, id, f)
			http.Redirect(w, r, web.OrgPath(c.OrgID, "/oauth/consent?flow="+url.QueryEscape(id)), http.StatusFound)
			return
		}
	}

	// the idp claim, read before the flow (or its pushed request) is used up, so that a failed read can be tried again
	idp, err := p.upstreamType(ctx, sess)
	if err != nil {
		if f.Device != "" {
			p.message(w, r, http.StatusServiceUnavailable, "Try again", "This could not be finished just now",
				"Try again in a moment: the code still works.")
			return
		}
		p.redirectError(w, r, f, "server_error", "temporarily unavailable")
		return
	}
	if f.Device != "" {
		_ = p.s.Eph.Delete(ctx, nsFlow, id)
		clearFlowCookie(w, id)
		if !p.decideDevice(ctx, f, true, sess, user, idp) {
			p.message(w, r, http.StatusBadRequest, "Code expired", "This code can no longer be used",
				"It has expired, or it was already used. Start again on your device to get a new code.")
			return
		}
		p.svc.Audit(ctx, service.ActorForUser(user, web.ClientIP(r)), user.OrgID, "oauth.device.approve", c.Name, map[string]string{"client_id": c.ClientID(),
			"scopes": strings.Join(f.Scopes, " ")})
		p.message(w, r, http.StatusOK, "Device signed in", "Your device is signed in to "+c.Name,
			"Return to your device: it carries on by itself. You can close this page.")
		return
	}
	if f.Pushed != "" && !p.usePushed(ctx, f.Pushed) { // another flow of the same request_uri was decided first
		_ = p.s.Eph.Delete(ctx, nsFlow, id)
		clearFlowCookie(w, id)
		p.redirectError(w, r, f, "invalid_request_uri", "the request_uri was already used")
		return
	}
	cd := codeData{GrantID: model.NewID(), ClientID: c.ID, RedirectURI: f.RedirectURI, Challenge: f.Challenge, Nonce: f.Nonce, SessionID: sess.ID,
		UserID: user.ID, OrgID: user.OrgID, AuthTime: sess.AuthTime.Unix(), AMR: sess.AMR, IdP: idp, UpstreamAMR: sess.UpstreamAMR, Scopes: f.Scopes,
		Resources: f.Resources, ADTypes: f.ADTypes, ClaimsUI: f.ClaimsUI, ClaimsID: f.ClaimsID, DPoPJKT: f.DPoPJKT}
	b, _ := json.Marshal(cd)
	code, err := p.s.Eph.New(ctx, nsCode, b, p.codeTTL(c))
	if err != nil {
		p.redirectError(w, r, f, "server_error", "temporarily unavailable")
		return
	}
	_ = p.s.Eph.Delete(ctx, nsFlow, id)
	clearFlowCookie(w, id)
	if c.SelfRegistered {
		p.svc.NoteSelfRegisteredUse(ctx, c, tenant) // a metadata-document application is stored now
	}
	p.respond(w, r, f, url.Values{"code": {code}})
}

// upstreamType is the type of the upstream provider the session signed in through ("microsoft", "google", ...), for
// the idp claim: empty for a sign-in of Quisora's own, and for a provider removed since. A provider that could not be
// read is an error: the grant keeps its idp for good, so a read that failed is not taken for "none".
func (p *Provider) upstreamType(ctx context.Context, sess *model.Session) (string, error) {
	if sess.Provider == "" {
		return "", nil
	}
	prov, err := p.svc.Providers.Get(ctx, sess.Provider)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", unavailable(err)
	}
	return prov.Type, nil
}

// methodAllowed reports whether the way the session was authenticated is among the sign-in methods the client's
// tenant allows for the user's org (service.SignInMethods.AllowsSession).
func methodAllowed(eff *service.SignInMethods, sess *model.Session) bool {
	return eff.AllowsSession(sess.AMR, sess.Provider)
}

// hasConsent reports whether the user already authorized confidential client c for these scopes and resources, in one
// approval (consent is remembered per scope set and per resource set): a live grant covers them, so the user is asked
// once per sign-in and again after signing out, or, for a client set to remember consent (service.RemembersConsent),
// their remembered consent (model.Consent) does, signed out or not.
func (p *Provider) hasConsent(ctx context.Context, userID string, c *model.Client, scopes, resources []string) bool {
	if service.RemembersConsent(c) && p.svc.ConsentCovers(ctx, userID, c.ID, scopes, resources) {
		return true
	}
	gs, err := p.svc.Grants.All(ctx, userID)
	if err != nil {
		return false
	}
	for _, g := range gs {
		if g.ClientID == c.ID && subset(scopes, consentScopes(g.Scopes, g.ClaimsUI, g.ClaimsID)) &&
			subset(resources, g.Resources) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------------------------
// Responses to the client

func (p *Provider) redirectError(w http.ResponseWriter, r *http.Request, f *flow, code, desc string) {
	v := url.Values{"error": {code}}
	if desc != "" {
		v.Set("error_description", desc)
	}
	p.respond(w, r, f, v)
}

// respond returns params (plus state and iss, RFC 9207) to the client's redirect URI using f's response mode.
func (p *Provider) respond(w http.ResponseWriter, r *http.Request, f *flow, params url.Values) {
	if f.Device != "" {
		p.deviceRespond(w, r, f, params)
		return
	}
	if f.State != "" {
		params.Set("state", f.State)
	}
	params.Set("iss", p.issuer(web.Org(r).ID))
	w.Header().Set("Referrer-Policy", "no-referrer")
	if f.Mode == "form_post" {
		u, err := url.Parse(f.RedirectURI)
		if err != nil {
			p.message(w, r, http.StatusBadRequest, "Invalid redirect", "This request cannot be completed", "")
			return
		}
		data := PostData{Action: f.RedirectURI}
		for _, k := range []string{"code", "error", "error_description", "state", "iss"} {
			if v := params.Get(k); v != "" {
				data.Fields = append(data.Fields, PostField{k, v})
			}
		}
		// The auto-submitting form must be allowed to post to the client's origin (the default CSP only allows
		// https:); everything else stays as strict as the global policy.
		target, ok := formActionSource(u)
		if !ok {
			p.message(w, r, http.StatusBadRequest, "Invalid redirect", "This request cannot be completed", "")
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "+
			"img-src 'self' data: https:; font-src 'self'; connect-src 'self'; form-action "+target+
			"; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		p.s.Render.Render(w, http.StatusOK, "oauth-post", p.s.Page(w, r, "Continue", "", data))
		return
	}
	u, err := url.Parse(f.RedirectURI)
	if err != nil {
		p.message(w, r, http.StatusBadRequest, "Invalid redirect", "This request cannot be completed", "")
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---------------------------------------------------------------------------------------------------------------
// Consent

var scopeDescriptions = map[string]string{
	"openid":         "Sign you in and identify you",
	"profile":        "Your name, username, language and time zone",
	"email":          "Your email address",
	"phone":          "Your phone number",
	"groups":         "The groups you belong to",
	"enterprise":     "Your work details: job title, department, manager, employee number and the like",
	"org":            "Your organization, tenant and role in it",
	"roles":          "Your roles and tags in this application",
	"offline_access": "Stay signed in and act while you are away",
	"scim":           "Manage users and groups",
}

var errWrongBrowser = errors.New("oidc: flow belongs to another browser")

// FlowWantsMFA reports whether the authorization request that a sign-in continues at next (its resume URL) asked
// for a second factor through acr_values (login.Options.StepUp).
func (p *Provider) FlowWantsMFA(ctx context.Context, next string) bool {
	u, err := url.Parse(next)
	if err != nil {
		return false
	}
	raw, err := p.s.Eph.Get(ctx, nsFlow, u.Query().Get("flow"))
	if err != nil {
		return false
	}
	var f flow
	return json.Unmarshal(raw, &f) == nil && f.MFA && u.Path == web.OrgPath(f.Org, "/oauth/authorize/resume")
}

func (p *Provider) loadFlow(r *http.Request, id string) (*flow, *model.Client, error) {
	ctx := r.Context()
	raw, err := p.s.Eph.Get(ctx, nsFlow, id)
	if err != nil {
		return nil, nil, err
	}
	var f flow
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, err
	}
	if f.Org != web.Org(r).ID {
		return nil, nil, ephemeral.ErrNotFound
	}
	if !flowBound(r, id, &f) {
		return nil, nil, errWrongBrowser
	}
	ce, err := p.appClient(ctx, r, f.Org, f.ClientID)
	if err != nil || !ce.c.Enabled {
		return nil, nil, ephemeral.ErrNotFound
	}
	c, _, err := p.forResources(ctx, ce.c, f.Resources)
	if err != nil {
		return nil, nil, ephemeral.ErrNotFound // the tenant no longer accepts it (or the resource moved)
	}
	return &f, c, nil
}

func (p *Provider) handleConsentPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("flow")
	f, c, err := p.loadFlow(r, id)
	if errors.Is(err, errWrongBrowser) {
		p.wrongBrowser(w, r)
		return
	}
	if err != nil {
		p.expired(w, r)
		return
	}
	u := web.User(r)
	data := ConsentData{Flow: id, ClientName: c.Name, Username: u.FullName(), ReturnURL: returnURL(f.RedirectURI),
		Remembered: service.RemembersConsent(c) && f.Device == ""}
	if t, err := p.clientTenant(r.Context(), c); err == nil && t.Name != model.DefaultTenantName {
		data.Tenant = t.DisplayName
	}
	if data.Username == "" {
		data.Username = u.Username
	}
	for _, s := range f.consent() {
		d := scopeDescriptions[s]
		if d == "" {
			d = "Access: " + s
		}
		data.Scopes = append(data.Scopes, ScopeInfo{Name: s, Description: d})
	}
	data.Resources = f.Resources
	if f.Device != "" {
		if raw, err := p.s.Eph.Get(r.Context(), nsDevice, f.Device); err == nil {
			var d deviceGrant
			if json.Unmarshal(raw, &d) == nil {
				data.UserCode = formatUserCode(d.UserCode)
			}
		}
	}
	if c.SelfRegistered {
		data.SelfRegistered = true
		if u, err := url.Parse(f.RedirectURI); err == nil {
			data.RedirectHost = u.Host
			if u.Scheme != "http" && u.Scheme != "https" { // a private-use scheme: an app on this device
				data.RedirectHost = u.Scheme + ":"
			}
		}
	}
	p.s.Render.Render(w, http.StatusOK, "consent", p.s.Page(w, r, "Authorize "+c.Name, "", data))
}

type consentRequest struct {
	Flow    string `json:"flow"`
	Approve bool   `json:"approve"`
}

func (p *Provider) handleConsent(w http.ResponseWriter, r *http.Request) {
	var in consentRequest
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	f, c, err := p.loadFlow(r, in.Flow)
	if errors.Is(err, errWrongBrowser) {
		web.WriteJSON(w, http.StatusForbidden, web.ErrorBody{Error: "This sign-in request was started in another browser. Return to the application and start again."})
		return
	}
	if err != nil {
		web.WriteJSON(w, http.StatusNotFound, web.ErrorBody{Error: "This request has expired. Return to the application and try again."})
		return
	}
	u := web.User(r)
	f.Decision, f.DecidedBy = "deny", u.ID
	if in.Approve {
		f.Decision = "allow"
	}
	p.saveFlow(r.Context(), in.Flow, f)
	detail := map[string]string{"client_id": c.ClientID(), "decision": f.Decision, "scopes": strings.Join(f.consent(), " ")}
	// Remembered (model.Consent): the application signs the user in again without asking, signed out or not, until
	// they or an administrator remove its access. A failure to remember only means being asked again next time.
	if in.Approve && service.RemembersConsent(c) && f.Device == "" {
		if err := p.svc.RememberConsent(r.Context(), u, c.ID, f.consent(), f.Resources); err != nil {
			p.log.WithError(err).Warn("oidc: consent not remembered", "client", c.ID, "user", u.ID)
		} else {
			detail["remembered"] = "true"
		}
	}
	p.svc.Audit(r.Context(), web.Actor(r), u.OrgID, "oauth.consent", c.Name, detail)
	web.WriteJSON(w, http.StatusOK, map[string]string{"redirect": resumePath(c.OrgID, in.Flow)})
}

// formActionSource is the CSP source a form_post page may post to for redirect URI u: its origin, or for a native
// app's private-use scheme (com.example.app:/cb) the scheme alone. A host or scheme with characters a CSP source
// cannot hold (separators, quotes, spaces) is refused: they would add directives of their own to the page.
func formActionSource(u *url.URL) (string, bool) {
	clean := func(s string) bool { return !strings.ContainsAny(s, ";,'\" \t\r\n") }
	if !clean(u.Scheme) || !clean(u.Host) || u.Scheme == "" {
		return "", false
	}
	if u.Host == "" {
		return u.Scheme + ":", true
	}
	return u.Scheme + "://" + u.Host, true
}
