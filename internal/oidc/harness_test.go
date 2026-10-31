package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

const rpCallback = "https://rp.example/cb"

// at is the address of an endpoint (like "/oauth/token") of the organization of client c: the primary one for a client
// with no organization (one an application named, not stored).
func (h *harness) at(c *model.Client, path string) string {
	if c.OrgID == "" {
		return h.orgBase + path
	}
	return web.OrgPath(c.OrgID, path)
}

// issuer is the primary organization's issuer.
func (h *harness) issuer() string { return h.env.Cfg.OrgIssuer(h.env.Primary.ID) }

type harness struct {
	t   testing.TB
	env *webtest.Env
	// orgBase is the address space of the primary organization, where the harness's clients and users live.
	orgBase string
	p       *Provider
	admin   *service.Actor
	user    *model.User
	http    *http.Client
}

func ptr[T any](v T) *T { return &v }

func setup(t testing.TB, cfgFn func(*config.Config)) *harness { return setupKey(t, cfgFn, nil) }

// setupKey is setup with a chosen master key.
func setupKey(t testing.TB, cfgFn func(*config.Config), masterKey []byte) *harness {
	t.Helper()
	return setupLogged(t, cfgFn, masterKey, nil)
}

// setupLogged is setupKey with the server's log (nil: none kept).
func setupLogged(t testing.TB, cfgFn func(*config.Config), masterKey []byte, log logger.Logger) *harness {
	t.Helper()
	var p *Provider
	env := webtest.New(t, webtest.Options{Configure: cfgFn, MasterKey: masterKey, Log: log, Modules: func(s *web.Server) []web.Module {
		p = New(s)
		return []web.Module{p}
	}})
	p.HTTP = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	h := &harness{t: t, env: env, p: p, admin: service.ActorForUser(env.Admin, ""), orgBase: web.OrgPath(env.Primary.ID, "")}
	h.http = &http.Client{Timeout: 10 * time.Second, Transport: env.HTTP.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pw := "correct horse battery"
	// Passwords are only ever set by the system (as an accepted invitation does), never at creation by an admin.
	u, err := env.Svc.CreateUser(context.Background(), service.System, env.Primary.ID, service.UserInput{
		Username: ptr("alice"), Email: ptr("alice@example.com"), Password: &pw, GivenName: ptr("Alice"), FamilyName: ptr("A"),
		Verified: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	h.user = u
	// Everyone may make api tokens, and the test applications accept them (newClient): most tests that make one are not
	// about who may. Tests of the setting and of the opt-in change them.
	st := env.Primary.Settings
	st.APITokens = model.APITokensEveryone
	h.setOrg(st)
	return h
}

// testResources are the resource indicators test clients are registered for (RFC 8707: a client may name only those).
var testResources = []string{"https://api.example/v1", "https://api.example", "https://api.example/a", "https://api.example/b",
	"urn:example:billing"}

// newClient creates a confidential first-party client unless edit changes it.
func (h *harness) newClient(edit func(*service.ClientInput)) (*model.Client, string) {
	h.t.Helper()
	in := service.ClientInput{Name: ptr("app"), RedirectURIs: &[]string{rpCallback},
		GrantTypes: &[]string{"authorization_code", "refresh_token", "client_credentials"},
		Scopes:     &[]string{"openid", "profile", "email", "groups", "org", "roles", "offline_access", "api"}, FirstParty: ptr(true),
		Resources: &testResources, AcceptsAPITokens: ptr(true),
		// Most tests present one refresh token several times: the static format. Tests of rotation (the default
		// for a new client: TestNewClientsRotateRefreshTokens) set it.
		RotateRefresh: ptr(false)}
	if edit != nil {
		edit(&in)
	}
	c, secret, err := h.env.Svc.CreateClient(context.Background(), h.admin, h.env.Primary.ID, in)
	if err != nil {
		h.t.Fatal(err)
	}
	return c, secret
}

func (h *harness) publicClient(edit func(*service.ClientInput)) *model.Client {
	h.t.Helper()
	c, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodNone)
		in.RedirectURIs = &[]string{"https://spa.example/cb", "http://127.0.0.1/cb", "com.example.app:/cb"}
		in.GrantTypes = &[]string{"authorization_code", "refresh_token"}
		in.FirstParty = ptr(false)
		if edit != nil {
			edit(in)
		}
	})
	return c
}

// session signs u in and returns a browser with its own cookie jar (webtest shares one jar between clients).
func (h *harness) session(u *model.User) (*http.Client, string) {
	h.t.Helper()
	c, csrf := h.env.Session(u)
	pu, _ := url.Parse(h.env.URL)
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(pu, c.Jar.Cookies(pu))
	cp := *c
	cp.Jar = jar
	// detach: later sessions replace the shared jar's cookie
	return &cp, csrf
}

func (h *harness) anon() *http.Client {
	jar, _ := cookiejar.New(nil)
	cp := *h.http
	cp.Jar = jar
	return &cp
}

// copyFlowCookies moves the flow-binding cookies from one browser to another (the user signing in in the browser
// that started the flow, whose session cookie the harness had to create separately).
func (h *harness) copyFlowCookies(from, to *http.Client) {
	h.t.Helper()
	pu, _ := url.Parse(h.env.URL)
	var flow []*http.Cookie
	for _, ck := range from.Jar.Cookies(pu) {
		if strings.HasPrefix(ck.Name, flowCookiePrefix) {
			flow = append(flow, ck)
		}
	}
	to.Jar.SetCookies(pu, flow)
}

func pkce() (verifier, challenge string) {
	verifier = b64.EncodeToString(randBytes(32))
	sum := sha256.Sum256([]byte(verifier))
	return verifier, b64.EncodeToString(sum[:])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// authzQuery builds an authorization request; extra values override (empty string removes a parameter).
func authzQuery(c *model.Client, challenge string, extra url.Values) url.Values {
	q := url.Values{"client_id": {c.ID}, "redirect_uri": {c.RedirectURIs[0]}, "response_type": {"code"},
		"scope": {"openid profile email offline_access"}, "state": {"st1"}, "nonce": {"n1"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}}
	for k, v := range extra {
		if len(v) == 1 && v[0] == "" {
			q.Del(k)
		} else {
			q[k] = v
		}
	}
	return q
}

func (h *harness) get(c *http.Client, path string, hdr ...string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.env.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func body(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

func loc(t testing.TB, resp *http.Response) *url.URL {
	t.Helper()
	body(resp)
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.Header.Get("Location") == "" {
		t.Fatalf("no Location (status %d)", resp.StatusCode)
	}
	return u
}

// authorize runs the request with the signed-in browser c and returns the redirect target.
func (h *harness) authorize(c *http.Client, q url.Values) *url.URL {
	return h.authorizeIn(h.env.Primary.ID, c, q)
}

// authorizeIn is authorize at the endpoint of organization orgID.
func (h *harness) authorizeIn(orgID string, c *http.Client, q url.Values) *url.URL {
	h.t.Helper()
	resp := h.get(c, web.OrgPath(orgID, "/oauth/authorize?"+q.Encode()))
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("authorize status %d: %s", resp.StatusCode, body(resp))
	}
	return loc(h.t, resp)
}

func (h *harness) getCode(c *http.Client, cl *model.Client, challenge string, extra url.Values) string {
	h.t.Helper()
	u := h.authorize(c, authzQuery(cl, challenge, extra))
	if code := u.Query().Get("code"); code != "" {
		if u.Query().Get("iss") != h.issuer() || u.Query().Get("state") != "st1" && extra.Get("state") == "" {
			h.t.Fatalf("bad response params %s", u)
		}
		return code
	}
	h.t.Fatalf("no code: %s", u)
	return ""
}

type tokResp struct {
	status int
	m      map[string]any
	hdr    http.Header
}

func (r tokResp) str(k string) string { s, _ := r.m[k].(string); return s }

func (h *harness) post(path string, form url.Values, basicID, basicSecret string, hdr ...string) tokResp {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return tokResp{resp.StatusCode, m, resp.Header}
}

func (h *harness) token(form url.Values, c *model.Client, secret string) tokResp {
	f := url.Values{}
	for k, v := range form {
		f[k] = v
	}
	f.Set("client_id", c.ID)
	if secret != "" {
		f.Set("client_secret", secret)
	}
	return h.post(h.at(c, "/oauth/token"), f, "", "")
}

// login runs a full code exchange for a first-party confidential client.
func (h *harness) login(cl *model.Client, secret string, extra url.Values) (tokResp, string) {
	h.t.Helper()
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, extra)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 200 {
		h.t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	return r, v
}

func claimsOf(t testing.TB, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func headerOf(t testing.TB, tok string) map[string]any {
	b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

// clientPost posts form to path, authenticating as c the way it is registered to (Basic or form fields).
func (h *harness) clientPost(path string, form url.Values, c *model.Client, secret string) tokResp {
	h.t.Helper()
	f := url.Values{}
	for k, v := range form {
		f[k] = v
	}
	if c.AuthMethod == model.AuthMethodSecretBasic {
		return h.post(path, f, c.ID, secret)
	}
	f.Set("client_id", c.ID)
	f.Set("client_secret", secret)
	return h.post(path, f, "", "")
}

func (h *harness) introspect(c *model.Client, secret, tok string) map[string]any {
	h.t.Helper()
	// the way the client is registered to authenticate (client_secret_post by default)
	f := url.Values{"token": {tok}}
	id, sec := "", ""
	if c.AuthMethod == model.AuthMethodSecretBasic {
		id, sec = c.ID, secret
	} else {
		f.Set("client_id", c.ID)
		f.Set("client_secret", secret)
	}
	r := h.post(h.at(c, "/oauth/introspect"), f, id, sec)
	if r.status != 200 {
		h.t.Fatalf("introspect %d %v", r.status, r.m)
	}
	return r.m
}

func (h *harness) refreshWith(c *model.Client, secret, rt string) tokResp {
	return h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, c, secret)
}

// sessionWith signs the user in with chosen amr and auth time.
func (h *harness) sessionWith(u *model.User, amr []string, authTime time.Time) *http.Client {
	h.t.Helper()
	c, _ := h.session(u)
	pu, _ := url.Parse(h.env.URL)
	var id string
	for _, ck := range c.Jar.Cookies(pu) {
		if ck.Name == web.SessionCookieFor(h.env.Primary.ID) {
			id = web.SessionID(ck.Value)
		}
	}
	s, err := h.env.Svc.Sessions.Get(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	s.AMR, s.AuthTime = amr, authTime
	if err := h.env.Svc.Sessions.Update(context.Background(), s); err != nil {
		h.t.Fatal(err)
	}
	h.env.Server.Sessions.Evict(id, "")
	return c
}

// decideConsent answers the consent screen of a flow from browser c (signed in, with its CSRF token). It returns the
// status of the decision and, when accepted, the redirect that resumes the flow.
func (h *harness) decideConsent(c *http.Client, csrf, flow string, approve bool) (int, string) {
	return h.decideConsentIn(h.env.Primary.ID, c, csrf, flow, approve)
}

// decideConsentIn is decideConsent at the endpoint of organization orgID.
func (h *harness) decideConsentIn(orgID string, c *http.Client, csrf, flow string, approve bool) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+web.OrgPath(orgID, "/api-internal/oauth/consent"),
		bytes.NewReader(mustJSON(map[string]any{"flow": flow, "approve": approve})))
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	var out map[string]string
	_ = json.Unmarshal([]byte(body(resp)), &out)
	return resp.StatusCode, out["redirect"]
}

func (h *harness) publicLogin(cl *model.Client, extra url.Values) (tokResp, string) {
	return h.publicLoginIn(h.env.Primary, h.user, cl, extra)
}

// publicLoginIn is publicLogin for user u of organization org, at its endpoints.
func (h *harness) publicLoginIn(org *model.Org, u *model.User, cl *model.Client, extra url.Values) (tokResp, string) {
	h.t.Helper()
	c, csrf := h.session(u)
	v, ch := pkce()
	redirectTo := h.authorizeIn(org.ID, c, authzQuery(cl, ch, extra))
	if redirectTo.Path != web.OrgPath(org.ID, "/oauth/consent") { // public clients always see the consent page
		h.t.Fatalf("public client skipped consent: %s", redirectTo)
	}
	_, redirect := h.decideConsentIn(org.ID, c, csrf, redirectTo.Query().Get("flow"), true)
	code := loc(h.t, h.get(c, redirect)).Query().Get("code")
	if code == "" {
		h.t.Fatal("no code")
	}
	r := h.post(web.OrgPath(org.ID, "/oauth/token"), url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cl.ID},
		"redirect_uri": {cl.RedirectURIs[0]}, "code_verifier": {v}}, "", "")
	return r, v
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// regexpValue returns the value of the hidden input named name.
func regexpValue(page, name string) string {
	i := strings.Index(page, `name="`+name+`" value="`)
	if i < 0 {
		return ""
	}
	rest := page[i+len(`name="`+name+`" value="`):]
	return rest[:strings.IndexByte(rest, '"')]
}

func outcomeOf(err error) string {
	var fe *service.FieldError
	if errors.As(err, &fe) {
		return "invalid"
	}
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func sessionsFor(t *testing.T, h *harness) []*model.Session {
	l, err := h.env.Svc.Sessions.All(context.Background(), h.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func reqWithCookies(h *harness, c *http.Client) *http.Request {
	req, _ := http.NewRequest("GET", h.env.URL+"/", nil)
	u, _ := url.Parse(h.env.URL)
	for _, ck := range c.Jar.Cookies(u) {
		req.AddCookie(ck)
	}
	return req
}

type rpServer struct {
	*httptest.Server
	got chan string
}

func newRP() *rpServer {
	rp := &rpServer{got: make(chan string, 10)}
	rp.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // back-channel URIs are https
		_ = r.ParseForm()
		rp.got <- r.PostForm.Get("logout_token")
	}))
	return rp
}

type assertionKey struct {
	alg  string
	priv crypto.Signer
	jwks string
}

func newAssertionKeys(t testing.TB) []assertionKey {
	t.Helper()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	var out []assertionKey
	for _, k := range []assertionKey{{AlgES256, ec, ""}, {AlgEdDSA, ed, ""}} {
		j, _ := EncodeJWK(k.priv.Public(), "ck1", k.alg)
		b, _ := json.Marshal(JWKS{Keys: []JWK{j}})
		k.jwks = string(b)
		out = append(out, k)
	}
	return out
}

func (h *harness) assertion(k assertionKey, claims map[string]any) string {
	b, _ := json.Marshal(claims)
	tok, err := signJWT(k.alg, k.priv, mkHeader(k.alg, "ck1", "JWT"), b)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func (h *harness) assertionClaims(c *model.Client, edit func(map[string]any)) map[string]any {
	m := map[string]any{"iss": c.ID, "sub": c.ID, "aud": h.env.URL + h.orgBase + "/oauth/token", "jti": b64.EncodeToString(randBytes(12)),
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	if edit != nil {
		edit(m)
	}
	return m
}

func (h *harness) ccWithAssertion(c *model.Client, tok string) tokResp {
	return h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType},
		"client_assertion": {tok}}, "", "")
}

// rsaAssertionKey is an RSA client key published with the given JWK alg ("" for none).
func rsaAssertionKey(t testing.TB, signAlg, jwkAlg string) assertionKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	j, _ := EncodeJWK(priv.Public(), "ck1", jwkAlg)
	b, _ := json.Marshal(JWKS{Keys: []JWK{j}})
	return assertionKey{alg: signAlg, priv: priv, jwks: string(b)}
}

func (h *harness) jwtClient(k assertionKey, edit func(*service.ClientInput)) *model.Client {
	h.t.Helper()
	c, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKS = ptr(k.jwks)
		if edit != nil {
			edit(in)
		}
	})
	return c
}

// orgScope asks for the organization claims (org, tenant, org_role) and the application ones (roles, tags) in ID
// tokens and at userinfo.
var orgScope = url.Values{"scope": {"openid profile email offline_access org roles"}}

func membersOnly() model.TenantSettings {
	return model.TenantSettings{MembersOnly: true, PasswordLogin: true, PasskeyLogin: true, AllProviders: true}
}

func (h *harness) grant(tn *model.Tenant, typ, id string, in service.AccessInput) *service.AccessEntry {
	h.t.Helper()
	in.SubjectType, in.SubjectID = typ, id
	e, err := h.env.Svc.AddAccess(context.Background(), h.admin, tn.ID, in)
	if err != nil {
		h.t.Fatal(err)
	}
	return e
}

// tryCode runs authorize for a signed-in browser and reports the code, or the status and body of the refusal.
func (h *harness) tryCode(c *http.Client, cl *model.Client, challenge string, extra url.Values) (code string, status int, text string) {
	h.t.Helper()
	resp := h.get(c, h.orgBase+"/oauth/authorize?"+authzQuery(cl, challenge, extra).Encode())
	if resp.StatusCode == http.StatusFound {
		u := loc(h.t, resp)
		return u.Query().Get("code"), resp.StatusCode, u.Query().Get("error")
	}
	return "", resp.StatusCode, body(resp)
}

func strsOf(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func (h *harness) tenant(name string, set model.TenantSettings) *model.Tenant {
	h.t.Helper()
	tn, err := h.env.Svc.CreateTenant(context.Background(), h.admin, h.env.Primary.ID,
		service.TenantInput{Name: ptr(name), Settings: &set})
	if err != nil {
		h.t.Fatal(err)
	}
	return tn
}

func (h *harness) tenantClient(tn *model.Tenant, edit func(*service.ClientInput)) (*model.Client, string) {
	h.t.Helper()
	return h.newClient(func(in *service.ClientInput) {
		in.TenantID = &tn.ID
		if edit != nil {
			edit(in)
		}
	})
}

// sessionFor signs the user in with the given amr and upstream provider.
func (h *harness) sessionFor(amr []string, provider string) *http.Client {
	h.t.Helper()
	c := h.sessionWith(h.user, amr, time.Now())
	h.signedInThrough(c, provider, nil)
	return c
}

// signedInThrough records on the session of browser c that it signed in through the upstream provider (an id), which
// said the person signed in to it as upstream (Session.UpstreamAMR), and, given, Quisora's own amr for it.
func (h *harness) signedInThrough(c *http.Client, provider string, upstream []string, amr ...string) {
	h.t.Helper()
	pu, _ := url.Parse(h.env.URL)
	for _, ck := range c.Jar.Cookies(pu) {
		if ck.Name == web.SessionCookieFor(h.env.Primary.ID) {
			id := web.SessionID(ck.Value)
			s, err := h.env.Svc.Sessions.Get(context.Background(), id)
			if err != nil {
				h.t.Fatal(err)
			}
			s.Provider, s.UpstreamAMR = provider, upstream
			if amr != nil {
				s.AMR = amr
			}
			if err := h.env.Svc.Sessions.Update(context.Background(), s); err != nil {
				h.t.Fatal(err)
			}
			h.env.Server.Sessions.Evict(id, "")
		}
	}
}

func (h *harness) setOrg(s model.OrgSettings) {
	h.t.Helper()
	if _, err := h.env.Svc.UpdateOrg(context.Background(), h.admin, h.env.Primary.ID, service.OrgInput{Settings: &s}); err != nil {
		h.t.Fatal(err)
	}
	h.env.Svc.InvalidateOrgs()
}

// auditEvents returns the stored audit events of one action.
func (h *harness) auditEvents(action string) []*model.Audit {
	h.t.Helper()
	l, _, err := h.env.Svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		h.t.Fatal(err)
	}
	var out []*model.Audit
	for _, a := range l {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

func (h *harness) userinfo(at string) map[string]any {
	h.t.Helper()
	resp := h.get(h.http, h.orgBase+"/oauth/userinfo", "Authorization", "Bearer "+at)
	if resp.StatusCode != 200 {
		h.t.Fatalf("userinfo: %d", resp.StatusCode)
	}
	m := map[string]any{}
	_ = json.Unmarshal([]byte(body(resp)), &m)
	return m
}

const mcpResource = "https://mcp.example.com/mcp"

// postJSON posts a JSON body and returns the status and decoded object.
func (h *harness) postJSON(path string, body any) tokResp {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	m := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	return tokResp{resp.StatusCode, m, resp.Header}
}

// register registers an application by RFC 7591 and returns it as a client (id and redirect URIs).
func (h *harness) register(redirect string) *model.Client {
	h.t.Helper()
	r := h.postJSON(h.orgBase+"/oauth/register", map[string]any{"client_name": "Claude", "redirect_uris": []string{redirect}})
	if r.status != http.StatusCreated || !strings.HasPrefix(r.str("client_id"), "dyn-") {
		h.t.Fatalf("register: %d %v", r.status, r.m)
	}
	return &model.Client{Meta: model.Meta{ID: r.str("client_id")}, RedirectURIs: []string{redirect}}
}

// mcpTenant is a tenant owning mcpResource, allowing self-registered applications when allow.
func (h *harness) mcpTenant(name string, allow bool) *model.Tenant {
	h.t.Helper()
	set := model.DefaultTenantSettings()
	set.SelfRegistration, set.RequireMFA = allow, false // the test sessions have no second factor
	tn, err := h.env.Svc.CreateTenant(context.Background(), h.admin, h.env.Primary.ID,
		service.TenantInput{Name: ptr(name), Settings: &set, Resources: &[]string{mcpResource}})
	if err != nil {
		h.t.Fatal(err)
	}
	return tn
}

// consentPage authorizes with the browser and returns the consent page's HTML and flow id.
func (h *harness) consentPage(c *http.Client, cl *model.Client, ch string, extra url.Values) (string, string) {
	h.t.Helper()
	u := h.authorize(c, authzQuery(cl, ch, extra))
	if u.Path != h.orgBase+"/oauth/consent" {
		h.t.Fatalf("no consent page: %s", u)
	}
	return body(h.get(c, u.String())), u.Query().Get("flow")
}

// rawPost posts a body as is (not necessarily a valid form).
func (h *harness) rawPost(path, payload string) tokResp {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+path, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return tokResp{status: resp.StatusCode, m: map[string]any{"body": body(resp)}, hdr: resp.Header}
}

func tokenErr(t *testing.T, r tokResp, status int, code string) {
	t.Helper()
	if r.status != status || r.m["error"] != code {
		t.Fatalf("want %d %s, got %d %v", status, code, r.status, r.m)
	}
}

// newTLSServer starts an HTTPS server (the URIs the provider calls out to are https) that counts the requests it
// serves, and closes it when the test ends.
func newTLSServer(t testing.TB, serve http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		serve(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// confirmLogout posts a form (as the confirmation page does) to the logout confirmation endpoint.
func (h *harness) confirmLogout(c *http.Client, form string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+h.orgBase+"/oauth/logout/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// withLogoutBackoff replaces the waits between a back-channel logout's retries until the test ends. The waits are a
// package variable, so a test that uses it cannot run in parallel with others.
func withLogoutBackoff(t testing.TB, waits ...time.Duration) {
	t.Helper()
	saved := logoutBackoff
	logoutBackoff = waits
	t.Cleanup(func() { logoutBackoff = saved })
}

// exchangeCode redeems an authorization code at the token endpoint with the client's first registered redirect URI.
func (h *harness) exchangeCode(cl *model.Client, secret, code, verifier string) tokResp {
	h.t.Helper()
	return h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {verifier}}, cl, secret)
}
