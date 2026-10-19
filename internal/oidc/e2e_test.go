package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

const rpCallback = "https://rp.example/cb"

type harness struct {
	t     testing.TB
	env   *webtest.Env
	p     *Provider
	admin *service.Actor
	user  *model.User
	http  *http.Client
}

func ptr[T any](v T) *T { return &v }

func setup(t testing.TB, cfgFn func(*config.Config)) *harness { return setupKey(t, cfgFn, nil) }

// setupKey is setup with a chosen master key.
func setupKey(t testing.TB, cfgFn func(*config.Config), masterKey []byte) *harness {
	t.Helper()
	var p *Provider
	env := webtest.New(t, webtest.Options{Configure: cfgFn, MasterKey: masterKey, Modules: func(s *web.Server) []web.Module {
		p = New(s)
		return []web.Module{p}
	}})
	p.HTTP = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	h := &harness{t: t, env: env, p: p, admin: service.ActorForUser(env.Admin, "")}
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
	return h
}

// newClient creates a confidential first-party client unless edit changes it.
// testResources are the resource indicators test clients are registered for (RFC 8707: a client may name only those).
var testResources = []string{"https://api.example/v1", "https://api.example", "https://api.example/a", "https://api.example/b",
	"urn:example:billing"}

func (h *harness) newClient(edit func(*service.ClientInput)) (*model.Client, string) {
	h.t.Helper()
	in := service.ClientInput{Name: ptr("app"), RedirectURIs: &[]string{rpCallback},
		GrantTypes: &[]string{"authorization_code", "refresh_token", "client_credentials"},
		Scopes:     &[]string{"openid", "profile", "email", "groups", "org", "offline_access", "api"}, FirstParty: ptr(true),
		Resources: &testResources}
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
	h.t.Helper()
	resp := h.get(c, "/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("authorize status %d: %s", resp.StatusCode, body(resp))
	}
	return loc(h.t, resp)
}

func (h *harness) getCode(c *http.Client, cl *model.Client, challenge string, extra url.Values) string {
	h.t.Helper()
	u := h.authorize(c, authzQuery(cl, challenge, extra))
	if code := u.Query().Get("code"); code != "" {
		if u.Query().Get("iss") != h.env.Cfg.Issuer() || u.Query().Get("state") != "st1" && extra.Get("state") == "" {
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
	return h.post("/oauth/token", f, "", "")
}

// exchange runs a full code exchange for a first-party confidential client.
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
	r := h.post("/oauth/introspect", f, id, sec)
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
		if ck.Name == web.SessionCookie {
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

// ---------------------------------------------------------------------------------------------------------------

func TestDiscoveryAndJWKS(t *testing.T) {
	h := setup(t, nil)
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		resp := h.get(h.http, path, "Origin", "https://anywhere.example")
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s: no CORS", path)
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(body(resp)), &d); err != nil {
			t.Fatal(err)
		}
		if d["issuer"] != h.env.URL || d["token_endpoint"] != h.env.URL+"/oauth/token" {
			t.Errorf("%s: %v", path, d)
		}
		if m, _ := d["token_endpoint_auth_methods_supported"].([]any); !slices.Contains(m, any("none")) || slices.Contains(m, any("")) {
			t.Errorf("auth methods %v", m)
		}
		if m, _ := d["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
			t.Errorf("pkce methods %v", m)
		}
	}
	resp := h.get(h.http, "/oauth/jwks")
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" || !strings.Contains(resp.Header.Get("Cache-Control"), "max-age") {
		t.Errorf("jwks headers %v", resp.Header)
	}
	set, err := ParseJWKS([]byte(body(resp)))
	if err != nil || len(set) != 1 || set[0].Kty != "EC" || set[0].Alg != AlgES256 || set[0].Kid == "" {
		t.Fatalf("jwks %+v %v", set, err)
	}
	if resp := h.get(h.http, "/oauth/jwks", "Origin", "https://x"); resp.StatusCode != 200 {
		t.Fatal("jwks")
	}
	// no CORS on the token endpoint for an unknown origin
	r := h.post("/oauth/token", url.Values{}, "", "", "Origin", "https://evil.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Error("token endpoint leaked CORS")
	}
}

func TestCodeFlowEndToEnd(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	grp, _ := h.env.Svc.CreateGroup(context.Background(), h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("devs")})
	_ = h.env.Svc.SetMembership(context.Background(), h.admin, grp.ID, h.user.ID, true)

	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile email groups org offline_access"}, "resource": {"https://api.example/v1"}})
	if r.str("token_type") != "Bearer" || r.str("refresh_token") == "" || r.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("%v %v", r.m, r.hdr)
	}
	at, idt := r.str("access_token"), r.str("id_token")

	// access token (RFC 9068)
	if hd := headerOf(t, at); hd["typ"] != "at+jwt" || hd["alg"] != "ES256" || hd["kid"] == "" {
		t.Fatalf("header %v", hd)
	}
	ac := claimsOf(t, at)
	aud, _ := ac["aud"].([]any)
	if ac["iss"] != h.env.URL || ac["sub"] != h.user.ID || ac["client_id"] != cl.ID || len(aud) != 2 || aud[0] != cl.ID ||
		aud[1] != "https://api.example/v1" || ac["org"] != h.env.Primary.ID || ac["org_name"] != "primary" ||
		ac["role"] != "user" || ac["jti"] == "" || ac["sid"] == "" || ac["acr"] != acrBasic {
		t.Fatalf("access claims %v", ac)
	}
	if g, _ := ac["groups"].([]any); len(g) != 1 || g[0] != "devs" {
		t.Fatalf("groups %v", ac["groups"])
	}
	// ID token
	if hd := headerOf(t, idt); hd["typ"] != "JWT" {
		t.Fatalf("id header %v", hd)
	}
	ic := claimsOf(t, idt)
	sum := sha256.Sum256([]byte(at))
	if ic["aud"] != cl.ID || ic["nonce"] != "n1" || ic["email"] != "alice@example.com" || ic["email_verified"] != true ||
		ic["preferred_username"] != "alice" || ic["name"] != "Alice A" || ic["sid"] != ac["sid"] ||
		ic["at_hash"] != b64.EncodeToString(sum[:16]) || ic["auth_time"] == nil || ic["amr"] == nil {
		t.Fatalf("id claims %v", ic)
	}
	// verify both against the published JWKS with an independent path
	jw, _ := ParseJWKS([]byte(body(h.get(h.http, "/oauth/jwks"))))
	pub, _ := jw[0].PublicKey()
	decodeIndependently(t, at, pub)
	decodeIndependently(t, idt, pub)

	// userinfo
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	var ui map[string]any
	_ = json.Unmarshal([]byte(body(resp)), &ui)
	if ui["sub"] != h.user.ID || ui["email"] != "alice@example.com" || ui["org_name"] != "primary" || ui["role"] != "user" {
		t.Fatalf("userinfo %v", ui)
	}
	// narrower scope -> fewer claims
	r2 := h.refreshWith(cl, secret, r.str("refresh_token"))
	if r2.status != 200 {
		t.Fatal(r2)
	}
	r3 := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.str("refresh_token")}, "scope": {"openid"}}, cl, secret)
	resp = h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+r3.str("access_token"))
	ui = map[string]any{}
	_ = json.Unmarshal([]byte(body(resp)), &ui)
	if ui["email"] != nil || ui["sub"] != h.user.ID {
		t.Fatalf("userinfo openid-only %v", ui)
	}
	// bad / missing bearer
	if resp := h.get(h.http, "/oauth/userinfo"); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
	resp = h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at+"x")
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatal(resp.StatusCode, resp.Header)
	}
}

func TestAuthorizeValidation(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()

	// errors that must NOT redirect
	for name, q := range map[string]url.Values{
		"unknown client": {"client_id": {"nope"}, "redirect_uri": {rpCallback}},
		"wrong redirect": authzQuery(cl, ch, url.Values{"redirect_uri": {"https://evil.example/cb"}}),
		"no redirect":    authzQuery(cl, ch, url.Values{"redirect_uri": {""}}),
		"prefix match":   authzQuery(cl, ch, url.Values{"redirect_uri": {rpCallback + "/x"}}),
		"http downgrade": authzQuery(cl, ch, url.Values{"redirect_uri": {"http://rp.example/cb"}}),
	} {
		resp := h.get(c, "/oauth/authorize?"+q.Encode())
		if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d location %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
		body(resp)
	}
	// errors that redirect back to the client
	for name, tc := range map[string]struct {
		extra url.Values
		code  string
	}{
		"no pkce":        {url.Values{"code_challenge": {""}, "code_challenge_method": {""}}, "invalid_request"},
		"plain":          {url.Values{"code_challenge_method": {"plain"}}, "invalid_request"},
		"bad challenge":  {url.Values{"code_challenge": {"short"}}, "invalid_request"},
		"token type":     {url.Values{"response_type": {"token"}}, "unsupported_response_type"},
		"scope":          {url.Values{"scope": {"openid admin"}}, "invalid_scope"},
		"prompt":         {url.Values{"prompt": {"bogus"}}, "invalid_request"},
		"none+login":     {url.Values{"prompt": {"none login"}}, "invalid_request"},
		"max_age":        {url.Values{"max_age": {"-1"}}, "invalid_request"},
		"request object": {url.Values{"request": {"x"}}, "request_not_supported"},
		"resource":       {url.Values{"resource": {"not a uri"}}, "invalid_target"},
		"response_mode":  {url.Values{"response_mode": {"fragment"}}, "invalid_request"},
	} {
		u := h.authorize(c, authzQuery(cl, ch, tc.extra))
		if u.Scheme+"://"+u.Host+u.Path != rpCallback || u.Query().Get("error") != tc.code ||
			u.Query().Get("iss") == "" {
			t.Errorf("%s: %s", name, u)
		}
		if name != "response_mode" && u.Query().Get("state") != "st1" {
			t.Errorf("%s: state lost", name)
		}
	}
	// disabled client
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(cl.ID)
	if resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, ch, nil).Encode()); resp.StatusCode != 400 {
		t.Errorf("disabled client status %d", resp.StatusCode)
	}
}

func TestLoopbackRedirectPort(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.RedirectURIs = &[]string{"http://127.0.0.1/cb", "https://rp.example/cb"}
	})
	c, _ := h.session(h.user)
	_, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, url.Values{"redirect_uri": {"http://127.0.0.1:53211/cb"}}))
	if u.Host != "127.0.0.1:53211" || u.Query().Get("code") == "" {
		t.Fatal(u)
	}
	for _, bad := range []string{"http://127.0.0.1:53211/other", "http://localhost:53211/cb", "https://rp.example:8443/cb", "http://evil.example/cb"} {
		resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, ch, url.Values{"redirect_uri": {bad}}).Encode())
		if resp.StatusCode != 400 {
			t.Errorf("%s accepted (%d)", bad, resp.StatusCode)
		}
	}
}

func TestSignInHandoff(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	anon := h.anon()

	u := h.authorize(anon, authzQuery(cl, ch, nil))
	if u.Path != "/login/primary" || u.Query().Get("reauth") != "" {
		t.Fatalf("handoff %s", u)
	}
	next := u.Query().Get("next")
	if !strings.HasPrefix(next, "/oauth/authorize/resume?flow=") {
		t.Fatal(next)
	}
	// prompt=none must not interact
	u2 := h.authorize(anon, authzQuery(cl, ch, url.Values{"prompt": {"none"}}))
	if u2.Query().Get("error") != "login_required" || u2.Host != "rp.example" {
		t.Fatalf("prompt=none: %s", u2)
	}
	// after sign-in the browser returns to resume and gets a code
	signed, _ := h.session(h.user)
	h.copyFlowCookies(anon, signed) // same browser: the flow cookie travels with the user through sign-in
	resp := h.get(signed, next)
	if resp.StatusCode != 302 || loc(t, resp).Query().Get("code") == "" {
		t.Fatalf("resume: %d", resp.StatusCode)
	}
	// the flow is consumed
	resp = h.get(signed, next)
	if resp.StatusCode != 400 {
		t.Fatalf("flow reuse: %d", resp.StatusCode)
	}
	// prompt=none with a session works silently
	u3 := h.authorize(signed, authzQuery(cl, ch, url.Values{"prompt": {"none"}}))
	if u3.Query().Get("code") == "" {
		t.Fatal(u3)
	}
	// wrong org: user of another org must re-authenticate
	org2, err := h.env.Svc.CreateOrg(context.Background(), h.admin, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")})
	if err != nil {
		t.Fatal(err)
	}
	cl2, _, _ := h.env.Svc.CreateClient(context.Background(), h.admin, org2.ID, service.ClientInput{Name: ptr("acme app"),
		RedirectURIs: &[]string{rpCallback}, GrantTypes: &[]string{"authorization_code"}, FirstParty: ptr(true)})
	u5 := h.authorize(signed, authzQuery(cl2, ch, url.Values{"scope": {"openid"}}))
	if u5.Path != "/login/acme" || u5.Query().Get("reauth") != "1" {
		t.Fatalf("wrong org: %s", u5)
	}
}

func TestPromptLoginAndMaxAge(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()

	old := h.sessionWith(h.user, []string{"pwd"}, time.Now().Add(-2*time.Hour))
	if u := h.authorize(old, authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("plain: %s", u)
	}
	u := h.authorize(old, authzQuery(cl, ch, url.Values{"max_age": {"60"}}))
	if u.Path != "/login/primary" || u.Query().Get("reauth") != "1" {
		t.Fatalf("max_age: %s", u)
	}
	if u := h.authorize(old, authzQuery(cl, ch, url.Values{"max_age": {"86400"}})); u.Query().Get("code") == "" {
		t.Fatal("max_age within limit refused")
	}
	if u := h.authorize(old, authzQuery(cl, ch, url.Values{"max_age": {"60"}, "prompt": {"none"}})); u.Query().Get("error") != "login_required" {
		t.Fatalf("none+max_age: %s", u)
	}
	// prompt=login with a session that predates the request
	fresh, _ := h.session(h.user)
	u = h.authorize(fresh, authzQuery(cl, ch, url.Values{"prompt": {"login"}}))
	if u.Query().Get("reauth") != "1" {
		t.Fatalf("prompt=login: %s", u)
	}
	// ... the user signs in again (new session after the flow began) and resumes: code issued
	again, _ := h.session(h.user)
	h.copyFlowCookies(fresh, again)
	resp := h.get(again, u.Query().Get("next"))
	if resp.StatusCode != 302 || loc(t, resp).Query().Get("code") == "" {
		t.Fatalf("resume after reauth: %d", resp.StatusCode)
	}
	// max_age=0 behaves like prompt=login and does not loop after re-authentication
	u = h.authorize(fresh, authzQuery(cl, ch, url.Values{"max_age": {"0"}}))
	if u.Query().Get("reauth") != "1" {
		t.Fatal(u)
	}
	again, _ = h.session(h.user)
	h.copyFlowCookies(fresh, again)
	if resp := h.get(again, u.Query().Get("next")); resp.StatusCode != 302 || loc(t, resp).Query().Get("code") == "" {
		t.Fatal("max_age=0 resume")
	}
}

func TestRequireMFA(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	_, err := h.env.Svc.UpdateOrg(context.Background(), h.admin, h.env.Primary.ID, service.OrgInput{
		Settings: &model.OrgSettings{PasswordLogin: true, PasskeyLogin: true, RequireMFA: true}})
	if err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateOrg(h.env.Primary.ID)
	weak := h.sessionWith(h.user, []string{"pwd"}, time.Now())
	u := h.authorize(weak, authzQuery(cl, ch, nil))
	if u.Path != "/login/primary" || u.Query().Get("reauth") != "1" {
		t.Fatalf("pwd only: %s", u)
	}
	// a passkey is two factors only when it verified its user
	if u := h.authorize(h.sessionWith(h.user, []string{"hwk"}, time.Now()), authzQuery(cl, ch, nil)); u.Query().Get("reauth") != "1" {
		t.Errorf("passkey without user verification accepted as MFA: %s", u)
	}
	for _, amr := range [][]string{{"pwd", "otp"}, {"hwk", "user"}, {"swk", "user"}, {"pwd", "mfa"}} {
		c := h.sessionWith(h.user, amr, time.Now())
		if u := h.authorize(c, authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
			t.Errorf("amr %v refused: %s", amr, u)
		}
	}
	// the sign-in loop is bounded when the requirement can never be met
	fu := h.authorize(weak, authzQuery(cl, ch, nil))
	flowURL := fu.Query().Get("next")
	for range 10 {
		body(h.get(weak, flowURL))
	}
	if resp := h.get(weak, flowURL); resp.StatusCode != 400 && resp.StatusCode != 403 {
		t.Fatalf("loop not bounded: %d %s %s", resp.StatusCode, flowURL, body(resp))
	}
}

func TestConsentFlow(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false); in.Name = ptr("Fancy App") })
	c, csrf := h.session(h.user)
	v, ch := pkce()

	u := h.authorize(c, authzQuery(cl, ch, nil))
	if u.Path != "/oauth/consent" {
		t.Fatalf("expected consent: %s", u)
	}
	flowID := u.Query().Get("flow")
	resp := h.get(c, u.RequestURI())
	page := body(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, "Fancy App") || !strings.Contains(page, "alice") && !strings.Contains(page, "Alice A") {
		t.Fatalf("consent page %d %s", resp.StatusCode, page)
	}
	if !strings.Contains(page, `x-data="oauthConsent"`) || strings.Contains(page, "onclick") {
		t.Fatal("consent page markup")
	}
	prompt := func(approve bool) string {
		b, _ := json.Marshal(map[string]any{"flow": flowID, "approve": approve})
		req, _ := http.NewRequest("POST", h.env.URL+"/api/oauth/consent", strings.NewReader(string(b)))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]string
		_ = json.Unmarshal([]byte(body(r)), &out)
		if r.StatusCode != 200 {
			t.Fatalf("consent api %d", r.StatusCode)
		}
		return out["redirect"]
	}
	// CSRF is enforced
	req, _ := http.NewRequest("POST", h.env.URL+"/api/oauth/consent", strings.NewReader(`{"flow":"x","approve":true}`))
	if r, _ := c.Do(req); r.StatusCode != 403 {
		t.Fatalf("no CSRF accepted: %d", r.StatusCode)
	}
	// deny
	resp = h.get(c, prompt(false))
	du := loc(t, resp)
	if du.Query().Get("error") != "access_denied" || du.Query().Get("state") != "st1" {
		t.Fatalf("deny: %s", du)
	}
	// new flow, approve
	u = h.authorize(c, authzQuery(cl, ch, nil))
	flowID = u.Query().Get("flow")
	resp = h.get(c, prompt(true))
	code := loc(t, resp).Query().Get("code")
	if code == "" {
		t.Fatal("no code after consent")
	}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, secret)
	if r.status != 200 {
		t.Fatal(r.m)
	}
	// consent is remembered while the grant lives
	_, ch2 := pkce()
	if u := h.authorize(c, authzQuery(cl, ch2, nil)); u.Query().Get("code") == "" {
		t.Fatalf("consent not remembered: %s", u)
	}
	// ... unless the client asks for it again
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"prompt": {"consent"}})); u.Path != "/oauth/consent" {
		t.Fatalf("prompt=consent: %s", u)
	}
	// prompt=none with a new scope that was never consented
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Scopes: &[]string{"openid", "profile", "email", "offline_access", "api"}})
	h.p.InvalidateClient(cl.ID)
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"scope": {"openid api"}, "prompt": {"none"}})); u.Query().Get("error") != "consent_required" {
		t.Fatalf("consent_required: %s", u)
	}
}

func TestFormPostResponseMode(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, ch, url.Values{"response_mode": {"form_post"}}).Encode())
	page := body(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, `action="`+rpCallback+`"`) || !strings.Contains(page, `name="code"`) ||
		!strings.Contains(page, `name="state" value="st1"`) || !strings.Contains(page, `name="iss"`) {
		t.Fatalf("form_post page: %s", page)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action https://rp.example") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "script-src 'self';") == false {
		t.Fatalf("csp %q", csp)
	}
	// errors use the same mode
	resp = h.get(c, "/oauth/authorize?"+authzQuery(cl, ch, url.Values{"response_mode": {"form_post"}, "scope": {"bogus"}}).Encode())
	if p := body(resp); !strings.Contains(p, `name="error" value="invalid_scope"`) {
		t.Fatal(p)
	}
}

func TestTokenEndpointPKCEAndBindings(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, otherSecret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	form := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}
	}
	expectErr := func(r tokResp, status int, code string) {
		t.Helper()
		if r.status != status || r.m["error"] != code {
			t.Fatalf("want %d %s, got %d %v", status, code, r.status, r.m)
		}
		if r.hdr.Get("Cache-Control") != "no-store" {
			t.Fatal("no-store missing")
		}
	}
	// wrong verifier burns the code
	code := h.getCode(c, cl, ch, nil)
	bad := form(code)
	bad.Set("code_verifier", strings.Repeat("a", 43))
	expectErr(h.token(bad, cl, secret), 400, "invalid_grant")
	expectErr(h.token(form(code), cl, secret), 400, "invalid_grant")
	// missing verifier
	code = h.getCode(c, cl, ch, nil)
	f := form(code)
	f.Del("code_verifier")
	expectErr(h.token(f, cl, secret), 400, "invalid_grant")
	// short verifier
	code = h.getCode(c, cl, ch, nil)
	f = form(code)
	f.Set("code_verifier", v[:20])
	expectErr(h.token(f, cl, secret), 400, "invalid_grant")
	// wrong redirect_uri
	code = h.getCode(c, cl, ch, nil)
	f = form(code)
	f.Set("redirect_uri", "https://evil.example/cb")
	expectErr(h.token(f, cl, secret), 400, "invalid_grant")
	// another client cannot redeem it
	code = h.getCode(c, cl, ch, nil)
	expectErr(h.token(form(code), other, otherSecret), 400, "invalid_grant")
	// wrong secret
	code = h.getCode(c, cl, ch, nil)
	r := h.token(form(code), cl, "qsrs_wrong")
	expectErr(r, 401, "invalid_client")
	if !strings.HasPrefix(r.hdr.Get("WWW-Authenticate"), "Basic") {
		t.Fatal("WWW-Authenticate missing")
	}
	// the code survived a failed client authentication
	if r := h.token(form(code), cl, secret); r.status != 200 {
		t.Fatalf("%v", r.m)
	}
	// unsupported / missing grant type, no auth at all, both auth methods
	expectErr(h.token(url.Values{"grant_type": {"password"}}, cl, secret), 400, "unsupported_grant_type")
	expectErr(h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, "", ""), 401, "invalid_client")
	expectErr(h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}, cl.ID, secret), 400, "invalid_request")
	// grant type not allowed for the client
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{GrantTypes: &[]string{"authorization_code"}})
	h.p.InvalidateClient(cl.ID)
	expectErr(h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret), 400, "unauthorized_client")
	// GET is not allowed
	if resp := h.get(h.http, "/oauth/token"); resp.StatusCode != 405 {
		t.Fatalf("GET token: %d", resp.StatusCode)
	}
}

func TestClientSecretBasic(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) })
	r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, cl.ID, secret)
	if r.status != 200 || r.str("scope") != "api" {
		t.Fatal(r)
	}
	if r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, cl.ID, secret+"x"); r.status != 401 {
		t.Fatal(r.status)
	}
	// a secret_post client may use Basic too (equivalent); a secret is never accepted for private_key_jwt clients
}

func TestCodeReplayRevokesGrant(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}
	first := h.token(form, cl, secret)
	if first.status != 200 {
		t.Fatal(first)
	}
	rt := first.str("refresh_token")
	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatal("refresh before replay", r.m)
	}
	if r := h.token(form, cl, secret); r.status != 400 || r.m["error"] != "invalid_grant" {
		t.Fatalf("replay: %v", r)
	}
	if r := h.refreshWith(cl, secret, rt); r.status != 400 {
		t.Fatalf("refresh token survived code replay: %v", r.m)
	}
	h.p.InvalidateGrant(claimsOf(t, first.str("access_token"))["gid"].(string))
	if m := h.introspect(cl, secret, first.str("access_token")); m["active"] != false {
		t.Fatalf("access token still active after replay: %v", m)
	}
}

func TestRefreshDefaultMode(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	if parts := strings.Split(rt, "."); len(parts) != 2 {
		t.Fatalf("default refresh token should be grantID.secret: %s", rt)
	}
	for range 3 { // a pure read: same token keeps working and no new one is returned
		r2 := h.refreshWith(cl, secret, rt)
		if r2.status != 200 || r2.str("refresh_token") != "" || r2.str("access_token") == "" || r2.str("id_token") == "" {
			t.Fatalf("%v", r2)
		}
	}
	// wrong secret part, wrong grant, garbage
	gid := strings.Split(rt, ".")[0]
	for _, bad := range []string{gid + "." + b64.EncodeToString(randBytes(32)), "x." + b64.EncodeToString(randBytes(32)), "garbage", "", gid, gid + ".!!!"} {
		if r := h.refreshWith(cl, secret, bad); r.status != 400 || r.m["error"] != "invalid_grant" {
			t.Errorf("%q: %v", bad, r)
		}
	}
	// another client cannot use it
	other, os := h.newClient(nil)
	if r := h.refreshWith(other, os, rt); r.status != 400 {
		t.Fatal("cross-client refresh")
	}
	// scope escalation
	if r := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {"openid groups"}}, cl, secret); r.m["error"] != "invalid_scope" {
		t.Fatalf("%v", r.m)
	}
	// narrower scope
	if r := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {"openid"}}, cl, secret); r.status != 200 || r.str("scope") != "openid" {
		t.Fatalf("%v", r.m)
	}
	// disabled user
	if _, err := h.env.Svc.UpdateUser(context.Background(), h.admin, h.user.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	if r := h.refreshWith(cl, secret, rt); r.status != 400 {
		t.Fatal("disabled user refreshed")
	}
	if m := h.introspect(cl, secret, r.str("access_token")); m["active"] != false {
		t.Fatal("disabled user's access token active")
	}
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token"))
	if resp.StatusCode != 401 {
		t.Fatal("userinfo for disabled user", resp.StatusCode)
	}
	// disabling the user also ended their grants: re-enabling does not bring the token back
	h.env.Svc.UpdateUser(context.Background(), h.admin, h.user.ID, service.UserInput{Active: ptr(true)})
	h.p.InvalidateUser(h.user.ID)
	if r := h.refreshWith(cl, secret, rt); r.status != 400 {
		t.Fatal("grant survived disabling the user")
	}
}

func TestRefreshSurvivesSessionExpiryButNotDeletion(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, secret)
	rt := r.str("refresh_token")
	sid := claimsOf(t, r.str("access_token"))["sid"].(string)
	if err := h.env.Server.Sessions.Delete(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	if r := h.refreshWith(cl, secret, rt); r.status != 400 {
		t.Fatal("refresh after session deletion")
	}
}

func TestRefreshRotation(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	rt0 := r.str("refresh_token")
	if len(strings.Split(rt0, ".")) != 3 {
		t.Fatalf("rotating token format: %s", rt0)
	}
	r1 := h.refreshWith(cl, secret, rt0)
	rt1 := r1.str("refresh_token")
	if r1.status != 200 || rt1 == "" || rt1 == rt0 {
		t.Fatalf("%v", r1)
	}
	r2 := h.refreshWith(cl, secret, rt1)
	rt2 := r2.str("refresh_token")
	if r2.status != 200 || rt2 == "" {
		t.Fatal(r2)
	}
	// replaying an old token kills the whole family, including the newest token
	if r := h.refreshWith(cl, secret, rt0); r.status != 400 {
		t.Fatal("old token accepted")
	}
	if r := h.refreshWith(cl, secret, rt2); r.status != 400 {
		t.Fatal("newest token survived reuse detection")
	}
	// forged MAC / counter never revoke anything
	r, _ = h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	parts := strings.Split(rt, ".")
	forged := parts[0] + ".5." + parts[2]
	if r := h.refreshWith(cl, secret, forged); r.status != 400 {
		t.Fatal("forged counter accepted")
	}
	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatal("forgery revoked the grant")
	}
}

func TestRefreshRotationRace(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.refreshWith(cl, secret, rt).status == 200 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d concurrent presentations of one one-time token succeeded", ok.Load())
	}
}

func TestRotateFlagUpgradesStaticToken(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	static := r.str("refresh_token")
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{RotateRefresh: ptr(true)})
	h.p.InvalidateClient(cl.ID)
	r2 := h.refreshWith(cl, secret, static)
	if r2.status != 200 || len(strings.Split(r2.str("refresh_token"), ".")) != 3 {
		t.Fatal(r2)
	}
	if r := h.refreshWith(cl, secret, static); r.status != 400 {
		t.Fatal("static token still valid after rotation began")
	}
	// presenting the pre-rotation token again is reuse: the family dies, including the newest token
	if r := h.refreshWith(cl, secret, r2.str("refresh_token")); r.status != 400 {
		t.Fatal("grant survived replay of a pre-rotation static token")
	}
}

func TestClientCredentials(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r := h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"https://api.example"}}, cl, secret)
	if r.status != 200 || r.str("refresh_token") != "" || r.str("id_token") != "" || r.str("scope") != "api" {
		t.Fatalf("%v", r)
	}
	ac := claimsOf(t, r.str("access_token"))
	if ac["sub"] != cl.ID || ac["client_id"] != cl.ID || ac["sid"] != nil || ac["role"] != nil || ac["org"] != h.env.Primary.ID {
		t.Fatalf("%v", ac)
	}
	for _, bad := range []string{"openid", "api scim", "admin", "offline_access"} {
		if r := h.token(url.Values{"grant_type": {"client_credentials"}, "scope": {bad}}, cl, secret); r.m["error"] != "invalid_scope" {
			t.Errorf("%q: %v", bad, r.m)
		}
	}
	// SCIM client gets the scim scope
	sc, ssecret := h.newClient(func(in *service.ClientInput) { in.SCIM = ptr(true) })
	r = h.token(url.Values{"grant_type": {"client_credentials"}}, sc, ssecret)
	if !slices.Contains(strings.Fields(r.str("scope")), "scim") {
		t.Fatalf("scim scope missing: %v", r.m)
	}
	// verified by the provider's resource-server helper
	cl2, err := h.p.VerifyAccessToken(context.Background(), r.str("access_token"))
	if err != nil || !cl2.HasScope("scim") {
		t.Fatal(err)
	}
	// disabled client
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(cl.ID)
	if r2 := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret); r2.status != 401 {
		t.Fatalf("disabled client: %d", r2.status)
	}
	if _, err := h.p.VerifyAccessToken(context.Background(), h.token(url.Values{"grant_type": {"client_credentials"}}, sc, ssecret).str("access_token")); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.UpdateClient(context.Background(), h.admin, sc.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(sc.ID)
	if _, err := h.p.VerifyAccessToken(context.Background(), r.str("access_token")); err == nil {
		t.Fatal("token of a disabled client verified")
	}
}

// -- private_key_jwt --------------------------------------------------------------------------------------------

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
	m := map[string]any{"iss": c.ID, "sub": c.ID, "aud": h.env.URL + "/oauth/token", "jti": b64.EncodeToString(randBytes(12)),
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	if edit != nil {
		edit(m)
	}
	return m
}

func (h *harness) ccWithAssertion(c *model.Client, tok string) tokResp {
	return h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType},
		"client_assertion": {tok}}, "", "")
}

func TestPrivateKeyJWT(t *testing.T) {
	for _, k := range newAssertionKeys(t) {
		t.Run(k.alg, func(t *testing.T) {
			h := setup(t, nil)
			cl, secret := h.newClient(func(in *service.ClientInput) {
				in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
				in.JWKS = ptr(k.jwks)
			})
			claims := h.assertionClaims(cl, nil)
			if r := h.ccWithAssertion(cl, h.assertion(k, claims)); r.status != 200 {
				t.Fatalf("valid assertion: %v", r.m)
			}
			// jti replay
			if r := h.ccWithAssertion(cl, h.assertion(k, claims)); r.status != 401 {
				t.Fatalf("replayed jti accepted: %d", r.status)
			}
			// issuer as audience is fine
			if r := h.ccWithAssertion(cl, h.assertion(k, h.assertionClaims(cl, func(m map[string]any) { m["aud"] = []string{h.env.URL} }))); r.status != 200 {
				t.Fatalf("issuer audience: %v", r.m)
			}
			for name, edit := range map[string]func(map[string]any){
				"wrong aud":     func(m map[string]any) { m["aud"] = "https://other.example/token" },
				"expired":       func(m map[string]any) { m["exp"] = time.Now().Add(-5 * time.Minute).Unix() },
				"too long":      func(m map[string]any) { m["exp"] = time.Now().Add(time.Hour).Unix() },
				"no exp":        func(m map[string]any) { delete(m, "exp") },
				"no jti":        func(m map[string]any) { delete(m, "jti") },
				"iss!=sub":      func(m map[string]any) { m["sub"] = "someone" },
				"wrong iss":     func(m map[string]any) { m["iss"] = "x"; m["sub"] = "x" },
				"future iat":    func(m map[string]any) { m["iat"] = time.Now().Add(time.Hour).Unix() },
				"not yet valid": func(m map[string]any) { m["nbf"] = time.Now().Add(time.Hour).Unix() },
			} {
				if r := h.ccWithAssertion(cl, h.assertion(k, h.assertionClaims(cl, edit))); r.status != 401 {
					t.Errorf("%s accepted (%d)", name, r.status)
				}
			}
			// signed by a different key
			rogue := newAssertionKeys(t)
			for _, rk := range rogue {
				if rk.alg == k.alg {
					if r := h.ccWithAssertion(cl, h.assertion(rk, h.assertionClaims(cl, nil))); r.status != 401 {
						t.Error("rogue key accepted")
					}
				}
			}
			// the shared secret cannot be used instead, and an assertion needs the right assertion type
			if r := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret); r.status != 401 {
				t.Errorf("secret accepted for private_key_jwt client: %d", r.status)
			}
			bad := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_assertion": {h.assertion(k, h.assertionClaims(cl, nil))}}, "", "")
			if bad.status != 401 && bad.status != 400 {
				t.Errorf("missing assertion type: %d", bad.status)
			}
			// a confidential-secret client cannot use an assertion
			sc, _ := h.newClient(nil)
			if r := h.ccWithAssertion(sc, h.assertion(k, h.assertionClaims(sc, nil))); r.status != 401 {
				t.Error("assertion accepted for secret client")
			}
			// unknown/forged header alg
			parts := strings.Split(h.assertion(k, h.assertionClaims(cl, nil)), ".")
			parts[0] = b64.EncodeToString([]byte(`{"alg":"none"}`))
			if r := h.ccWithAssertion(cl, strings.Join(parts[:2], ".")+"."); r.status != 401 {
				t.Error("alg none accepted")
			}
		})
	}
}

func TestPrivateKeyJWTWithJWKSURI(t *testing.T) {
	keys := newAssertionKeys(t)
	k := keys[0]
	var hits atomic.Int32
	jwks := k.jwks
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(jwks))
	}))
	defer srv.Close()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/jwks")
	})
	for range 3 {
		if r := h.ccWithAssertion(cl, h.assertion(k, h.assertionClaims(cl, nil))); r.status != 200 {
			t.Fatalf("%v", r.m)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("jwks fetched %d times, want 1 (cached)", hits.Load())
	}
	// key rotation at the client: new key published, unknown kid triggers one refetch
	nk := newAssertionKeys(t)[0]
	j, _ := EncodeJWK(nk.priv.Public(), "ck2", nk.alg)
	jb, _ := json.Marshal(JWKS{Keys: []JWK{j}})
	jwks = string(jb)
	h.p.remoteKey[srv.URL+"/jwks"].forced = time.Time{}
	rb, _ := json.Marshal(h.assertionClaims(cl, nil))
	rot, err := signJWT(nk.alg, nk.priv, mkHeader(nk.alg, "ck2", "JWT"), rb)
	if err != nil {
		t.Fatal(err)
	}
	if r := h.ccWithAssertion(cl, rot); r.status != 200 {
		t.Fatalf("rotated client key: %v", r.m)
	}
}

func TestSafeClientBlocksPrivateAddresses(t *testing.T) {
	h := setup(t, nil)
	p := New(h.env.Server)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	if _, err := p.fetch(context.Background(), srv.URL, 100); err == nil {
		t.Fatal("loopback fetch allowed")
	}
	p.AllowPrivateNetworks = true
	if _, err := p.fetch(context.Background(), srv.URL, 100); err != nil {
		t.Fatalf("loopback with AllowPrivateNetworks: %v", err)
	}
	if _, err := p.fetch(context.Background(), "http://169.254.169.254/latest/meta-data", 100); err == nil {
		t.Fatal("metadata address reachable")
	}
}

// -- introspection / revocation ---------------------------------------------------------------------------------

func TestIntrospection(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at, rt := r.str("access_token"), r.str("refresh_token")

	m := h.introspect(cl, secret, at)
	if m["active"] != true || m["sub"] != h.user.ID || m["client_id"] != cl.ID || m["username"] != "alice" ||
		m["token_type"] != "Bearer" || m["scope"] != "openid profile email offline_access" || m["exp"] == nil || m["iss"] != h.env.URL {
		t.Fatalf("jwt: %v", m)
	}
	m = h.introspect(cl, secret, rt)
	if m["active"] != true || m["token_type"] != nil || m["token_kind"] != "refresh_token" || m["sub"] != h.user.ID || m["username"] != "alice" {
		t.Fatalf("refresh: %v", m)
	}
	// another client may introspect JWTs but not our refresh token
	other, osecret := h.newClient(nil)
	if h.introspect(other, osecret, at)["active"] != true {
		t.Fatal("jwt introspection by another client")
	}
	if h.introspect(other, osecret, rt)["active"] != false {
		t.Fatal("refresh token visible to another client")
	}
	// API token
	tok, plain, err := h.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(h.user, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}, Expires: 30})
	if err != nil {
		t.Fatal(err)
	}
	m = h.introspect(other, osecret, plain)
	if m["active"] != true || m["token_type"] != "Bearer" || m["token_kind"] != "api_token" || m["sub"] != h.user.ID || m["scope"] != "api" || m["username"] != "alice" ||
		m["org"] != h.env.Primary.ID || m["exp"] == nil {
		t.Fatalf("api token: %v", m)
	}
	if h.introspect(other, osecret, plain+"x")["active"] != false {
		t.Fatal("bad api token active")
	}
	_ = tok
	// garbage, forged, wrong typ, expired
	for _, bad := range []string{"garbage", "eyJhbGciOiJub25lIn0.e30.", at + "x", at[:len(at)-4], "qsr_x_y"} {
		if h.introspect(cl, secret, bad)["active"] != false {
			t.Errorf("%q active", bad)
		}
	}
	if h.introspect(cl, secret, r.str("id_token"))["active"] != false {
		t.Error("ID token introspected as access token")
	}
	// client credentials JWT
	cc := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret)
	if m := h.introspect(cl, secret, cc.str("access_token")); m["active"] != true || m["sub"] != cl.ID {
		t.Fatalf("cc: %v", m)
	}
	// unauthenticated and wrong credentials
	if r := h.post("/oauth/introspect", url.Values{"token": {at}}, "", ""); r.status != 401 {
		t.Fatal(r.status)
	}
	if r := h.clientPost("/oauth/introspect", url.Values{"token": {at}}, cl, "wrong"); r.status != 401 {
		t.Fatal(r.status)
	}
	if r := h.clientPost("/oauth/introspect", url.Values{}, cl, secret); r.status != 400 {
		t.Fatal(r.status)
	}
	// expired token
	short := setup(t, func(c *config.Config) { c.Tokens.AccessTTL = 1 })
	cl2, s2 := short.newClient(nil)
	r2, _ := short.login(cl2, s2, nil)
	time.Sleep(2100 * time.Millisecond)
	if short.introspect(cl2, s2, r2.str("access_token"))["active"] != false {
		t.Fatal("expired token active")
	}
}

func TestIntrospectionRejectsForeignKeyAndAlgConfusion(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	hd := headerOf(t, at)
	// valid kid, signature from an attacker key
	k := genKeys(t)[0]
	forged := signWith(t, k, hd["kid"].(string), "at+jwt", string(mustJSON(claimsOf(t, at))))
	if h.introspect(cl, secret, forged)["active"] != false {
		t.Fatal("forged token active")
	}
	// HS256 using the public JWK as the secret
	jw := body(h.get(h.http, "/oauth/jwks"))
	hh := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"` + hd["kid"].(string) + `","typ":"at+jwt"}`))
	pl := b64.EncodeToString(mustJSON(claimsOf(t, at)))
	tok := hh + "." + pl + "." + b64.EncodeToString([]byte(jw))
	if h.introspect(cl, secret, tok)["active"] != false {
		t.Fatal("HS256 token active")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestRevocation(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, osecret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	rt, at := r.str("refresh_token"), r.str("access_token")

	// another client's revoke is a no-op but still 200
	if x := h.clientPost("/oauth/revoke", url.Values{"token": {rt}}, other, osecret); x.status != 200 {
		t.Fatal(x.status)
	}
	if h.refreshWith(cl, secret, rt).status != 200 {
		t.Fatal("foreign revoke worked")
	}
	for _, junk := range []string{"garbage", "qsr_a_b", "a.b"} {
		if x := h.clientPost("/oauth/revoke", url.Values{"token": {junk}}, cl, secret); x.status != 200 {
			t.Fatalf("%q: %d", junk, x.status)
		}
	}
	if x := h.post("/oauth/revoke", url.Values{"token": {rt}}, "", ""); x.status != 401 {
		t.Fatal("unauthenticated revoke", x.status)
	}
	if x := h.clientPost("/oauth/revoke", url.Values{"token": {rt}}, cl, secret); x.status != 200 {
		t.Fatal(x.status)
	}
	if h.refreshWith(cl, secret, rt).status != 400 {
		t.Fatal("revoked refresh token works")
	}
	h.p.InvalidateGrant(claimsOf(t, at)["gid"].(string))
	if h.introspect(cl, secret, at)["active"] != false {
		t.Fatal("access token active after its grant was revoked")
	}
	// API tokens are not revocable here
	_, plain, _ := h.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(h.user, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}, Expires: 30})
	if x := h.clientPost("/oauth/revoke", url.Values{"token": {plain}}, cl, secret); x.status != 200 {
		t.Fatal(x.status)
	}
	if h.introspect(cl, secret, plain)["active"] != true {
		t.Fatal("API token revoked through /oauth/revoke")
	}
	// revoking an access token ends its grant
	r, _ = h.login(cl, secret, nil)
	h.clientPost("/oauth/revoke", url.Values{"token": {r.str("access_token")}}, cl, secret)
	if h.refreshWith(cl, secret, r.str("refresh_token")).status != 400 {
		t.Fatal("refresh survived access token revocation")
	}
}

// -- logout -----------------------------------------------------------------------------------------------------

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

func TestLogoutWithBackchannel(t *testing.T) {
	rp := newRP()
	defer rp.Close()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.BackchannelURI = ptr(rp.URL + "/logout")
		in.PostLogoutURIs = &[]string{"https://rp.example/bye"}
	})
	silent, ssecret := h.newClient(nil) // no back-channel URI: must not be contacted, must not break anything
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, secret)
	v2, ch2 := pkce()
	code2 := h.getCode(c, silent, ch2, nil)
	r2 := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code2}, "redirect_uri": {rpCallback}, "code_verifier": {v2}}, silent, ssecret)
	idt, rt := r.str("id_token"), r.str("refresh_token")
	sid := claimsOf(t, idt)["sid"].(string)

	// unregistered post-logout redirect is refused and nothing happens
	bad := "/oauth/logout?" + url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {"https://evil.example/"}}.Encode()
	if resp := h.get(c, bad); resp.StatusCode != 400 {
		t.Fatalf("bad redirect: %d", resp.StatusCode)
	}
	if resp := h.get(c, "/oauth/logout?id_token_hint="+idt+"x"); resp.StatusCode != 400 {
		t.Fatal("forged hint accepted")
	}
	if h.refreshWith(cl, secret, rt).status != 200 {
		t.Fatal("rejected logout had effects")
	}

	q := url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"xyz"}}
	resp := h.get(c, "/oauth/logout?"+q.Encode())
	u := loc(t, resp)
	if resp.StatusCode != 302 || u.Scheme+"://"+u.Host+u.Path != "https://rp.example/bye" || u.Query().Get("state") != "xyz" {
		t.Fatalf("logout redirect: %d %s", resp.StatusCode, u)
	}
	select {
	case lt := <-rp.got:
		pj, err := ParseJWT(lt)
		if err != nil || pj.Header.Typ != "logout+jwt" {
			t.Fatalf("logout token header %v %v", pj, err)
		}
		key := h.p.keyByKID(context.Background(), pj.Header.Kid)
		if key == nil || pj.Verify(key.pub) != nil {
			t.Fatal("logout token signature")
		}
		lc := claimsOf(t, lt)
		ev, _ := lc["events"].(map[string]any)
		if _, ok := ev[backchannelEvent]; !ok || lc["sid"] != sid || lc["sub"] != h.user.ID || lc["aud"] != cl.ID ||
			lc["iss"] != h.env.URL || lc["jti"] == "" || lc["iat"] == nil || lc["exp"] == nil || lc["nonce"] != nil {
			t.Fatalf("logout claims %v", lc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no back-channel logout received")
	}
	h.p.Wait()
	select {
	case <-rp.got:
		t.Fatal("more than one logout token delivered")
	default:
	}
	// session and grants are gone
	if resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, ch, nil).Encode()); resp.StatusCode != 302 || loc(t, resp).Path != "/login/primary" {
		t.Fatal("session survived logout")
	}
	if h.refreshWith(cl, secret, rt).status != 400 || h.refreshWith(silent, ssecret, r2.str("refresh_token")).status != 400 {
		t.Fatal("grants survived logout")
	}
}

func TestLogoutConfirmationWithoutHint(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, csrf := h.session(h.user)
	// GET without hint must not log out
	resp := h.get(c, "/oauth/logout?"+url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"s"}}.Encode())
	page := body(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, `action="/oauth/logout/confirm"`) {
		t.Fatalf("expected confirmation page: %d", resp.StatusCode)
	}
	id, pageCSRF := regexpValue(page, "id"), regexpValue(page, "csrf")
	if pageCSRF != csrf {
		t.Fatalf("the page's form carries %q, not the session's token", pageCSRF)
	}
	if _, sess := h.env.Server.Sessions.Current(reqWithCookies(h, c)); sess == nil {
		t.Fatal("logged out without confirmation")
	}
	// a plain form post (no JavaScript needed); a wrong CSRF token is refused and keeps the request
	post := func(token string) *http.Response {
		req, _ := http.NewRequest("POST", h.env.URL+"/oauth/logout/confirm", strings.NewReader(url.Values{"id": {id}, "csrf": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := post("wrong"); r.StatusCode != 400 {
		t.Fatalf("bad csrf: %d", r.StatusCode)
	}
	r := post(csrf)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "https://rp.example/bye?state=s" {
		t.Fatalf("confirm: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if _, sess := h.env.Server.Sessions.Current(reqWithCookies(h, c)); sess != nil {
		t.Fatal("session survived")
	}
	_ = secret
	// no session at all: straight to the redirect
	anon := h.anon()
	resp = h.get(anon, "/oauth/logout?"+url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}}.Encode())
	if resp.StatusCode != 302 {
		t.Fatalf("anon logout: %d", resp.StatusCode)
	}
	// no redirect: plain message
	resp = h.get(anon, "/oauth/logout")
	if resp.StatusCode != 200 || !strings.Contains(body(resp), "signed out") {
		t.Fatal("signed out page")
	}
}

func regexpAttr(page, attr string) string {
	i := strings.Index(page, attr+`="`)
	if i < 0 {
		return ""
	}
	rest := page[i+len(attr)+2:]
	return rest[:strings.IndexByte(rest, '"')]
}

func reqWithCookies(h *harness, c *http.Client) *http.Request {
	req, _ := http.NewRequest("GET", h.env.URL+"/", nil)
	u, _ := url.Parse(h.env.URL)
	for _, ck := range c.Jar.Cookies(u) {
		req.AddCookie(ck)
	}
	return req
}

func TestBackchannelLogoutAPIAndFailures(t *testing.T) {
	rp := newRP()
	defer rp.Close()
	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer failing.Close()
	h := setup(t, nil)
	good, gs := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	bad, bs := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(failing.URL) })
	c, _ := h.session(h.user)
	for _, cs := range []struct {
		cl *model.Client
		s  string
	}{{good, gs}, {bad, bs}} {
		v, ch := pkce()
		code := h.getCode(c, cs.cl, ch, nil)
		if r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cs.cl, cs.s); r.status != 200 {
			t.Fatal(r.m)
		}
	}
	list, _ := h.env.Svc.Sessions.All(context.Background(), h.user.ID)
	var ids []string
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	h.p.BackchannelLogout(context.Background(), ids...)
	h.p.Wait() // the failing RP must not block or panic anything
	select {
	case <-rp.got:
	default:
		t.Fatal("API did not deliver the logout token")
	}
	h.p.BackchannelLogoutUser(context.Background(), h.user.ID)
	h.p.Wait()
	select {
	case <-rp.got:
	default:
		t.Fatal("BackchannelLogoutUser did not deliver")
	}
}

// -- signing keys -----------------------------------------------------------------------------------------------

func TestKeyLifecycle(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Tokens.KeyRotationDays = 1 })
	ctx := context.Background()
	p := h.p
	ks, _ := p.keys(ctx)
	if len(ks.list) != 1 || ks.list[0].alg != AlgES256 {
		t.Fatalf("expected one ES256 key at start, got %d", len(ks.list))
	}
	if err := p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if ks, _ = p.keys(ctx); len(ks.list) != 1 {
		t.Fatalf("rotated too early: %d keys", len(ks.list))
	}
	first := ks.list[0].kid
	// age the key: pretend it became active 25 hours ago
	k, _ := h.env.Svc.Keys.Get(ctx, first)
	k.NotBefore = time.Now().Add(-25 * time.Hour)
	k.RetireAt = k.NotBefore.Add(24*time.Hour + keyOverlap)
	if err := h.env.Svc.Keys.Update(ctx, k); err != nil {
		t.Fatal(err)
	}
	p.Invalidate()
	if err := p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	ks, _ = p.keys(ctx)
	if len(ks.list) != 2 {
		t.Fatalf("expected a successor, have %d keys", len(ks.list))
	}
	succ := ks.list[1]
	if !succ.rec.NotBefore.After(time.Now().Add(keyOverlap - time.Minute)) {
		t.Fatalf("successor active too early: %v", succ.rec.NotBefore)
	}
	// published at once, signs only after the overlap; the retired key keeps signing until then
	var set JWKS
	_ = json.Unmarshal([]byte(body(h.get(h.http, "/oauth/jwks"))), &set)
	if len(set.Keys) != 2 {
		t.Fatalf("jwks has %d keys", len(set.Keys))
	}
	if got := ks.signer(AlgES256, time.Now()); got.kid != first {
		t.Fatal("successor signs before its NotBefore")
	}
	if got := ks.signer(AlgES256, time.Now().Add(keyOverlap+time.Minute)); got.kid != succ.kid {
		t.Fatal("successor does not take over")
	}
	// the old key outlives the last token it signed
	if !ks.list[0].rec.Expires.After(ks.list[0].rec.RetireAt.Add(p.cfg.Tokens.Access())) {
		t.Fatal("old key expires before its tokens do")
	}
	// a second scheduled check is a no-op
	if err := p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if ks, _ = p.keys(ctx); len(ks.list) != 2 {
		t.Fatalf("rotated twice: %d", len(ks.list))
	}
}

// An administrator's rotation takes effect at once: the new key signs from now on, the old one stays published so
// the tokens it signed keep verifying.
func TestForcedKeyRotation(t *testing.T) {
	h := setup(t, nil) // no scheduled rotation configured
	ctx := context.Background()
	cl, secret := h.newClient(nil)
	before, _ := h.login(cl, secret, nil)
	oldKID := headerOf(t, before.str("access_token"))["kid"]
	if err := h.p.RotateKeys(ctx); err != nil {
		t.Fatal(err)
	}
	var set JWKS
	_ = json.Unmarshal([]byte(body(h.get(h.http, "/oauth/jwks"))), &set)
	if len(set.Keys) != 2 {
		t.Fatalf("jwks after rotation has %d keys", len(set.Keys))
	}
	after, _ := h.login(cl, secret, nil)
	if kid := headerOf(t, after.str("access_token"))["kid"]; kid == oldKID {
		t.Fatal("the old key still signs after a forced rotation")
	}
	if _, err := h.p.VerifyAccessToken(ctx, before.str("access_token")); err != nil {
		t.Fatalf("token signed by the previous key: %v", err)
	}
}

func TestSigningAlgorithms(t *testing.T) {
	// EdDSA default; client-requested RS256 generated lazily
	h := setup(t, func(c *config.Config) { c.Tokens.SigningAlg = "EdDSA" })
	cl, secret := h.newClient(nil)
	rs, rsecret := h.newClient(func(in *service.ClientInput) { in.SigningAlg = ptr("RS256") })
	ks, _ := h.p.keys(context.Background())
	for _, k := range ks.list {
		if k.alg == AlgRS256 {
			t.Fatal("RS256 key generated eagerly")
		}
	}
	r, _ := h.login(cl, secret, nil)
	if headerOf(t, r.str("access_token"))["alg"] != "EdDSA" || headerOf(t, r.str("id_token"))["alg"] != "EdDSA" {
		t.Fatal("default alg")
	}
	r2, _ := h.login(rs, rsecret, nil)
	if headerOf(t, r2.str("id_token"))["alg"] != "RS256" || headerOf(t, r2.str("access_token"))["alg"] != "RS256" {
		t.Fatal("RS256 client")
	}
	jw, _ := ParseJWKS([]byte(body(h.get(h.http, "/oauth/jwks"))))
	algs := map[string]bool{}
	for _, j := range jw {
		algs[j.Alg] = true
		if j.Alg == AlgRS256 || j.Alg == AlgEdDSA {
			pub, err := j.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			tok := r2.str("id_token")
			if j.Alg == AlgEdDSA {
				tok = r.str("id_token")
			}
			decodeIndependently(t, tok, pub)
		}
	}
	if !algs[AlgRS256] || !algs[AlgEdDSA] {
		t.Fatalf("jwks algs %v", algs)
	}
	// RS256 at_hash uses SHA-256 left half; EdDSA uses SHA-512 left half
	sum := sha256.Sum256([]byte(r2.str("access_token")))
	if claimsOf(t, r2.str("id_token"))["at_hash"] != b64.EncodeToString(sum[:16]) {
		t.Fatal("RS256 at_hash")
	}
	if h.introspect(rs, rsecret, r2.str("access_token"))["active"] != true {
		t.Fatal("RS256 token does not verify")
	}
}

func TestUnknownKIDTriggersReload(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	// another node rotates: this node's cache does not know the new key yet
	h.p.keyMu.Lock()
	nk, err := h.p.createKey(context.Background(), AlgES256, time.Now().Add(-time.Minute))
	h.p.keyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := h.p.keys(context.Background())
	if ks.byKID[nk.ID] != nil {
		t.Fatal("cache already knew the key")
	}
	if h.p.keyByKID(context.Background(), nk.ID) == nil {
		t.Fatal("unknown kid did not trigger a reload")
	}
	_ = r
	// unknown kids do not hammer the store
	h.p.lastKIDReload.Store(time.Now().UnixNano())
	if h.p.keyByKID(context.Background(), "nope") != nil {
		t.Fatal("bogus kid found")
	}
}

func TestResourceIndicatorOnToken(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, url.Values{"resource": {"https://api.example/a", "https://api.example/b"}})
	// asking for a resource that was not authorized is refused
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}, "resource": {"https://evil.example"}}, cl, secret)
	if r.m["error"] != "invalid_target" {
		t.Fatalf("%v", r.m)
	}
	code = h.getCode(c, cl, ch, url.Values{"resource": {"https://api.example/a", "https://api.example/b"}})
	r = h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, secret)
	aud, _ := claimsOf(t, r.str("access_token"))["aud"].([]any)
	if len(aud) != 3 || aud[0] != cl.ID {
		t.Fatalf("aud %v", aud)
	}
}

// -- public clients --------------------------------------------------------------------------------

func (h *harness) publicLogin(cl *model.Client, extra url.Values) (tokResp, string) {
	h.t.Helper()
	c, csrf := h.session(h.user)
	v, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, extra))
	if u.Path != "/oauth/consent" { // public clients always see the consent page
		h.t.Fatalf("public client skipped consent: %s", u)
	}
	flow := u.Query().Get("flow")
	b, _ := json.Marshal(map[string]any{"flow": flow, "approve": true})
	req, _ := http.NewRequest("POST", h.env.URL+"/api/oauth/consent", strings.NewReader(string(b)))
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	var out map[string]string
	_ = json.Unmarshal([]byte(body(resp)), &out)
	code := loc(h.t, h.get(c, out["redirect"])).Query().Get("code")
	if code == "" {
		h.t.Fatal("no code")
	}
	r := h.post("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cl.ID},
		"redirect_uri": {cl.RedirectURIs[0]}, "code_verifier": {v}}, "", "")
	return r, v
}

func TestPublicClientFlow(t *testing.T) {
	h := setup(t, nil)
	cl := h.publicClient(nil)
	r, v := h.publicLogin(cl, nil)
	if r.status != 200 || r.str("access_token") == "" || r.str("id_token") == "" {
		t.Fatalf("%v", r)
	}
	rt := r.str("refresh_token")
	if len(strings.Split(rt, ".")) != 3 {
		t.Fatalf("public client refresh token must rotate: %s", rt)
	}
	// even after a prior grant consent is asked again (checked in publicLogin); verifier problems:
	c, _ := h.session(h.user)
	_, ch := pkce()
	_ = ch
	v2, ch2 := pkce()
	u := h.authorize(c, authzQuery(cl, ch2, nil))
	_ = u
	pub := func(code, verifier string) tokResp {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cl.ID}, "redirect_uri": {cl.RedirectURIs[0]}}
		if verifier != "" {
			f.Set("code_verifier", verifier)
		}
		return h.post("/oauth/token", f, "", "")
	}
	_ = v
	_ = v2
	_ = pub
	// PKCE is mandatory at authorize for public clients too
	_, ch3 := pkce()
	if u := h.authorize(c, authzQuery(cl, ch3, url.Values{"code_challenge": {""}, "code_challenge_method": {""}})); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("%s", u)
	}
	// refresh rotation and reuse detection, with client_id only
	rf := func(tok string) tokResp {
		return h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {cl.ID}}, "", "")
	}
	r1 := rf(rt)
	if r1.status != 200 || r1.str("refresh_token") == "" || r1.str("refresh_token") == rt {
		t.Fatalf("%v", r1)
	}
	if rf(rt).status != 400 {
		t.Fatal("old public refresh token accepted")
	}
	if rf(r1.str("refresh_token")).status != 400 {
		t.Fatal("reuse did not revoke the family")
	}
	// the private-use scheme redirect is accepted exactly
	if u := h.authorize(c, authzQuery(cl, ch3, url.Values{"redirect_uri": {"com.example.app:/cb"}})); u.Path != "/oauth/consent" {
		t.Fatalf("private scheme: %s", u)
	}
	if resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, ch3, url.Values{"redirect_uri": {"com.example.app:/other"}}).Encode()); resp.StatusCode != 400 {
		t.Fatal("private scheme prefix accepted")
	}
}

func TestPublicClientTokenEndpointRules(t *testing.T) {
	h := setup(t, nil)
	cl := h.publicClient(nil)
	conf, csecret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	_ = c
	// client_credentials is never available to public clients (even if misconfigured)
	if r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}}, "", ""); r.status != 400 || r.m["error"] != "unauthorized_client" {
		t.Fatalf("cc for public: %v", r)
	}
	// a public client presenting a secret (post or basic) or an assertion is refused
	for name, r := range map[string]tokResp{
		"post":  h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}, "client_id": {cl.ID}, "client_secret": {"qsrs_x"}}, "", ""),
		"basic": h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}}, cl.ID, "qsrs_x"),
		"jwt": h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}, "client_id": {cl.ID},
			"client_assertion_type": {assertionType}, "client_assertion": {"x.y.z"}}, "", ""),
	} {
		if r.status != 401 {
			t.Errorf("%s: public client with credentials got %d", name, r.status)
		}
	}
	// a confidential client never falls back to "none"
	if r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {conf.ID}}, "", ""); r.status != 401 {
		t.Fatalf("confidential client authenticated without a secret: %d", r.status)
	}
	_ = csecret
	// unknown / disabled public client
	if r := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"nope"}}, "", ""); r.status != 401 {
		t.Fatal(r.status)
	}
	// missing and wrong verifier
	r, _ := h.publicLogin(cl, nil)
	_ = r
	uu := h.authorize(mustSession(h, h.user), authzQuery(cl, ch, nil))
	if uu.Path != "/oauth/consent" {
		t.Fatal(uu)
	}
	_ = v
}

func mustSession(h *harness, u *model.User) *http.Client { c, _ := h.session(u); return c }

func TestPublicClientVerifier(t *testing.T) {
	h := setup(t, nil)
	cl := h.publicClient(nil)
	run := func(verifier func(v string) string) tokResp {
		c, csrf := h.session(h.user)
		v, ch := pkce()
		u := h.authorize(c, authzQuery(cl, ch, nil))
		b, _ := json.Marshal(map[string]any{"flow": u.Query().Get("flow"), "approve": true})
		req, _ := http.NewRequest("POST", h.env.URL+"/api/oauth/consent", strings.NewReader(string(b)))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		resp, _ := c.Do(req)
		var out map[string]string
		_ = json.Unmarshal([]byte(body(resp)), &out)
		code := loc(t, h.get(c, out["redirect"])).Query().Get("code")
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cl.ID}, "redirect_uri": {cl.RedirectURIs[0]}}
		if vv := verifier(v); vv != "" {
			f.Set("code_verifier", vv)
		}
		return h.post("/oauth/token", f, "", "")
	}
	if r := run(func(v string) string { return v }); r.status != 200 {
		t.Fatalf("%v", r)
	}
	if r := run(func(string) string { return "" }); r.status != 400 || r.m["error"] != "invalid_grant" {
		t.Fatalf("missing verifier: %v", r)
	}
	if r := run(func(string) string { return strings.Repeat("b", 43) }); r.status != 400 || r.m["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %v", r)
	}
}

func TestPublicClientCORS(t *testing.T) {
	h := setup(t, nil)
	cl := h.publicClient(nil)
	other := h.publicClient(func(in *service.ClientInput) { in.RedirectURIs = &[]string{"https://other.example/cb"} })
	conf, _ := h.newClient(nil)
	_ = conf
	preflight := func(path, origin string) *http.Response {
		req, _ := http.NewRequest("OPTIONS", h.env.URL+path, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
		resp, err := h.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for _, path := range []string{"/oauth/token", "/oauth/revoke", "/oauth/userinfo"} {
		resp := preflight(path, "https://spa.example")
		if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Origin") != "https://spa.example" ||
			!strings.Contains(resp.Header.Get("Vary"), "Origin") || resp.Header.Get("Access-Control-Allow-Credentials") != "" ||
			strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "DPoP") || len(resp.Header.Values("Vary")) != 1 ||
			!strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Authorization") ||
			resp.Header.Get("Access-Control-Max-Age") == "" {
			t.Errorf("%s preflight: %d %v", path, resp.StatusCode, resp.Header)
		}
		// loopback on any port
		if resp := preflight(path, "http://127.0.0.1:5173"); resp.Header.Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5173" {
			t.Errorf("%s: loopback origin refused", path)
		}
		for _, o := range []string{"https://evil.example", "http://spa.example", "https://spa.example:8443", "http://localhost:5173", "null"} {
			if resp := preflight(path, o); resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s: origin %s allowed", path, o)
			}
		}
	}
	// actual requests
	v, ch := pkce()
	_, _ = v, ch
	r := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {cl.ID}}, "", "", "Origin", "https://spa.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "https://spa.example" || !strings.Contains(r.hdr.Get("Vary"), "Origin") {
		t.Errorf("token actual: %v", r.hdr)
	}
	// the origin of ANOTHER public client does not work for this client
	r = h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {cl.ID}}, "", "", "Origin", "https://other.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Error("cross-client origin allowed on token endpoint")
	}
	r = h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {other.ID}}, "", "", "Origin", "https://other.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "https://other.example" {
		t.Error("own origin refused")
	}
	// userinfo for a public client's token from its origin, and not from another
	pr, _ := h.publicLogin(cl, nil)
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"), "Origin", "https://spa.example")
	if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "https://spa.example" {
		t.Errorf("userinfo CORS: %d %v", resp.StatusCode, resp.Header)
	}
	resp = h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"), "Origin", "https://other.example")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("userinfo CORS for another client's origin")
	}
	// no Origin header, no CORS headers
	resp = h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"))
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS without Origin")
	}
	// a disabled public client's origin stops being allowed once evicted
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(cl.ID)
	if resp := preflight("/oauth/token", "https://spa.example"); resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("disabled client's origin still allowed")
	}
}

func TestPublicClientRevokeAndIntrospect(t *testing.T) {
	h := setup(t, nil)
	cl := h.publicClient(nil)
	r, _ := h.publicLogin(cl, nil)
	rt := r.str("refresh_token")
	// introspection is for confidential clients only
	if x := h.post("/oauth/introspect", url.Values{"token": {r.str("access_token")}, "client_id": {cl.ID}}, "", ""); x.status != 401 || x.m["error"] != "invalid_client" {
		t.Fatalf("public introspect: %v", x)
	}
	// a public client may revoke its own refresh token
	if x := h.post("/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}}, "", ""); x.status != 200 {
		t.Fatalf("revoke: %d", x.status)
	}
	if x := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {cl.ID}}, "", ""); x.status != 400 {
		t.Fatal("revoked token still refreshes")
	}
	// but not someone else's
	r2, _ := h.publicLogin(cl, nil)
	other := h.publicClient(nil)
	h.post("/oauth/revoke", url.Values{"token": {r2.str("refresh_token")}, "client_id": {other.ID}}, "", "")
	if x := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r2.str("refresh_token")}, "client_id": {cl.ID}}, "", ""); x.status != 200 {
		t.Fatal("foreign public client revoked a token")
	}
}

// -- concurrency ------------------------------------------------------------------------------------------------

func TestConcurrentTokenRequests(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	var wg sync.WaitGroup
	var bad atomic.Int32
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if h.refreshWith(cl, secret, rt).status != 200 || h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret).status != 200 {
					bad.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d failures", bad.Load())
	}
}

func TestGroupsCacheInvalidation(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	cl, secret := h.newClient(nil)
	grp, err := h.env.Svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("devs")})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid groups offline_access"}})
	rt := r.str("refresh_token")
	groups := func() []any {
		t.Helper()
		x := h.refreshWith(cl, secret, rt)
		if x.status != 200 {
			t.Fatal(x.m)
		}
		g, _ := claimsOf(t, x.str("access_token"))["groups"].([]any)
		return g
	}
	if g := groups(); len(g) != 1 || g[0] != "devs" {
		t.Fatalf("groups %v", g)
	}
	// removed membership: still cached until invalidated, then gone at once
	if err := h.env.Svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, false); err != nil {
		t.Fatal(err)
	}
	if g := groups(); len(g) != 1 {
		t.Fatalf("expected the cached list, got %v", g)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	if g := groups(); len(g) != 0 {
		t.Fatalf("membership still present after invalidation: %v", g)
	}
	// another org's invalidation does not matter; the TTL backstop does
	if err := h.env.Svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership("other-org")
	if g := groups(); len(g) != 0 {
		t.Fatalf("unrelated invalidation dropped the cache: %v", g)
	}
	h.p.InvalidateMembership("")
	if g := groups(); len(g) != 1 {
		t.Fatalf("global invalidation: %v", g)
	}
}

// regexpValue returns the value of the hidden input named name.
func regexpValue(page, name string) string {
	i := strings.Index(page, `name="`+name+`" value="`)
	if i < 0 {
		return ""
	}
	rest := page[i+len(`name="`+name+`" value="`):]
	return rest[:strings.IndexByte(rest, '"')]
}

// "localhost" is not a loopback IP literal: a registered http://localhost address matches exactly, with no port
// flexibility (RFC 8252 §8.3); the IP literals keep it.
func TestLocalhostRedirectExact(t *testing.T) {
	if !redirectMatches([]string{"http://[::1]/cb"}, "http://[::1]:4100/cb") {
		t.Error("::1 lost port flexibility")
	}
	reg := []string{"http://localhost:8080/cb"}
	if !redirectMatches(reg, "http://localhost:8080/cb") {
		t.Error("exact localhost refused")
	}
	if redirectMatches(reg, "http://localhost:9999/cb") || redirectMatches([]string{"http://localhost/cb"}, "http://localhost:4100/cb") {
		t.Error("localhost got port flexibility")
	}
}

// Parameters must not be repeated (RFC 6749 §3.1, §3.2); resource indicators may be (RFC 8707).
func TestRepeatedParameters(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	raw := authzQuery(cl, ch, nil).Encode()
	// which application or where to is in doubt: an error page, no redirect
	for _, extra := range []string{"&client_id=" + cl.ID, "&redirect_uri=" + url.QueryEscape(cl.RedirectURIs[0])} {
		if resp := h.get(c, "/oauth/authorize?"+raw+extra); resp.StatusCode != 400 {
			t.Errorf("repeated %s: %d", extra, resp.StatusCode)
		}
	}
	// anything else: invalid_request back to the client
	resp := h.get(c, "/oauth/authorize?"+raw+"&scope=openid")
	if loc := loc(t, resp); loc.Query().Get("error") != "invalid_request" {
		t.Errorf("repeated scope: %s", loc)
	}
	// resource may repeat
	ok := h.get(c, "/oauth/authorize?"+raw+"&resource=https://api.example/a&resource=https://api.example/b")
	if l := loc(t, ok); l.Query().Get("error") == "invalid_request" && strings.Contains(l.Query().Get("error_description"), "repeated") {
		t.Errorf("repeated resource refused: %s", l)
	}
	// token endpoint
	r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials", "client_credentials"}, "client_id": {cl.ID},
		"client_secret": {secret}}, "", "")
	if r.status != 400 || r.str("error") != "invalid_request" {
		t.Errorf("repeated grant_type: %d %v", r.status, r.m)
	}
}

// Public clients revoke their own tokens, so discovery lists "none" for revocation; introspection is confidential only.
func TestDiscoveryRevocationAuthMethods(t *testing.T) {
	h := setup(t, nil)
	var d map[string]any
	_ = json.Unmarshal([]byte(body(h.get(h.http, "/.well-known/openid-configuration"))), &d)
	has := func(k, v string) bool {
		for _, x := range d[k].([]any) {
			if x == v {
				return true
			}
		}
		return false
	}
	if !has("revocation_endpoint_auth_methods_supported", "none") || has("introspection_endpoint_auth_methods_supported", "none") {
		t.Errorf("auth methods: %v / %v", d["revocation_endpoint_auth_methods_supported"], d["introspection_endpoint_auth_methods_supported"])
	}
}

// Failed client authentications are limited per client and IP address: past the limit failures answer 429, but the
// right secret still works, and other clients from the same address are not affected.
func TestClientAuthFailureLimit(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, osecret := h.newClient(nil)
	form := func(c *model.Client, s string) url.Values {
		return url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ID}, "client_secret": {s}}
	}
	for i := 0; i < clientAuthFailuresPerMin; i++ {
		if r := h.post("/oauth/token", form(cl, "wrong"), "", ""); r.status != 401 {
			t.Fatalf("attempt %d: %d", i, r.status)
		}
	}
	r := h.post("/oauth/token", form(cl, "wrong"), "", "")
	if r.status != 429 || r.hdr.Get("Retry-After") == "" || r.str("error") != "invalid_client" {
		t.Fatalf("over the limit: %d %v", r.status, r.m)
	}
	// over the limit even the right secret is refused (guessing cannot go on, and a hit teaches nothing)
	if r := h.post("/oauth/token", form(cl, secret), "", ""); r.status != 429 {
		t.Errorf("right secret while limited: %d", r.status)
	}
	if r := h.post("/oauth/token", form(other, "wrong"), "", ""); r.status != 401 {
		t.Errorf("another client from the same address: %d", r.status)
	}
	_ = osecret
}

// Failures that need no secret (unknown client ids, no client authentication at all) do not lock out real clients from
// the same address: not one sending client_id, nor a private_key_jwt client leaving it out (RFC 7523 §3).
func TestClientAuthFailureLimitStrangers(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	k := newAssertionKeys(t)[0]
	jc, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKS = ptr(k.jwks)
	})
	for i := 0; i <= clientAuthFailuresPerMin; i++ {
		h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {fmt.Sprintf("nope-%d", i)},
			"client_secret": {"x"}}, "", "")
		h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, "", "")
		h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType},
			"client_assertion": {"x.y.z"}}, "", "")
	}
	if r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}, "client_secret": {secret}}, "", ""); r.status != 200 {
		t.Errorf("client_secret_post after the burst: %d %v", r.status, r.m)
	}
	for _, path := range []string{"/oauth/introspect", "/oauth/revoke"} {
		if r := h.post(path, url.Values{"token": {"x"}, "client_id": {cl.ID}, "client_secret": {secret}}, "", ""); r.status != 200 {
			t.Errorf("%s after the burst: %d %v", path, r.status, r.m)
		}
	}
	if r := h.ccWithAssertion(jc, h.assertion(k, h.assertionClaims(jc, nil))); r.status != 200 {
		t.Errorf("private_key_jwt without client_id after the burst: %d %v", r.status, r.m)
	}
}

// The Basic user name is form-urlencoded (RFC 6749 §2.3.1): encoding the client id differently does not get a
// fresh budget for guessing its secret.
func TestClientAuthFailureLimitEncodedID(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	for i := 0; i < clientAuthFailuresPerMin; i++ {
		h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, cl.ID, "wrong")
	}
	enc := ""
	for _, b := range []byte(cl.ID) {
		enc += fmt.Sprintf("%%%02X", b)
	}
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+"/oauth/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(enc, "wrong")
	resp, err := h.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Errorf("percent-encoded client id past the limit: %d", resp.StatusCode)
	}
}

// Without offline_access a refresh token lasts only as long as the user's session; with it, it outlives the session's
// expiry (OIDC Core §11).
func TestRefreshNeedsOfflineAccessToOutliveSession(t *testing.T) {
	ctx := context.Background()
	for _, offline := range []bool{false, true} {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		scope := "openid profile"
		if offline {
			scope += " offline_access"
		}
		r, _ := h.login(cl, secret, url.Values{"scope": {scope}})
		rt := r.str("refresh_token")
		if rt == "" {
			t.Fatalf("offline=%v: no refresh token", offline)
		}
		if r := h.refreshWith(cl, secret, rt); r.status != 200 {
			t.Fatalf("offline=%v: refresh while signed in: %d %v", offline, r.status, r.m)
		}
		rt2 := h.refreshWith(cl, secret, rt).str("refresh_token")
		if rt2 == "" {
			rt2 = rt
		}
		sid := claimsOf(t, r.str("access_token"))["sid"].(string)
		s, err := h.env.Svc.Sessions.Get(ctx, sid)
		if err != nil {
			t.Fatal(err)
		}
		s.LastSeen, s.IdleTTL = time.Now().Add(-48*time.Hour), 60 // idle for two days: expired
		if err := h.env.Svc.Sessions.Update(ctx, s); err != nil {
			t.Fatal(err)
		}
		got := h.refreshWith(cl, secret, rt2).status
		if offline && got != 200 || !offline && got != 400 {
			t.Errorf("offline=%v: refresh after the session expired: %d", offline, got)
		}
	}
}

// PKCE is required unless a confidential client opts out (require_pkce off); a public client cannot. An opted-out
// client may still use PKCE, and then the verifier is checked; a code issued without a challenge refuses a verifier.
func TestRequirePKCESetting(t *testing.T) {
	h := setup(t, nil)
	strict, ssecret := h.newClient(nil)
	loose, lsecret := h.newClient(func(in *service.ClientInput) { in.RequirePKCE = ptr(false) })
	c, _ := h.session(h.user)
	noPKCE := url.Values{"code_challenge": {""}, "code_challenge_method": {""}}

	// default: refused without PKCE
	if u := h.authorize(c, authzQuery(strict, "", noPKCE)); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("strict client without PKCE: %s", u)
	}
	// opted out: a code without PKCE, exchanged without a verifier
	exchange := func(cl *model.Client, secret, code, verifier string) tokResp {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]}}
		if verifier != "" {
			f.Set("code_verifier", verifier)
		}
		return h.token(f, cl, secret)
	}
	code := h.getCode(c, loose, "", noPKCE)
	if r := exchange(loose, lsecret, code, ""); r.status != 200 || r.str("id_token") == "" {
		t.Fatalf("opted-out exchange: %d %v", r.status, r.m)
	}
	// ...a verifier for a code issued without a challenge is refused
	code = h.getCode(c, loose, "", noPKCE)
	v, _ := pkce()
	if r := exchange(loose, lsecret, code, v); r.status != 400 {
		t.Fatalf("verifier without a challenge: %d", r.status)
	}
	// ...and PKCE used anyway is still checked
	v, ch := pkce()
	code = h.getCode(c, loose, ch, nil)
	if r := exchange(loose, lsecret, code, ""); r.status != 400 {
		t.Fatalf("challenge without the verifier: %d", r.status)
	}
	code = h.getCode(c, loose, ch, nil)
	if r := exchange(loose, lsecret, code, v); r.status != 200 {
		t.Fatalf("challenge with the verifier: %d", r.status)
	}
	_ = ssecret

	// the client JSON says so; a public client cannot opt out
	if !strict.RequirePKCE() || loose.RequirePKCE() {
		t.Fatal("RequirePKCE")
	}
	_, _, err := h.env.Svc.CreateClient(context.Background(), h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("spa"),
		AuthMethod: ptr(model.AuthMethodNone), RedirectURIs: &[]string{"https://spa.example/cb"}, RequirePKCE: ptr(false)})
	if !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("public client without PKCE: %v", err)
	}
}

// A client authenticates only the way it is registered to (token_endpoint_auth_method).
func TestClientAuthMethodEnforced(t *testing.T) {
	h := setup(t, nil)
	post, psecret := h.newClient(nil) // client_secret_post
	basic, bsecret := h.newClient(func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) })
	tok := url.Values{"token": {"x"}}
	if r := h.post("/oauth/introspect", tok, post.ID, psecret); r.status != 401 {
		t.Errorf("post client over Basic: %d", r.status)
	}
	if r := h.post("/oauth/introspect", url.Values{"token": {"x"}, "client_id": {basic.ID}, "client_secret": {bsecret}}, "", ""); r.status != 401 {
		t.Errorf("basic client over the form: %d", r.status)
	}
	for _, c := range []struct {
		cl     *model.Client
		secret string
	}{{post, psecret}, {basic, bsecret}} {
		if r := h.clientPost("/oauth/introspect", tok, c.cl, c.secret); r.status != 200 {
			t.Errorf("%s the registered way: %d", c.cl.AuthMethod, r.status)
		}
	}
}

// Resource indicators (RFC 8707): URNs are accepted; a refresh may narrow the authorized resources but never widen
// them; without a resource it keeps the authorized ones.
func TestRefreshResourceBounds(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"resource": {"https://api.example/a", "urn:example:billing"}})
	if r.status != 200 {
		t.Fatalf("login with resources: %v", r.m)
	}
	rt := r.str("refresh_token")
	aud := func(tok string) []string {
		switch v := claimsOf(t, tok)["aud"].(type) {
		case string:
			return []string{v}
		case []any:
			out := []string{}
			for _, x := range v {
				out = append(out, x.(string))
			}
			return out
		}
		return nil
	}
	if a := aud(h.refreshWith(cl, secret, rt).str("access_token")); !slices.Contains(a, "urn:example:billing") || !slices.Contains(a, "https://api.example/a") {
		t.Errorf("refresh without resource: %v", a)
	}
	x := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {"https://api.example/a"}}, cl, secret)
	if a := aud(x.str("access_token")); x.status != 200 || slices.Contains(a, "urn:example:billing") {
		t.Errorf("narrowed refresh: %d %v", x.status, a)
	}
	x = h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {"https://other.example/"}}, cl, secret)
	if x.status != 400 || x.str("error") != "invalid_target" {
		t.Errorf("widened refresh: %d %v", x.status, x.m)
	}
	// a grant made without resources cannot gain one
	r2, _ := h.login(cl, secret, nil)
	x = h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r2.str("refresh_token")}, "resource": {"https://api.example/a"}}, cl, secret)
	if x.status != 400 || x.str("error") != "invalid_target" {
		t.Errorf("resource added at refresh: %d %v", x.status, x.m)
	}
}

// The code exchange needs the user's session to still be valid (expiry and idle timeout), not merely to exist.
func TestCodeExchangeNeedsLiveSession(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	for _, s := range sessionsFor(t, h) {
		s.LastSeen, s.IdleTTL = time.Now().Add(-time.Hour), 60
		if err := h.env.Svc.Sessions.Update(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("exchange after the session went idle: %d %v", r.status, r.m)
	}
}

func sessionsFor(t *testing.T, h *harness) []*model.Session {
	l, err := h.env.Svc.Sessions.All(context.Background(), h.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Disabling an application stops its user access tokens at once (userinfo, introspection, in-process resources).
func TestDisabledClientTokensStop(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, osecret := h.newClient(func(in *service.ClientInput) { in.Name = ptr("other") })
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	if resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at); resp.StatusCode != 200 {
		t.Fatalf("userinfo before: %d", resp.StatusCode)
	}
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(cl.ID)
	if resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at); resp.StatusCode != 401 {
		t.Errorf("userinfo after disable: %d", resp.StatusCode)
	}
	if m := h.introspect(other, osecret, at); m["active"] != false {
		t.Errorf("introspection after disable: %v", m)
	}
	if _, err := h.p.VerifyAccessToken(context.Background(), at); err == nil {
		t.Error("VerifyAccessToken accepted a disabled client's token")
	}
}

// RFC 6750 §2: a client must not use more than one method to send the token; query tokens are not supported.
func TestUserinfoOneTokenMethod(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	send := func(q string, hdr bool, form url.Values) int {
		req, _ := http.NewRequest(http.MethodPost, h.env.URL+"/oauth/userinfo"+q, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if hdr {
			req.Header.Set("Authorization", "Bearer "+at)
		}
		resp, err := h.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := send("", true, nil); s != 200 {
		t.Errorf("header: %d", s)
	}
	if s := send("", false, url.Values{"access_token": {at}}); s != 200 {
		t.Errorf("body: %d", s)
	}
	if s := send("", true, url.Values{"access_token": {at}}); s != 400 {
		t.Errorf("header and body: %d", s)
	}
	if s := send("?access_token="+at, false, nil); s != 400 {
		t.Errorf("query: %d", s)
	}
}

// The stored grant secret is only a seed: a refresh token built from it directly (a database copy without the master
// key) is refused.
func TestRefreshNotForgeableFromDatabase(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	gid, _, _ := strings.Cut(r.str("refresh_token"), ".")
	g, err := h.env.Svc.Grants.Get(context.Background(), gid)
	if err != nil {
		t.Fatal(err)
	}
	forged := gid + "." + base64.RawURLEncoding.EncodeToString(g.Secret)
	if x := h.refreshWith(cl, secret, forged); x.status != 400 {
		t.Errorf("forged from the stored seed: %d", x.status)
	}
	if x := h.refreshWith(cl, secret, r.str("refresh_token")); x.status != 200 {
		t.Errorf("genuine: %d %v", x.status, x.m)
	}
}

// A code issued without resource indicators cannot gain one at the exchange.
func TestCodeExchangeCannotAddResources(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}, "resource": {"https://api.other.example/"}}, cl, secret)
	if r.status != 400 || r.str("error") != "invalid_target" {
		t.Fatalf("resource added at exchange: %d %v", r.status, r.m)
	}
}

// An application whose refresh grant was revoked still holds the user's sign-in: it is told when the session ends.
func TestBackchannelAfterGrantRevoked(t *testing.T) {
	rp := newRP()
	defer rp.Close()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL + "/logout") })
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, secret)
	if r.status != 200 {
		t.Fatal(r.m)
	}
	// the application revokes its refresh token: no grant is left on the session
	if res := h.clientPost("/oauth/revoke", url.Values{"token": {r.str("refresh_token")}}, cl, secret); res.status != 200 {
		t.Fatalf("revoke: %d", res.status)
	}
	if gs, _ := h.env.Svc.Grants.All(context.Background(), h.user.ID); len(gs) != 0 {
		t.Fatalf("grants left: %d", len(gs))
	}
	// the user signs out everywhere
	if err := h.env.Svc.RevokeSessions(context.Background(), h.admin, h.user.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case lt := <-rp.got:
		if claimsOf(t, lt)["aud"] != cl.ID {
			t.Fatal("logout token for another client")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an application without a grant was not told its session ended")
	}
	h.p.Wait()
}

// At the user's end date their tokens stop at once (before any sweep has disabled them).
func TestValidUntilStopsTokens(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	u, _ := h.env.Svc.Users.Get(context.Background(), h.user.ID)
	past := time.Now().Add(-time.Second)
	u.ValidUntil = &past
	if err := h.env.Svc.Users.Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(u.ID)
	if x := h.refreshWith(cl, secret, r.str("refresh_token")); x.status != 400 {
		t.Errorf("refresh after the end date: %d", x.status)
	}
	if resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token")); resp.StatusCode != 401 {
		t.Errorf("userinfo after the end date: %d", resp.StatusCode)
	}
}

// The enterprise scope carries the work details as one "enterprise" object (ID token, userinfo, access token);
// without the scope they are absent. The profile scope carries locale and zoneinfo.
func TestEnterpriseScope(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.Scopes = &[]string{"openid", "profile", "email", "enterprise", "offline_access"}
	})
	until := "2099-06-30"
	if _, err := h.env.Svc.UpdateUser(context.Background(), service.System, h.user.ID, service.UserInput{
		Locale: ptr("en-GB"), ZoneInfo: ptr("Europe/London"), UserType: ptr("contractor"), ValidUntil: &until,
		Work: &service.WorkInput{Title: ptr("Engineer"), Department: ptr("QA"), CostCenter: ptr("CC-9")}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile enterprise offline_access"}})
	for name, tok := range map[string]string{"id token": r.str("id_token"), "access token": r.str("access_token")} {
		c := claimsOf(t, tok)
		ent, _ := c["enterprise"].(map[string]any)
		if ent["department"] != "QA" || ent["title"] != "Engineer" || ent["cost_center"] != "CC-9" || ent["user_type"] != "contractor" || ent["valid_until"] == nil {
			t.Errorf("%s enterprise claim: %v", name, c["enterprise"])
		}
	}
	if c := claimsOf(t, r.str("id_token")); c["zoneinfo"] != "Europe/London" || c["locale"] != "en-GB" {
		t.Errorf("profile claims: %v %v", c["zoneinfo"], c["locale"])
	}
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token"))
	var ui map[string]any
	_ = json.Unmarshal([]byte(body(resp)), &ui)
	if ui["enterprise"] == nil {
		t.Errorf("userinfo without enterprise: %v", ui)
	}
	// not asked for: not sent
	r2, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	if c := claimsOf(t, r2.str("id_token")); c["enterprise"] != nil {
		t.Error("enterprise claim without the scope")
	}
}

// Master key rotation: a refresh token stays the same across a rotation and keeps working once the old key is
// removed, because the grant's own key is re-sealed with the new one; the old key alone opens nothing any more.
func TestRefreshTokenAcrossMasterKeyRotation(t *testing.T) {
	ctx := context.Background()
	k0, k1 := secure.RandomBytes(32), secure.RandomBytes(32)
	h := setupKey(t, nil, k0)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	rt := r.str("refresh_token")
	if rt == "" {
		t.Fatal("no refresh token")
	}
	rotating, rsecret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ = h.login(rotating, rsecret, url.Values{"scope": {"openid profile offline_access"}})
	rrt := r.str("refresh_token")

	ring, _ := secure.NewKeyring(k1, k0)
	h.env.Svc.Sealer = ring
	if r := h.refreshWith(cl, secret, rt); r.status != 200 || r.str("refresh_token") != "" {
		t.Fatalf("during the rotation: %d %v", r.status, r.m)
	}
	if res, err := h.env.Svc.ResealSecrets(ctx, 1000); err != nil || !res.Done() {
		t.Fatalf("reseal: %+v %v", res, err)
	}

	only1, _ := secure.NewSealer(k1)
	h.env.Svc.Sealer = only1
	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatalf("the same token after the old key was removed: %d %v", r.status, r.m)
	}
	r = h.refreshWith(rotating, rsecret, rrt)
	if r.status != 200 || r.str("refresh_token") == "" {
		t.Fatalf("rotating token after the old key was removed: %d %v", r.status, r.m)
	}
	if r := h.refreshWith(rotating, rsecret, r.str("refresh_token")); r.status != 200 {
		t.Fatalf("the next rotating token: %d %v", r.status, r.m)
	}

	// nothing stored opens with the old key any more
	old, _ := secure.NewSealer(k0)
	gs, _, _ := h.env.Svc.Grants.List(ctx, store.ListQuery{})
	for _, g := range gs {
		if _, err := old.OpenFor(service.GrantKeyBinding(g.ID), g.Key); err == nil {
			t.Fatalf("grant %s still opens with the old key", g.ID)
		}
	}
}

// A refresh grant from before grants had their own key (its key derived from the master key over a stored seed) is
// converted: by the re-seal pass when there is one master key, or when its token is next used during a rotation. Its
// token stays the same either way.
func TestLegacyGrantKeyConversion(t *testing.T) {
	ctx := context.Background()
	k0, k1 := secure.RandomBytes(32), secure.RandomBytes(32)
	h := setupKey(t, nil, k0)
	cl, secret := h.newClient(nil)
	legacy := func() (*model.Grant, string) {
		g := &model.Grant{ClientID: cl.ID, UserID: h.user.ID, OrgID: h.user.OrgID, SessionID: "legacy",
			Scopes: []string{"openid", "offline_access"}, AMR: []string{"pwd"}, AuthTime: time.Now(),
			Secret: secure.RandomBytes(32), Expires: time.Now().Add(time.Hour)}
		g.ID = model.NewID()
		if err := h.env.Svc.Grants.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
		return g, g.ID + "." + b64.EncodeToString(h.env.Svc.Sealer.MAC("refresh", g.ID, string(g.Secret)))
	}
	sessionLive := func(g *model.Grant) { // the grant's session must exist for a refresh
		t.Helper()
		_ = h.env.Svc.Sessions.Create(ctx, &model.Session{Meta: model.Meta{ID: g.SessionID}, UserID: g.UserID,
			OrgID: g.OrgID, AuthTime: time.Now(), Expires: time.Now().Add(time.Hour), LastSeen: time.Now()})
	}

	// one master key: the re-seal pass converts it
	g1, t1 := legacy()
	sessionLive(g1)
	if r := h.refreshWith(cl, secret, t1); r.status != 200 {
		t.Fatalf("legacy token: %d %v", r.status, r.m)
	}
	g2, t2 := legacy()
	if res, err := h.env.Svc.ResealSecrets(ctx, 1000); err != nil || !res.Done() {
		t.Fatalf("reseal: %+v %v", res, err)
	}
	if g, _ := h.env.Svc.Grants.Get(ctx, g2.ID); g.Key == "" || len(g.Secret) != 0 {
		t.Fatalf("not converted: %+v", g)
	}

	// during a rotation it cannot be converted blind: it waits for its token, and holds the rotation open
	g3, t3 := legacy()
	ring, _ := secure.NewKeyring(k1, k0)
	h.env.Svc.Sealer = ring
	if res, _ := h.env.Svc.ResealSecrets(ctx, 1000); res.Legacy != 1 || res.Done() {
		t.Fatalf("legacy grant during a rotation: %+v", res)
	}
	if r := h.refreshWith(cl, secret, t3); r.status != 200 {
		t.Fatalf("legacy token during a rotation: %d %v", r.status, r.m)
	}
	if res, _ := h.env.Svc.ResealSecrets(ctx, 1000); !res.Done() {
		t.Fatalf("after its token was used: %+v", res)
	}
	only1, _ := secure.NewSealer(k1)
	h.env.Svc.Sealer = only1
	for _, tok := range []string{t1, t2, t3} {
		if r := h.refreshWith(cl, secret, tok); r.status != 200 {
			t.Fatalf("converted token %s after the old key was removed: %d %v", tok, r.status, r.m)
		}
	}
	_ = g3
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

// The OAuth side of the audit trail: a user's consent, every grant a code exchange makes, a code presented twice,
// refresh token reuse, revocation, and (with audit.tokens) every refresh; each with the request's id.
func TestOAuthAuditEvents(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Audit.Tokens = true })

	// consent, by the signed-in user
	third, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false); in.Name = ptr("Third Party") })
	c, csrf := h.session(h.user)
	_, ch := pkce()
	u := h.authorize(c, authzQuery(third, ch, nil))
	b, _ := json.Marshal(map[string]any{"flow": u.Query().Get("flow"), "approve": true})
	req, _ := http.NewRequest("POST", h.env.URL+"/api/oauth/consent", strings.NewReader(string(b)))
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	if r, err := c.Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("consent: %v", err)
	} else if r.Header.Get("X-Request-ID") == "" {
		t.Fatal("no X-Request-ID")
	}
	ev := h.auditEvents("oauth.consent")
	if len(ev) != 1 || ev[0].Detail["decision"] != "allow" || ev[0].Detail["client_id"] != third.ID ||
		ev[0].ActorID != h.user.ID || ev[0].RequestID == "" || ev[0].SessionID == "" || ev[0].UserAgent == "" {
		t.Fatalf("oauth.consent: %+v", ev)
	}

	// a grant, a refresh (audit.tokens) and a revocation
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	if ev := h.auditEvents("oauth.grant"); len(ev) != 1 || ev[0].Target != "alice" || ev[0].Detail["client_id"] != cl.ID ||
		ev[0].Outcome != "success" {
		t.Fatalf("oauth.grant: %+v", ev)
	}
	rt := r.str("refresh_token")
	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatalf("refresh: %d", r.status)
	}
	if ev := h.auditEvents("oauth.refresh"); len(ev) != 1 {
		t.Fatalf("oauth.refresh: %+v", ev)
	}
	if r := h.clientPost("/oauth/revoke", url.Values{"token": {rt}}, cl, secret); r.status != 200 {
		t.Fatalf("revoke: %d", r.status)
	}
	if ev := h.auditEvents("oauth.revoke"); len(ev) != 1 || ev[0].Detail["token"] != "refresh" {
		t.Fatalf("oauth.revoke: %+v", ev)
	}

	// a code presented twice: the grant goes, and it is recorded as a failure
	c2, _ := h.session(h.user)
	v, ch2 := pkce()
	code := h.getCode(c2, cl, ch2, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}
	if r := h.token(form, cl, secret); r.status != 200 {
		t.Fatalf("exchange: %d", r.status)
	}
	if r := h.token(form, cl, secret); r.status != 400 {
		t.Fatalf("replay: %d", r.status)
	}
	if ev := h.auditEvents("oauth.code.replay"); len(ev) != 1 || ev[0].Outcome != "failure" || ev[0].Detail["grant_revoked"] != "true" {
		t.Fatalf("oauth.code.replay: %+v", ev)
	}

	// signing keys made by the server are on record
	if len(h.auditEvents("keys.create")) == 0 {
		t.Fatal("no keys.create event")
	}
}

// A rotated-out refresh token presented again revokes the grant and is recorded as a failure.
func TestRefreshReuseIsAudited(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	old := r.str("refresh_token")
	if r := h.refreshWith(cl, secret, old); r.status != 200 {
		t.Fatalf("refresh: %d", r.status)
	}
	if r := h.refreshWith(cl, secret, old); r.status != 400 {
		t.Fatalf("reuse: %d", r.status)
	}
	if ev := h.auditEvents("oauth.refresh.reuse"); len(ev) != 1 || ev[0].Outcome != "failure" || ev[0].Target != "alice" {
		t.Fatalf("oauth.refresh.reuse: %+v", ev)
	}
	if len(h.auditEvents("oauth.refresh")) != 0 {
		t.Fatal("refreshes audited without audit.tokens")
	}
}
