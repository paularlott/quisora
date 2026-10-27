package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

func TestAuthorizeValidation(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	noCode, _ := h.newClient(func(in *service.ClientInput) { in.GrantTypes = &[]string{"client_credentials"} })
	c, _ := h.session(h.user)
	_, ch := pkce()
	manyResources := make([]string, 11)
	for i := range manyResources {
		manyResources[i] = "https://api.example/r" + string(rune('a'+i))
	}

	// errors that must NOT redirect
	for name, q := range map[string]url.Values{
		"unknown client": {"client_id": {"nope"}, "redirect_uri": {rpCallback}},
		"wrong redirect": authzQuery(cl, ch, url.Values{"redirect_uri": {"https://evil.example/cb"}}),
		"no redirect":    authzQuery(cl, ch, url.Values{"redirect_uri": {""}}),
		"prefix match":   authzQuery(cl, ch, url.Values{"redirect_uri": {rpCallback + "/x"}}),
		"http downgrade": authzQuery(cl, ch, url.Values{"redirect_uri": {"http://rp.example/cb"}}),
	} {
		resp := h.get(c, orgBase+"/oauth/authorize?"+q.Encode())
		if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d location %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
		body(resp)
	}
	// errors that redirect back to the client
	for name, tc := range map[string]struct {
		client *model.Client // cl unless set
		extra  url.Values
		code   string
	}{
		"no pkce":            {nil, url.Values{"code_challenge": {""}, "code_challenge_method": {""}}, "invalid_request"},
		"plain":              {nil, url.Values{"code_challenge_method": {"plain"}}, "invalid_request"},
		"bad challenge":      {nil, url.Values{"code_challenge": {"short"}}, "invalid_request"},
		"challenge alphabet": {nil, url.Values{"code_challenge": {strings.Repeat("+", 43)}}, "invalid_request"},
		"token type":         {nil, url.Values{"response_type": {"token"}}, "unsupported_response_type"},
		"no code grant":      {noCode, nil, "unauthorized_client"},
		"scope":              {nil, url.Values{"scope": {"openid admin"}}, "invalid_scope"},
		"prompt":             {nil, url.Values{"prompt": {"bogus"}}, "invalid_request"},
		"none+login":         {nil, url.Values{"prompt": {"none login"}}, "invalid_request"},
		"max_age":            {nil, url.Values{"max_age": {"-1"}}, "invalid_request"},
		"request object":     {nil, url.Values{"request": {"x"}}, "request_not_supported"},
		"resource":           {nil, url.Values{"resource": {"not a uri"}}, "invalid_target"},
		"too many resources": {nil, url.Values{"resource": manyResources}, "invalid_target"},
		"response_mode":      {nil, url.Values{"response_mode": {"fragment"}}, "invalid_request"},
		"state twice":        {nil, url.Values{"state": {"a", "b"}}, "invalid_request"},
		"long state":         {nil, url.Values{"state": {strings.Repeat("s", 2049)}}, "invalid_request"},
		"long nonce":         {nil, url.Values{"nonce": {strings.Repeat("n", 1025)}}, "invalid_request"},
		"bad claims":         {nil, url.Values{"claims": {"[]"}}, "invalid_request"},
	} {
		client := cl
		if tc.client != nil {
			client = tc.client
		}
		u := h.authorize(c, authzQuery(client, ch, tc.extra))
		if u.Scheme+"://"+u.Host+u.Path != rpCallback || u.Query().Get("error") != tc.code ||
			u.Query().Get("iss") == "" {
			t.Errorf("%s: %s", name, u)
		}
		if name != "response_mode" && tc.extra.Get("state") == "" && u.Query().Get("state") != "st1" {
			t.Errorf("%s: state lost", name)
		}
	}
	// no scope asked: the client's own
	if u := h.authorize(c, authzQuery(cl, ch, url.Values{"scope": {""}})); u.Query().Get("code") == "" {
		t.Errorf("default scope: %s", u)
	}
	// an unreadable query
	resp := h.get(c, orgBase+"/oauth/authorize?%zz")
	if body(resp); resp.StatusCode != 400 {
		t.Errorf("unreadable query: %d", resp.StatusCode)
	}
	// disabled client
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(cl.ID)
	if resp := h.get(c, orgBase+"/oauth/authorize?"+authzQuery(cl, ch, nil).Encode()); resp.StatusCode != 400 {
		t.Errorf("disabled client status %d", resp.StatusCode)
	}
}

func TestAuthorizeLoopbackRedirectPort(t *testing.T) {
	t.Parallel()
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
	resp := h.get(c, orgBase+"/oauth/authorize?"+authzQuery(cl, ch, url.Values{"redirect_uri": {"http://127.0.0.1:53211/other"}}).Encode())
	if body(resp); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("another path accepted (%d)", resp.StatusCode)
	}
}

// An http redirect URI on the loopback interface (localhost, 127.0.0.1, [::1]) matches any port (RFC 8252 §7.3), with
// the host, path and query registered; any other address matches exactly.
func TestRedirectMatchesLoopbackPorts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		registered, got string
		want            bool
	}{
		{"http://[::1]/cb", "http://[::1]:4100/cb", true},
		{"http://localhost:8080/cb", "http://localhost:8080/cb", true},
		{"http://localhost:8080/cb", "http://localhost:9999/cb", true},
		{"http://localhost/cb", "http://localhost:4100/cb", true},
		{"http://127.0.0.1/cb", "http://127.0.0.1:53211/cb", true},
		{"http://localhost:8080/cb", "http://127.0.0.1:8080/cb", false},
		{"http://127.0.0.1/cb", "http://localhost:53211/cb", false},
		{"http://localhost:8080/cb", "http://localhost:8080/other", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:53211/other", false},
		{"http://localhost:8080/cb", "https://localhost:8080/cb", false},
		{"http://app.example/cb", "http://app.example:81/cb", false},
		{"https://rp.example/cb", "https://rp.example:8443/cb", false},
		{"https://rp.example/cb", "http://evil.example/cb", false},
		{"com.example.app:/cb", "com.example.app:/cb", true},
		{"com.example.app:/cb", "com.example.app:/other", false},
	} {
		if got := redirectMatches([]string{tc.registered}, tc.got); got != tc.want {
			t.Errorf("registered %s, asked %s: matches %v, want %v", tc.registered, tc.got, got, tc.want)
		}
	}
}

func TestSignInHandoff(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	anon := h.anon()

	u := h.authorize(anon, authzQuery(cl, ch, nil))
	if u.Path != orgBase+"/login" || u.Query().Get("reauth") != "" {
		t.Fatalf("handoff %s", u)
	}
	next := u.Query().Get("next")
	if !strings.HasPrefix(next, orgBase+"/oauth/authorize/resume?flow=") {
		t.Fatal(next)
	}
	// the sign-in page is told the login hint
	if u := h.authorize(anon, authzQuery(cl, ch, url.Values{"login_hint": {"alice@example.com"}})); u.Query().Get("login_hint") != "alice@example.com" {
		t.Fatalf("login hint: %s", u)
	}
	// an over-long login hint is not passed on
	if u := h.authorize(anon, authzQuery(cl, ch, url.Values{"login_hint": {strings.Repeat("h", 300)}})); u.Query().Get("login_hint") != "" {
		t.Fatalf("long login hint: %s", u)
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
	// Another organization's client is unknown at this organization's endpoint, and at its own endpoint this
	// organization's session is no session: the browser is sent to its sign-in page.
	org2, err := h.env.Svc.CreateOrg(context.Background(), h.admin, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")})
	if err != nil {
		t.Fatal(err)
	}
	cl2, _, _ := h.env.Svc.CreateClient(context.Background(), h.admin, org2.ID, service.ClientInput{Name: ptr("acme app"),
		RedirectURIs: &[]string{rpCallback}, GrantTypes: &[]string{"authorization_code"}, FirstParty: ptr(true)})
	q2 := authzQuery(cl2, ch, url.Values{"scope": {"openid"}}).Encode()
	if resp := h.get(signed, orgBase+"/oauth/authorize?"+q2); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body(resp), "not recognised") {
		t.Fatalf("a client of another organization: %d", resp.StatusCode)
	}
	u5 := loc(t, h.get(signed, web.OrgPath(org2.ID, "/oauth/authorize?"+q2)))
	if u5.Path != web.OrgPath(org2.ID, "/login") || u5.Query().Get("reauth") != "" {
		t.Fatalf("another organization's session: %s", u5)
	}
}

func TestPromptLoginAndMaxAge(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()

	old := h.sessionWith(h.user, []string{"pwd"}, time.Now().Add(-2*time.Hour))
	if u := h.authorize(old, authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("plain: %s", u)
	}
	u := h.authorize(old, authzQuery(cl, ch, url.Values{"max_age": {"60"}}))
	if u.Path != orgBase+"/login" || u.Query().Get("reauth") != "1" {
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

func TestFormPostResponseMode(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	resp := h.get(c, orgBase+"/oauth/authorize?"+authzQuery(cl, ch, url.Values{"response_mode": {"form_post"}}).Encode())
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
	resp = h.get(c, orgBase+"/oauth/authorize?"+authzQuery(cl, ch, url.Values{"response_mode": {"form_post"}, "scope": {"bogus"}}).Encode())
	if p := body(resp); !strings.Contains(p, `name="error" value="invalid_scope"`) {
		t.Fatal(p)
	}
}

// Parameters must not be repeated (RFC 6749 §3.1, §3.2); resource indicators may be (RFC 8707).
func TestRepeatedParameters(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	raw := authzQuery(cl, ch, nil).Encode()
	// which application or where to is in doubt: an error page, no redirect
	for _, extra := range []string{"&client_id=" + cl.ID, "&redirect_uri=" + url.QueryEscape(cl.RedirectURIs[0])} {
		if resp := h.get(c, orgBase+"/oauth/authorize?"+raw+extra); resp.StatusCode != 400 {
			t.Errorf("repeated %s: %d", extra, resp.StatusCode)
		}
	}
	// anything else: invalid_request back to the client
	resp := h.get(c, orgBase+"/oauth/authorize?"+raw+"&scope=openid")
	if loc := loc(t, resp); loc.Query().Get("error") != "invalid_request" {
		t.Errorf("repeated scope: %s", loc)
	}
	// resource may repeat
	ok := h.get(c, orgBase+"/oauth/authorize?"+raw+"&resource=https://api.example/a&resource=https://api.example/b")
	if l := loc(t, ok); l.Query().Get("code") == "" {
		t.Errorf("repeated resource refused: %s", l)
	}
	// token endpoint
	r := h.post(orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials", "client_credentials"}, "client_id": {cl.ID},
		"client_secret": {secret}}, "", "")
	if r.status != 400 || r.str("error") != "invalid_request" {
		t.Errorf("repeated grant_type: %d %v", r.status, r.m)
	}
}

// Authorization requests that start a sign-in flow are limited per address: each holds a flow in memory.
func TestAuthorizeLimitedPerAddress(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	for i := range authorizePerIPMin {
		resp := h.get(c, orgBase+"/oauth/authorize?"+authzQuery(cl, ch, nil).Encode())
		if u := loc(t, resp); u.Query().Get("error") != "" {
			t.Fatalf("request %d refused: %s", i+1, u)
		}
	}
	resp := h.get(c, orgBase+"/oauth/authorize?"+authzQuery(cl, ch, nil).Encode())
	body(resp)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Location") != "" {
		t.Fatalf("over the limit: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Requests naming no real client count too (each costs a store read).
	h2 := setup(t, nil)
	c2, _ := h2.session(h2.user)
	for range authorizePerIPMin {
		body(h2.get(c2, orgBase+"/oauth/authorize?client_id=nope&redirect_uri=https://x.example/cb"))
	}
	if resp := h2.get(c2, orgBase+"/oauth/authorize?client_id=nope&redirect_uri=https://x.example/cb"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("unknown-client flood not limited: %d", resp.StatusCode)
	}
}

// Flow binding (flow fixation).
func TestFlowBoundToBrowser(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()

	// browser A starts a flow signed out
	a := h.anon()
	u := h.authorize(a, authzQuery(cl, ch, nil))
	next := u.Query().Get("next")
	if !strings.HasPrefix(next, orgBase+"/oauth/authorize/resume?flow=") {
		t.Fatal(u)
	}
	// browser B (signed in, but never started the flow) cannot resume it
	b, _ := h.session(h.user)
	resp := h.get(b, next)
	page := body(resp)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(page, "started in another browser") {
		t.Fatalf("foreign browser: %d %s", resp.StatusCode, page)
	}
	// a wrong cookie value does not do either
	pu, _ := url.Parse(h.env.URL)
	bad, _ := h.session(h.user)
	for _, ck := range a.Jar.Cookies(pu) {
		if strings.HasPrefix(ck.Name, flowCookiePrefix) {
			bad.Jar.SetCookies(pu, []*http.Cookie{{Name: ck.Name, Value: ck.Value + "x", Path: "/", Secure: true}})
		}
	}
	if resp := h.get(bad, next); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong cookie value: %d", resp.StatusCode)
	}
	// the flow survives those attempts; the starting browser (after signing in) completes it
	same, _ := h.session(h.user)
	h.copyFlowCookies(a, same)
	resp = h.get(same, next)
	if resp.StatusCode != 302 || loc(t, resp).Query().Get("code") == "" {
		t.Fatalf("same browser: %d", resp.StatusCode)
	}
}

func TestFlowCookieAttributes(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	resp := h.get(h.anon(), orgBase+"/oauth/authorize?"+authzQuery(cl, ch, nil).Encode())
	body(resp)
	var got *http.Cookie
	for _, ck := range resp.Cookies() {
		if strings.HasPrefix(ck.Name, "__Host-quisora_flow") {
			got = ck
		}
	}
	if got == nil || !got.Secure || !got.HttpOnly || got.SameSite != http.SameSiteLaxMode || got.Path != "/" ||
		got.Domain != "" || got.MaxAge <= 0 || got.MaxAge > int(flowTTL/time.Second) || len(got.Value) < 32 {
		t.Fatalf("flow cookie: %+v", got)
	}
}

func TestFormActionSource(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"https://app.example.com:8443/cb":     "https://app.example.com:8443",
		"com.example.app:/cb":                 "com.example.app:",
		"https://evil.example;script-src*/cb": "",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			continue // a host url.Parse refuses never gets this far
		}
		got, ok := formActionSource(u)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", raw, got, ok, want)
		}
	}
	if _, ok := formActionSource(&url.URL{Scheme: "https", Host: "evil.example; script-src *"}); ok {
		t.Error("a host with a separator made a source")
	}
}

func TestResumeAndConsentRefuseUnknownOrStaleFlows(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	c, csrf := h.session(h.user)
	ctx := context.Background()
	status := func(path string) int {
		resp := h.get(c, path)
		body(resp)
		return resp.StatusCode
	}
	garbage, err := h.env.Server.Eph.New(ctx, nsFlow, []byte("not json"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{orgBase + "/oauth/authorize/resume?flow=" + garbage, orgBase + "/oauth/authorize/cancel?flow=" + garbage,
		orgBase + "/oauth/authorize/resume?flow=unknown", orgBase + "/oauth/consent?flow=" + garbage, orgBase + "/oauth/consent?flow=unknown"} {
		if st := status(path); st != http.StatusBadRequest {
			t.Errorf("%s: %d", path, st)
		}
	}
	// a flow whose client is disabled before it resumes
	_, ch := pkce()
	id := h.authorize(c, authzQuery(cl, ch, nil)).Query().Get("flow")
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	for _, path := range []string{orgBase + "/oauth/authorize/resume?flow=" + id, orgBase + "/oauth/consent?flow=" + id} {
		if st := status(path); st != http.StatusBadRequest {
			t.Errorf("disabled client %s: %d", path, st)
		}
	}
	if st, _ := h.decideConsent(c, csrf, id, true); st != http.StatusNotFound {
		t.Errorf("consent for a disabled client: %d", st)
	}
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+orgBase+"/api-internal/oauth/consent", strings.NewReader("not json"))
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	if r, err := c.Do(req); err != nil || r.StatusCode != http.StatusBadRequest {
		t.Errorf("consent with a broken body: %v %v", r, err)
	}
}
