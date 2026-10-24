package oidc

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// push posts an authorization request to the PAR endpoint as client c (secret "" for a public client).
func (h *harness) push(c *model.Client, secret string, q url.Values) tokResp {
	h.t.Helper()
	f := url.Values{}
	for k, v := range q {
		if k != "client_id" {
			f[k] = v
		}
	}
	if secret == "" {
		f.Set("client_id", c.ID)
		return h.post("/oauth/par", f, "", "")
	}
	return h.clientPost("/oauth/par", f, c, secret)
}

func pushedQuery(c *model.Client, requestURI string) url.Values {
	return url.Values{"client_id": {c.ID}, "request_uri": {requestURI}}
}

func TestPushedAuthorizationRequest(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	v, ch := pkce()
	r := h.push(cl, secret, authzQuery(cl, ch, url.Values{"state": {"pushed"}}))
	uri := r.str("request_uri")
	if r.status != 201 || !strings.HasPrefix(uri, parURNPrefix) || r.m["expires_in"] != float64(60) ||
		r.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("push: %d %v", r.status, r.m)
	}
	// Only the pushed parameters count: whatever else the URL carries is ignored.
	c, _ := h.session(h.user)
	q := pushedQuery(cl, uri)
	q.Set("state", "from-url")
	q.Set("scope", "openid admin")
	q.Set("redirect_uri", "https://evil.example/cb")
	u := h.authorize(c, q)
	code := u.Query().Get("code")
	if u.Scheme+"://"+u.Host+u.Path != rpCallback || code == "" || u.Query().Get("state") != "pushed" {
		t.Fatalf("authorize: %s", u)
	}
	tr := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
		"code_verifier": {v}}, cl, secret)
	if tr.status != 200 || tr.str("id_token") == "" || tr.str("scope") != "openid profile email offline_access" {
		t.Fatalf("exchange: %d %v", tr.status, tr.m)
	}
	// single use: presented again after the code, it is sent back to the client as invalid_request_uri
	u = h.authorize(c, pushedQuery(cl, uri))
	if u.Scheme+"://"+u.Host+u.Path != rpCallback || u.Query().Get("error") != "invalid_request_uri" || u.Query().Get("state") != "pushed" {
		t.Fatalf("reused request_uri: %s", u)
	}
	// only by the client that pushed it
	other, _ := h.newClient(nil)
	r = h.push(cl, secret, authzQuery(cl, ch, nil))
	resp := h.get(c, "/oauth/authorize?"+pushedQuery(other, r.str("request_uri")).Encode())
	if b := body(resp); resp.StatusCode != 400 || resp.Header.Get("Location") != "" || !strings.Contains(b, "This sign-in request is not valid") {
		t.Fatalf("another client's request_uri: %d", resp.StatusCode)
	}
	// an unknown one
	resp = h.get(c, "/oauth/authorize?"+pushedQuery(cl, parURNPrefix+"nope").Encode())
	if b := body(resp); resp.StatusCode != 400 || !strings.Contains(b, "This sign-in request is not valid") {
		t.Fatalf("unknown request_uri: %d", resp.StatusCode)
	}
	// a request_uri that is not a pushed one is still not supported
	u = h.authorize(c, authzQuery(cl, ch, url.Values{"request_uri": {"https://rp.example/req.jwt"}}))
	if u.Query().Get("error") != "request_uri_not_supported" {
		t.Fatalf("foreign request_uri: %s", u)
	}
}

func TestPushedAuthorizationRequestValidation(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	for name, tc := range map[string]struct {
		extra  url.Values
		status int
		code   string
	}{
		"wrong redirect": {url.Values{"redirect_uri": {"https://evil.example/cb"}}, 400, "invalid_request"},
		"no redirect":    {url.Values{"redirect_uri": {""}}, 400, "invalid_request"},
		"no pkce":        {url.Values{"code_challenge": {""}, "code_challenge_method": {""}}, 400, "invalid_request"},
		"scope":          {url.Values{"scope": {"openid admin"}}, 400, "invalid_scope"},
		"token type":     {url.Values{"response_type": {"token"}}, 400, "unsupported_response_type"},
		"request object": {url.Values{"request": {"x"}}, 400, "request_not_supported"},
		"request_uri":    {url.Values{"request_uri": {parURNPrefix + "x"}}, 400, "invalid_request"},
		"resource":       {url.Values{"resource": {"https://other.example"}}, 400, "invalid_target"},
		"repeated":       {url.Values{"scope": {"openid", "email"}}, 400, "invalid_request"},
	} {
		if r := h.push(cl, secret, authzQuery(cl, ch, tc.extra)); r.status != tc.status || r.m["error"] != tc.code {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
	// client authentication is required, and must be right
	if r := h.push(cl, "wrong", authzQuery(cl, ch, nil)); r.status != 401 || r.m["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", r.status, r.m)
	}
	if r := h.push(cl, "", authzQuery(cl, ch, nil)); r.status != 401 {
		t.Errorf("confidential client without a secret: %d %v", r.status, r.m)
	}
	// the stored request holds no client credentials
	r := h.push(cl, secret, authzQuery(cl, ch, nil))
	raw, err := h.env.Server.Eph.Get(context.Background(), nsPAR, strings.TrimPrefix(r.str("request_uri"), parURNPrefix))
	if err != nil {
		t.Fatal(err)
	}
	var pr pushedRequest
	_ = json.Unmarshal(raw, &pr)
	if pr.ClientID != cl.ID || strings.Contains(pr.Params, "client_secret") || strings.Contains(pr.Params, secret) {
		t.Fatalf("stored: %+v", pr)
	}
}

func TestPushedAuthorizationRequestPublicAndBasic(t *testing.T) {
	h := setup(t, nil)
	// a public client pushes with its client_id alone
	pub := h.publicClient(func(in *service.ClientInput) { in.FirstParty = ptr(true) })
	_, ch := pkce()
	r := h.push(pub, "", authzQuery(pub, ch, nil))
	if r.status != 201 {
		t.Fatalf("public push: %d %v", r.status, r.m)
	}
	c, _ := h.session(h.user)
	if u := h.authorize(c, pushedQuery(pub, r.str("request_uri"))); u.Query().Get("code") == "" {
		t.Fatalf("public authorize: %s", u)
	}
	// client_secret_basic: the client_id need not be in the body
	basic, bsecret := h.newClient(func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) })
	r = h.push(basic, bsecret, authzQuery(basic, ch, nil))
	if r.status != 201 {
		t.Fatalf("basic push: %d %v", r.status, r.m)
	}
	if u := h.authorize(c, pushedQuery(basic, r.str("request_uri"))); u.Query().Get("code") == "" {
		t.Fatalf("basic authorize: %s", u)
	}
}

func TestRequirePushedAuthorizationRequests(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RequirePAR = ptr(true) })
	if !cl.RequirePAR {
		t.Fatal("flag not stored")
	}
	c, _ := h.session(h.user)
	_, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, nil))
	if u.Query().Get("error") != "invalid_request" || u.Query().Get("state") != "st1" ||
		!strings.Contains(u.Query().Get("error_description"), "RFC 9126") {
		t.Fatalf("unpushed request: %s", u)
	}
	r := h.push(cl, secret, authzQuery(cl, ch, nil))
	if u := h.authorize(c, pushedQuery(cl, r.str("request_uri"))); u.Query().Get("code") == "" {
		t.Fatalf("pushed request: %s", u)
	}
}

func TestDiscoveryPAR(t *testing.T) {
	h := setup(t, nil)
	resp := h.get(h.http, "/.well-known/openid-configuration")
	var d map[string]any
	_ = json.Unmarshal([]byte(body(resp)), &d)
	if d["pushed_authorization_request_endpoint"] != h.env.Cfg.Issuer()+"/oauth/par" || d["require_pushed_authorization_requests"] != false {
		t.Fatalf("%v", d)
	}
}

// A request_uri is used up when the request is decided, not when the browser first opens it (FAPI 2.0 §5.3.2.2): the
// sign-in page can be reloaded, and only one of two flows of the same request_uri gets a code.
func TestPushedRequestUsedWhenDecided(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	uri := h.push(cl, secret, authzQuery(cl, ch, nil)).str("request_uri")
	anon := h.anon()
	for i := 0; i < 2; i++ { // not signed in: sent to the sign-in page, twice
		if u := h.authorize(anon, pushedQuery(cl, uri)); !strings.HasPrefix(u.Path, "/login/") {
			t.Fatalf("visit %d: %s", i, u)
		}
	}
	// two signed-in browsers start flows from it; the first to be decided gets the code
	b1, _ := h.session(h.user)
	b2, _ := h.session(h.user)
	u1 := h.authorize(b1, pushedQuery(cl, uri))
	u2 := h.authorize(b2, pushedQuery(cl, uri))
	if u1.Query().Get("code") == "" || u2.Query().Get("error") != "invalid_request_uri" {
		t.Fatalf("decided twice: %s / %s", u1, u2)
	}
}

func TestCancelSignIn(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	for name, q := range map[string]url.Values{"plain": authzQuery(cl, ch, nil),
		"pushed": pushedQuery(cl, h.push(cl, secret, authzQuery(cl, ch, nil)).str("request_uri"))} {
		b := h.anon()
		login := h.authorize(b, q)
		next := login.Query().Get("next") // the sign-in page's Cancel link (login.cancelURL) is built from it
		cancel := "/oauth/authorize/cancel?" + strings.TrimPrefix(next, "/oauth/authorize/resume?")
		if !strings.HasPrefix(next, "/oauth/authorize/resume?flow=") {
			t.Fatalf("%s: next %q", name, next)
		}
		// another browser cannot cancel it
		if resp := h.get(h.anon(), cancel); resp.StatusCode != 403 {
			t.Errorf("%s: cancel from another browser: %d", name, resp.StatusCode)
		}
		u := loc(t, h.get(b, cancel))
		if u.Scheme+"://"+u.Host+u.Path != rpCallback || u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "st1" {
			t.Fatalf("%s: cancel: %s", name, u)
		}
		if name == "pushed" {
			if u := h.authorize(b, q); u.Query().Get("error") != "invalid_request_uri" {
				t.Fatalf("cancelled request_uri reused: %s", u)
			}
		}
	}
}

// A pushed request is kept in memory until it is used: one larger than parMaxParams is refused, not kept.
func TestPushedRequestTooLarge(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	q := authzQuery(cl, ch, url.Values{"x_padding": {strings.Repeat("x", parMaxParams)}})
	if r := h.push(cl, secret, q); r.status != 400 || r.m["error"] != "invalid_request" {
		t.Fatalf("oversized push: %d %v", r.status, r.m)
	}
}
