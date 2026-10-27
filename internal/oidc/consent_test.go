package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// The consent page's way back to the application: a web app's home, nothing for a native app.
func TestReturnURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"https://knot.example.com/auth/callback?x=1", "https://knot.example.com/"},
		{"https://knot.example.com:8443/cb", "https://knot.example.com:8443/"},
		{"http://localhost:3000/callback", "http://localhost:3000/"},
		{"http://127.0.0.1:51234/callback", ""}, // native app on a loopback IP: the port changes every time
		{"http://[::1]:51234/callback", ""},
		{"com.example.app:/oauth2redirect", ""}, // native app, custom scheme
		{"javascript:alert(1)", ""},
		{"", ""},
	} {
		if got := returnURL(tc.in); got != tc.want {
			t.Errorf("returnURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestConsentFlow(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false); in.Name = ptr("Fancy App") })
	c, csrf := h.session(h.user)
	v, ch := pkce()

	u := h.authorize(c, authzQuery(cl, ch, nil))
	if u.Path != orgBase+"/oauth/consent" {
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
		st, redirect := h.decideConsent(c, csrf, flowID, approve)
		if st != 200 {
			t.Fatalf("consent api %d", st)
		}
		return redirect
	}
	// CSRF is enforced
	req, _ := http.NewRequest("POST", h.env.URL+orgBase+"/api-internal/oauth/consent", strings.NewReader(`{"flow":"x","approve":true}`))
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
	r := h.exchangeCode(cl, secret, code, v)
	if r.status != 200 {
		t.Fatal(r.m)
	}
	// consent is remembered while the grant lives
	_, ch2 := pkce()
	if u := h.authorize(c, authzQuery(cl, ch2, nil)); u.Query().Get("code") == "" {
		t.Fatalf("consent not remembered: %s", u)
	}
	// ... unless the client asks for it again
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"prompt": {"consent"}})); u.Path != orgBase+"/oauth/consent" {
		t.Fatalf("prompt=consent: %s", u)
	}
	// prompt=none with a new scope that was never consented
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Scopes: &[]string{"openid", "profile", "email", "offline_access", "api"}})
	h.p.InvalidateClient(cl.ID)
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"scope": {"openid api"}, "prompt": {"none"}})); u.Query().Get("error") != "consent_required" {
		t.Fatalf("consent_required: %s", u)
	}
}

func TestConsentBoundToBrowserAndParallelFlows(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	a, csrfA := h.session(h.user)
	b, csrfB := h.session(h.user)

	consent := func(c *http.Client, csrf, flowID string, approve bool) int {
		st, redirect := h.decideConsent(c, csrf, flowID, approve)
		if st == 200 {
			resp := h.get(c, redirect)
			if resp.StatusCode != 302 || loc(t, resp).Query().Get("code") == "" {
				t.Fatalf("resume after consent: %d", resp.StatusCode)
			}
		}
		return st
	}

	// two flows in browser A at the same time
	_, ch1 := pkce()
	_, ch2 := pkce()
	u1 := h.authorize(a, authzQuery(cl, ch1, nil))
	u2 := h.authorize(a, authzQuery(cl, ch2, nil))
	f1, f2 := u1.Query().Get("flow"), u2.Query().Get("flow")
	if u1.Path != orgBase+"/oauth/consent" || u2.Path != orgBase+"/oauth/consent" || f1 == f2 {
		t.Fatalf("%s %s", u1, u2)
	}
	// browser B cannot view or answer A's consent
	if resp := h.get(b, u1.RequestURI()); resp.StatusCode != 403 {
		t.Fatalf("consent page in other browser: %d", resp.StatusCode)
	}
	if st := consent(b, csrfB, f1, true); st != 403 {
		t.Fatalf("consent POST in other browser: %d", st)
	}
	// browser A can answer both, in either order
	if resp := h.get(a, u2.RequestURI()); resp.StatusCode != 200 {
		t.Fatalf("consent page: %d", resp.StatusCode)
	}
	if st := consent(a, csrfA, f2, true); st != 200 {
		t.Fatalf("flow 2: %d", st)
	}
	if st := consent(a, csrfA, f1, true); st != 200 {
		t.Fatalf("flow 1: %d", st)
	}
}

// A scope the server has no description for is shown by name.
func TestConsentNamesScopesWithoutDescription(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	c, _ := h.session(h.user)
	_, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, url.Values{"scope": {"openid api"}}))
	if u.Path != orgBase+"/oauth/consent" {
		t.Fatalf("consent: %s", u)
	}
	if page := body(h.get(c, u.RequestURI())); !strings.Contains(page, "Access: api") {
		t.Fatalf("consent page: %s", page)
	}
}
