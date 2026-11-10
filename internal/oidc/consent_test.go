package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
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
	if u.Path != h.orgBase+"/oauth/consent" {
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
	req, _ := http.NewRequest("POST", h.env.URL+h.orgBase+"/api-internal/oauth/consent", strings.NewReader(`{"flow":"x","approve":true}`))
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
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"prompt": {"consent"}})); u.Path != h.orgBase+"/oauth/consent" {
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
	if u1.Path != h.orgBase+"/oauth/consent" || u2.Path != h.orgBase+"/oauth/consent" || f1 == f2 {
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
	if u.Path != h.orgBase+"/oauth/consent" {
		t.Fatalf("consent: %s", u)
	}
	if page := body(h.get(c, u.RequestURI())); !strings.Contains(page, "Access: api") {
		t.Fatalf("consent page: %s", page)
	}
}

// A client set to remember consent remembers it past signing out (model.Consent), per approval, until the
// application's access is removed; never a public client.
func TestConsentRememberedAcrossSignOut(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.FirstParty = ptr(false)
		in.RememberConsent = ptr(true)
		in.Scopes = &[]string{"openid", "profile", "email", "offline_access", "api"}
	})
	approve := func(c *http.Client, csrf string, extra url.Values) {
		t.Helper()
		_, ch := pkce()
		u := h.authorize(c, authzQuery(cl, ch, extra))
		if u.Path != h.orgBase+"/oauth/consent" {
			t.Fatalf("expected consent: %s", u)
		}
		if st, _ := h.decideConsent(c, csrf, u.Query().Get("flow"), true); st != 200 {
			t.Fatalf("consent api %d", st)
		}
	}
	asks := func(c *http.Client, extra url.Values) bool {
		t.Helper()
		_, ch := pkce()
		u := h.authorize(c, authzQuery(cl, ch, extra))
		if u.Path == h.orgBase+"/oauth/consent" {
			return true
		}
		if u.Query().Get("code") == "" {
			t.Fatalf("neither consent nor a code: %s", u)
		}
		return false
	}
	signOutEverywhere := func() (*http.Client, string) {
		t.Helper()
		if err := h.env.Svc.RevokeSessions(ctx, h.admin, h.user.ID); err != nil {
			t.Fatal(err)
		}
		u, err := h.env.Svc.Users.Get(ctx, h.user.ID)
		if err != nil {
			t.Fatal(err)
		}
		return h.session(u)
	}

	c, csrf := h.session(h.user)
	_, ch0 := pkce()
	if u := h.authorize(c, authzQuery(cl, ch0, nil)); !strings.Contains(body(h.get(c, u.RequestURI())), "will not ask again, even after you sign out") {
		t.Fatal("the consent page does not say it is remembered")
	}
	approve(c, csrf, nil) // no code exchanged: nothing but the approval is remembered
	c, csrf = signOutEverywhere()
	if asks(c, nil) {
		t.Fatal("consent not remembered after signing out")
	}
	// a scope never allowed is asked for, and then remembered too; prompt=consent still asks
	if !asks(c, url.Values{"scope": {"openid api"}}) {
		t.Fatal("a new scope was not asked for")
	}
	approve(c, csrf, url.Values{"scope": {"openid api"}})
	if asks(c, url.Values{"scope": {"openid api"}}) || asks(c, nil) {
		t.Fatal("approvals not remembered")
	}
	if !asks(c, url.Values{"prompt": {"consent"}}) {
		t.Fatal("prompt=consent did not ask")
	}
	// the account's Connected apps list shows it, and removing access forgets it
	apps, err := h.env.Svc.ConnectedApps(ctx, h.user.ID)
	if err != nil || len(apps) != 1 || !apps[0].Remembered || apps[0].ClientID != cl.ID {
		t.Fatalf("connected apps %+v %v", apps, err)
	}
	if n, err := h.env.Svc.RevokeAppAccess(ctx, h.user.ID, cl.ID); err != nil || n == 0 {
		t.Fatalf("revoke %d %v", n, err)
	}
	if !asks(c, nil) {
		t.Fatal("consent remembered after access was removed")
	}
	if n, err := h.env.Svc.RevokeAppAccess(ctx, h.user.ID, cl.ID); err != nil || n != 0 {
		t.Fatalf("second revoke %d %v", n, err)
	}

	// a public client asks every time
	pub := h.publicClient(func(in *service.ClientInput) { in.FirstParty = ptr(false); in.RememberConsent = ptr(true) })
	_, ch := pkce()
	u := h.authorize(c, authzQuery(pub, ch, nil))
	if u.Path != h.orgBase+"/oauth/consent" {
		t.Fatalf("public client: expected consent: %s", u)
	}
	if strings.Contains(body(h.get(c, u.RequestURI())), "will not ask again") {
		t.Fatal("a public client's consent page says it is remembered")
	}
	if st, _ := h.decideConsent(c, csrf, u.Query().Get("flow"), true); st != 200 {
		t.Fatalf("consent api %d", st)
	}
	if u := h.authorize(c, authzQuery(pub, ch, nil)); u.Path != h.orgBase+"/oauth/consent" {
		t.Fatalf("public client consent remembered: %s", u)
	}
	if _, err := h.env.Svc.Consents.Get(ctx, model.ConsentID(h.user.ID, pub.ID)); err == nil {
		t.Fatal("public client consent stored")
	}
}

// One approval covers a request only with all of its scopes and resources: scopes allowed for one resource are not
// allowed for another.
func TestRememberConsentSets(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	svc, uid := h.env.Svc, h.user.ID
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	cl := &model.Client{Meta: model.Meta{ID: "cl"}, RememberConsent: true}
	must(svc.RememberConsent(ctx, h.user, cl, []string{"openid", "email"}, []string{"https://a"}))
	must(svc.RememberConsent(ctx, h.user, cl, []string{"openid", "api"}, []string{"https://b"}))
	for _, tc := range []struct {
		scopes, resources []string
		want              bool
	}{
		{[]string{"openid"}, nil, true},
		{[]string{"email"}, []string{"https://a"}, true},
		{[]string{"api"}, []string{"https://b"}, true},
		{[]string{"email"}, []string{"https://b"}, false},
		{[]string{"email", "api"}, nil, false},
		{[]string{"openid"}, []string{"https://a", "https://b"}, false},
	} {
		if got := svc.ConsentCovers(ctx, uid, cl, tc.scopes, tc.resources); got != tc.want {
			t.Errorf("covers %v %v = %v, want %v", tc.scopes, tc.resources, got, tc.want)
		}
	}
	if svc.ConsentCovers(ctx, uid, &model.Client{Meta: model.Meta{ID: "other"}, RememberConsent: true}, []string{"openid"}, nil) {
		t.Error("another client covered")
	}
	// an approval covering earlier ones replaces them
	must(svc.RememberConsent(ctx, h.user, cl, []string{"openid", "email", "api"}, []string{"https://a", "https://b"}))
	c, err := svc.Consents.Get(ctx, model.ConsentID(uid, "cl"))
	if err != nil || len(c.Allowed) != 1 {
		t.Fatalf("sets %+v %v", c, err)
	}
}

// By default (remember_consent off) consent works as it always has: asked once per sign-in, remembered while a grant of
// it lives, and asked again after signing out; nothing is stored. The setting is moot for a public client.
func TestConsentNotRemembered(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	cl, secret := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	if cl.RememberConsent {
		t.Fatal("a new client remembers consent by default")
	}
	c, csrf := h.session(h.user)
	v, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, nil))
	if u.Path != h.orgBase+"/oauth/consent" {
		t.Fatalf("expected consent: %s", u)
	}
	if page := body(h.get(c, u.RequestURI())); strings.Contains(page, "will not ask again") {
		t.Fatal("the consent page says it is remembered")
	}
	_, redirect := h.decideConsent(c, csrf, u.Query().Get("flow"), true)
	code := loc(t, h.get(c, redirect)).Query().Get("code")
	if r := h.exchangeCode(cl, secret, code, v); r.status != 200 {
		t.Fatal(r.m)
	}
	// while the sign-in's grant lives, it is not asked again
	_, ch2 := pkce()
	if u := h.authorize(c, authzQuery(cl, ch2, nil)); u.Query().Get("code") == "" {
		t.Fatalf("asked again while signed in: %s", u)
	}
	if _, err := h.env.Svc.Consents.Get(ctx, model.ConsentID(h.user.ID, cl.ID)); err == nil {
		t.Fatal("consent stored")
	}
	// signed out, it is asked again
	if err := h.env.Svc.RevokeSessions(ctx, h.admin, h.user.ID); err != nil {
		t.Fatal(err)
	}
	fresh, err := h.env.Svc.Users.Get(ctx, h.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	c, _ = h.session(fresh)
	if u := h.authorize(c, authzQuery(cl, ch2, nil)); u.Path != h.orgBase+"/oauth/consent" {
		t.Fatalf("not asked after signing out: %s", u)
	}
	// a public client cannot be set to remember
	pub := h.publicClient(func(in *service.ClientInput) { in.RememberConsent = ptr(true) })
	if pub.RememberConsent {
		t.Fatal("public client set to remember consent")
	}
	// the setting can be turned on and off again
	on, off := true, false
	if got, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{RememberConsent: &on}); err != nil || !got.RememberConsent {
		t.Fatalf("turn on: %v", err)
	}
	if got, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{RememberConsent: &off}); err != nil || got.RememberConsent {
		t.Fatalf("turn off: %v", err)
	}
}

// What a user allowed an application does not carry over to the application pointed elsewhere: an administrator who
// adds a redirect URI (or rotates the secret) of an application users already allowed must not collect their codes
// at the new address without them being asked. A change that does neither (the description) keeps it.
func TestConsentNotCarriedToChangedRedirects(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	cl, secret := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	c, csrf := h.session(h.user)
	v, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, nil))
	_, redirect := h.decideConsent(c, csrf, u.Query().Get("flow"), true)
	code := loc(t, h.get(c, redirect)).Query().Get("code")
	if r := h.exchangeCode(cl, secret, code, v); r.status != 200 {
		t.Fatal(r.m)
	}
	_, ch2 := pkce()
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{Description: ptr("the app")}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	if u := h.authorize(c, authzQuery(cl, ch2, nil)); u.Query().Get("code") == "" {
		t.Fatalf("a description change asked again: %s", u)
	}
	evil := "https://attacker.example/cb"
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{RedirectURIs: &[]string{cl.RedirectURIs[0], evil}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	u = h.authorize(c, authzQuery(cl, ch2, url.Values{"redirect_uri": {evil}}))
	if u.Path != h.orgBase+"/oauth/consent" {
		t.Fatalf("a code went to the new redirect URI without asking: %s", u)
	}
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"redirect_uri": {evil}, "prompt": {"none"}})); u.Query().Get("error") != "consent_required" {
		t.Fatalf("prompt=none after the change: %s", u)
	}
}
