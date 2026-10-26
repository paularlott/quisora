package login_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

func TestUpstreamOIDCSignIn(t *testing.T) {
	u := newUpEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	p := u.oidcProvider(t, nil)
	b := u.browser(t)

	// The provider shows as a button on the organization page.
	_, body := b.get("/login/acme?next=/x")
	if !strings.Contains(body, "Continue with Corp SSO") || !strings.Contains(body, "/login/acme/provider/"+p.ID+"?next=%2Fx") {
		t.Fatalf("provider button missing: %.800s", body)
	}

	res := b.via(t, u, p, "acme", "/x", claims("sub-1", "pat@corp.example"))
	if res.StatusCode != 303 || res.Header.Get("Location") != "/x" || !b.hasSession() {
		t.Fatalf("callback: %d %q session=%v", res.StatusCode, res.Header.Get("Location"), b.hasSession())
	}
	user, err := u.Svc.FindUserByEmail(context.Background(), u.org.ID, "pat@corp.example")
	if err != nil || !user.EmailVerified || user.PasswordHash != "" || user.Role != model.RoleUser {
		t.Fatalf("provisioned user %+v %v", user, err)
	}
	sess := sessionsOf(t, u.env, user)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "fed" {
		t.Fatalf("sessions %+v", sess)
	}
	if res, body := b.get("/account"); res.StatusCode != 200 || !strings.Contains(body, "Your account") {
		t.Fatalf("account: %d", res.StatusCode)
	}
	if n := len(u.audits(t, "login.success")); n != 1 {
		t.Fatalf("login.success audits %d", n)
	}
	if n := len(u.audits(t, "user.provision")); n != 1 {
		t.Fatalf("provision audits %d", n)
	}
	// the user cannot sign in with a password they never set
	res2, out := u.browser(t).login("acme", "pat@corp.example", "")
	wantStatus(t, res2, out, 422)
	res2, out = u.browser(t).login("acme", "pat@corp.example", "anything at all")
	wantStatus(t, res2, out, 401)

	// Same identity again: same user, not a second one, default next.
	b2 := u.browser(t)
	res = b2.via(t, u, p, "acme", "", claims("sub-1", "changed@corp.example"))
	if res.StatusCode != 303 || res.Header.Get("Location") != "/account" {
		t.Fatalf("second sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if n, _ := u.Svc.Users.Count(context.Background(), u.org.ID); n != 1 {
		t.Fatalf("users %d", n)
	}
	// The state cookie is cleared after the callback.
	for _, c := range res.Cookies() {
		if c.Name == "__Host-quisora_up" && c.MaxAge >= 0 {
			t.Fatalf("state cookie kept: %+v", c)
		}
	}
}

func TestUpstreamHostileNext(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	res := b.via(t, u, p, "acme", "//evil.example/steal", claims("s1", "a@corp.example"))
	if res.StatusCode != 303 || res.Header.Get("Location") != "/account" {
		t.Fatalf("hostile next: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestUpstreamFailuresRedirectToLoginWithMessage(t *testing.T) {
	u := newUpEnv(t, nil)
	closed := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Closed"); in.AutoProvision = ptr(false) })
	domains := u.oidcProvider(t, func(in *service.ProviderInput) {
		in.Name = ptr("Domains")
		in.AllowedDomains = &[]string{"corp.example"}
	})
	existing := "taken@corp.example"
	name := "taken"
	if _, err := u.Svc.CreateUser(context.Background(), service.System, u.org.ID, service.UserInput{GivenName: ptr("T"), Username: &name, Email: &existing}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		p     *model.Provider
		c     map[string]any
		code  string
		fragm string
	}{
		{"not linked", closed, claims("x1", "new@corp.example"), "not_linked", "No account here is linked"},
		{"domain", domains, claims("x2", "new@evil.example"), "domain", "email domain is not allowed"},
		{"unverified", domains, map[string]any{"sub": "x3", "email": "a@corp.example", "email_verified": false}, "unverified", "not verified your email"},
		{"email already used", domains, claims("x4", existing), "exists", "already exists"},
	} {
		b := u.browser(t)
		res := b.via(t, u, tc.p, "acme", "/back", tc.c)
		want := "/login/acme?error=" + tc.code + "&next=%2Fback"
		if res.StatusCode != 302 || res.Header.Get("Location") != want || b.hasSession() {
			t.Errorf("%s: %d %q session=%v (want %s)", tc.name, res.StatusCode, res.Header.Get("Location"), b.hasSession(), want)
			continue
		}
		_, body := b.get(res.Header.Get("Location"))
		if !strings.Contains(body, tc.fragm) {
			t.Errorf("%s: page does not show the message: %.500s", tc.name, body)
		}
	}
	// the existing local user was never linked or touched
	if ids, _ := u.Svc.Identities.All(context.Background(), ""); len(ids) != 0 {
		t.Fatalf("identities created: %d", len(ids))
	}
	if n := len(u.audits(t, "login.failure")); n != 4 {
		t.Fatalf("failure audits %d", n)
	}
	// An arbitrary error code in the URL is never reflected.
	_, body := u.browser(t).get("/login/acme?error=%3Cscript%3Ealert(1)%3C/script%3E")
	if strings.Contains(body, "<script>alert") {
		t.Fatal("error parameter reflected")
	}
}

func TestUpstreamStateProtection(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)

	// A callback without the cookie of the browser that started it (login CSRF): refused, nothing signed in.
	b := u.browser(t)
	res, _ := b.get("/login/acme/provider/" + p.ID)
	loc := res.Header.Get("Location")
	lu, _ := url.Parse(loc)
	code := u.oidc.Authorize(loc, claims("c1", "c1@corp.example"))
	attacker := u.browser(t)
	res, _ = attacker.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + code)
	if res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), "/?error=failed") || attacker.hasSession() {
		t.Fatalf("callback without cookie: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// ...and the state is burnt, so the real browser cannot finish it either.
	res, _ = b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + code)
	if b.hasSession() {
		t.Fatalf("burnt state accepted: %d", res.StatusCode)
	}
	// Unknown state, empty callback.
	for _, q := range []string{"state=n1.nope&code=x", "", "code=x"} {
		res, _ = u.browser(t).get("/login/callback/" + p.ID + "?" + q)
		if res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), "/?error=") {
			t.Fatalf("callback %q: %d %q", q, res.StatusCode, res.Header.Get("Location"))
		}
	}
	// A callback for a provider id that does not exist, and a denial with a state that was never issued.
	b0 := u.browser(t)
	res, _ = b0.get("/login/callback/nope?state=x&code=y")
	if res.StatusCode != 302 || b0.hasSession() {
		t.Fatalf("callback for unknown provider: %d", res.StatusCode)
	}
	res, _ = u.browser(t).get("/login/callback/" + p.ID + "?error=access_denied&state=unknown")
	if res.Header.Get("Location") != "/?error=failed" {
		t.Fatalf("denied with an unknown state: %q", res.Header.Get("Location"))
	}
	// The user denied access at the provider.
	b = u.browser(t)
	res, _ = b.get("/login/acme/provider/" + p.ID + "?next=/n")
	st, _ := url.Parse(res.Header.Get("Location"))
	res, _ = b.get("/login/callback/" + p.ID + "?error=access_denied&state=" + url.QueryEscape(st.Query().Get("state")))
	if res.StatusCode != 302 || res.Header.Get("Location") != "/login/acme?error=denied&next=%2Fn" {
		t.Fatalf("denied: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestUpstreamProviderScoping(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	u.org2(t)
	b := u.browser(t)
	// A provider id from another organization's page does nothing.
	res, _ := b.get("/login/other/provider/" + p.ID)
	if res.StatusCode != 302 || res.Header.Get("Location") != "/login/other?error=disabled" {
		t.Fatalf("cross-org provider: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = b.get("/login/acme/provider/nope")
	if res.Header.Get("Location") != "/login/acme?error=disabled" {
		t.Fatalf("unknown provider: %q", res.Header.Get("Location"))
	}
	res, _ = b.get("/login/nope/provider/" + p.ID)
	if res.StatusCode != 404 {
		t.Fatalf("unknown org: %d", res.StatusCode)
	}
	// disabled providers are neither listed nor startable
	off := false
	if _, err := u.Svc.UpdateProvider(context.Background(), service.System, p.ID, service.ProviderInput{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	_, body := b.get("/login/acme")
	if strings.Contains(body, "Continue with Corp SSO") {
		t.Fatal("disabled provider listed")
	}
	res, _ = b.get("/login/acme/provider/" + p.ID)
	if res.Header.Get("Location") != "/login/acme?error=disabled" {
		t.Fatalf("disabled provider start: %q", res.Header.Get("Location"))
	}
}

func TestUpstreamInactiveLinkedUser(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	b.via(t, u, p, "acme", "", claims("i1", "i1@corp.example"))
	user, _ := u.Svc.FindUserByEmail(context.Background(), u.org.ID, "i1@corp.example")
	off := false
	if _, err := u.Svc.UpdateUser(context.Background(), service.System, user.ID, service.UserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	b2 := u.browser(t)
	res := b2.via(t, u, p, "acme", "", claims("i1", "i1@corp.example"))
	if res.Header.Get("Location") != "/login/acme?error=disabled" || b2.hasSession() {
		t.Fatalf("inactive user: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestUpstreamGitHub(t *testing.T) {
	u := newUpEnv(t, nil)
	p, err := u.Svc.CreateProvider(context.Background(), service.System, u.org.ID, service.ProviderInput{Type: ptr(model.ProviderGitHub),
		Name: ptr("GitHub"), ClientID: ptr("gh-cid"), ClientSecret: ptr("gh-secret"), AutoProvision: ptr(true),
		AllowedDomains: &[]string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	b := u.browser(t)
	res := b.via(t, u, p, "acme", "/gh", nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/gh" || !b.hasSession() {
		t.Fatalf("github sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	user, err := u.Svc.FindUserByEmail(context.Background(), u.org.ID, "octo@example.com")
	if err != nil || user.FullName() != "The Octocat" {
		t.Fatalf("github user %+v %v", user, err)
	}
	// Unverified primary email: no account.
	u.gh.ID = 99
	u.gh.Emails = []map[string]any{{"email": "x@example.com", "primary": true, "verified": false}}
	b2 := u.browser(t)
	res = b2.via(t, u, p, "acme", "", nil)
	if res.Header.Get("Location") != "/login/acme?error=unverified" || b2.hasSession() {
		t.Fatalf("unverified github email: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// Domain outside the allow list.
	u.gh.Emails = []map[string]any{{"email": "x@other.org", "primary": true, "verified": true}}
	b3 := u.browser(t)
	res = b3.via(t, u, p, "acme", "", nil)
	if res.Header.Get("Location") != "/login/acme?error=domain" {
		t.Fatalf("github domain: %q", res.Header.Get("Location"))
	}
}

// The provider client is guarded like back-channel logout and client JWKS: an issuer on a loopback or private
// address is refused unless allow_private_networks is set.
func TestProviderRequestsAreGuarded(t *testing.T) {
	for _, allow := range []bool{false, true} {
		e := newEnv(t, func(c *config.Config) { c.Server.AllowPrivateNetworks = allow })
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
		res, err := e.Mod.Upstream.HTTP.Get(srv.URL + "/.well-known/openid-configuration")
		srv.Close()
		if allow {
			if err != nil || res.StatusCode != 404 {
				t.Errorf("allowed: %v", err)
			}
		} else if !errors.Is(err, secure.ErrDestination) {
			t.Errorf("loopback provider reached without allow_private_networks: %v", err)
		}
	}
}

// A provider sign-in is a first factor: a user with an Authenticator App enters its code before the session starts
// (the provider's own MFA claims are not trusted), and the session still records the provider. The step's ticket
// travels in a cookie, never the URL.
func TestUpstreamSignInNeedsSecondFactor(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	if res := b.via(t, u, p, "acme", "/x", claims("sub-9", "kim@corp.example")); !b.hasSession() || res.StatusCode != 303 {
		t.Fatalf("first sign-in: %d", res.StatusCode)
	}
	kim, _ := u.Svc.FindUserByEmail(context.Background(), u.org.ID, "kim@corp.example")
	secret := u.giveTOTP(t, kim)

	b2 := u.browser(t)
	c := claims("sub-9", "kim@corp.example")
	c["amr"] = []string{"mfa", "otp"} // what the provider says counts for nothing here
	res := b2.via(t, u, p, "acme", "/x", c)
	loc := res.Header.Get("Location")
	if res.StatusCode != 303 || !strings.HasPrefix(loc, "/login/acme?") || !strings.Contains(loc, "step=1") || strings.Contains(loc, "ticket") || b2.hasSession() {
		t.Fatalf("callback: %d %q session=%v", res.StatusCode, loc, b2.hasSession())
	}
	_, body := b2.get(loc)
	ticket := attr(body, "data-ticket")
	if !strings.Contains(body, `data-step="totp"`) || ticket == "" {
		t.Fatalf("sign-in page does not continue with the code step: %.600s", body)
	}
	// another browser (no step cookie) is not shown the step
	if _, other := u.browser(t).get(loc); strings.Contains(other, "data-ticket") {
		t.Fatal("step shown without its cookie")
	}
	res2, out := b2.post("/api-internal/login/totp", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	wantStatus(t, res2, out, 200)
	if str(out, "next") != "/x" || !b2.hasSession() {
		t.Fatalf("after the code: %v", out)
	}
	var fed *model.Session
	for _, s := range sessionsOf(t, u.env, kim) {
		if slices.Contains(s.AMR, "fed") && slices.Contains(s.AMR, "otp") {
			fed = s
		}
	}
	if fed == nil || fed.Provider != p.ID || !slices.Contains(fed.AMR, "mfa") {
		t.Fatalf("session after provider + code: %+v", fed)
	}
}

// Leaver detection: the provider's refresh token, kept from the sign-in, is replayed; a rotated one replaces it, a
// transient failure changes nothing, and invalid_grant ends the user's sessions and refresh grants.
func TestUpstreamLeaverDetection(t *testing.T) {
	u := newUpEnv(t, nil)
	ctx := context.Background()
	u.oidc.IssueRefresh, u.oidc.RotateRefresh = true, true
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	if res := b.via(t, u, p, "acme", "/x", claims("leaver-sub", "lee@corp.example")); res.StatusCode != 303 || !b.hasSession() {
		t.Fatalf("sign-in: %d", res.StatusCode)
	}
	lee, err := u.Svc.FindUserByEmail(ctx, u.org.ID, "lee@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := u.Svc.Identities.GetByUnique(ctx, model.IdentityKey(p.ID, "leaver-sub"))
	if err != nil || ident.Refresh == "" || strings.Contains(ident.Refresh, "rt-") {
		t.Fatalf("refresh token not kept (sealed): %+v %v", ident, err)
	}
	sid := b.sessionID()
	g := &model.Grant{ClientID: "rp", UserID: lee.ID, OrgID: lee.OrgID, SessionID: sid, Scopes: []string{"openid"},
		Expires: time.Now().Add(time.Hour)}
	if err := u.Svc.Grants.Create(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Nothing is due within the interval.
	if r, err := u.Mod.Upstream.CheckSessions(ctx, time.Hour); err != nil || r.Checked != 0 {
		t.Fatalf("check within the interval: %+v %v", r, err)
	}
	// Accepted, and rotated: the new token replaces the old one.
	before := u.oidc.LiveRefresh()
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("first check: %+v %v", r, err)
	}
	after := u.oidc.LiveRefresh()
	if len(before) != 1 || len(after) != 1 || before[0] == after[0] {
		t.Fatalf("rotation: %v -> %v", before, after)
	}
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("check with the rotated token: %+v %v", r, err)
	}
	// A transient failure ends nothing.
	u.oidc.Mu.Lock()
	u.oidc.RefreshFail = 503
	u.oidc.Mu.Unlock()
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0); err != nil || r.Failed != 1 || r.Ended != 0 {
		t.Fatalf("transient failure: %+v %v", r, err)
	}
	if _, err := u.Svc.Sessions.Get(ctx, sid); err != nil {
		t.Fatal("a transient failure ended the session")
	}
	u.oidc.Mu.Lock()
	u.oidc.RefreshFail = 0
	u.oidc.Mu.Unlock()

	// The account is gone at the provider: its sessions and grants end here.
	u.oidc.RevokeRefresh()
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0); err != nil || r.Ended != 1 {
		t.Fatalf("leaver: %+v %v", r, err)
	}
	if _, err := u.Svc.Sessions.Get(ctx, sid); err == nil {
		t.Fatal("the leaver's session survived")
	}
	if _, err := u.Svc.Grants.Get(ctx, g.ID); err == nil {
		t.Fatal("the leaver's refresh grant survived")
	}
	if res, _ := b.get("/account"); res.StatusCode == 200 {
		t.Fatal("the browser is still signed in")
	}
	if id, _ := u.Svc.Identities.Get(ctx, ident.ID); id == nil || id.Refresh != "" {
		t.Fatalf("the refused token was kept: %+v", id)
	}
	if len(u.audits(t, "identity.refresh.refused")) != 1 {
		t.Fatal("not audited")
	}
	// With no session through the provider, nothing is replayed.
	refreshCalls := func() int { u.oidc.Mu.Lock(); defer u.oidc.Mu.Unlock(); return u.oidc.RefreshCalls }
	calls := refreshCalls()
	if r, _ := u.Mod.Upstream.CheckSessions(ctx, 0); r.Checked != 0 || refreshCalls() != calls {
		t.Fatalf("replayed without a session: %+v", r)
	}
}

// An ID token that does not match the request it answers (another nonce or audience), has expired, comes from another
// issuer or says nothing about its nonce or subject signs nobody in and links nothing.
func TestUpstreamRejectsInvalidIDTokens(t *testing.T) {
	u := newUpEnv(t, auditLogins)
	p := u.oidcProvider(t, nil)
	cases := []struct {
		name  string
		extra map[string]any
	}{
		{"nonce mismatch", map[string]any{"nonce": "somebody-elses-nonce"}},
		{"no nonce", map[string]any{"nonce": nil}},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}},
		{"wrong issuer", map[string]any{"iss": "https://evil.example"}},
		{"another audience", map[string]any{"aud": "other"}},
		{"no subject", map[string]any{"sub": nil}},
		{"not yet issued", map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := claims("sub-"+tc.name, "x@corp.example")
			for k, v := range tc.extra {
				c[k] = v
			}
			b := u.browser(t)
			res := b.via(t, u, p, "acme", "", c)
			loc := res.Header.Get("Location")
			if res.StatusCode != http.StatusFound || loc != "/login/acme?error=failed" || b.hasSession() {
				t.Fatalf("%d %q session=%v", res.StatusCode, loc, b.hasSession())
			}
			if _, body := b.get(loc); !strings.Contains(body, "did not work") {
				t.Fatalf("page does not show the message: %.500s", body)
			}
		})
	}
	if ids, _ := u.Svc.Identities.All(context.Background(), ""); len(ids) != 0 {
		t.Fatalf("identities created from rejected tokens: %d", len(ids))
	}
	if n := len(u.audits(t, "login.failure")); n != len(cases) {
		t.Fatalf("failures audited: %d", n)
	}
}

// The step a provider sign-in leaves behind is only shown for its own organization, and a ticket from a password
// sign-in (which is no provider's) is never shown through the step cookie.
func TestProviderStepCookieIsScoped(t *testing.T) {
	u := newUpEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	if res := b.via(t, u, p, "acme", "/x", claims("sub-1", "kim@corp.example")); !b.hasSession() || res.StatusCode != 303 {
		t.Fatalf("first sign-in: %d", res.StatusCode)
	}
	kim, _ := u.Svc.FindUserByEmail(t.Context(), u.org.ID, "kim@corp.example")
	u.giveTOTP(t, kim)
	b2 := u.browser(t)
	res := b2.via(t, u, p, "acme", "/x", claims("sub-1", "kim@corp.example"))
	loc := res.Header.Get("Location")
	if _, body := b2.get(loc); !strings.Contains(body, `data-step="totp"`) {
		t.Fatalf("the step is not shown to its own browser: %.400s", body)
	}
	// the same cookie at another organization's page shows nothing
	other := u.org2(t)
	if _, body := b2.get("/login/" + other.Name + "?step=1"); strings.Contains(body, "data-ticket") {
		t.Fatal("step shown for another organization")
	}
	// without ?step=1 nothing is shown either
	if _, body := b2.get("/login/acme"); strings.Contains(body, `data-step="totp"`) {
		t.Fatal("step shown without step=1")
	}

	// a password sign-in's ticket planted in the step cookie is not a provider step
	pat := u.user(t, u.org, "pat", model.RoleUser)
	u.giveTOTP(t, pat)
	b3 := u.browser(t)
	_, out := b3.login("acme", "pat", userPassword)
	tk := str(out, "ticket")
	if tk == "" {
		t.Fatalf("no ticket: %v", out)
	}
	hu, _ := url.Parse(u.URL)
	b3.c.Jar.SetCookies(hu, []*http.Cookie{{Name: "__Host-quisora_step", Value: tk, Path: "/", Secure: true}})
	if _, body := b3.get("/login/acme?step=1"); strings.Contains(body, "data-ticket") {
		t.Fatal("a password ticket was shown through the step cookie")
	}
	// oversized and unknown values are ignored
	for _, v := range []string{strings.Repeat("a", 300), "n1.unknown"} {
		b3.c.Jar.SetCookies(hu, []*http.Cookie{{Name: "__Host-quisora_step", Value: v, Path: "/", Secure: true}})
		if res, body := b3.get("/login/acme?step=1"); res.StatusCode != 200 || strings.Contains(body, "data-ticket") {
			t.Fatalf("cookie %.10q: %d", v, res.StatusCode)
		}
	}
}
