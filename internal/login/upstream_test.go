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
	ut "github.com/paularlott/quisora/internal/upstream/upstreamtest"
)

type upEnv struct {
	*env
	org  *model.Org
	oidc *ut.FakeOIDC
	gh   *ut.FakeGitHub
}

func newUpEnv(t *testing.T, mut func(*config.Config)) *upEnv {
	e := newEnv(t, mut)
	u := &upEnv{env: e, org: e.org(t, "acme", nil), oidc: ut.NewFakeOIDC(t), gh: ut.NewFakeGitHub(t)}
	e.Mod.Upstream.HTTP = ut.HTTPClient()
	e.Mod.Upstream.GitHubAuthURL, e.Mod.Upstream.GitHubTokenURL, e.Mod.Upstream.GitHubAPIURL =
		u.gh.Srv.URL+"/authorize", u.gh.Srv.URL+"/token", u.gh.Srv.URL
	return u
}

func ptr[T any](v T) *T { return &v }

func (u *upEnv) oidcProvider(t *testing.T, mut func(*service.ProviderInput)) *model.Provider {
	in := service.ProviderInput{Type: ptr(model.ProviderOIDC), Name: ptr("Corp SSO"), Issuer: ptr(u.oidc.Srv.URL), ClientID: ptr("cid"),
		ClientSecret: ptr("s3cret"), AutoProvision: ptr(true)}
	if mut != nil {
		mut(&in)
	}
	p, err := u.Svc.CreateProvider(context.Background(), service.System, u.org.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func claims(sub, email string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "name": "Pat Doe"}
}

// via runs the provider round trip and returns the callback response.
func (b *browser) via(t *testing.T, u *upEnv, p *model.Provider, org, next string, c map[string]any) *http.Response {
	t.Helper()
	path := "/login/" + org + "/provider/" + p.ID
	if next != "" {
		path += "?next=" + url.QueryEscape(next)
	}
	res, _ := b.get(path)
	if res.StatusCode != 302 {
		t.Fatalf("provider start: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	loc := res.Header.Get("Location")
	state := ""
	if lu, err := url.Parse(loc); err == nil {
		state = lu.Query().Get("state")
	}
	var code string
	if p.Type == model.ProviderGitHub {
		code = u.gh.Authorize(loc)
	} else {
		code = u.oidc.Authorize(loc, c)
	}
	res2, _ := b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code))
	return res2
}

// viaTenant is via for a sign-in made on behalf of a tenant.
func (b *browser) viaTenant(t *testing.T, u *upEnv, p *model.Provider, org, tenant, next string, c map[string]any) *http.Response {
	t.Helper()
	res, _ := b.get("/login/" + org + "/provider/" + p.ID + "?tenant=" + tenant + "&next=" + url.QueryEscape(next))
	if res.StatusCode != 302 {
		t.Fatalf("provider start: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	loc := res.Header.Get("Location")
	lu, _ := url.Parse(loc)
	code := u.oidc.Authorize(loc, c)
	res2, _ := b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + url.QueryEscape(code))
	return res2
}

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
	if _, err := u.Svc.CreateUser(context.Background(), service.System, u.org.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: &existing}); err != nil {
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
		{"bad token", domains, map[string]any{"sub": "x5", "email": "a@corp.example", "email_verified": true, "aud": "other"}, "failed", "did not work"},
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
	if n := len(u.audits(t, "login.failure")); n != 5 {
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

func (u *upEnv) org2(t *testing.T) *model.Org { return u.env.org(t, "other", nil) }

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
	res2, out := b2.post("/api/login/totp", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
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

func attr(body, name string) string {
	i := strings.Index(body, name+`="`)
	if i < 0 {
		return ""
	}
	rest := body[i+len(name)+2:]
	return rest[:strings.IndexByte(rest, '"')]
}

// An administrator (never linked by email) connects a provider from the account page, after re-authenticating; the
// identity then signs them in (with their second factor). An identity already linked to someone else is refused, and
// the last way to sign in cannot be disconnected.
func TestConnectProviderToAccount(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	admin := u.user(t, u.org, "ada", model.RoleAdmin)
	b := u.signedIn(t, admin)

	// by email: refused for an administrator
	if br := u.browser(t); !strings.Contains(br.via(t, u, p, "acme", "", claims("ada-sub", admin.Email)).Header.Get("Location"), "error=") || br.hasSession() {
		t.Fatal("an admin was signed in through an unconnected provider")
	}
	// connecting needs a recent re-authentication
	res, out := b.post("/api/account/providers/"+p.ID+"/connect", nil)
	wantStatus(t, res, out, 403)
	b.markReauth()
	res, out = b.post("/api/account/providers/"+p.ID+"/connect", nil)
	wantStatus(t, res, out, 200)
	code := u.oidc.Authorize(str(out, "url"), claims("ada-sub", "ada@elsewhere.example"))
	lu, _ := url.Parse(str(out, "url"))
	res, _ = b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + url.QueryEscape(code))
	if res.StatusCode != 303 || res.Header.Get("Location") != "/account?provider=connected#providers" {
		t.Fatalf("connect callback: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, out = b.api("GET", "/api/account/providers", nil)
	if it := items(t, out); len(it) != 1 || it[0]["connected"] != true {
		t.Fatalf("providers: %v", out["_raw"])
	}
	if len(u.audits(t, "account.provider.connect")) != 1 {
		t.Error("connect not audited")
	}
	// the identity now signs Ada in, and as an administrator she continues with a second factor (she has none yet,
	// so the sign-in page asks her to set one up) even though the organization does not require one
	if res := u.browser(t).via(t, u, p, "acme", "/x", claims("ada-sub", "whatever@x.example")); !strings.Contains(res.Header.Get("Location"), "step=1") {
		t.Fatalf("sign-in with the connected identity: %q", res.Header.Get("Location"))
	}

	// someone else cannot take that identity
	bob := u.user(t, u.org, "bob", model.RoleUser)
	bb := u.signedIn(t, bob)
	bb.markReauth()
	_, out = bb.post("/api/account/providers/"+p.ID+"/connect", nil)
	code = u.oidc.Authorize(str(out, "url"), claims("ada-sub", "bob@corp.example"))
	lu, _ = url.Parse(str(out, "url"))
	res, _ = bb.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + url.QueryEscape(code))
	if res.Header.Get("Location") != "/account?provider=taken#providers" {
		t.Fatalf("taken identity: %q", res.Header.Get("Location"))
	}

	// disconnect: needs reauth; refused when it is the last way in
	b.markReauth() // (Ada has a password: the test helper sets one)
	res, out = b.api("DELETE", "/api/account/providers/"+p.ID, nil)
	wantStatus(t, res, out, 204)
	solo := u.user(t, u.org, "solo", model.RoleUser)
	fresh, _ := u.Svc.Users.Get(context.Background(), solo.ID)
	fresh.PasswordHash = ""
	_ = u.Svc.Users.Update(context.Background(), fresh)
	_ = u.Svc.Identities.Create(context.Background(), model.NewIdentity(solo, p, "solo-sub", "", "admin"))
	sb := u.signedIn(t, solo)
	sb.markReauth()
	res, out = sb.api("DELETE", "/api/account/providers/"+p.ID, nil)
	wantStatus(t, res, out, 409)
}

// A tenant that requires a second factor asks for one after a provider sign-in, unless the provider is marked as
// counting as one (TrustMFA): then the user's own code is not asked for either, and the session carries "mfa".
func TestUpstreamTrustedProviderCountsAsSecondFactor(t *testing.T) {
	u := newUpEnv(t, nil)
	ctx := context.Background()
	if d, err := u.Svc.DefaultTenant(ctx, u.org.ID); err != nil || !d.Settings.RequireMFA {
		t.Fatalf("a new organization's default tenant should require a second factor: %+v %v", d, err)
	}

	// Not trusted: the tenant's requirement holds after the provider.
	plain := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Plain SSO") })
	b := u.browser(t)
	res := b.viaTenant(t, u, plain, "acme", "default", "/x", claims("sub-p", "lee@corp.example"))
	if loc := res.Header.Get("Location"); res.StatusCode != 303 || !strings.Contains(loc, "step=1") || b.hasSession() {
		t.Fatalf("untrusted provider: %d %q session=%v", res.StatusCode, loc, b.hasSession())
	}

	// Trusted: straight in, even for a user with a code of their own, and the session satisfies the requirement.
	trusted := u.oidcProvider(t, func(in *service.ProviderInput) { in.TrustMFA = ptr(true) })
	if res := u.browser(t).via(t, u, trusted, "acme", "/x", claims("sub-t", "kim@corp.example")); res.StatusCode != 303 {
		t.Fatalf("first sign-in: %d", res.StatusCode)
	}
	kim, _ := u.Svc.FindUserByEmail(ctx, u.org.ID, "kim@corp.example")
	u.giveTOTP(t, kim)
	b2 := u.browser(t)
	res = b2.viaTenant(t, u, trusted, "acme", "default", "/x", claims("sub-t", "kim@corp.example"))
	if res.StatusCode != 303 || res.Header.Get("Location") != "/x" || !b2.hasSession() {
		t.Fatalf("trusted provider: %d %q session=%v", res.StatusCode, res.Header.Get("Location"), b2.hasSession())
	}
	ok := false
	for _, s := range sessionsOf(t, u.env, kim) {
		ok = ok || (slices.Contains(s.AMR, "fed") && model.MFA(s.AMR) && s.Provider == trusted.ID)
	}
	if !ok {
		t.Fatalf("sessions: %+v", sessionsOf(t, u.env, kim))
	}
}

// A sign-in through a provider trusted as a second factor (TrustMFA) skips the user's own code, so it does not count
// as the recent re-authentication that connecting another provider needs: that would let it add further ways in that
// skip the code too. A re-authentication (which asks for the code) does; and an account with no second factor of its
// own connects straight after any sign-in, as before.
func TestConnectNeedsOwnSecondFactor(t *testing.T) {
	u := newUpEnv(t, nil)
	ctx := context.Background()
	trusted := u.oidcProvider(t, func(in *service.ProviderInput) { in.TrustMFA = ptr(true) })
	other := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Other SSO"); in.AutoProvision = ptr(false) })
	if res := u.browser(t).via(t, u, trusted, "acme", "/x", claims("sub-k", "kim@corp.example")); res.StatusCode != 303 {
		t.Fatalf("first sign-in: %d", res.StatusCode)
	}
	kim, _ := u.Svc.FindUserByEmail(ctx, u.org.ID, "kim@corp.example")

	// no second factor of her own yet: a fresh provider sign-in is enough
	b := u.browser(t)
	if res := b.via(t, u, trusted, "acme", "/x", claims("sub-k", "kim@corp.example")); !b.hasSession() {
		t.Fatalf("sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	sessionCSRF(t, b)
	res, out := b.post("/api/account/providers/"+other.ID+"/connect", nil)
	wantStatus(t, res, out, 200)

	// with an authenticator, the trusted provider's sign-in no longer is
	u.giveTOTP(t, kim)
	b = u.browser(t)
	if res := b.via(t, u, trusted, "acme", "/x", claims("sub-k", "kim@corp.example")); !b.hasSession() {
		t.Fatalf("sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	sessionCSRF(t, b)
	res, out = b.post("/api/account/providers/"+other.ID+"/connect", nil)
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Fatalf("refusal: %v", out["_raw"])
	}
	b.markReauth()
	res, out = b.post("/api/account/providers/"+other.ID+"/connect", nil)
	wantStatus(t, res, out, 200)
}

// sessionCSRF loads the account page into b's CSRF token (refresh is for signed-out pages).
func sessionCSRF(t *testing.T, b *browser) {
	t.Helper()
	_, body := b.get("/account")
	m := metaRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf meta on the account page: %.300s", body)
	}
	b.csrf = m[1]
}
