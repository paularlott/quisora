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
	"github.com/paularlott/quisora/internal/upstream"
	"github.com/paularlott/quisora/internal/web"
)

func TestUpstreamOIDCSignIn(t *testing.T) {
	u := newUpEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	p := u.oidcProvider(t, nil)
	b := u.browser(t)

	// The provider shows as a button on the organization page.
	_, body := b.get("/o/acme/login?next=" + url.QueryEscape(u.at("/x")))
	if !strings.Contains(body, "Continue with Corp SSO") || !strings.Contains(body, u.at("/login/provider/"+p.ID+"?next=")+url.QueryEscape(u.at("/x"))) {
		t.Fatalf("provider button missing: %.800s", body)
	}

	res := b.via(t, u, p, "acme", "/x", claims("sub-1", "pat@corp.example"))
	if res.StatusCode != 303 || res.Header.Get("Location") != u.at("/x") || !b.hasSession() {
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
	if res.StatusCode != 303 || res.Header.Get("Location") != u.at("/account") {
		t.Fatalf("second sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if n, _ := u.Svc.Users.Count(context.Background(), u.org.ID); n != 1 {
		t.Fatalf("users %d", n)
	}
	// The state cookie is cleared after the callback.
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, "__Host-quisora_up") && c.MaxAge >= 0 {
			t.Fatalf("state cookie kept: %+v", c)
		}
	}
}

// A guest a provider created at its first sign-in, once promoted to a manager, no longer signs in through that
// provider: the provider's side controls that link, and the account has no second factor yet, so whoever held the
// provider's account could otherwise enrol their own second factor and act as the manager.
func TestPromotedGuestCannotSignInThroughItsProvider(t *testing.T) {
	ctx := context.Background()
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	if res := u.browser(t).via(t, u, p, "acme", "", claims("sub-1", "pat@corp.example")); !strings.Contains(res.Header.Get("Location"), "/account") {
		t.Fatalf("first sign-in: %q", res.Header.Get("Location"))
	}
	guest, err := u.Svc.FindUserByEmail(ctx, u.org.ID, "pat@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Svc.UpdateUser(ctx, service.System, guest.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
		t.Fatal(err)
	}
	b := u.browser(t)
	res := b.via(t, u, p, "acme", "/x", claims("sub-1", "pat@corp.example"))
	if b.hasSession() || strings.Contains(res.Header.Get("Location"), "/account") {
		t.Fatalf("the promoted guest signed in through the provider: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if ids, err := u.Svc.Identities.All(ctx, guest.ID); err != nil || len(ids) != 0 {
		t.Fatalf("links after the promotion: %v %v", ids, err)
	}
}

// A sign-in through a provider that was between its steps when the account was promoted cannot be finished: the
// promotion took the provider link it signed in with, so the ticket (here at the enrolment of a second factor, which
// the account has none of) is dead, and whoever holds the provider's account cannot enrol their own authenticator app
// and become the manager.
func TestPromotionEndsProviderSignInInProgress(t *testing.T) {
	ctx := context.Background()
	u := newUpEnv(t, nil)
	u.setSettings(t, u.org, func(s *model.OrgSettings) { s.RequireMFA = true })
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	res := b.via(t, u, p, "acme", "/x", claims("sub-1", "pat@corp.example"))
	loc := res.Header.Get("Location")
	if res.StatusCode != 303 || !strings.Contains(loc, "step=1") || b.hasSession() {
		t.Fatalf("callback: %d %q session=%v", res.StatusCode, loc, b.hasSession())
	}
	_, body := b.get(loc)
	ticket := attr(body, "data-ticket")
	if !strings.Contains(body, `data-step="enrol"`) || ticket == "" {
		t.Fatalf("sign-in page does not continue with enrolment: %.600s", body)
	}
	res2, out := b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res2, out, 200)
	secret := str(out, "secret")

	pat, err := u.Svc.FindUserByEmail(ctx, u.org.ID, "pat@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
		t.Fatal(err)
	}
	res2, out = b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	wantStatus(t, res2, out, 401)
	res2, out = b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res2, out, 401)
	if b.hasSession() {
		t.Fatal("the sign-in begun through the provider made a session after the promotion")
	}
	if fresh, err := u.Svc.Users.Get(ctx, pat.ID); err != nil || fresh.HasTOTP() {
		t.Fatalf("authenticator app enrolled after the promotion: %v", err)
	}
	if n := len(sessionsOf(t, u.env, pat)); n != 0 {
		t.Fatalf("sessions %d", n)
	}
}

// The credentials a sign-in through a provider set up, while the account had no second factor of its own, go with the
// provider's link when the account is promoted: whoever held the provider's account could have set up both the
// authenticator app (at the sign-in's enrolment step) and the password (on the account page), and must not sign in to
// the manager's account with them afterwards.
func TestPromotionTakesCredentialsAProviderSetUp(t *testing.T) {
	ctx := context.Background()
	u := newUpEnv(t, nil)
	u.setSettings(t, u.org, func(s *model.OrgSettings) { s.RequireMFA = true })
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	res := b.via(t, u, p, "acme", "/x", claims("sub-1", "pat@corp.example"))
	_, body := b.get(res.Header.Get("Location"))
	ticket := attr(body, "data-ticket")
	res2, out := b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res2, out, 200)
	secret := str(out, "secret")
	res2, out = b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	wantStatus(t, res2, out, 200)
	sessionCSRF(t, b)
	const password = "the provider's holder chose this one"
	res2, out = b.api("POST", "/api-internal/account/password", map[string]any{"new": password})
	wantStatus(t, res2, out, 200)
	pat, err := u.Svc.FindUserByEmail(ctx, u.org.ID, "pat@corp.example")
	if err != nil || pat.SetUpBy != p.ID || pat.PasswordHash == "" || !pat.HasTOTP() {
		t.Fatalf("set up by %q, password %v, app %v: %v", pat.SetUpBy, pat.PasswordHash != "", pat.HasTOTP(), err)
	}

	if _, err := u.Svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
		t.Fatal(err)
	}
	b2 := u.browser(t)
	res2, out = b2.login("acme", "pat@corp.example", password)
	if res2.StatusCode == 200 {
		res2, out = b2.post("/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": totpAt(secret, time.Now().Add(30*time.Second))})
		t.Fatalf("the password and app set up through the provider still sign in: %d %v session=%v", res2.StatusCode, out["_raw"], b2.hasSession())
	}
	fresh, err := u.Svc.Users.Get(ctx, pat.ID)
	if err != nil || fresh.PasswordHash != "" || fresh.HasTOTP() || fresh.SetUpBy != "" || fresh.CredEpoch == pat.CredEpoch {
		t.Fatalf("after the promotion: password %v, app %v, set up by %q, same epoch %v: %v", fresh.PasswordHash != "",
			fresh.HasTOTP(), fresh.SetUpBy, fresh.CredEpoch == pat.CredEpoch, err)
	}
	if n := len(u.audits(t, "user.signin.reset")); n != 1 {
		t.Fatalf("user.signin.reset audits %d", n)
	}
}

// Credentials of the account's own, set up while it had a second factor, are not the provider's: a promotion leaves
// them.
func TestPromotionKeepsCredentialsOfTheAccountsOwn(t *testing.T) {
	ctx := context.Background()
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	if res := u.browser(t).via(t, u, p, "acme", "", claims("sub-1", "pat@corp.example")); !strings.Contains(res.Header.Get("Location"), "/account") {
		t.Fatalf("first sign-in: %q", res.Header.Get("Location"))
	}
	pat, err := u.Svc.FindUserByEmail(ctx, u.org.ID, "pat@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	secret := u.giveTOTP(t, pat) // set up outside any provider's sign-in
	b := u.browser(t)
	res := b.via(t, u, p, "acme", "/x", claims("sub-1", "pat@corp.example"))
	_, body := b.get(res.Header.Get("Location"))
	res2, out := b.post("/api-internal/login/totp", map[string]any{"ticket": attr(body, "data-ticket"), "code": totpAt(secret, time.Now())})
	wantStatus(t, res2, out, 200)
	sessionCSRF(t, b)
	b.markReauth()
	res2, out = b.api("POST", "/api-internal/account/password", map[string]any{"new": "a password of pat's own"})
	wantStatus(t, res2, out, 200)
	if _, err := u.Svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
		t.Fatal(err)
	}
	if fresh, err := u.Svc.Users.Get(ctx, pat.ID); err != nil || !fresh.HasTOTP() || fresh.PasswordHash == "" || fresh.SetUpBy != "" {
		t.Fatalf("the account's own credentials were taken: %v", err)
	}
}

// A personal API token made, or another sign-in provider connected, from a sign-in through a provider while the
// account has no second factor of its own is that provider's too: it is recorded on the account in the write that
// makes it, and a promotion that takes the provider's link ends it (the reset's new credential epoch). With a second
// factor of the account's own nothing is recorded, and the promotion leaves them.
func TestPromotionTakesTokensAndProvidersAProviderSetUp(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ownFactor bool
		token     bool // make an API token; otherwise connect another provider
	}{
		{"token, no second factor", false, true},
		{"connected provider, no second factor", false, false},
		{"token, own second factor", true, true},
		{"connected provider, own second factor", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			u := newUpEnv(t, nil)
			u.setSettings(t, u.org, allowAPITokens)
			p := u.oidcProvider(t, nil)
			other := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name, in.AutoProvision = ptr("Other SSO"), ptr(false) })
			b := u.browser(t)
			res := b.via(t, u, p, "acme", "", claims("sub-1", "pat@corp.example"))
			if !strings.Contains(res.Header.Get("Location"), "/account") {
				t.Fatalf("first sign-in: %q", res.Header.Get("Location"))
			}
			pat, err := u.Svc.FindUserByEmail(ctx, u.org.ID, "pat@corp.example")
			if err != nil {
				t.Fatal(err)
			}
			if tc.ownFactor {
				secret := u.giveTOTP(t, pat) // set up outside any provider's sign-in
				b = u.browser(t)
				res = b.via(t, u, p, "acme", "/x", claims("sub-1", "pat@corp.example"))
				_, body := b.get(res.Header.Get("Location"))
				res2, out := b.post("/api-internal/login/totp", map[string]any{"ticket": attr(body, "data-ticket"), "code": totpAt(secret, time.Now())})
				wantStatus(t, res2, out, 200)
			}
			sessionCSRF(t, b)
			var plain string
			if tc.token {
				b.markReauth()
				res2, out := b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}})
				wantStatus(t, res2, out, 201)
				plain = str(out, "token")
			} else {
				authURL := u.connectURL(t, b, other)
				if loc := u.connectCallback(t, b, other, authURL, claims("other-sub", "pat@elsewhere.example")); loc != u.at("/account?provider=connected#providers") {
					t.Fatalf("connect callback: %q", loc)
				}
			}
			set, err := u.Svc.Users.Get(ctx, pat.ID)
			if err != nil {
				t.Fatal(err)
			}
			if want := map[bool]string{false: p.ID, true: ""}[tc.ownFactor]; set.SetUpBy != want {
				t.Errorf("set up by %q, want %q", set.SetUpBy, want)
			}

			if _, err := u.Svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
				t.Fatal(err)
			}
			fresh, err := u.Svc.Users.Get(ctx, pat.ID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.ownFactor != (fresh.CredEpoch == set.CredEpoch) {
				t.Errorf("after the promotion: same epoch %v", fresh.CredEpoch == set.CredEpoch)
			}
			if tc.token {
				if _, _, err := u.Svc.ValidateAPIToken(ctx, plain); tc.ownFactor != (err == nil) {
					t.Fatalf("the token after the promotion: %v", err)
				}
				return
			}
			// (the reset's tidying may have deleted the link already)
			id, err := u.Svc.Identities.GetByUnique(ctx, model.IdentityKey(other.ID, "other-sub"))
			if counts := err == nil && fresh.Counts(id); tc.ownFactor != counts {
				t.Errorf("the connected provider counts %v after the promotion: %v", counts, err)
			}
			if tc.ownFactor {
				return
			}
			b2 := u.browser(t)
			if loc := b2.via(t, u, other, "acme", "/x", claims("other-sub", "pat@elsewhere.example")).Header.Get("Location"); !strings.Contains(loc, "error=") || b2.hasSession() {
				t.Fatalf("the provider connected through the other one still signs in: %q session=%v", loc, b2.hasSession())
			}
		})
	}
}

// The sign-in page shows the step a provider sign-in left only while its ticket still binds to the account, as every
// step's POST checks: after a promotion (or any change of what signs the account in) the page is the sign-in form to
// start again from, with the message a POST would give, and not the enrolment the ticket was at.
func TestSignInPageDropsAStaleStep(t *testing.T) {
	ctx := context.Background()
	u := newUpEnv(t, nil)
	u.setSettings(t, u.org, func(s *model.OrgSettings) { s.RequireMFA = true })
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	loc := b.via(t, u, p, "acme", "/x", claims("sub-1", "pat@corp.example")).Header.Get("Location")
	if _, body := b.get(loc); !strings.Contains(body, `data-step="enrol"`) || attr(body, "data-ticket") == "" {
		t.Fatalf("sign-in page does not continue with enrolment: %.600s", body)
	}
	pat, err := u.Svc.FindUserByEmail(ctx, u.org.ID, "pat@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
		t.Fatal(err)
	}
	_, body := b.get(loc)
	if strings.Contains(body, `data-step="enrol"`) || attr(body, "data-ticket") != "" {
		t.Fatalf("the page still shows the step of a stale ticket: %.600s", body)
	}
	if !strings.Contains(body, "Your sign-in has expired. Start again.") {
		t.Fatalf("no message to start again: %.600s", body)
	}
}

func TestUpstreamHostileNext(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	res := b.via(t, u, p, "acme", "//evil.example/steal", claims("s1", "a@corp.example"))
	if res.StatusCode != 303 || res.Header.Get("Location") != u.at("/account") {
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
		want := u.at("/login?error=" + tc.code + "&next=" + url.QueryEscape(u.at("/back")))
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
	_, body := u.browser(t).get("/o/acme/login?error=%3Cscript%3Ealert(1)%3C/script%3E")
	if strings.Contains(body, "<script>alert") {
		t.Fatal("error parameter reflected")
	}
}

func TestUpstreamStateProtection(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)

	// A callback without the cookie of the browser that started it (login CSRF): refused, nothing signed in.
	b := u.browser(t)
	res, _ := b.get("/o/acme/login/provider/" + p.ID)
	loc := res.Header.Get("Location")
	lu, _ := url.Parse(loc)
	code := u.oidc.Authorize(loc, claims("c1", "c1@corp.example"))
	attacker := u.browserAt(t, u.org)
	res, _ = attacker.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + code)
	if res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), u.at("/login?error=failed")) || attacker.hasSession() {
		t.Fatalf("callback without cookie: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// ...and the state is burnt, so the real browser cannot finish it either.
	res, _ = b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + code)
	if b.hasSession() {
		t.Fatalf("burnt state accepted: %d", res.StatusCode)
	}
	// Unknown state, empty callback.
	for _, q := range []string{"state=n1.nope&code=x", "", "code=x"} {
		res, _ = u.browserAt(t, u.org).get("/login/callback/" + p.ID + "?" + q)
		if res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), u.at("/login?error=")) {
			t.Fatalf("callback %q: %d %q", q, res.StatusCode, res.Header.Get("Location"))
		}
	}
	// A callback for a provider id that does not exist, and a denial with a state that was never issued.
	b0 := u.browserAt(t, u.org)
	res, _ = b0.get("/login/callback/nope?state=x&code=y")
	if res.StatusCode != 302 || b0.hasSession() {
		t.Fatalf("callback for unknown provider: %d", res.StatusCode)
	}
	res, _ = u.browserAt(t, u.org).get("/login/callback/" + p.ID + "?error=access_denied&state=unknown")
	if res.Header.Get("Location") != u.at("/login?error=failed") {
		t.Fatalf("denied with an unknown state: %q", res.Header.Get("Location"))
	}
	// The user denied access at the provider.
	b = u.browser(t)
	res, _ = b.get("/o/acme/login/provider/" + p.ID + "?next=" + url.QueryEscape(u.at("/n")))
	st, _ := url.Parse(res.Header.Get("Location"))
	res, _ = b.get("/login/callback/" + p.ID + "?error=access_denied&state=" + url.QueryEscape(st.Query().Get("state")))
	if res.StatusCode != 302 || res.Header.Get("Location") != u.at("/login?error=denied&next="+url.QueryEscape(u.at("/n"))) {
		t.Fatalf("denied: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

// A provider's callback address is its organization's, and a response that arrives at another organization's is
// refused as an unknown state is: the state is burnt, nobody is signed in, and the browser goes to the sign-in page of
// the organization whose address it reached.
func TestUpstreamCallbackIsPerOrganization(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	other := u.org2(t)
	if got, want := u.Mod.Upstream.CallbackURL(u.org.ID, p.ID), u.Cfg.Server.PublicURL+"/o/"+u.org.ID+"/login/callback/"+p.ID; got != want {
		t.Fatalf("callback url %q, want %q", got, want)
	}
	if upstream.CallbackPath(u.org.ID, p.ID) == upstream.CallbackPath(other.ID, p.ID) {
		t.Fatal("two organizations share a callback path")
	}

	b := u.browser(t)
	res, _ := b.get("/o/acme/login/provider/" + p.ID)
	loc := res.Header.Get("Location")
	lu, _ := url.Parse(loc)
	if got, want := lu.Query().Get("redirect_uri"), u.Mod.Upstream.CallbackURL(u.org.ID, p.ID); got != want {
		t.Fatalf("redirect_uri %q, want %q", got, want)
	}
	code := u.oidc.Authorize(loc, claims("c1", "c1@corp.example"))
	state := url.QueryEscape(lu.Query().Get("state"))
	res, _ = b.get("/o/other/login/callback/" + p.ID + "?state=" + state + "&code=" + code)
	if res.StatusCode != 302 || res.Header.Get("Location") != web.OrgPath(other.ID, "/login?error=failed") || b.hasSession() {
		t.Fatalf("callback at another organization: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// the state is burnt: the right address cannot finish it now either
	res, _ = b.get("/o/acme/login/callback/" + p.ID + "?state=" + state + "&code=" + code)
	if b.hasSession() || res.Header.Get("Location") != u.at("/login?error=failed") {
		t.Fatalf("burnt state: %d %q session=%v", res.StatusCode, res.Header.Get("Location"), b.hasSession())
	}
	if n, _ := u.Svc.Users.Count(context.Background(), u.org.ID); n != 0 {
		t.Fatalf("a user was provisioned: %d", n)
	}
	// a denial that arrives at another organization's address does not consume the state either
	res, _ = b.get("/o/acme/login/provider/" + p.ID)
	lu, _ = url.Parse(res.Header.Get("Location"))
	st := url.QueryEscape(lu.Query().Get("state"))
	res, _ = b.get("/o/other/login/callback/" + p.ID + "?error=access_denied&state=" + st)
	if res.Header.Get("Location") != web.OrgPath(other.ID, "/login?error=failed") {
		t.Fatalf("denial at another organization: %q", res.Header.Get("Location"))
	}
}

func TestUpstreamProviderScoping(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	other := u.org2(t)
	b := u.browser(t)
	// A provider id from another organization's page does nothing.
	res, _ := b.get("/o/other/login/provider/" + p.ID)
	if res.StatusCode != 302 || res.Header.Get("Location") != web.OrgPath(other.ID, "/login?error=disabled") {
		t.Fatalf("cross-org provider: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = b.get("/o/acme/login/provider/nope")
	if res.Header.Get("Location") != u.at("/login?error=disabled") {
		t.Fatalf("unknown provider: %q", res.Header.Get("Location"))
	}
	res, _ = b.get("/o/nope/login/provider/" + p.ID)
	if res.StatusCode != 404 {
		t.Fatalf("unknown org: %d", res.StatusCode)
	}
	// disabled providers are neither listed nor startable
	off := false
	if _, err := u.Svc.UpdateProvider(context.Background(), service.System, p.ID, service.ProviderInput{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	_, body := b.get("/o/acme/login")
	if strings.Contains(body, "Continue with Corp SSO") {
		t.Fatal("disabled provider listed")
	}
	res, _ = b.get("/o/acme/login/provider/" + p.ID)
	if res.Header.Get("Location") != u.at("/login?error=disabled") {
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
	if res.Header.Get("Location") != u.at("/login?error=disabled") || b2.hasSession() {
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
	if res.StatusCode != 303 || res.Header.Get("Location") != u.at("/gh") || !b.hasSession() {
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
	if res.Header.Get("Location") != u.at("/login?error=unverified") || b2.hasSession() {
		t.Fatalf("unverified github email: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// Domain outside the allow list.
	u.gh.Emails = []map[string]any{{"email": "x@other.org", "primary": true, "verified": true}}
	b3 := u.browser(t)
	res = b3.via(t, u, p, "acme", "", nil)
	if res.Header.Get("Location") != u.at("/login?error=domain") {
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
// (the provider's own MFA claims are not trusted), and the session still records the provider, and keeps what the
// provider said (its amr) apart from what Quisora verified, for the tokens to pass on. The step's ticket travels in a
// cookie, never the URL.
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
	if res.StatusCode != 303 || !strings.HasPrefix(loc, u.at("/login?")) || !strings.Contains(loc, "step=1") || strings.Contains(loc, "ticket") || b2.hasSession() {
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
	if str(out, "next") != u.at("/x") || !b2.hasSession() {
		t.Fatalf("after the code: %v", out)
	}
	var fed *model.Session
	for _, s := range sessionsOf(t, u.env, kim) {
		if slices.Contains(s.AMR, "fed") && slices.Contains(s.AMR, "otp") {
			fed = s
		}
	}
	if fed == nil || fed.Provider != p.ID || !slices.Equal(fed.AMR, []string{"fed", "otp", "mfa"}) ||
		!slices.Equal(fed.UpstreamAMR, []string{"mfa", "otp"}) {
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
	if r, err := u.Mod.Upstream.CheckSessions(ctx, time.Hour, time.Minute); err != nil || r.Checked != 0 {
		t.Fatalf("check within the interval: %+v %v", r, err)
	}
	// Accepted, and rotated: the new token replaces the old one.
	before := u.oidc.LiveRefresh()
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0, time.Minute); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("first check: %+v %v", r, err)
	}
	after := u.oidc.LiveRefresh()
	if len(before) != 1 || len(after) != 1 || before[0] == after[0] {
		t.Fatalf("rotation: %v -> %v", before, after)
	}
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0, time.Minute); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("check with the rotated token: %+v %v", r, err)
	}
	// A transient failure ends nothing.
	u.oidc.Mu.Lock()
	u.oidc.RefreshFail = 503
	u.oidc.Mu.Unlock()
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0, time.Minute); err != nil || r.Failed != 1 || r.Ended != 0 {
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
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0, time.Minute); err != nil || r.Ended != 1 {
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
	if r, _ := u.Mod.Upstream.CheckSessions(ctx, 0, time.Minute); r.Checked != 0 || refreshCalls() != calls {
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
			if res.StatusCode != http.StatusFound || loc != u.at("/login?error=failed") || b.hasSession() {
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
	if _, body := b2.get("/o/acme/login"); strings.Contains(body, `data-step="totp"`) {
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
	if _, body := b3.get("/o/acme/login?step=1"); strings.Contains(body, "data-ticket") {
		t.Fatal("a password ticket was shown through the step cookie")
	}
	// oversized and unknown values are ignored
	for _, v := range []string{strings.Repeat("a", 300), "n1.unknown"} {
		b3.c.Jar.SetCookies(hu, []*http.Cookie{{Name: "__Host-quisora_step", Value: v, Path: "/", Secure: true}})
		if res, body := b3.get("/o/acme/login?step=1"); res.StatusCode != 200 || strings.Contains(body, "data-ticket") {
			t.Fatalf("cookie %.10q: %d", v, res.StatusCode)
		}
	}
}

// A provider sign-in started while another is under way in the same browser does not break the first: each is bound
// to the browser by its own state cookie. This is how a guest of an organization provider signs in when the source
// organization's sign-in page in turn sends them to its own provider - the inner sign-in finishes first, then the
// outer one's callback must still find its state.
func TestNestedProviderSignInsKeepTheirOwnState(t *testing.T) {
	u := newUpEnv(t, nil)
	outer := u.oidcProvider(t, nil)
	inner := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Inner SSO") })
	b := u.browser(t)
	begin := func(p *model.Provider) (state, code string) {
		res, _ := b.get("/o/acme/login/provider/" + p.ID)
		if res.StatusCode != 302 {
			t.Fatalf("provider start: %d", res.StatusCode)
		}
		loc := res.Header.Get("Location")
		lu, _ := url.Parse(loc)
		return lu.Query().Get("state"), u.oidc.Authorize(loc, claims("sub-1", "pat@corp.example"))
	}
	finish := func(p *model.Provider, state, code string) *http.Response {
		res, _ := b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code))
		return res
	}
	outerState, outerCode := begin(outer)
	innerState, innerCode := begin(inner)
	if res := finish(inner, innerState, innerCode); res.StatusCode != 303 || strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatalf("inner sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if res := finish(outer, outerState, outerCode); res.StatusCode != 303 || strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatalf("outer sign-in after the inner one: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}
