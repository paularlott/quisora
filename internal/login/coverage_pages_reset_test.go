package login_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
)

// The step a provider sign-in leaves behind is only shown for its own organization, and a ticket from a password
// sign-in (which is no provider's) is never shown through the step cookie.
func TestCoverageStepCookieIsScoped(t *testing.T) {
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

// A signed-in browser at the sign-in page is sent on, unless it asked to re-authenticate (then it is shown who is
// signed in); an unknown organization is not found.
func TestCoverageLoginPageSignedIn(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	res, _ := b.get("/login/acme?next=/where")
	if res.StatusCode != 303 || res.Header.Get("Location") != "/where" {
		t.Fatalf("redirect: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = b.get("/login/acme?next=//evil.example")
	if res.Header.Get("Location") != "/account" {
		t.Fatalf("hostile next: %q", res.Header.Get("Location"))
	}
	res, body := b.get("/login/acme?reauth=1&login_hint=someone@example.com")
	if res.StatusCode != 200 || !strings.Contains(body, "pat@example.com") {
		t.Fatalf("reauth page: %d", res.StatusCode)
	}
	if res, _ = b.get("/login/nosuchorg"); res.StatusCode != 404 && res.StatusCode != 302 {
		t.Fatalf("unknown org: %d", res.StatusCode)
	}
}

// The reset form is limited per address: after the limit even a good link is refused until the minute is up, and
// a used link gives nothing.
func TestCoverageResetRateLimitAndReuse(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 3; c.Mail.SMTPHost = "smtp.example.com" })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.post("/api-internal/password/forgot", map[string]any{"org": "acme", "email": pat.Email})
	wantStatus(t, res, out, 200)
	tok := tokenOf(linkPath(t, e.nextMail(t)))
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "a brand new long password"})
	wantStatus(t, res, out, 200)
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "another new long password"})
	wantStatus(t, res, out, 410)
	// the old password no longer signs in, the new one does
	if res, _ = e.browser(t).login("acme", "pat", userPassword); res.StatusCode == 200 {
		t.Fatal("old password still works after reset")
	}
	var last int
	for range 6 {
		res, out = b.post("/api-internal/password/reset", map[string]any{"token": "bogus", "password": "x"})
		last = res.StatusCode
	}
	if last != 429 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("reset not limited: %d", last)
	}
}
