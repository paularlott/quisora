package login_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

func TestForgotAndReset(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	e.user(t, org, "gone", model.RoleUser)
	f := false
	gone, _ := e.Svc.FindUserByEmail(context.Background(), org.ID, "gone@example.com")
	e.Svc.UpdateUser(context.Background(), service.System, gone.ID, service.UserInput{Active: &f})

	b := e.browserAt(t, org)
	// Always 200 and the same body; no mail unless the account exists, is active and has an address.
	var bodies []string
	for _, tr := range []map[string]any{{"email": "ghost@example.com"}, {"email": "gone@example.com"}, {"email": "pat@example.com"}} {
		res, out := b.post("/api-internal/password/forgot", tr)
		wantStatus(t, res, out, 200)
		bodies = append(bodies, str(out, "_raw"))
	}
	for _, x := range bodies[1:] {
		if x != bodies[0] {
			t.Fatalf("forgot responses differ: %q vs %q", x, bodies[0])
		}
	}
	m := e.nextMail(t)
	e.noMail(t)
	if m.To != "pat@example.com" || !strings.Contains(m.Subject, "Reset") {
		t.Fatalf("mail %+v", m)
	}
	link := linkPath(t, m)
	if !strings.HasPrefix(link, web.OrgPath(org.ID, "/reset?token=")) {
		t.Fatalf("link %s", link)
	}

	// Existing sessions are ended by a reset.
	old := e.signedIn(t, pat)
	if res, _ := old.get("/account"); res.StatusCode != 200 {
		t.Fatal("setup: session not valid")
	}

	res, body := b.get(link)
	if res.StatusCode != 200 || !strings.Contains(body, "Choose a new password") || !strings.Contains(body, `x-data="passwordSetup"`) ||
		!strings.Contains(body, "pat") {
		t.Fatalf("reset page: %d %.300s", res.StatusCode, body)
	}
	tok := tokenOf(link)

	// A weak password does not burn the link.
	res2, out := b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "short"})
	wantStatus(t, res2, out, 422)
	if str(out, "field") != "password" {
		t.Fatalf("weak password: %v", out)
	}
	if res, _ := b.get(link); res.StatusCode != 200 {
		t.Fatal("weak password burnt the link")
	}
	res2, out = b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "a brand new password"})
	wantStatus(t, res2, out, 200)
	if str(out, "next") != web.OrgPath(org.ID, "/login") {
		t.Fatalf("reset response %v", out)
	}
	// single use
	res2, out = b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "another new password"})
	wantStatus(t, res2, out, http.StatusGone)
	if res, _ := b.get(link); res.StatusCode != http.StatusGone {
		t.Fatal("link still valid after use")
	}
	// old password dead, new one works, old sessions gone
	res2, out = e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res2, out, 401)
	res2, out = e.browser(t).login("acme", "pat", "a brand new password")
	wantStatus(t, res2, out, 200)
	if res, _ := old.get("/account"); res.StatusCode == 200 {
		t.Fatal("session survived a password reset")
	}
	if n := len(e.audits(t, "password.reset")); n != 1 {
		t.Fatalf("audit %d", n)
	}
}

func TestResetClearsLockout(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LockoutAttempts = 2; c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browserAt(t, org)
	b.login("acme", "pat", "x")
	b.login("acme", "pat", "x")
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if err := e.Mailer.SendReset(context.Background(), pat, org); err != nil {
		t.Fatal(err)
	}
	tok := tokenOf(linkPath(t, e.nextMail(t)))
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "yet another password"})
	wantStatus(t, res, out, 200)
	res, out = b.login("acme", "pat", "yet another password")
	wantStatus(t, res, out, 200)
}

func TestForgotThrottleAndDisabledPassword(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browserAt(t, org)
	for range 8 {
		res, out := b.post("/o/acme/api-internal/password/forgot", map[string]any{"email": "pat@example.com"})
		wantStatus(t, res, out, 200)
	}
	if n := e.drainMails(t); n != 5 {
		t.Fatalf("expected 5 reset mails an hour per account, got %d", n)
	}
	// org without password sign-in: nothing is mailed
	org2 := e.org(t, "nopw", func(s *model.OrgSettings) { s.PasswordLogin = false })
	e.user(t, org2, "sam", model.RoleUser) // has a password, but the org does not allow password sign-in
	res, out := b.post("/o/nopw/api-internal/password/forgot", map[string]any{"email": "sam@example.com"})
	wantStatus(t, res, out, 200)
	e.noMail(t)
	// the "forgot" link appears on the page of an organization that signs in with passwords, not on that org's
	_, body := b.get("/o/acme/login")
	if !strings.Contains(body, "Forgot your password?") {
		t.Fatal("forgot link missing")
	}
	if _, body = b.get("/o/nopw/login"); strings.Contains(body, "Forgot your password?") {
		t.Fatal("forgot link on an organization without password sign-in")
	}
}

func TestNoMailerDisablesLinks(t *testing.T) {
	e := newEnv(t, nil)
	e.Mod.Mail = nil // as when no mailer is wired in
	b := e.browser(t)
	res, out := b.post("/o/primary/api-internal/password/forgot", map[string]any{"email": "admin@example.com"})
	wantStatus(t, res, out, 200)
	e.noMail(t)
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": "x", "password": "a long enough password"})
	wantStatus(t, res, out, 410) // links are durable service records: they resolve with or without a mailer
	if res, _ := b.get("/reset?token=x"); res.StatusCode != http.StatusGone {
		t.Fatalf("reset page: %d", res.StatusCode)
	}
	_, body := b.get("/o/primary/login")
	if strings.Contains(body, "Forgot your password?") {
		t.Fatal("forgot link shown without a mailer")
	}
}

// Anyone can ask for a reset link for any address, so a request does not end the link an earlier mail carries: both
// open until one is used, and the password it sets ends the other.
func TestResetRequestKeepsEarlierLink(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browserAt(t, org)
	forgot := func() string {
		res, out := b.post("/o/acme/api-internal/password/forgot", map[string]any{"email": "pat@example.com"})
		wantStatus(t, res, out, 200)
		return tokenOf(linkPath(t, e.nextMail(t)))
	}
	first, second := forgot(), forgot()
	res, out := b.post("/api-internal/password/reset", map[string]any{"token": first, "password": "a brand new password"})
	wantStatus(t, res, out, 200)
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": second, "password": "another new password"})
	if res.StatusCode == 200 {
		t.Fatalf("the second link still worked after the password changed: %v", out)
	}
	res, out = e.browser(t).login("acme", "pat", "a brand new password")
	wantStatus(t, res, out, 200)
}

// The reset form is limited: after a few tries even a good link is refused until the minute is up.
func TestResetFormIsRateLimited(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 3 })
	b := e.browser(t)
	var res *http.Response
	var out map[string]any
	for range 6 {
		res, out = b.post("/api-internal/password/reset", map[string]any{"token": "bogus", "password": "x"})
	}
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
}

// Anyone who knows an address may ask for its account's reset mails, so the hourly allowance is the requesting
// address's: five requests from one address do not use up the owner's own from another. All addresses together still
// get at most twenty an hour, so the form cannot flood the inbox.
func TestForgotAllowanceIsPerAddress(t *testing.T) {
	e := newEnv(t, noIPLimit, trustLoopbackProxy)
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	forgot := func(ip string, times int) {
		t.Helper()
		b := e.browserAt(t, org)
		b.fromAddress(ip)
		for range times {
			res, out := b.post("/o/acme/api-internal/password/forgot", map[string]any{"email": "pat@example.com"})
			wantStatus(t, res, out, 200)
		}
	}
	forgot("203.0.113.66", 8)
	if n := e.drainMails(t); n != 5 {
		t.Fatalf("one address was sent %d reset mails, want 5", n)
	}
	forgot("198.51.100.7", 1) // the owner, from elsewhere
	if n := e.drainMails(t); n != 1 {
		t.Fatalf("the owner's own request was sent %d mails after another address used its allowance", n)
	}
	for i := range 6 { // 30 requests from other addresses: the account's 20 an hour, 6 of which are sent
		forgot("192.0.2."+strconv.Itoa(i+1), 5)
	}
	if n := e.drainMails(t); n != 14 {
		t.Fatalf("every address together was sent %d more, want 14 (20 an hour)", n)
	}
}
