package login_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// lockEnv is a server that sends mail, locks an account after 3 failures and does not limit sign-ins per address.
func lockEnv(t *testing.T) (*env, *model.Org) {
	e := newEnv(t, func(c *config.Config) {
		c.Mail.SMTPHost = "smtp.example.com"
		c.Audit.Logins = true
		c.Limits.LockoutAttempts = 3
		c.Limits.LoginPerIPMin = 0
	})
	return e, e.org(t, "acme", func(s *model.OrgSettings) { s.EmailCodes = true })
}

func (e *env) lockedReasons(t *testing.T) int {
	t.Helper()
	n := 0
	for _, a := range e.audits(t, "login.failure") {
		if a.Detail["reason"] == "locked" {
			n++
		}
	}
	return n
}

// Once an account has used up its failed attempts, a second-factor step that was begun before is refused too, with
// the right answer, whichever factor it is: the lockout cannot be walked around through a ticket held earlier.
func TestCoverageSecondFactorsRefuseLockedAccount(t *testing.T) {
	e, org := lockEnv(t)
	pat := e.verifiedUser(t, org, "pat", model.RoleUser)
	secret := e.giveTOTP(t, pat)
	fresh, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	codes, err := e.Svc.CreateRecoveryCodes(context.Background(), service.System, fresh)
	if err != nil {
		t.Fatal(err)
	}

	begin := func() (*browser, string) {
		b := e.browser(t)
		res, out := b.login("acme", "pat", userPassword)
		wantStatus(t, res, out, 200)
		if str(out, "step") != "totp" {
			t.Fatalf("step %v", out)
		}
		return b, str(out, "ticket")
	}
	bT, tkTotp := begin()
	bR, tkRec := begin()

	// three wrong authenticator codes lock the account
	for range 3 {
		res, out := bT.post("/api-internal/login/totp", map[string]any{"ticket": tkTotp, "code": "000000"})
		wantStatus(t, res, out, 401)
	}
	if n := len(e.audits(t, "login.lockout")); n != 1 {
		t.Fatalf("lockout audits %d", n)
	}
	for name, probe := range map[string]struct {
		b    *browser
		path string
		body map[string]any
	}{
		"totp":     {bT, "/api-internal/login/totp", map[string]any{"ticket": tkTotp, "code": totpAt(secret, time.Now().Add(30*time.Second))}},
		"recovery": {bR, "/api-internal/login/recovery", map[string]any{"ticket": tkRec, "code": codes[0]}},
	} {
		res, out := probe.b.post(probe.path, probe.body)
		if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" || probe.b.hasSession() {
			t.Errorf("%s while locked: %d %v session=%v", name, res.StatusCode, out["_raw"], probe.b.hasSession())
		}
	}
	if n := e.lockedReasons(t); n != 2 {
		t.Fatalf("locked refusals audited: %d", n)
	}
	// the recovery code was not used up by the refused attempt
	if left, _ := e.Svc.Users.Get(context.Background(), pat.ID); left == nil {
		t.Fatal("user vanished")
	}
	if sess, _ := e.Svc.Sessions.All(context.Background(), pat.ID); len(sess) != 0 {
		t.Fatalf("sessions created while locked: %d", len(sess))
	}
}

// Wrong recovery codes burn the ticket after five tries, a recovery code works once, and the second-factor endpoints
// refuse tickets of the wrong kind.
func TestCoverageRecoveryAttemptsAndReuse(t *testing.T) {
	e, org := lockEnv(t)
	e.Cfg.Limits.LockoutAttempts = 0 // attempts per ticket are the limit under test
	pat := e.verifiedUser(t, org, "pat", model.RoleUser)
	e.giveTOTP(t, pat)
	fresh, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	codes, _ := e.Svc.CreateRecoveryCodes(context.Background(), service.System, fresh)

	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	tk := str(out, "ticket")
	for range 5 {
		res, out := b.post("/api-internal/login/recovery", map[string]any{"ticket": tk, "code": "AAAA-AAAA-AAAA-AAAA"})
		wantStatus(t, res, out, 401)
	}
	res, out := b.post("/api-internal/login/recovery", map[string]any{"ticket": tk, "code": codes[0]})
	wantStatus(t, res, out, 401)
	if !strings.Contains(str(out, "error"), "Too many") && !strings.Contains(str(out, "_raw"), "Too many") {
		t.Fatalf("not the attempts message: %v", out["_raw"])
	}
	if b.hasSession() {
		t.Fatal("session after burnt ticket")
	}

	// a fresh ticket accepts the code once; the code does not work a second time
	b2 := e.browser(t)
	_, out = b2.login("acme", "pat", userPassword)
	res, out = b2.post("/api-internal/login/recovery", map[string]any{"ticket": str(out, "ticket"), "code": codes[0]})
	wantStatus(t, res, out, 200)
	b3 := e.browser(t)
	_, out = b3.login("acme", "pat", userPassword)
	res, out = b3.post("/api-internal/login/recovery", map[string]any{"ticket": str(out, "ticket"), "code": codes[0]})
	wantStatus(t, res, out, 401)
	if b3.hasSession() {
		t.Fatal("a used recovery code signed in again")
	}
	// an email-code ticket is refused by the TOTP endpoint and vice versa (a step for another factor)
	res, out = b3.post("/api-internal/login/totp", map[string]any{"ticket": "n1.unknown", "code": "123456"})
	wantStatus(t, res, out, 401)
}

// An emailed code (for an account with no second factor of its own): too many wrong codes burn the sign-in.
func TestCoverageEmailCodeAttempts(t *testing.T) {
	e, _ := lockEnv(t)
	e.Cfg.Limits.LockoutAttempts = 0
	org := e.org(t, "mfa", func(s *model.OrgSettings) { s.EmailCodes, s.RequireMFA = true, true })
	e.verifiedUser(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("mfa", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "step") != "email_code" {
		t.Fatalf("step %v", out)
	}
	tk := str(out, "ticket")
	code := codeFrom(t, e)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	// codes of the wrong shape never match
	for _, c := range []string{"", "12345", "1234567", "abcdef"} {
		res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": c})
		wantStatus(t, res, out, 401)
	}
	res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": wrong})
	wantStatus(t, res, out, 401) // the fifth try on the ticket
	res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": code})
	wantStatus(t, res, out, 401) // the sixth: the ticket is burnt, the right code too late (refused unaudited)
	if b.hasSession() {
		t.Fatal("a burnt ticket signed in")
	}
	if len(e.audits(t, "login.failure")) != 5 {
		t.Fatalf("failures audited: %d", len(e.audits(t, "login.failure")))
	}
}

// The step endpoints refuse a body that is not the JSON they take (and unknown fields), before anything else.
func TestCoverageMalformedBodies(t *testing.T) {
	e, org := lockEnv(t)
	e.verifiedUser(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	for _, p := range []string{"login/password", "login/totp", "login/recovery", "login/email/send", "login/email", "login/passkey/begin",
		"login/passkey/finish", "login/enrol/totp/begin", "login/enrol/totp/confirm", "login/enrol/passkey/begin", "login/enrol/passkey/finish",
		"password/forgot", "password/reset", "invite/passkey/begin", "invite/complete"} {
		for _, body := range []string{"{not json", `{"unknown_field":1}`} {
			res, out := b.post("/api-internal/"+p, body)
			if res.StatusCode != 400 && res.StatusCode != 422 {
				t.Errorf("%s with %q: %d %v", p, body, res.StatusCode, out["_raw"])
			}
			if b.hasSession() {
				t.Fatalf("%s created a session", p)
			}
		}
	}
	if e.mailCount() != 0 {
		t.Fatal("mail sent for a malformed body")
	}
}
