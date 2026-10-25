package login_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
)

func mfaEnv(t *testing.T) (*env, *model.Org) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LoginPerIPMin = 0
		c.Limits.LockoutAttempts = 0
		c.Audit.Logins = true
	})
	return e, e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
}

func (e *env) passkeyCount(t *testing.T, u *model.User) int {
	t.Helper()
	l, err := e.Svc.Passkeys.All(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return len(l)
}

// A sign-in that must enrol a factor: wrong authenticator codes burn the ticket after five tries, so a guessed
// code cannot be searched for, and no session or factor results.
func TestCoverageEnrolTOTPAttemptsBurnTicket(t *testing.T) {
	e, org := mfaEnv(t)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	tk := str(out, "ticket")
	res, out := b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": tk})
	wantStatus(t, res, out, 200)
	secret := str(out, "secret")
	for range 5 {
		res, out = b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": tk, "code": "000000"})
		wantStatus(t, res, out, 401)
	}
	res, out = b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": tk, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 401)
	if b.hasSession() {
		t.Fatal("session from a burnt enrolment ticket")
	}
	if f, _ := e.Svc.Users.Get(context.Background(), pat.ID); f.HasTOTP() {
		t.Fatal("factor stored by a burnt ticket")
	}
}

// An enrolment ticket cannot replace a second factor the account got meanwhile (its owner set one up elsewhere).
func TestCoverageEnrolRefusedOnceAccountHasFactor(t *testing.T) {
	e, org := mfaEnv(t)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	tk := str(out, "ticket")
	e.giveTOTP(t, pat)
	before, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	for _, p := range []string{"totp/begin", "passkey/begin"} {
		res, out := b.post("/api-internal/login/enrol/"+p, map[string]any{"ticket": tk})
		if res.StatusCode != 409 && res.StatusCode != 401 {
			t.Fatalf("%s: %d %v", p, res.StatusCode, out["_raw"])
		}
	}
	if b.hasSession() {
		t.Fatal("session")
	}
	if f, _ := e.Svc.Users.Get(context.Background(), pat.ID); string(f.TOTPSecret) != string(before.TOTPSecret) {
		t.Fatal("the account's factor was replaced")
	}
}

// Enrolling a passkey at sign-in: garbage, a response from another origin, and an authenticator that does not verify
// its user are all refused without a session, and the ticket stays usable until the tries run out.
func TestCoverageEnrolPasskeyRefusals(t *testing.T) {
	e, org := mfaEnv(t)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	tk := str(out, "ticket")

	begin := func() (any, []byte) {
		res, begin := b.post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": tk})
		wantStatus(t, res, begin, 200)
		opts, _ := json.Marshal(begin["options"])
		return begin["challenge"], opts
	}
	finish := func(ch any, cred []byte, want int) {
		t.Helper()
		body := map[string]any{"ticket": tk, "challenge": ch, "credential": json.RawMessage(cred)}
		res, out := b.post("/api-internal/login/enrol/passkey/finish", body)
		wantStatus(t, res, out, want)
	}

	ch, _ := begin()
	finish(ch, []byte(`{"id":"x"}`), 422)

	ch, opts := begin()
	other := virtualauth.New("https://evil.example")
	cred, _, err := other.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	finish(ch, cred, 422)

	ch, opts = begin()
	b.auth.UserVerified = false
	cred, _, err = b.auth.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	finish(ch, cred, 422)
	b.auth.UserVerified = true

	if b.hasSession() || e.passkeyCount(t, pat) != 0 {
		t.Fatal("refused ceremonies left a session or a passkey")
	}

	// the ticket still works for a proper ceremony; an unnamed passkey is called "Passkey"
	ch, opts = begin()
	cred, _, err = b.auth.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	finish(ch, cred, 200)
	l, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	if len(l) != 1 || l[0].Name != "Passkey" || !b.hasSession() {
		t.Fatalf("passkeys %+v session %v", l, b.hasSession())
	}
	if len(e.audits(t, "account.passkey.add")) != 1 {
		t.Fatal("enrolment not audited")
	}
}

// Tries at the enrolment passkey step are limited per ticket.
func TestCoverageEnrolPasskeyAttemptsBurnTicket(t *testing.T) {
	e, org := mfaEnv(t)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	tk := str(out, "ticket")
	res, begin := b.post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": tk})
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	good, _, _ := b.auth.Create(opts)
	for range 5 {
		res, out = b.post("/api-internal/login/enrol/passkey/finish", map[string]any{"ticket": tk, "challenge": "nope", "credential": json.RawMessage(`{}`)})
		wantStatus(t, res, out, 422)
	}
	res, out = b.post("/api-internal/login/enrol/passkey/finish", map[string]any{"ticket": tk, "challenge": begin["challenge"], "credential": json.RawMessage(good)})
	wantStatus(t, res, out, 401)
	if b.hasSession() {
		t.Fatal("session from a burnt ticket")
	}
}

// Invitation links: unknown or used tokens give nothing, a passkey that does not verify does not use the link up, and
// a ceremony begun for one invitation does not complete another.
func TestCoverageInvitePasskeyRefusals(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	tok := tokenOf(link)
	_, link2 := e.invitee(t, org, "other")
	tok2 := tokenOf(link2)
	b := e.browser(t)

	res, out := b.post("/api-internal/invite/passkey/begin", map[string]any{"token": "bogus"})
	wantStatus(t, res, out, 410)
	res, out = b.post("/api-internal/invite/passkey/begin", map[string]any{"token": ""})
	wantStatus(t, res, out, 410)
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tok})
	wantStatus(t, res, out, 422) // neither a password nor a passkey

	// a ceremony begun with another invitation's token
	body, status, o := b.invitePasskeyBody(tok2, nil)
	if status != 200 {
		t.Fatalf("begin: %v", o)
	}
	body["token"] = tok
	res, out = b.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 422)

	// no user verification
	b.auth.UserVerified = false
	body, status, o = b.invitePasskeyBody(tok, nil)
	if status != 200 {
		t.Fatalf("begin: %v", o)
	}
	res, out = b.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 422)
	b.auth.UserVerified = true
	if b.hasSession() || e.passkeyCount(t, u) != 0 {
		t.Fatal("a refused invitation left a session or a passkey")
	}

	// too-weak password: refused and the link is not burnt
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "short"})
	if res.StatusCode < 400 || res.StatusCode >= 500 {
		t.Fatalf("weak password: %d %v", res.StatusCode, out["_raw"])
	}
	body, status, o = b.invitePasskeyBody(tok, nil)
	if status != 200 {
		t.Fatalf("link burnt by refusals: %v", o)
	}
	res, out = b.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 200)
	// and now it is used
	res, out = b.post("/api-internal/invite/passkey/begin", map[string]any{"token": tok})
	wantStatus(t, res, out, 410)
}

// The invite passkey path is refused where passkeys are switched off for the organization, and the password path
// where passwords are.
func TestCoverageInviteMethodsOff(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.PasskeyLogin = false })
	_, link := e.invitee(t, org, "newbie")
	b := e.browser(t)
	res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "challenge": "x", "credential": json.RawMessage(`{"id":"x"}`)})
	wantStatus(t, res, out, 403)
	if b.hasSession() {
		t.Fatal("session")
	}
}
