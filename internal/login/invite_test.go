package login_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

func TestInviteSignUpWithPassword(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Audit.Logins = true; c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	if u.PasswordHash != "" {
		t.Fatal("setup: user has a password")
	}
	b := e.browserAt(t, org)
	res, body := b.get(link)
	if res.StatusCode != 200 || !strings.Contains(body, "Welcome, newbie") || !strings.Contains(body, "Confirm password") ||
		!strings.Contains(body, "Create a passkey") {
		t.Fatalf("invite page %d: %.400s", res.StatusCode, body)
	}
	if res, _ := b.get(link); res.StatusCode != 200 {
		t.Fatal("peeking burnt the invitation")
	}
	// An invitation is neither a reset link nor a verification link.
	if res, _ := b.get(strings.Replace(link, "/invite", "/reset", 1)); res.StatusCode != http.StatusGone {
		t.Fatalf("invite token on reset page: %d", res.StatusCode)
	}
	tok := tokenOf(link)
	res2, out := b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "my first password"})
	wantStatus(t, res2, out, 410)
	if res, _ := b.verifyLink(strings.Replace(link, "/invite", "/verify-email", 1)); res.Header.Get("Location") != b.base+"/account?email=invalid#profile" {
		t.Fatalf("invite token verified an address: %q", res.Header.Get("Location"))
	}

	// Policy errors do not burn the link.
	res2, out = b.post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "short"})
	wantStatus(t, res2, out, 422)
	if str(out, "field") != "password" {
		t.Fatalf("field %v", out)
	}
	res2, out = b.post("/api-internal/invite/complete", map[string]any{"token": tok})
	wantStatus(t, res2, out, 422)
	res2, out = b.post("/api-internal/invite/complete", map[string]any{"token": "nope", "password": "my first password"})
	wantStatus(t, res2, out, 410)

	res2, out = b.post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "my first password"})
	wantStatus(t, res2, out, 200)
	if str(out, "next") != b.base+"/account" || !b.hasSession() {
		t.Fatalf("not signed in: %v", out)
	}
	if res, body := b.get("/account"); res.StatusCode != 200 || !strings.Contains(body, "Your account") {
		t.Fatalf("account: %d", res.StatusCode)
	}
	fresh, _ := e.Svc.Users.Get(context.Background(), u.ID)
	if fresh.PasswordHash == "" {
		t.Fatal("password not stored")
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), u.ID)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "pwd" {
		t.Fatalf("sessions %+v", sess)
	}

	// Single use: the same link is dead, on the page and at the API.
	if res, _ := e.browserAt(t, org).get(link); res.StatusCode != http.StatusGone {
		t.Fatalf("used link still valid: %d", res.StatusCode)
	}
	res2, out = e.browserAt(t, org).post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "another password!"})
	wantStatus(t, res2, out, 410)
	res2, out = e.browserAt(t, org).login("acme", "newbie", "my first password")
	wantStatus(t, res2, out, 200)
	if n := len(e.audits(t, "invite.accept")); n != 1 {
		t.Fatalf("audit %d", n)
	}
}

func TestInviteSignUpWithPasskey(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	tok := tokenOf(link)
	b := e.browserAt(t, org)

	// A foreign ceremony cannot be replayed here: the passkey ceremony is bound to the invitation's user and purpose.
	body, st, out := b.invitePasskeyBody(tok, nil)
	if st != 200 {
		t.Fatalf("begin: %d %v", st, out)
	}
	delete(body, "credential")
	res, out := b.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 422) // no password and no credential

	body, _, _ = b.invitePasskeyBody(tok, nil)
	res, out = b.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 200)
	if str(out, "next") != b.base+"/account" || !b.hasSession() {
		t.Fatalf("not signed in: %v", out)
	}
	list, _ := e.Svc.Passkeys.All(context.Background(), u.ID)
	if len(list) != 1 || list[0].Name != "Key" || list[0].OrgID != org.ID {
		t.Fatalf("passkeys %+v", list)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), u.ID)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "hwk,user" {
		t.Fatalf("amr %+v", sess)
	}
	fresh, _ := e.Svc.Users.Get(context.Background(), u.ID)
	if fresh.PasswordHash != "" {
		t.Fatal("a password appeared")
	}
	// Single use, and the passkey now signs in at the org page.
	res, out = e.browserAt(t, org).post("/api-internal/invite/passkey/begin", map[string]any{"token": tok})
	wantStatus(t, res, out, 410)
	b2 := e.browserAt(t, org)
	b2.auth = b.auth
	if st, out := b2.passkeyLogin(map[string]any{"org": "acme"}); st != 200 {
		t.Fatalf("passkey sign-in: %d %v", st, out)
	}
	// No password: username+password sign-in fails generically.
	res, out = e.browserAt(t, org).login("acme", "newbie", "whatever password")
	wantStatus(t, res, out, 401)
}

func TestInviteBothPasswordAndPasskey(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	b := e.browserAt(t, org)
	body, st, out := b.invitePasskeyBody(tokenOf(link), map[string]any{"password": "both ways password"})
	if st != 200 {
		t.Fatal(out)
	}
	res, out := b.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 200)
	fresh, _ := e.Svc.Users.Get(context.Background(), u.ID)
	list, _ := e.Svc.Passkeys.All(context.Background(), u.ID)
	if fresh.PasswordHash == "" || len(list) != 1 {
		t.Fatalf("both expected: password %v passkeys %d", fresh.PasswordHash != "", len(list))
	}
	res, out = e.browserAt(t, org).login("acme", "newbie", "both ways password")
	wantStatus(t, res, out, 200)
}

func TestInviteBadPasswordKeepsPasskeyCeremonyOutOfIt(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	b := e.browserAt(t, org)
	body, _, _ := b.invitePasskeyBody(tokenOf(link), map[string]any{"password": "short"})
	res, out := b.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 422)
	if list, _ := e.Svc.Passkeys.All(context.Background(), u.ID); len(list) != 0 {
		t.Fatal("a rejected sign-up stored a passkey")
	}
	if res, _ := b.get(link); res.StatusCode != 200 {
		t.Fatal("rejected sign-up burnt the invitation")
	}
}

func TestInviteOrgWithoutPasswords(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "nopw", func(s *model.OrgSettings) { s.PasswordLogin = false })
	u, link := e.invitee(t, org, "sam")
	b := e.browserAt(t, org)
	res, body := b.get(link)
	if res.StatusCode != 200 || strings.Contains(body, "Confirm password") || strings.Contains(body, "f-password") ||
		!strings.Contains(body, "Create a passkey") {
		t.Fatalf("passkey-only page %d: %.600s", res.StatusCode, body)
	}
	res2, out := b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "a long enough password"})
	wantStatus(t, res2, out, 403)
	if fresh, _ := e.Svc.Users.Get(context.Background(), u.ID); fresh.PasswordHash != "" {
		t.Fatal("password stored in an org without passwords")
	}
	if res, _ := b.get(link); res.StatusCode != 200 {
		t.Fatal("refused request burnt the invitation")
	}
	// Providers only: nothing to set up here.
	org2 := e.org(t, "sso", func(s *model.OrgSettings) { s.PasswordLogin = false; s.PasskeyLogin = false })
	_, link2 := e.invitee(t, org2, "sue")
	res, body = b.get(link2)
	if res.StatusCode != 200 || strings.Contains(body, "Confirm password") || strings.Contains(body, "Create a passkey") ||
		!strings.Contains(body, `href="`+web.OrgPath(org2.ID, "/login")+`"`) || !strings.Contains(body, "sign-in providers") {
		t.Fatalf("providers-only page %d: %.800s", res.StatusCode, body)
	}
	res2, out = b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link2), "password": "a long enough password"})
	wantStatus(t, res2, out, 403)
	res2, out = b.post("/api-internal/invite/passkey/begin", map[string]any{"token": tokenOf(link2)})
	wantStatus(t, res2, out, 403)
}

func TestInviteRequireMFAEnrolsBeforeSession(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "mfa", func(s *model.OrgSettings) { s.RequireMFA = true })
	u, link := e.invitee(t, org, "newbie")
	b := e.browserAt(t, org)
	res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "my first password"})
	wantStatus(t, res, out, 200)
	ticket := str(out, "ticket")
	if str(out, "step") != "enrol" || ticket == "" || b.hasSession() {
		t.Fatalf("expected the enrolment step without a session: %v", out)
	}
	if res, _ := b.get("/account"); res.StatusCode == 200 {
		t.Fatal("account reachable before enrolment")
	}
	res, out = b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res, out, 200)
	secret := str(out, "secret")
	res, out = b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)
	if !b.hasSession() || str(out, "next") != b.base+"/account" {
		t.Fatalf("no session after enrolment: %v", out)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), u.ID)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "pwd,otp,mfa" {
		t.Fatalf("amr %+v", sess)
	}
	// The dates are recorded; the link was handed over by an administrator, not emailed, so it proves no address.
	if f, _ := e.Svc.Users.Get(context.Background(), u.ID); f.MFAEnrolledAt == nil || f.PasswordChangedAt == nil || f.EmailVerified {
		t.Fatalf("after the invitation: mfa %v password %v verified %v", f.MFAEnrolledAt, f.PasswordChangedAt, f.EmailVerified)
	}

	// A passkey counts as the whole sign-in (it is a second factor on its own): no enrolment step.
	_, link2 := e.invitee(t, org, "keyuser")
	b2 := e.browserAt(t, org)
	body, _, _ := b2.invitePasskeyBody(tokenOf(link2), nil)
	res, out = b2.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 200)
	if !b2.hasSession() || str(out, "step") != "" {
		t.Fatalf("passkey sign-up: %v", out)
	}
}

// Accepting an invitation starts the account afresh (it is how a compromised or locked-out account is recovered):
// every session ends and the old password, authenticator app, passkeys, connected providers and API tokens go. In an
// organization that requires MFA the user then sets up a new second factor at once.
func TestInviteResetsTheAccount(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.PasskeyLogin = false; allowAPITokens(s) })
	pat := e.user(t, org, "pat", model.RoleUser)
	e.giveTOTP(t, pat)
	old := e.signedIn(t, pat) // e.g. an attacker's session
	_ = e.Svc.Identities.Create(ctx, &model.Identity{UserID: pat.ID, OrgID: org.ID, ProviderID: "p-x", Subject: "attacker"})
	if _, _, err := e.Svc.CreateAPIToken(ctx, service.ActorForUser(pat, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}}); err != nil {
		t.Fatal(err)
	}
	link := e.invite(t, pat)
	b := e.browserAt(t, org)
	res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "a brand new password"})
	wantStatus(t, res, out, 200)
	if !b.hasSession() || str(out, "step") != "" {
		t.Fatalf("after the invitation: %v", out)
	}
	if res, _ := old.api("GET", "/api-internal/account", nil); res.StatusCode != 401 {
		t.Errorf("the old session survived: %d", res.StatusCode)
	}
	fresh, _ := e.Svc.Users.Get(ctx, pat.ID)
	if fresh.HasTOTP() {
		t.Error("the authenticator app survived")
	}
	if ids, _ := e.Svc.Identities.All(ctx, pat.ID); len(ids) != 0 {
		t.Error("a connected provider survived")
	}
	if toks, _ := e.Svc.APITokens.All(ctx, pat.ID); len(toks) != 0 {
		t.Error("an API token survived")
	}
	// the new password works, the old one does not
	if res, out := e.browserAt(t, org).login("acme", pat.Email, "a brand new password"); res.StatusCode != 200 {
		t.Errorf("new password: %d %v", res.StatusCode, out["_raw"])
	}

	// MFA required: the reset user sets up a new second factor straight away
	org2 := e.org(t, "strict", func(s *model.OrgSettings) { s.PasskeyLogin = false; s.RequireMFA = true })
	kim := e.user(t, org2, "kim", model.RoleUser)
	e.giveTOTP(t, kim)
	link = e.invite(t, kim)
	b = e.browserAt(t, org2)
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "another new password"})
	wantStatus(t, res, out, 200)
	if str(out, "step") != "enrol" || b.hasSession() {
		t.Fatalf("MFA org after reset: %v", out)
	}
}

func TestRemovedPasswordAndReinvite(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0; c.Limits.LockoutAttempts = 3 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	old := e.signedIn(t, pat)
	res, out := e.browserAt(t, org).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	if err := e.Svc.RemovePassword(context.Background(), service.System, pat.ID); err != nil {
		t.Fatal(err)
	}
	if res, _ := old.get("/account"); res.StatusCode == 200 {
		t.Fatal("session survived password removal")
	}
	res, out = e.browserAt(t, org).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 401)
	if str(out, "error") != "The email address or password is incorrect." {
		t.Fatalf("not generic: %v", out)
	}
	// Forgot-password sends nothing to an account without a password: it needs a new invitation.
	b := e.browserAt(t, org)
	res, out = b.post("/o/acme/api-internal/password/forgot", map[string]any{"email": "pat@example.com"})
	wantStatus(t, res, out, 200)
	e.noMail(t)
	// ... and a reset link that was issued before the removal no longer works.
	tok, _, err := e.Svc.IssueLink(context.Background(), pat, service.LinkReset, pat.Email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "a brand new password"})
	wantStatus(t, res, out, 410)

	// The new invitation lets the existing account choose a new password.
	link := e.invite(t, pat)
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "a brand new password"})
	wantStatus(t, res, out, 200)
	res, out = e.browserAt(t, org).login("acme", "pat", "a brand new password")
	wantStatus(t, res, out, 200)
	res, out = e.browserAt(t, org).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 401)
}

func TestInviteClearsLockoutAndRevokesOlderLink(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0; c.Limits.LockoutAttempts = 2 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browserAt(t, org)
	b.login("acme", "pat", "x")
	b.login("acme", "pat", "x")
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)

	first := e.invite(t, pat)
	second := e.invite(t, pat)
	if res, _ := b.get(first); res.StatusCode != http.StatusGone {
		t.Fatalf("older invitation still valid: %d", res.StatusCode)
	}
	if res, _ := b.get(second); res.StatusCode != 200 {
		t.Fatalf("newest invitation: %d", res.StatusCode)
	}
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(first), "password": "a brand new password"})
	wantStatus(t, res, out, 410)
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(second), "password": "a brand new password"})
	wantStatus(t, res, out, 200)
	res, out = e.browserAt(t, org).login("acme", "pat", "a brand new password")
	wantStatus(t, res, out, 200)
}

func TestInviteExpiredAndInactive(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, _ := e.invitee(t, org, "newbie")
	tok, _, err := e.Svc.IssueLink(context.Background(), u, service.LinkInvite, "", -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b := e.browserAt(t, org)
	if res, _ := b.get("/invite?token=" + tok); res.StatusCode != http.StatusGone {
		t.Fatalf("expired page: %d", res.StatusCode)
	}
	res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "a long enough password"})
	wantStatus(t, res, out, 410)
	// A disabled account's invitation stops working.
	tok2, _, _ := e.Svc.IssueLink(context.Background(), u, service.LinkInvite, "", time.Hour)
	off := false
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, u.ID, service.UserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tok2, "password": "a long enough password"})
	wantStatus(t, res, out, 410)
}

func TestInviteMailLinkWorksThroughTheModule(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, _ := e.invitee(t, org, "newbie")
	e.mailInvite(t, u, org)
	m := e.nextMail(t)
	link := linkPath(t, m)
	if !strings.HasPrefix(link, web.OrgPath(org.ID, "/invite?token=")) || !strings.Contains(m.Text, "invited") || !strings.Contains(m.Text, "7 days") {
		t.Fatalf("mail %s", m.Text)
	}
	res, out := e.browserAt(t, org).post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "my first password"})
	wantStatus(t, res, out, 200)
}

// An invitation that Quisora emailed proves the address once accepted; the address changing in between does not
// prove the new one.
func TestEmailedInvitationVerifiesAddress(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	ctx := context.Background()
	for _, change := range []bool{false, true} {
		name := "mailed"
		if change {
			name = "moved"
		}
		email := name + "@acme.test"
		u, err := e.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: &name, Email: &email, GivenName: &name})
		if err != nil {
			t.Fatal(err)
		}
		e.mailInvite(t, u, org)
		link := linkPath(t, e.nextMail(t))
		if change {
			other := "elsewhere@acme.test"
			if _, err := e.Svc.UpdateUser(ctx, service.System, u.ID, service.UserInput{Email: &other}); err != nil {
				t.Fatal(err)
			}
		}
		res, out := e.browserAt(t, org).post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "my first password"})
		if change {
			// The invitation went to an address that is no longer the account's: it opens nothing (it would have
			// set the password of an account whose mail now goes elsewhere).
			wantStatus(t, res, out, 410)
			continue
		}
		wantStatus(t, res, out, 200)
		if f, _ := e.Svc.Users.Get(ctx, u.ID); !f.EmailVerified {
			t.Fatal("an emailed invitation did not verify its address")
		}
	}
}

// Invitation links: unknown tokens give nothing, a passkey that does not verify does not use the link up, and a
// ceremony begun for one invitation does not complete another.
func TestInvitePasskeyRefusedCeremonies(t *testing.T) {
	e := newEnv(t, noIPLimit)
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	tok := tokenOf(link)
	_, link2 := e.invitee(t, org, "other")
	tok2 := tokenOf(link2)
	b := e.browserAt(t, org)

	for _, token := range []string{"bogus", ""} {
		res, out := b.post("/api-internal/invite/passkey/begin", map[string]any{"token": token})
		wantStatus(t, res, out, 410)
	}
	res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tok})
	wantStatus(t, res, out, 422) // neither a password nor a passkey

	t.Run("a ceremony begun with another invitation's token", func(t *testing.T) {
		body, status, o := b.invitePasskeyBody(tok2, nil)
		if status != 200 {
			t.Fatalf("begin: %v", o)
		}
		body["token"] = tok
		res, out := b.post("/api-internal/invite/complete", body)
		wantStatus(t, res, out, 422)
	})
	t.Run("no user verification", func(t *testing.T) {
		b.auth.UserVerified = false
		defer func() { b.auth.UserVerified = true }()
		body, status, o := b.invitePasskeyBody(tok, nil)
		if status != 200 {
			t.Fatalf("begin: %v", o)
		}
		res, out := b.post("/api-internal/invite/complete", body)
		wantStatus(t, res, out, 422)
	})
	if b.hasSession() || e.passkeyCount(t, u) != 0 {
		t.Fatal("a refused invitation left a session or a passkey")
	}

	// the refusals did not burn the link: it still takes a proper ceremony, once
	body, status, o := b.invitePasskeyBody(tok, nil)
	if status != 200 {
		t.Fatalf("link burnt by refusals: %v", o)
	}
	res, out = b.post("/api-internal/invite/complete", body)
	wantStatus(t, res, out, 200)
	res, out = b.post("/api-internal/invite/passkey/begin", map[string]any{"token": tok})
	wantStatus(t, res, out, 410)
}

// The invite passkey path is refused where passkeys are switched off for the organization, and nothing is burnt or
// stored by the refusal.
func TestInvitePasskeyRefusedWhereOrgDisablesPasskeys(t *testing.T) {
	e := newEnv(t, noIPLimit)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.PasskeyLogin = false })
	u, link := e.invitee(t, org, "newbie")
	b := e.browserAt(t, org)
	res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "challenge": "x", "credential": json.RawMessage(`{"id":"x"}`)})
	wantStatus(t, res, out, 403)
	if b.hasSession() || e.passkeyCount(t, u) != 0 {
		t.Fatal("the refusal left a session or a passkey")
	}
	// the link is still good for the other ways the organization allows
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tokenOf(link), "password": "a long enough password"})
	wantStatus(t, res, out, 200)
}

// inviteGate pauses the first write of a passkey for userID (the last step before the flow commits the account change)
// until release is closed.
type inviteGate struct {
	store.Store
	userID  string
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (s *inviteGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindPasskey && r.Scope == s.userID && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// The losing acceptance must neither replace the winner's passkey nor register a usable credential.
func TestInviteLosingConcurrentCompletionDoesNotReplaceWinnerPasskey(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	a, b := e.browserAt(t, org), e.browserAt(t, org)
	bodyA, st, out := a.invitePasskeyBody(tokenOf(link), nil)
	if st != 200 {
		t.Fatalf("begin A: %d %v", st, out)
	}
	bodyB, st, out := b.invitePasskeyBody(tokenOf(link), nil)
	if st != 200 {
		t.Fatalf("begin B: %d %v", st, out)
	}
	gate := &inviteGate{Store: e.Svc.Store, userID: u.ID, entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	}()
	e.Svc.Store = gate
	e.Svc.Passkeys.S = gate
	gate.armed.Store(true)
	done := make(chan int, 1)
	go func() {
		res, _, err := a.send(http.MethodPost, "/api-internal/invite/complete", bodyA, nil)
		if err != nil {
			done <- -1
			return
		}
		done <- res.StatusCode
	}()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request A did not reach storing its passkey")
	}
	res, out := b.post("/api-internal/invite/complete", bodyB)
	wantStatus(t, res, out, 200)
	winner, err := e.Svc.Passkeys.All(context.Background(), u.ID)
	if err != nil || len(winner) != 1 {
		t.Fatalf("winner passkeys: %v %v", winner, err)
	}
	close(gate.release)
	select {
	case st = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request A did not finish")
	}
	if st != 410 {
		t.Fatalf("loser status: %d", st)
	}
	remaining, err := e.Svc.Passkeys.All(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	probe := e.browserAt(t, org)
	probe.auth = a.auth
	loserStatus, loserOut := probe.passkeyLogin(map[string]any{"org": "acme"})
	if len(remaining) != 1 || remaining[0].ID != winner[0].ID || loserStatus == 200 {
		ids := make([]string, 0, len(remaining))
		for _, pk := range remaining {
			ids = append(ids, pk.ID)
		}
		t.Fatalf("rejected completion replaced winner credential: winner=%s remaining=%v rejected passkey login=%d %v", winner[0].ID, ids, loserStatus, loserOut)
	}
}
