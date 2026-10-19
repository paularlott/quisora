package login_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// invitee creates a user without a password and returns it with the path+query of a fresh invitation.
func (e *env) invitee(t testing.TB, org *model.Org, name string) (*model.User, string) {
	t.Helper()
	email := name + "@example.com"
	u, err := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{Username: &name, Email: &email, GivenName: &name})
	if err != nil {
		t.Fatal(err)
	}
	return u, e.invite(t, u)
}

func (e *env) invite(t testing.TB, u *model.User) string {
	t.Helper()
	link, _, err := e.Svc.CreateInvite(context.Background(), service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(link, e.Cfg.Server.PublicURL)
}

func tokenOf(link string) string { return link[strings.Index(link, "token=")+len("token="):] }

// invitePasskey runs the passkey ceremony of an invitation and returns the completion request body.
func (b *browser) invitePasskeyBody(token string, extra map[string]any) (map[string]any, int, map[string]any) {
	b.t.Helper()
	res, begin := b.post("/api/invite/passkey/begin", map[string]any{"token": token})
	if res.StatusCode != 200 {
		return nil, res.StatusCode, begin
	}
	opts, _ := json.Marshal(begin["options"])
	cred, _, err := b.auth.Create(opts)
	if err != nil {
		b.t.Fatal(err)
	}
	body := map[string]any{"token": token, "challenge": begin["challenge"], "name": "Key", "credential": json.RawMessage(cred)}
	for k, v := range extra {
		body[k] = v
	}
	return body, 200, nil
}

func TestInviteSignUpWithPassword(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Audit.Logins = true; c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	if u.PasswordHash != "" {
		t.Fatal("setup: user has a password")
	}
	b := e.browser(t)
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
	res2, out := b.post("/api/password/reset", map[string]any{"token": tok, "password": "my first password"})
	wantStatus(t, res2, out, 410)
	if res, _ := b.get(strings.Replace(link, "/invite", "/verify-email", 1)); res.Header.Get("Location") != "/account?email=invalid#profile" {
		t.Fatalf("invite token verified an address: %q", res.Header.Get("Location"))
	}

	// Policy errors do not burn the link.
	res2, out = b.post("/api/invite/complete", map[string]any{"token": tok, "password": "short"})
	wantStatus(t, res2, out, 422)
	if str(out, "field") != "password" {
		t.Fatalf("field %v", out)
	}
	res2, out = b.post("/api/invite/complete", map[string]any{"token": tok})
	wantStatus(t, res2, out, 422)
	res2, out = b.post("/api/invite/complete", map[string]any{"token": "nope", "password": "my first password"})
	wantStatus(t, res2, out, 410)

	res2, out = b.post("/api/invite/complete", map[string]any{"token": tok, "password": "my first password"})
	wantStatus(t, res2, out, 200)
	if str(out, "next") != "/account" || !b.hasSession() {
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
	if res, _ := e.browser(t).get(link); res.StatusCode != http.StatusGone {
		t.Fatalf("used link still valid: %d", res.StatusCode)
	}
	res2, out = e.browser(t).post("/api/invite/complete", map[string]any{"token": tok, "password": "another password!"})
	wantStatus(t, res2, out, 410)
	res2, out = e.browser(t).login("acme", "newbie", "my first password")
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
	b := e.browser(t)

	// A foreign ceremony cannot be replayed here: the passkey ceremony is bound to the invitation's user and purpose.
	body, st, out := b.invitePasskeyBody(tok, nil)
	if st != 200 {
		t.Fatalf("begin: %d %v", st, out)
	}
	delete(body, "credential")
	res, out := b.post("/api/invite/complete", body)
	wantStatus(t, res, out, 422) // no password and no credential

	body, _, _ = b.invitePasskeyBody(tok, nil)
	res, out = b.post("/api/invite/complete", body)
	wantStatus(t, res, out, 200)
	if str(out, "next") != "/account" || !b.hasSession() {
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
	res, out = e.browser(t).post("/api/invite/passkey/begin", map[string]any{"token": tok})
	wantStatus(t, res, out, 410)
	b2 := e.browser(t)
	b2.auth = b.auth
	if st, out := b2.passkeyLogin(map[string]any{"org": "acme"}); st != 200 {
		t.Fatalf("passkey sign-in: %d %v", st, out)
	}
	// No password: username+password sign-in fails generically.
	res, out = e.browser(t).login("acme", "newbie", "whatever password")
	wantStatus(t, res, out, 401)
}

func TestInviteBothPasswordAndPasskey(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	b := e.browser(t)
	body, st, out := b.invitePasskeyBody(tokenOf(link), map[string]any{"password": "both ways password"})
	if st != 200 {
		t.Fatal(out)
	}
	res, out := b.post("/api/invite/complete", body)
	wantStatus(t, res, out, 200)
	fresh, _ := e.Svc.Users.Get(context.Background(), u.ID)
	list, _ := e.Svc.Passkeys.All(context.Background(), u.ID)
	if fresh.PasswordHash == "" || len(list) != 1 {
		t.Fatalf("both expected: password %v passkeys %d", fresh.PasswordHash != "", len(list))
	}
	res, out = e.browser(t).login("acme", "newbie", "both ways password")
	wantStatus(t, res, out, 200)
}

func TestInviteBadPasswordKeepsPasskeyCeremonyOutOfIt(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	b := e.browser(t)
	body, _, _ := b.invitePasskeyBody(tokenOf(link), map[string]any{"password": "short"})
	res, out := b.post("/api/invite/complete", body)
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
	b := e.browser(t)
	res, body := b.get(link)
	if res.StatusCode != 200 || strings.Contains(body, "Confirm password") || strings.Contains(body, "f-password") ||
		!strings.Contains(body, "Create a passkey") {
		t.Fatalf("passkey-only page %d: %.600s", res.StatusCode, body)
	}
	res2, out := b.post("/api/invite/complete", map[string]any{"token": tokenOf(link), "password": "a long enough password"})
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
		!strings.Contains(body, `href="/login/sso"`) || !strings.Contains(body, "sign-in providers") {
		t.Fatalf("providers-only page %d: %.800s", res.StatusCode, body)
	}
	res2, out = b.post("/api/invite/complete", map[string]any{"token": tokenOf(link2), "password": "a long enough password"})
	wantStatus(t, res2, out, 403)
	res2, out = b.post("/api/invite/passkey/begin", map[string]any{"token": tokenOf(link2)})
	wantStatus(t, res2, out, 403)
}

func TestInviteRequireMFAEnrolsBeforeSession(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "mfa", func(s *model.OrgSettings) { s.RequireMFA = true })
	u, link := e.invitee(t, org, "newbie")
	b := e.browser(t)
	res, out := b.post("/api/invite/complete", map[string]any{"token": tokenOf(link), "password": "my first password"})
	wantStatus(t, res, out, 200)
	ticket := str(out, "ticket")
	if str(out, "step") != "enrol" || ticket == "" || b.hasSession() {
		t.Fatalf("expected the enrolment step without a session: %v", out)
	}
	if res, _ := b.get("/account"); res.StatusCode == 200 {
		t.Fatal("account reachable before enrolment")
	}
	res, out = b.post("/api/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res, out, 200)
	secret := str(out, "secret")
	res, out = b.post("/api/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)
	if !b.hasSession() || str(out, "next") != "/account" {
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
	b2 := e.browser(t)
	body, _, _ := b2.invitePasskeyBody(tokenOf(link2), nil)
	res, out = b2.post("/api/invite/complete", body)
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
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.PasskeyLogin = false })
	pat := e.user(t, org, "pat", model.RoleUser)
	e.giveTOTP(t, pat)
	old := e.signedIn(t, pat) // e.g. an attacker's session
	_ = e.Svc.Identities.Create(ctx, &model.Identity{UserID: pat.ID, OrgID: org.ID, ProviderID: "p-x", Subject: "attacker"})
	if _, _, err := e.Svc.CreateAPIToken(ctx, service.ActorForUser(pat, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}}); err != nil {
		t.Fatal(err)
	}
	link := e.invite(t, pat)
	b := e.browser(t)
	res, out := b.post("/api/invite/complete", map[string]any{"token": tokenOf(link), "password": "a brand new password"})
	wantStatus(t, res, out, 200)
	if !b.hasSession() || str(out, "step") != "" {
		t.Fatalf("after the invitation: %v", out)
	}
	if res, _ := old.api("GET", "/api/account", nil); res.StatusCode != 401 {
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
	if res, out := e.browser(t).login("acme", pat.Email, "a brand new password"); res.StatusCode != 200 {
		t.Errorf("new password: %d %v", res.StatusCode, out["_raw"])
	}

	// MFA required: the reset user sets up a new second factor straight away
	org2 := e.org(t, "strict", func(s *model.OrgSettings) { s.PasskeyLogin = false; s.RequireMFA = true })
	kim := e.user(t, org2, "kim", model.RoleUser)
	e.giveTOTP(t, kim)
	link = e.invite(t, kim)
	b = e.browser(t)
	res, out = b.post("/api/invite/complete", map[string]any{"token": tokenOf(link), "password": "another new password"})
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
	res, out := e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	if err := e.Svc.RemovePassword(context.Background(), service.System, pat.ID); err != nil {
		t.Fatal(err)
	}
	if res, _ := old.get("/account"); res.StatusCode == 200 {
		t.Fatal("session survived password removal")
	}
	res, out = e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 401)
	if str(out, "error") != "The email address or password is incorrect." {
		t.Fatalf("not generic: %v", out)
	}
	// Forgot-password sends nothing to an account without a password: it needs a new invitation.
	b := e.browser(t)
	res, out = b.post("/api/password/forgot", map[string]any{"org": "acme", "email": "pat@example.com"})
	wantStatus(t, res, out, 200)
	e.noMail(t)
	// ... and a reset link that was issued before the removal no longer works.
	tok, _, err := e.Svc.IssueLink(context.Background(), pat, service.LinkReset, pat.Email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	res, out = b.post("/api/password/reset", map[string]any{"token": tok, "password": "a brand new password"})
	wantStatus(t, res, out, 410)

	// The new invitation lets the existing account choose a new password.
	link := e.invite(t, pat)
	res, out = b.post("/api/invite/complete", map[string]any{"token": tokenOf(link), "password": "a brand new password"})
	wantStatus(t, res, out, 200)
	res, out = e.browser(t).login("acme", "pat", "a brand new password")
	wantStatus(t, res, out, 200)
	res, out = e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 401)
}

func TestInviteClearsLockoutAndRevokesOlderLink(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0; c.Limits.LockoutAttempts = 2 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
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
	res, out = b.post("/api/invite/complete", map[string]any{"token": tokenOf(first), "password": "a brand new password"})
	wantStatus(t, res, out, 410)
	res, out = b.post("/api/invite/complete", map[string]any{"token": tokenOf(second), "password": "a brand new password"})
	wantStatus(t, res, out, 200)
	res, out = e.browser(t).login("acme", "pat", "a brand new password")
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
	b := e.browser(t)
	if res, _ := b.get("/invite?token=" + tok); res.StatusCode != http.StatusGone {
		t.Fatalf("expired page: %d", res.StatusCode)
	}
	res, out := b.post("/api/invite/complete", map[string]any{"token": tok, "password": "a long enough password"})
	wantStatus(t, res, out, 410)
	// A disabled account's invitation stops working.
	tok2, _, _ := e.Svc.IssueLink(context.Background(), u, service.LinkInvite, "", time.Hour)
	off := false
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, u.ID, service.UserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	res, out = b.post("/api/invite/complete", map[string]any{"token": tok2, "password": "a long enough password"})
	wantStatus(t, res, out, 410)
}

func TestInviteMailLinkWorksThroughTheModule(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, _ := e.invitee(t, org, "newbie")
	if err := e.Mailer.SendInvite(context.Background(), u, org); err != nil {
		t.Fatal(err)
	}
	m := e.nextMail(t)
	link := linkPath(t, m)
	if !strings.HasPrefix(link, "/invite?token=") || !strings.Contains(m.Text, "invited") || !strings.Contains(m.Text, "7 days") {
		t.Fatalf("mail %s", m.Text)
	}
	res, out := e.browser(t).post("/api/invite/complete", map[string]any{"token": tokenOf(link), "password": "my first password"})
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
		if err := e.Mailer.SendInvite(ctx, u, org); err != nil {
			t.Fatal(err)
		}
		link := linkPath(t, e.nextMail(t))
		if change {
			other := "elsewhere@acme.test"
			if _, err := e.Svc.UpdateUser(ctx, service.System, u.ID, service.UserInput{Email: &other}); err != nil {
				t.Fatal(err)
			}
		}
		res, out := e.browser(t).post("/api/invite/complete", map[string]any{"token": tokenOf(link), "password": "my first password"})
		wantStatus(t, res, out, 200)
		if f, _ := e.Svc.Users.Get(ctx, u.ID); f.EmailVerified == change {
			t.Fatalf("address changed=%v: verified=%v", change, f.EmailVerified)
		}
	}
}
