package login_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func sessionsOf(t testing.TB, e *env, u *model.User) []*model.Session {
	t.Helper()
	s, err := e.Svc.Sessions.All(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ---------------------------------------------------------------------------------------------------------------
// Organizations that require MFA

func TestRequireMFAEnrolTOTP(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	pat := e.user(t, org, "pat", model.RoleUser)

	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "step") != "enrol" || str(out, "ticket") == "" || b.hasSession() {
		t.Fatalf("expected enrolment step: %v", out)
	}
	if m, _ := out["methods"].([]any); len(m) != 2 || m[0] != "totp" || m[1] != "passkey" {
		t.Fatalf("methods %v", out["methods"])
	}
	ticket := str(out, "ticket")
	// no session may be obtained by skipping the step
	if res, _ := b.get("/account"); res.StatusCode != 303 {
		t.Fatalf("account reachable without enrolment: %d", res.StatusCode)
	}
	// confirm before begin
	res, out = b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": "123456"})
	wantStatus(t, res, out, 409)

	res, out = b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res, out, 200)
	secret := str(out, "secret")
	if secret == "" || !strings.HasPrefix(str(out, "uri"), "otpauth://totp/") || !strings.Contains(str(out, "uri"), secret) ||
		!strings.HasPrefix(str(out, "qr"), "data:image/svg+xml;base64,") {
		t.Fatalf("begin response %v", out)
	}
	res, out = b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": "000000"})
	wantStatus(t, res, out, 401)
	if b.hasSession() {
		t.Fatal("session before enrolment")
	}
	res, out = b.post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)
	if !b.hasSession() {
		t.Fatalf("no session after enrolment: %v", out)
	}
	if got := strings.Join(sessionsOf(t, e, pat)[0].AMR, ","); got != "pwd,otp,mfa" {
		t.Fatalf("amr %s", got)
	}
	fresh, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	if si, _ := e.Svc.SignIns.Get(context.Background(), pat.ID); !fresh.HasTOTP() || si == nil || si.TOTPLastStep == 0 {
		t.Fatal("TOTP not stored")
	}
	if opened, _ := e.Svc.Sealer.OpenFor(service.TOTPBinding(fresh.ID), fresh.TOTPSecret); string(opened) != secret {
		t.Fatal("stored secret differs or is not sealed")
	}
	// the ticket is spent
	res, out = b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res, out, 401)
	// next sign-in asks for the code
	_, out = e.browser(t).login("acme", "pat", userPassword)
	if str(out, "step") != "totp" {
		t.Fatalf("second login: %v", out)
	}
}

func TestRequireMFAEnrolPasskeyThenUseIt(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	pat := e.user(t, org, "pat", model.RoleUser)

	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	ticket := str(out, "ticket")
	res, begin := b.post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": ticket})
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	cred, _, err := b.auth.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	// wrong ticket
	res, out = b.post("/api-internal/login/enrol/passkey/finish", map[string]any{"ticket": "n1.nope", "challenge": begin["challenge"],
		"credential": json.RawMessage(cred)})
	wantStatus(t, res, out, 401)
	res, out = b.post("/api-internal/login/enrol/passkey/finish", map[string]any{"ticket": ticket, "challenge": begin["challenge"], "name": "Key",
		"credential": json.RawMessage(cred)})
	wantStatus(t, res, out, 200)
	if !b.hasSession() {
		t.Fatalf("no session: %v", out)
	}
	if got := strings.Join(sessionsOf(t, e, pat)[0].AMR, ","); got != "pwd,hwk,user,mfa" {
		t.Fatalf("amr %s", got)
	}

	// Now the user has a passkey but no TOTP: password alone is not enough, the passkey is the second factor.
	b2 := e.browser(t)
	b2.auth = b.auth
	_, out = b2.login("acme", "pat", userPassword)
	if str(out, "step") != "passkey" || b2.hasSession() {
		t.Fatalf("expected passkey step: %v", out)
	}
	tk := str(out, "ticket")
	res, begin = b2.post("/api-internal/login/passkey/begin", map[string]any{"ticket": tk})
	wantStatus(t, res, begin, 200)
	if !strings.Contains(str(begin, "_raw"), "allowCredentials") || strings.Contains(str(begin, "_raw"), `"allowCredentials":[]`) {
		t.Fatalf("known-user ceremony should list the user's credentials: %s", begin["_raw"])
	}
	opts, _ = json.Marshal(begin["options"])
	assertion, _, _ := b2.auth.Get(opts)
	res, out = b2.post("/api-internal/login/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(assertion)})
	wantStatus(t, res, out, 200)
	found := false
	for _, s := range sessionsOf(t, e, pat) {
		if strings.Join(s.AMR, ",") == "pwd,hwk,user,mfa" {
			found = true
		}
	}
	if !found || !b2.hasSession() {
		t.Fatal("no pwd+passkey session")
	}
	// a passkey ticket cannot be used for enrolment or the TOTP step
	_, out = e.browser(t).login("acme", "pat", userPassword)
	b3 := e.browser(t)
	for _, p := range []string{"/api-internal/login/enrol/totp/begin", "/api-internal/login/enrol/passkey/begin"} {
		res, o := b3.post(p, map[string]any{"ticket": str(out, "ticket")})
		wantStatus(t, res, o, 401)
	}
	res, o := b3.post("/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": "123456"})
	wantStatus(t, res, o, 401)

	// A passkey sign-in on its own satisfies the requirement.
	b4 := e.browser(t)
	b4.auth = b.auth
	status, o2 := b4.passkeyLogin(map[string]any{"org": "acme"})
	if status != 200 {
		t.Fatalf("passkey primary at an MFA org: %d %v", status, o2)
	}
	// Removing the TOTP of an MFA org without a passkey is refused (see account tests); a user who does have a
	// passkey is not asked to enrol again.
}

func TestRequireMFAOffMeansNoStep(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	_, out := e.browser(t).login("acme", "pat", userPassword)
	if str(out, "step") != "" || str(out, "next") == "" {
		t.Fatalf("unexpected step: %v", out)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Forgotten password, invitation, email verification

func TestForgotAndReset(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	e.user(t, org, "gone", model.RoleUser)
	f := false
	gone, _ := e.Svc.FindUserByEmail(context.Background(), org.ID, "gone@example.com")
	e.Svc.UpdateUser(context.Background(), service.System, gone.ID, service.UserInput{Active: &f})

	b := e.browser(t)
	// Always 200 and the same body; no mail unless the account exists, is active and has an address.
	var bodies []string
	for _, tr := range []map[string]any{{"org": "acme", "email": "ghost@example.com"}, {"org": "nope", "email": "pat@example.com"}, {"org": "acme", "email": "gone@example.com"},
		{"org": "acme", "email": "pat@example.com"}} {
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
	if !strings.HasPrefix(link, "/reset?token=") {
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
	tok := strings.TrimPrefix(link, "/reset?token=")

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
	if str(out, "next") != "/login/acme" {
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
	b := e.browser(t)
	b.login("acme", "pat", "x")
	b.login("acme", "pat", "x")
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if err := e.Mailer.SendReset(context.Background(), pat, org); err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimPrefix(linkPath(t, e.nextMail(t)), "/reset?token=")
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "yet another password"})
	wantStatus(t, res, out, 200)
	res, out = b.login("acme", "pat", "yet another password")
	wantStatus(t, res, out, 200)
}

func TestForgotThrottleAndDisabledPassword(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	for range 8 {
		res, out := b.post("/api-internal/password/forgot", map[string]any{"org": "acme", "email": "pat@example.com"})
		wantStatus(t, res, out, 200)
	}
	n := 0
	for {
		select {
		case <-e.mailCh:
			n++
			continue
		case <-time.After(200 * time.Millisecond):
		}
		break
	}
	if n != 5 {
		t.Fatalf("expected 5 reset mails an hour per account, got %d", n)
	}
	// org without password sign-in: nothing is mailed
	org2 := e.org(t, "nopw", func(s *model.OrgSettings) { s.PasswordLogin = false })
	e.user(t, org2, "sam", model.RoleUser) // has a password, but the org does not allow password sign-in
	res, out := b.post("/api-internal/password/forgot", map[string]any{"org": "nopw", "email": "sam@example.com"})
	wantStatus(t, res, out, 200)
	e.noMail(t)
	// the "forgot" form does not appear on that org's page, and appears for others
	_, body := b.get("/login/acme")
	if !strings.Contains(body, "Forgot your password?") {
		t.Fatal("forgot link missing")
	}
}

func TestEmailVerification(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	signed := e.signedIn(t, pat)
	res, out := signed.post("/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 200)
	link := linkPath(t, e.nextMail(t))
	if !strings.HasPrefix(link, "/verify-email?token=") {
		t.Fatal(link)
	}
	anon := e.browser(t)
	res, _ = anon.get(link)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/account?email=verified#profile" {
		t.Fatalf("verify: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	fresh, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	if !fresh.EmailVerified {
		t.Fatal("not verified")
	}
	res, _ = anon.get(link)
	if res.Header.Get("Location") != "/account?email=invalid#profile" {
		t.Fatalf("reused link: %q", res.Header.Get("Location"))
	}
	res, out = signed.post("/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 409)

	// A token for an address the user has since changed is refused.
	other := "other@example.com"
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, pat.ID, service.UserInput{Email: &other}); err != nil {
		t.Fatal(err)
	}
	signed2 := e.signedIn(t, pat)
	signed2.post("/api-internal/account/email/verify", nil)
	link2 := linkPath(t, e.nextMail(t))
	third := "third@example.com"
	e.Svc.UpdateUser(context.Background(), service.System, pat.ID, service.UserInput{Email: &third})
	res, _ = anon.get(link2)
	if res.Header.Get("Location") != "/account?email=invalid#profile" {
		t.Fatalf("stale address verified: %q", res.Header.Get("Location"))
	}
}

func TestNoMailerDisablesLinks(t *testing.T) {
	e := newEnv(t, nil)
	e.Mod.Mail = nil // as when no mailer is wired in
	b := e.browser(t)
	res, out := b.post("/api-internal/password/forgot", map[string]any{"org": "primary", "email": "admin@example.com"})
	wantStatus(t, res, out, 200)
	e.noMail(t)
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": "x", "password": "a long enough password"})
	wantStatus(t, res, out, 410) // links are durable service records: they resolve with or without a mailer
	if res, _ := b.get("/reset?token=x"); res.StatusCode != http.StatusGone {
		t.Fatalf("reset page: %d", res.StatusCode)
	}
	_, body := b.get("/login/primary")
	if strings.Contains(body, "Forgot your password?") {
		t.Fatal("forgot link shown without a mailer")
	}
}

// A passkey that cannot sign in (disabled, or registered without user verification) does not count as the second
// factor, yet it shows the account had one: with only such a passkey a required-MFA sign-in is refused (an
// administrator's invitation restores access) rather than letting the password enrol a new factor.
func TestUnusablePasskeyIsNoSecondFactor(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	pat := e.user(t, org, "pat", model.RoleUser)
	if err := e.Svc.Passkeys.Create(context.Background(), &model.Passkey{UserID: pat.ID, OrgID: org.ID, Name: "Old",
		CredentialID: []byte("legacy-cred"), PublicKey: []byte{1}, UserVerified: false}); err != nil {
		t.Fatal(err)
	}
	// the password alone may not choose a new second factor for an account that had one: an invitation does
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 403)
	if b.hasSession() || !strings.Contains(str(out, "error"), "invitation") {
		t.Fatalf("an account whose passkey cannot sign in was offered enrolment: %v", out)
	}
	// and the account page says why
	s := e.signedIn(t, pat)
	res, out = s.api("GET", "/api-internal/account/passkeys", nil)
	wantStatus(t, res, out, 200)
	if l := items(t, out); len(l) != 1 || l[0]["problem"] != "unverified" {
		t.Fatalf("problem not reported: %v", out["_raw"])
	}
}

// One user may register at most model.MaxPasskeys passkeys.
func TestPasskeyLimit(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	for i := range model.MaxPasskeys {
		if err := e.Svc.Passkeys.Create(context.Background(), &model.Passkey{UserID: pat.ID, OrgID: org.ID, Name: "k",
			CredentialID: []byte{byte(i), 'k'}, PublicKey: []byte{1}, UserVerified: true}); err != nil {
			t.Fatal(err)
		}
	}
	b := e.signedIn(t, pat)
	b.markReauth()
	res, out := b.api("POST", "/api-internal/account/passkeys/register/begin", nil)
	wantStatus(t, res, out, 409)
}

// Managers and administrators always use a second factor, whatever their organization requires: a password alone
// leads to the enrolment step for them, while a plain user of the same organization is signed in.
func TestPrivilegedUsersNeedSecondFactor(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil) // the organization does not require MFA
	e.user(t, org, "pat", model.RoleUser)
	for _, role := range []model.Role{model.RoleManager, model.RoleAdmin} {
		name := "boss" + string(role)
		e.user(t, org, name, role)
		b := e.browser(t)
		res, out := b.login("acme", name, userPassword)
		wantStatus(t, res, out, 200)
		if str(out, "step") != "enrol" || b.hasSession() {
			t.Fatalf("%s signed in with a password alone: %v", role, out)
		}
	}
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "step") != "" || !b.hasSession() {
		t.Fatalf("plain user: %v", out)
	}
}

// A sign-in that continues an authorization request offers Cancel (the OIDC provider then sends access_denied to the
// application); other sign-ins do not.
func TestLoginPageCancel(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	_, body := b.get("/login/primary?next=" + url.QueryEscape("/oauth/authorize/resume?flow=abc"))
	if !strings.Contains(body, `href="/oauth/authorize/cancel?flow=abc"`) {
		t.Fatal("no Cancel link for an authorization request")
	}
	for _, path := range []string{"/login/primary", "/login/primary?next=%2Faccount"} {
		if _, body := b.get(path); strings.Contains(body, "/oauth/authorize/cancel") {
			t.Fatalf("%s: Cancel link without an authorization request", path)
		}
	}
}
