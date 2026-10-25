package login_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

var mailCodeRe = regexp.MustCompile(`\b(\d{6})\b`)

// emailEnv is a server that sends mail, with an organization whose settings mut sets.
func emailEnv(t *testing.T, mut func(*model.OrgSettings)) (*env, *model.Org) {
	e := newEnv(t, func(c *config.Config) { c.Mail.SMTPHost = "smtp.example.com"; c.Audit.Logins = true })
	return e, e.org(t, "acme", mut)
}

// verifiedUser creates a user whose address is verified.
func (e *env) verifiedUser(t *testing.T, org *model.Org, name string, role model.Role) *model.User {
	t.Helper()
	u := e.user(t, org, name, role)
	yes := true
	u, err := e.Svc.UpdateUser(context.Background(), service.System, u.ID, service.UserInput{Verified: &yes})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func codeFrom(t *testing.T, e *env) string {
	t.Helper()
	m := e.nextMail(t)
	if !strings.Contains(m.Subject, "sign-in code") {
		t.Fatalf("not a code: %q", m.Subject)
	}
	g := mailCodeRe.FindStringSubmatch(m.Text)
	if g == nil {
		t.Fatalf("no code in %q", m.Text)
	}
	if strings.Contains(m.Subject, g[1]) {
		t.Fatalf("the code is in the subject (shown in notification previews): %q", m.Subject)
	}
	return g[1]
}

// Codes by email are off by default: a user without a second factor is asked to set one up, and the endpoints refuse.
func TestEmailCodesOffByDefault(t *testing.T) {
	e, org := emailEnv(t, func(s *model.OrgSettings) { s.RequireMFA = true })
	e.verifiedUser(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "step") != "enrol" {
		t.Fatalf("step %v", out)
	}
	res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": str(out, "ticket")})
	wantStatus(t, res, out, 401) // an enrolment ticket is not a second-factor step
	e.noMail(t)
}

// With the organization allowing it, a user with no second factor gets a code by email instead of enrolling, and it
// signs in once, as two factors.
func TestEmailCodeStep(t *testing.T) {
	e, org := emailEnv(t, func(s *model.OrgSettings) { s.RequireMFA = true; s.EmailCodes = true })
	u := e.verifiedUser(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "step") != "email_code" || str(out, "email") != "p•••@example.com" {
		t.Fatalf("step %v", out)
	}
	tk := str(out, "ticket")
	code := codeFrom(t, e)

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": wrong})
	wantStatus(t, res, out, 401)
	if str(out, "field") != "mcode" {
		t.Fatalf("wrong code: %v", out)
	}
	if len(e.audits(t, "login.failure")) != 1 {
		t.Fatal("a wrong code is not a failure")
	}

	// asking again at once is refused; after the interval a new code ends the old one
	res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": tk})
	wantStatus(t, res, out, 429)
	e.Mod.AgeEmailCode(tk)
	res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": tk})
	wantStatus(t, res, out, 200)
	code2 := codeFrom(t, e)
	if code2 != code {
		res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": code})
		wantStatus(t, res, out, 401)
	}

	res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": code2})
	wantStatus(t, res, out, 200)
	if !b.hasSession() {
		t.Fatalf("no session: %v", out)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), u.ID)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "pwd,otp,mfa" {
		t.Fatalf("amr %+v", sess)
	}
	if len(e.audits(t, "login.email_code.sent")) != 2 {
		t.Fatal("sends not audited")
	}

	// the ticket and code are used up
	res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": code2})
	wantStatus(t, res, out, 401)
}

// A sign-in can have at most five codes sent.
func TestEmailCodeSendLimit(t *testing.T) {
	e, org := emailEnv(t, func(s *model.OrgSettings) { s.RequireMFA = true; s.EmailCodes = true })
	e.verifiedUser(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	tk := str(out, "ticket")
	codeFrom(t, e)
	for i := 0; i < 4; i++ {
		e.Mod.AgeEmailCode(tk)
		res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": tk})
		wantStatus(t, res, out, 200)
		codeFrom(t, e)
	}
	e.Mod.AgeEmailCode(tk)
	res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": tk})
	wantStatus(t, res, out, 429)
	e.noMail(t)
}

// Users with an authenticator app keep it as their second factor: codes by email are not among the alternatives,
// and a ticket of their sign-in cannot ask for one (whoever reads the mailbox and knows the password would get past
// the stronger factor). Managers and above, and addresses that are not verified, never get them either.
func TestEmailCodeNotAnAlternative(t *testing.T) {
	e, org := emailEnv(t, func(s *model.OrgSettings) { s.EmailCodes = true })
	alts := func(name string) ([]any, string, string) {
		res, out := e.browser(t).login("acme", name, userPassword)
		wantStatus(t, res, out, 200)
		a, _ := out["alternatives"].([]any)
		return a, str(out, "step"), str(out, "ticket")
	}

	pat := e.verifiedUser(t, org, "pat", model.RoleUser)
	e.giveTOTP(t, pat)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if a, _ := out["alternatives"].([]any); str(out, "step") != "totp" || len(a) != 0 || str(out, "email") != "" {
		t.Fatalf("alternatives %v", out)
	}
	tk := str(out, "ticket")
	res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": tk})
	wantStatus(t, res, out, 401)
	e.noMail(t)
	if b.hasSession() {
		t.Fatal("session")
	}

	mgr := e.verifiedUser(t, org, "mgr", model.RoleManager)
	e.giveTOTP(t, mgr)
	if a, step, tk := alts("mgr"); step != "totp" || len(a) != 0 {
		t.Fatalf("manager: %s %v", step, a)
	} else {
		res, out := e.browser(t).post("/api-internal/login/email/send", map[string]any{"ticket": tk})
		wantStatus(t, res, out, 401)
	}

	unv := e.user(t, org, "unv", model.RoleUser)
	e.giveTOTP(t, unv)
	if a, step, _ := alts("unv"); step != "totp" || len(a) != 0 {
		t.Fatalf("unverified: %s %v", step, a)
	}
	e.noMail(t)
}

// The organization setting needs the server to send email.
func TestEmailCodesNeedMail(t *testing.T) {
	e := newEnv(t, nil)
	name := "acme"
	s := model.DefaultOrgSettings()
	s.EmailCodes = true
	_, err := e.Svc.CreateOrg(context.Background(), service.System, service.OrgInput{Name: &name, Settings: &s})
	if err == nil || !strings.Contains(err.Error(), "email_codes") {
		t.Fatalf("no mail, allowed: %v", err)
	}
}
