package login_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestTOTPStep(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	u := e.user(t, e.Primary, "pat", model.RoleUser)
	secret := e.giveTOTP(t, u)

	b := e.browser(t)
	res, out := b.login("primary", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "step") != "totp" || str(out, "ticket") == "" || b.hasSession() {
		t.Fatalf("expected totp step without session: %v", out)
	}
	ticket := str(out, "ticket")

	// wrong code
	res, out = b.post("/api-internal/login/totp", map[string]any{"ticket": ticket, "code": "000000"})
	wantStatus(t, res, out, 401)
	if str(out, "field") != "code" || b.hasSession() {
		t.Fatalf("wrong code: %v", out)
	}
	// unknown ticket
	res, out = b.post("/api-internal/login/totp", map[string]any{"ticket": "n1.unknown", "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 401)

	code := totpAt(secret, time.Now())
	res, out = b.post("/api-internal/login/totp", map[string]any{"ticket": ticket, "code": code})
	wantStatus(t, res, out, 200)
	if str(out, "next") != b.base+"/account" || !b.hasSession() {
		t.Fatalf("totp success: %v", out)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), u.ID)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "pwd,otp,mfa" {
		t.Fatalf("amr %+v", sess)
	}
	// the ticket is single use
	res, out = b.post("/api-internal/login/totp", map[string]any{"ticket": ticket, "code": code})
	wantStatus(t, res, out, 401)

	// The same code cannot be used again on a fresh sign-in (replay protection)...
	b2 := e.browser(t)
	_, out = b2.login("primary", "pat", userPassword)
	res, out2 := b2.post("/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": code})
	wantStatus(t, res, out2, 401)
	if b2.hasSession() {
		t.Fatal("replayed code created a session")
	}
	// ...while the next time step still works.
	res, out2 = b2.post("/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": totpAt(secret, time.Now().Add(30*time.Second))})
	wantStatus(t, res, out2, 200)
	if si, _ := e.Svc.SignIns.Get(context.Background(), u.ID); si == nil || si.TOTPLastStep == 0 {
		t.Fatal("TOTPLastStep not stored")
	}
}

// Wrong authenticator codes count toward the account lockout shared with passwords.
func TestTOTPWrongCodesCountTowardLockout(t *testing.T) {
	e := newEnv(t, lockoutAfter(3), noIPLimit)
	u := e.user(t, e.Primary, "pat", model.RoleUser)
	e.giveTOTP(t, u)
	b := e.browser(t)
	_, out := b.login("primary", "pat", userPassword)
	tk := str(out, "ticket")
	for range 3 {
		res, out := b.post("/api-internal/login/totp", map[string]any{"ticket": tk, "code": "222222"})
		wantStatus(t, res, out, 401)
	}
	res, out := b.login("primary", "pat", userPassword)
	wantStatus(t, res, out, 429)
}

// burnCase is a sign-in step that takes five tries per ticket: wrong holds five refused tries, right the correct
// answer that is refused after them.
type burnCase struct {
	e     *env
	b     *browser
	wrong []burnTry
	right burnTry
	after func(t *testing.T, out map[string]any) // further checks, given the response to the right answer
}

type burnTry struct {
	path string
	body map[string]any
	want int
}

// Five wrong answers burn the ticket of a second-factor or enrolment step, so a guessed code cannot be searched for:
// the sixth, correct, answer is refused too, and no session or factor results.
func TestStepTicketBurnsAfterFiveWrongTries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) burnCase
	}{
		{"authenticator code", func(t *testing.T) burnCase {
			e := newEnv(t, lockoutAfter(8), noIPLimit)
			u := e.user(t, e.Primary, "pat", model.RoleUser)
			secret := e.giveTOTP(t, u)
			b := e.browser(t)
			_, out := b.login("primary", "pat", userPassword)
			tk := str(out, "ticket")
			wrong := burnTry{"login/totp", map[string]any{"ticket": tk, "code": "111111"}, 401}
			return burnCase{e: e, b: b, wrong: repeat(wrong, 5),
				right: burnTry{"login/totp", map[string]any{"ticket": tk, "code": totpAt(secret, time.Now())}, 401}}
		}},
		{"recovery code", func(t *testing.T) burnCase {
			e := newEnv(t, lockoutAfter(0), noIPLimit)
			pat := e.verifiedUser(t, e.org(t, "acme", nil), "pat", model.RoleUser)
			e.giveTOTP(t, pat)
			fresh, _ := e.Svc.Users.Get(context.Background(), pat.ID)
			codes, err := e.Svc.CreateRecoveryCodes(context.Background(), service.System, fresh)
			if err != nil {
				t.Fatal(err)
			}
			b := e.browser(t)
			_, out := b.login("acme", "pat", userPassword)
			tk := str(out, "ticket")
			wrong := burnTry{"login/recovery", map[string]any{"ticket": tk, "code": "AAAA-AAAA-AAAA-AAAA"}, 401}
			return burnCase{e: e, b: b, wrong: repeat(wrong, 5),
				right: burnTry{"login/recovery", map[string]any{"ticket": tk, "code": codes[0]}, 401},
				after: func(t *testing.T, out map[string]any) {
					if !strings.Contains(str(out, "error"), "Too many") {
						t.Fatalf("not the attempts message: %v", out["_raw"])
					}
					if left, _ := e.Svc.RecoveryCodesLeft(context.Background(), fresh); left != len(codes) {
						t.Fatalf("recovery codes left: %d, want %d", left, len(codes))
					}
				}}
		}},
		{"e-mailed code", func(t *testing.T) burnCase {
			e := newEnv(t, withSMTP, noIPLimit, auditLogins, lockoutAfter(0))
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
			try := func(c string) burnTry { return burnTry{"login/email", map[string]any{"ticket": tk, "code": c}, 401} }
			return burnCase{e: e, b: b,
				// codes of the wrong shape count as tries and never match
				wrong: []burnTry{try(""), try("12345"), try("1234567"), try("abcdef"), try(wrong)},
				right: try(code),
				after: func(t *testing.T, _ map[string]any) {
					// the sixth is refused before it is judged, and of the five wrong tries only the first is
					// audited, the others held back for the account's next event in a minute (detail.suppressed)
					if f := e.audits(t, "login.failure"); len(f) != 1 || f[0].Detail["reason"] != "email_code" {
						t.Fatalf("failures audited: %d", len(f))
					}
				}}
		}},
		{"enrolling an authenticator app", func(t *testing.T) burnCase {
			e, org := mfaEnv(t)
			pat := e.user(t, org, "pat", model.RoleUser)
			b := e.browser(t)
			_, out := b.login("acme", "pat", userPassword)
			tk := str(out, "ticket")
			res, out := b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": tk})
			wantStatus(t, res, out, 200)
			secret := str(out, "secret")
			wrong := burnTry{"login/enrol/totp/confirm", map[string]any{"ticket": tk, "code": "000000"}, 401}
			return burnCase{e: e, b: b, wrong: repeat(wrong, 5),
				right: burnTry{"login/enrol/totp/confirm", map[string]any{"ticket": tk, "code": totpAt(secret, time.Now())}, 401},
				after: func(t *testing.T, _ map[string]any) {
					if f, _ := e.Svc.Users.Get(context.Background(), pat.ID); f.HasTOTP() {
						t.Fatal("factor stored by a burnt ticket")
					}
				}}
		}},
		{"enrolling a passkey", func(t *testing.T) burnCase {
			e, org := mfaEnv(t)
			pat := e.user(t, org, "pat", model.RoleUser)
			b := e.browser(t)
			_, out := b.login("acme", "pat", userPassword)
			tk := str(out, "ticket")
			res, begin := b.post("/api-internal/login/enrol/passkey/begin", map[string]any{"ticket": tk})
			wantStatus(t, res, begin, 200)
			opts, _ := json.Marshal(begin["options"])
			good, _, _ := b.auth.Create(opts)
			wrong := burnTry{"login/enrol/passkey/finish", map[string]any{"ticket": tk, "challenge": "nope", "credential": json.RawMessage(`{}`)}, 422}
			return burnCase{e: e, b: b, wrong: repeat(wrong, 5),
				right: burnTry{"login/enrol/passkey/finish", map[string]any{"ticket": tk, "challenge": begin["challenge"], "credential": json.RawMessage(good)}, 401},
				after: func(t *testing.T, _ map[string]any) {
					if n := e.passkeyCount(t, pat); n != 0 {
						t.Fatalf("passkeys stored by a burnt ticket: %d", n)
					}
				}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.setup(t)
			for i, try := range c.wrong {
				res, out := c.b.post("/api-internal/"+try.path, try.body)
				if res.StatusCode != try.want {
					t.Fatalf("try %d: status %d, want %d: %v", i+1, res.StatusCode, try.want, out["_raw"])
				}
			}
			res, out := c.b.post("/api-internal/"+c.right.path, c.right.body)
			wantStatus(t, res, out, c.right.want)
			if c.b.hasSession() {
				t.Fatal("session from a burnt ticket")
			}
			if c.after != nil {
				c.after(t, out)
			}
		})
	}
}

func repeat[T any](v T, n int) []T {
	l := make([]T, n)
	for i := range l {
		l[i] = v
	}
	return l
}

func TestRecoveryCodeStep(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	u := e.user(t, e.Primary, "pat", model.RoleUser)
	e.giveTOTP(t, u)
	u, _ = e.Svc.Users.Get(context.Background(), u.ID)
	codes, err := e.Svc.CreateRecoveryCodes(context.Background(), service.System, u)
	if err != nil {
		t.Fatal(err)
	}
	ticket := func(b *browser) string {
		res, out := b.login("primary", "pat", userPassword)
		wantStatus(t, res, out, 200)
		if str(out, "step") != "totp" {
			t.Fatalf("no second-factor step: %v", out)
		}
		return str(out, "ticket")
	}

	b := e.browser(t)
	tk := ticket(b)
	res, out := b.post("/api-internal/login/recovery", map[string]any{"ticket": tk, "code": "AAAA-AAAA-AAAA-AAAA"})
	wantStatus(t, res, out, 401)
	if str(out, "field") != "rcode" || b.hasSession() {
		t.Fatalf("wrong code: %v", out)
	}
	res, out = b.post("/api-internal/login/recovery", map[string]any{"ticket": tk, "code": strings.ToLower(codes[2])})
	wantStatus(t, res, out, 200)
	if str(out, "next") != b.base+"/account" || !b.hasSession() {
		t.Fatalf("recovery sign-in: %v", out)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), u.ID)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "pwd,otp,mfa" {
		t.Fatalf("amr %+v", sess)
	}
	if m := e.nextMail(t); !strings.Contains(m.Subject, "recovery code was used") || !strings.Contains(m.Text, "9 of them are left") {
		t.Fatalf("notice: %q %q", m.Subject, m.Text)
	}
	if len(e.audits(t, "login.recovery_code")) != 1 {
		t.Fatal("not audited")
	}

	// the same code again, from another browser: refused
	b2 := e.browser(t)
	res, out = b2.post("/api-internal/login/recovery", map[string]any{"ticket": ticket(b2), "code": codes[2]})
	wantStatus(t, res, out, 401)

	// a ticket that has not passed the first factor, or an unknown one: refused
	res, out = b2.post("/api-internal/login/recovery", map[string]any{"ticket": "n1.unknown", "code": codes[3]})
	wantStatus(t, res, out, 401)
}

// Once an account has used up its failed attempts, a second-factor step that was begun before is refused too, with
// the right answer, whichever factor it is: the lockout cannot be walked around through a ticket held earlier.
func TestStepsHeldBeforeLockoutAreRefused(t *testing.T) {
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
	if left, _ := e.Svc.RecoveryCodesLeft(context.Background(), fresh); left != len(codes) {
		t.Fatalf("recovery codes left: %d, want %d", left, len(codes))
	}
	if sess, _ := e.Svc.Sessions.All(context.Background(), pat.ID); len(sess) != 0 {
		t.Fatalf("sessions created while locked: %d", len(sess))
	}
}

// "Try another way" at the authenticator-code step: the step lists the account's other ways (a passkey, recovery
// codes left), and a passkey is accepted there in place of the code.
func TestSecondFactorAlternatives(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	e.giveTOTP(t, pat)
	alts := func() ([]any, string) {
		res, out := e.browser(t).login("acme", "pat", userPassword)
		wantStatus(t, res, out, 200)
		a, _ := out["alternatives"].([]any)
		return a, str(out, "step")
	}
	if a, step := alts(); step != "totp" || len(a) != 0 {
		t.Fatalf("no other way: %s %v", step, a)
	}

	signed := e.signedIn(t, pat)
	signed.registerPasskey("Laptop")
	u, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	if _, err := e.Svc.CreateRecoveryCodes(context.Background(), nil, u); err != nil {
		t.Fatal(err)
	}
	if a, step := alts(); step != "totp" || len(a) != 2 || a[0] != "passkey" || a[1] != "recovery" {
		t.Fatalf("passkey and codes: %s %v", step, a)
	}

	// the passkey in place of the code, with the authenticator-code step's ticket
	b := e.browser(t)
	b.auth = signed.auth
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	status, done := b.passkeyLogin(map[string]any{"ticket": str(out, "ticket")})
	if status != 200 || !b.hasSession() {
		t.Fatalf("passkey at the code step: %d %v", status, done)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), pat.ID)
	found := false
	for _, s := range sess {
		if strings.HasPrefix(strings.Join(s.AMR, ","), "pwd,") && strings.HasSuffix(strings.Join(s.AMR, ","), ",mfa") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no two-factor session: %+v", sess)
	}
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
