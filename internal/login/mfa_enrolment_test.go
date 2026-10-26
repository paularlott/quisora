package login_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
	"github.com/paularlott/quisora/internal/service"
)

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

// Enrolling a passkey at sign-in: garbage, a response from another origin, and an authenticator that does not verify
// its user are all refused without a session, and the ticket stays usable until the tries run out.
func TestEnrolPasskeyRefusedCeremonies(t *testing.T) {
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

	for _, tc := range []struct {
		name       string
		credential func(t *testing.T, opts []byte) []byte
	}{
		{"garbage", func(*testing.T, []byte) []byte { return []byte(`{"id":"x"}`) }},
		{"another origin", func(t *testing.T, opts []byte) []byte {
			cred, _, err := virtualauth.New("https://evil.example").Create(opts)
			if err != nil {
				t.Fatal(err)
			}
			return cred
		}},
		{"no user verification", func(t *testing.T, opts []byte) []byte {
			b.auth.UserVerified = false
			defer func() { b.auth.UserVerified = true }()
			cred, _, err := b.auth.Create(opts)
			if err != nil {
				t.Fatal(err)
			}
			return cred
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch, opts := begin()
			finish(ch, tc.credential(t, opts), 422)
		})
	}

	if b.hasSession() || e.passkeyCount(t, pat) != 0 {
		t.Fatal("refused ceremonies left a session or a passkey")
	}

	// the ticket still works for a proper ceremony; an unnamed passkey is called "Passkey"
	ch, opts := begin()
	cred, _, err := b.auth.Create(opts)
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

// A passkey that cannot sign in (disabled, or registered without user verification) does not count as the second
// factor, yet it shows the account had one: with only such a passkey a required-MFA sign-in is refused (an
// administrator's invitation restores access) rather than letting the password enrol a new factor. A passkey left from
// before a reset is inert and stands in the way of nothing.
func TestPasskeysThatCannotSignInAndMFAEnrolment(t *testing.T) {
	for _, tc := range []struct {
		name    string
		passkey model.Passkey
		epoch   bool // the account's credential epoch has moved on from the passkey's
		problem string
		enrol   bool
	}{
		{"unverified", model.Passkey{Name: "Old", CredentialID: []byte("legacy-cred"), PublicKey: []byte{1}}, false, "unverified", false},
		{"disabled", model.Passkey{Name: "Old", CredentialID: []byte("legacy-cred"), PublicKey: []byte{1}, UserVerified: true, Disabled: true}, false, "disabled", false},
		// failed cleanup or a delayed losing invitation can leave such a record stored
		{"from an earlier epoch", model.Passkey{Name: "Old", CredentialID: []byte("old-epoch-key"), UserVerified: true}, true, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
			pat := e.user(t, org, "pat", model.RoleUser)
			if tc.epoch {
				pat.CredEpoch = service.NewCredEpoch()
				if err := e.Svc.Users.Update(context.Background(), pat); err != nil {
					t.Fatal(err)
				}
			}
			pk := tc.passkey
			pk.UserID, pk.OrgID = pat.ID, org.ID
			if err := e.Svc.Passkeys.Create(context.Background(), &pk); err != nil {
				t.Fatal(err)
			}
			b := e.browser(t)
			res, out := b.login("acme", "pat", userPassword)
			if tc.enrol {
				wantStatus(t, res, out, 200)
				if str(out, "step") != "enrol" {
					t.Fatalf("not offered enrolment: %v", out)
				}
				return
			}
			wantStatus(t, res, out, 403)
			if b.hasSession() || !strings.Contains(str(out, "error"), "invitation") {
				t.Fatalf("an account whose passkey cannot sign in was offered enrolment: %v", out)
			}
			// and the account page says why
			res, out = e.signedIn(t, pat).api("GET", "/api-internal/account/passkeys", nil)
			wantStatus(t, res, out, 200)
			if l := items(t, out); len(l) != 1 || l[0]["problem"] != tc.problem {
				t.Fatalf("problem not reported: %v", out["_raw"])
			}
		})
	}
}
