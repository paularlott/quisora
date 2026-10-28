package login_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/service"
	"golang.org/x/crypto/bcrypt"
)

// A user imported with a password hash and an authenticator secret (the 16-character kind other systems make, and a
// 160-bit one) signs in with the password and a code from the app they already have, as a user who set it up here;
// the app is a second factor with no recovery codes, which the account page says (it offers to make them).
func TestImportedTOTPSignsIn(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	bc, err := bcrypt.GenerateFromPassword([]byte("old system password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, given, secret string }{
		{"short", "jbsw y3dp ehpk 3pxp", "JBSWY3DPEHPK3PXP"},
		{"long", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"},
	} {
		t.Run(c.name, func(t *testing.T) {
			u, err := e.Svc.CreateUser(context.Background(), service.System, e.Primary.ID, service.UserInput{GivenName: ptr("Pat"),
				Username: ptr(c.name), Email: ptr(c.name + "@example.com"), PasswordHash: ptr(string(bc)), TOTPSecret: ptr(c.given)})
			if err != nil {
				t.Fatal(err)
			}
			b := e.browser(t)
			res, out := b.login("primary", c.name, "old system password")
			wantStatus(t, res, out, 200)
			if str(out, "step") != "totp" || b.hasSession() {
				t.Fatalf("expected the authenticator step: %v", out)
			}
			// a wrong code, then the right one from the app (the clock's current step)
			res, out2 := b.post("/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": "000000"})
			wantStatus(t, res, out2, 401)
			res, out2 = b.post("/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": totpAt(c.secret, time.Now())})
			wantStatus(t, res, out2, 200)
			if !b.hasSession() {
				t.Fatalf("no session: %v", out2)
			}
			sess, _ := e.Svc.Sessions.All(context.Background(), u.ID)
			if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "pwd,otp,mfa" {
				t.Fatalf("amr %+v", sess)
			}

			// no recovery codes yet: the account page offers them
			_, body := b.get("/api-internal/account")
			var acct struct {
				Security struct {
					TOTP              bool       `json:"totp"`
					RecoveryAvailable bool       `json:"recovery_available"`
					RecoveryCreated   *time.Time `json:"recovery_created"`
					RecoveryLeft      int        `json:"recovery_left"`
				}
			}
			if err := json.Unmarshal([]byte(body), &acct); err != nil {
				t.Fatal(err)
			}
			if s := acct.Security; !s.TOTP || !s.RecoveryAvailable || s.RecoveryCreated != nil || s.RecoveryLeft != 0 {
				t.Fatalf("security: %+v", s)
			}
		})
	}
}

// A user imported with a link to an organization's provider signs in through it with the subject the provider
// asserts, whatever address the provider sends; another subject is not that user, and the provider (which does not
// create accounts here) signs nobody in.
func TestImportedLinkSignsIn(t *testing.T) {
	u := newUpEnv(t)
	p := u.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	pat, err := u.Svc.CreateUser(context.Background(), service.System, u.org.ID, service.UserInput{GivenName: ptr("Pat"),
		Email: ptr("pat@acme.example"), Identities: []service.IdentityInput{{Provider: strings.ToLower(p.Name), Subject: "freedom3-42"}}})
	if err != nil {
		t.Fatal(err)
	}

	b := u.browser(t)
	res := b.via(t, u, p, "acme", "/x", claims("freedom3-42", "unrelated@corp.example"))
	if res.StatusCode != 303 || res.Header.Get("Location") != u.at("/x") || !b.hasSession() {
		t.Fatalf("callback: %d %q session=%v", res.StatusCode, res.Header.Get("Location"), b.hasSession())
	}
	if sess := sessionsOf(t, u.env, pat); len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "fed" {
		t.Fatalf("sessions %+v", sess)
	}

	b2 := u.browser(t)
	if res := b2.via(t, u, p, "acme", "/x", claims("freedom3-43", "pat@acme.example")); b2.hasSession() {
		t.Fatalf("a subject nobody linked signed in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if n, _ := u.Svc.Users.Count(context.Background(), u.org.ID); n != 1 {
		t.Fatalf("users %d", n)
	}
}
