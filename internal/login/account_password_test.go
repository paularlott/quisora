package login_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestAccountPassword(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LockoutAttempts = 3; c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	cur := e.signedIn(t, pat)
	other := e.signedIn(t, pat)                   // a second session of the same user
	baseline := len(e.audits(t, "user.password")) // the fixture set the first password as the system

	res, out := cur.api("POST", "/api-internal/account/password", map[string]any{"current": "nope", "new": "a perfectly fine password"})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "current" {
		t.Fatalf("wrong current: %v", out)
	}
	res, out = cur.api("POST", "/api-internal/account/password", map[string]any{"current": "", "new": "a perfectly fine password"})
	wantStatus(t, res, out, 422)
	res, out = cur.api("POST", "/api-internal/account/password", map[string]any{"current": userPassword, "new": "short"})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "new" {
		t.Fatalf("weak: %v", out)
	}
	res, out = cur.api("POST", "/api-internal/account/password", map[string]any{"current": userPassword, "new": userPassword})
	wantStatus(t, res, out, 422)

	res, out = cur.api("POST", "/api-internal/account/password", map[string]any{"current": userPassword, "new": "a perfectly fine password"})
	wantStatus(t, res, out, 200)
	if out["signed_out"] != float64(1) {
		t.Fatalf("signed_out %v", out)
	}
	if res, _ := cur.get("/account"); res.StatusCode != 200 {
		t.Fatal("current session ended by password change")
	}
	if res, _ := other.api("GET", "/api-internal/account", nil); res.StatusCode != 401 {
		t.Fatalf("other session survived: %d", res.StatusCode)
	}
	res, out = e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 401)
	res, out = e.browser(t).login("acme", "pat", "a perfectly fine password")
	wantStatus(t, res, out, 200)

	// Wrong current passwords count toward the lockout (shared with sign-in).
	for range 3 {
		cur.api("POST", "/api-internal/account/password", map[string]any{"current": "wrong", "new": "x"})
	}
	res, out = cur.api("POST", "/api-internal/account/password", map[string]any{"current": "a perfectly fine password", "new": "another fine password"})
	wantStatus(t, res, out, 429)
	if n := len(e.audits(t, "user.password")) - baseline; n != 1 {
		t.Fatalf("password audit %d", n)
	}
}

// An account without a password (set up with an authenticator app, a passkey or a provider) adds its first one from
// the account page, where its organization uses passwords, after confirming it is them with what it already signs in
// with: a session alone cannot add a way in.
func TestAccountPasswordForPasswordlessUser(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	name, email := "fed", "fed@example.com"
	u, _ := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{GivenName: ptr("T"), Username: &name, Email: &email})
	secret := e.giveTOTP(t, u)
	b := e.signedIn(t, u)

	res, out := b.api("GET", "/api-internal/account", nil)
	sec := out["security"].(map[string]any)
	if sec["has_password"] != false || sec["passwords_allowed"] != true {
		t.Fatalf("security: %v", out["_raw"])
	}
	// not without confirming first
	res, out = b.api("POST", "/api-internal/account/password", map[string]any{"new": "my first password!"})
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Fatalf("not confirmed: %v", out)
	}
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)
	res, out = b.api("POST", "/api-internal/account/password", map[string]any{"new": "short"})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "new" {
		t.Fatalf("short password: %v", out)
	}
	res, out = b.api("POST", "/api-internal/account/password", map[string]any{"new": "my first password!"})
	wantStatus(t, res, out, 200)
	got, _ := e.Svc.Users.Get(context.Background(), u.ID)
	if ok, err := e.Svc.VerifyPassword(context.Background(), "", got, "my first password!"); err != nil || !ok {
		t.Fatalf("password not set: %v %v", ok, err)
	}
	// the session that set it carries on, and from now on changing it needs the current one
	res, out = b.api("POST", "/api-internal/account/password", map[string]any{"new": "yet another password"})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "current" {
		t.Fatalf("change without the current password: %v", out)
	}

	// a passkey-only account confirms with its passkey
	name2, email2 := "pk", "pk@example.com"
	pk, _ := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{GivenName: ptr("P"), Username: &name2, Email: &email2})
	setup := e.signedIn(t, pk)
	setup.fresh()
	setup.registerPasskey("Key")
	c := e.signedIn(t, pk) // another browser, signed in an hour ago
	c.auth = setup.auth
	res, out = c.api("POST", "/api-internal/account/password", map[string]any{"new": "passkey user password"})
	wantStatus(t, res, out, 403)
	res, begin := c.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	assertion, _, err := c.auth.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, out = c.api("POST", "/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(assertion)})
	wantStatus(t, res, out, 200)
	res, out = c.api("POST", "/api-internal/account/password", map[string]any{"new": "passkey user password"})
	wantStatus(t, res, out, 200)

	// an organization without passwords offers none
	nopw := e.org(t, "nopw", func(s *model.OrgSettings) { s.PasswordLogin = false })
	name3, email3 := "np", "np@example.com"
	np, _ := e.Svc.CreateUser(context.Background(), service.System, nopw.ID, service.UserInput{GivenName: ptr("N"), Username: &name3, Email: &email3})
	d := e.signedIn(t, np)
	d.fresh()
	res, out = d.api("GET", "/api-internal/account", nil)
	if out["security"].(map[string]any)["passwords_allowed"] != false {
		t.Fatalf("passwords_allowed: %v", out["_raw"])
	}
	res, out = d.api("POST", "/api-internal/account/password", map[string]any{"new": "not allowed here!"})
	wantStatus(t, res, out, 409)
}
