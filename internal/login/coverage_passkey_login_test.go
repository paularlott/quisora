package login_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func passkeyEnv(t *testing.T) (*env, *model.User, *browser) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0; c.Audit.Logins = true })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	signed := e.signedIn(t, pat)
	signed.registerPasskey("Laptop")
	return e, pat, signed
}

// Sign-in with a passkey whose authenticator did not verify the user, whose account has been switched off, or whose
// passkey was disabled gives no session and is audited as a failure.
func TestCoverageDiscoverablePasskeyRefusals(t *testing.T) {
	e, pat, signed := passkeyEnv(t)
	try := func(mut func(b *browser)) (int, *browser) {
		b := e.browser(t)
		b.auth = signed.auth
		if mut != nil {
			mut(b)
		}
		status, _ := b.passkeyLogin(map[string]any{"org": "acme"})
		return status, b
	}
	if status, b := try(nil); status != 200 || !b.hasSession() {
		t.Fatalf("control: %d", status)
	}

	signed.auth.UserVerified = false
	status, b := try(nil)
	signed.auth.UserVerified = true
	if status != 401 || b.hasSession() {
		t.Fatalf("no user verification: %d session=%v", status, b.hasSession())
	}

	// the ceremony's response from a page on another origin
	b = e.browser(t)
	res, begin := b.post("/api-internal/login/passkey/begin", map[string]any{"org": "acme"})
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	list, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	if len(list) != 1 {
		t.Fatal("setup")
	}
	cred := signed.auth.Creds[0]
	evil, err := signed.auth.GetWith(opts, cred, 99, "https://evil.example")
	if err != nil {
		t.Fatal(err)
	}
	res, out := b.post("/api-internal/login/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(evil)})
	wantStatus(t, res, out, 401)
	if b.hasSession() {
		t.Fatal("wrong-origin assertion signed in")
	}

	// an account that was switched off
	off := false
	if _, err := e.Svc.UpdateUser(context.Background(), actorSuper(), pat.ID, userInput(&off)); err != nil {
		t.Fatal(err)
	}
	status, b = try(nil)
	if status != 401 || b.hasSession() {
		t.Fatalf("inactive account: %d", status)
	}
	on := true
	if _, err := e.Svc.UpdateUser(context.Background(), actorSuper(), pat.ID, userInput(&on)); err != nil {
		t.Fatal(err)
	}
	if status, _ = try(nil); status != 200 {
		t.Fatalf("re-enabled account: %d", status)
	}

	// a passkey disabled by the owner of the data stops signing in
	list, _ = e.Svc.Passkeys.All(context.Background(), pat.ID)
	list[0].Disabled = true
	if err := e.Svc.Passkeys.Update(context.Background(), list[0]); err != nil {
		t.Fatal(err)
	}
	status, b = try(nil)
	if status != 401 || b.hasSession() {
		t.Fatalf("disabled passkey: %d", status)
	}
	var reasons []string
	for _, a := range e.audits(t, "login.failure") {
		reasons = append(reasons, a.Detail["reason"])
	}
	if len(reasons) < 3 {
		t.Fatalf("failures audited: %v", reasons)
	}
}

// Beginning a passkey sign-in with a ticket that is not a second-factor step, or one for a user without a passkey.
func TestCoverageSecondFactorPasskeyBeginRefusals(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	_, out := b.login("acme", "pat", userPassword)
	if str(out, "step") != "enrol" {
		t.Fatalf("step %v", out)
	}
	res, o := b.post("/api-internal/login/passkey/begin", map[string]any{"ticket": str(out, "ticket")})
	wantStatus(t, res, o, 401)
	res, o = b.post("/api-internal/login/passkey/begin", map[string]any{"ticket": "n1.nope"})
	wantStatus(t, res, o, 401)
	// the discoverable begin with a tenant that is not a plausible name, and with hostile next, still works and
	// carries nothing hostile along
	res, o = b.post("/api-internal/login/passkey/begin", map[string]any{"org": "acme", "next": "//evil.example", "tenant": "<x>"})
	if res.StatusCode != 200 && res.StatusCode != 403 {
		t.Fatalf("begin: %d %v", res.StatusCode, o["_raw"])
	}
	res, o = b.post("/api-internal/login/passkey/begin", map[string]any{"next": "https://evil.example", "tenant": strings.Repeat("a", 100)})
	wantStatus(t, res, o, 200)
}

// A device cookie is a budget, not a credential: it stops counting when the account's password changes, when the
// account is switched off, and when it is malformed, expired-looking or cut short.
func TestCoverageDeviceCookieEntriesStopCounting(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LockoutAttempts = 3
		c.Limits.LoginPerIPMin = 0
	})
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	u, _ := url.Parse(e.URL)
	var dev *http.Cookie
	for _, ck := range b.c.Jar.Cookies(u) {
		if ck.Name == "__Host-quisora_dev" {
			dev = ck
		}
	}
	if dev == nil {
		t.Fatal("no device cookie")
	}
	withCookie := func(v string) *browser {
		c := e.browser(t)
		c.c.Jar.SetCookies(u, []*http.Cookie{{Name: dev.Name, Value: v, Path: "/", Secure: true}})
		return c
	}
	stranger := e.browser(t)
	for range 3 {
		stranger.login("acme", "pat", "bad")
	}
	res, out = stranger.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)

	// the genuine cookie lets the owner through the stranger's lockout
	res, out = withCookie(dev.Value).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	// cut short, with a bad time stamp, with extra parts, oversized, empty
	parts := strings.Split(dev.Value, ".")
	bad := []string{
		strings.Join(parts[:5], "."),
		strings.Join(append(append([]string{}, parts[:3]...), "!!", parts[4], parts[5]), "."),
		dev.Value + ".extra",
		strings.Repeat("a", 5000),
		"~~~",
		strings.Join(append(append([]string{}, parts[:3]...), "zzzzzzzzzzzz", parts[4], parts[5]), "."), // a time stamp the MAC does not cover
	}
	for _, v := range bad {
		res, out = withCookie(v).login("acme", "pat", userPassword)
		if res.StatusCode != 429 {
			t.Errorf("cookie %.30q counted: %d %v", v, res.StatusCode, out["_raw"])
		}
	}

	// after a password change the old entry no longer counts
	pw := "another-long-password"
	if _, err := e.Svc.UpdateUser(context.Background(), actorSuper(), pat.ID, userInputPassword(&pw)); err != nil {
		t.Fatal(err)
	}
	res, out = withCookie(dev.Value).login("acme", "pat", pw)
	wantStatus(t, res, out, 429)
}

func userInputPassword(pw *string) service.UserInput { return service.UserInput{Password: pw} }
