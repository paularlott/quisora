package login_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestPagesRender(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)

	// A plain visit explains how to sign in (through an application or the organization's link) — no form.
	res, body := b.get("/")
	if res.StatusCode != 200 || !strings.Contains(body, "Sign in through your application") ||
		strings.Contains(body, "/login/your-organization") || strings.Contains(body, `x-data="landing"`) {
		t.Fatalf("landing: %d %.400s", res.StatusCode, body)
	}
	// With next too: there is no organization picker; sign-in is at /login/<org> only.
	res, body = b.get("/?next=/oauth/authorize/resume")
	if res.StatusCode != 200 || !strings.Contains(body, "Sign in through your application") || strings.Contains(body, `name="org"`) ||
		strings.Contains(body, "webauthn") {
		t.Fatalf("landing with next: %d %.400s", res.StatusCode, body)
	}
	res, body = b.get("/login/primary")
	if res.StatusCode != 200 || !strings.Contains(body, `data-org="primary"`) || !strings.Contains(body, `id="f-email"`) ||
		!strings.Contains(body, `autocomplete="email webauthn"`) {
		t.Fatalf("login page: %d %.400s", res.StatusCode, body)
	}
	// An unknown organization: the help page, as a 404.
	res, body = b.get("/login/nope?next=/oauth/authorize%3Fflow%3D1")
	if res.StatusCode != 404 || !strings.Contains(body, "Sign in through your application") || !strings.Contains(body, "does not exist") {
		t.Fatalf("unknown org: %d %.300s", res.StatusCode, body)
	}
	// There is no /login route of its own: the organization is always in the path.
	for _, p := range []string{"/login", "/login?org=primary", "/login/"} {
		if res, body = b.get(p); res.StatusCode != 404 || strings.Contains(body, `id="f-email"`) {
			t.Fatalf("%s: %d %.300s", p, res.StatusCode, body)
		}
	}
	// Pages that need a session.
	res, _ = b.get("/account")
	if res.StatusCode != 303 || res.Header.Get("Location") != "/" { // the help page: signing in needs the organization
		t.Fatalf("account signed out: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = b.get("/logout")
	if res.StatusCode != 303 || res.Header.Get("Location") != "/" {
		t.Fatalf("logout signed out: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// invalid invite / reset links
	for _, p := range []string{"/invite?token=nope", "/reset?token=nope", "/invite", "/reset"} {
		res, body = b.get(p)
		if res.StatusCode != http.StatusGone || !strings.Contains(body, "expired") {
			t.Fatalf("%s: %d", p, res.StatusCode)
		}
	}
}

func TestPageMethods(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.PasswordLogin, s.PasskeyLogin = false, false })
	b := e.browser(t)
	_, body := b.get("/login/acme")
	if !strings.Contains(body, "No sign-in method is enabled") || strings.Contains(body, `id="f-email"`) {
		t.Fatalf("no methods page: %.600s", body)
	}
	e.setSettings(t, org, func(s *model.OrgSettings) { s.PasswordLogin, s.PasskeyLogin = true, false })
	_, body = b.get("/login/acme")
	if !strings.Contains(body, `id="f-email"`) || strings.Contains(body, `data-passkey="1"`) {
		t.Fatalf("password-only page: %.600s", body)
	}
	// password login switched off is enforced by the endpoint too, with the same generic failure as an unknown org
	e.setSettings(t, org, func(s *model.OrgSettings) { s.PasswordLogin = false })
	e.user(t, org, "pat", model.RoleUser)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 401)
	res2, out2 := b.login("no-such-org", "pat", userPassword)
	wantStatus(t, res2, out2, 401)
	if str(out, "error") != str(out2, "error") || str(out, "field") != str(out2, "field") {
		t.Fatalf("disabled org %v differs from unknown org %v", out, out2)
	}
}

func TestPasswordLogin(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	b := e.browser(t)
	m := e.member(t)

	res, out := b.login("primary", "member", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "next") != "/account" || !b.hasSession() {
		t.Fatalf("login response %v session=%v", out, b.hasSession())
	}
	// Email works as login too, and is case-insensitive.
	b2 := e.browser(t)
	res, out = b2.login("Primary", "MEMBER@example.com", userPassword)
	wantStatus(t, res, out, 200)

	// The session works for the account page and shows the user.
	res, body := b.get("/account")
	if res.StatusCode != 200 || !strings.Contains(body, "Your account") || !strings.Contains(body, `x-data="accountProfile"`) {
		t.Fatalf("account: %d %.300s", res.StatusCode, body)
	}
	// Signed in: landing and login pages redirect to next (local) or /account.
	for path, want := range map[string]string{"/": "/account", "/?next=/oauth/authorize%3Fx=1": "/oauth/authorize?x=1",
		"/login/primary": "/account", "/login/primary?next=/admin": "/admin", "/?next=//evil.example": "/account",
		"/?next=https://evil.example": "/account"} {
		res, _ = b.get(path)
		if res.StatusCode != 303 || res.Header.Get("Location") != want {
			t.Fatalf("%s -> %d %q, want %q", path, res.StatusCode, res.Header.Get("Location"), want)
		}
	}

	// Sessions record "pwd"; the audit log notes the sign-in and LastLogin is set (on the sign-in record, never on
	// the user: a sign-in does not rewrite the user record).
	sess, _ := e.Svc.Sessions.All(context.Background(), m.ID)
	if len(sess) != 2 || len(sess[0].AMR) != 1 || sess[0].AMR[0] != "pwd" {
		t.Fatalf("sessions %+v", sess)
	}
	if n := len(e.audits(t, "login.success")); n != 2 {
		t.Fatalf("login.success audits: %d", n)
	}
	u, _ := e.Svc.GetUser(context.Background(), nil, m.ID)
	if u.LastLogin.IsZero() {
		t.Fatal("LastLogin not set")
	}
	if raw, _ := e.Svc.Users.Get(context.Background(), m.ID); raw.Version != m.Version {
		t.Fatal("signing in rewrote the user record")
	}
}

func TestSuccessNotAuditedByDefault(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	res, out := b.login("primary", "admin", e.Password)
	wantStatus(t, res, out, 200)
	if n := len(e.audits(t, "login.success")); n != 0 {
		t.Fatalf("login.success audited without audit.logins: %d", n)
	}
	// ...but failures always are
	b2 := e.browser(t)
	b2.login("primary", "admin", "wrong")
	if n := len(e.audits(t, "login.failure")); n != 1 {
		t.Fatalf("login.failure audits: %d", n)
	}
}

func TestNextParameterIsLocalOnly(t *testing.T) {
	e := newEnv(t, nil)
	e.member(t)
	cases := map[string]string{
		"/oauth/authorize?flow=abc": "/oauth/authorize?flow=abc",
		"/admin":                    "/admin",
		"//evil.example":            "/account",
		"https://evil.example":      "/account",
		"/\\evil.example":           "/account",
		"\\\\evil.example":          "/account",
		"javascript:alert(1)":       "/account",
		"/%0d%0aSet-Cookie:x=1":     "/%0d%0aSet-Cookie:x=1", // percent-encoded stays a path
		"/a\r\nb":                   "/account",
		"/a\tb":                     "/account",
		"":                          "/account",
		"evil":                      "/account",
	}
	for next, want := range cases {
		b := e.browser(t)
		res, out := b.post("/api/login/password", map[string]any{"org": "primary", "email": "member@example.com", "password": userPassword, "next": next})
		wantStatus(t, res, out, 200)
		if str(out, "next") != want {
			t.Errorf("next %q -> %q, want %q", next, str(out, "next"), want)
		}
	}
	// And the provider redirect never carries a hostile next around.
	b := e.browser(t)
	res, _ := b.get("/login/primary/provider/nope?next=//evil.example")
	if res.StatusCode != 302 || strings.Contains(res.Header.Get("Location"), "evil") {
		t.Fatalf("provider redirect: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestGenericFailures(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	u := e.user(t, org, "pat", model.RoleUser)
	off := e.user(t, org, "gone", model.RoleUser)
	f := false
	if _, err := e.Svc.UpdateUser(context.Background(), actorSuper(), off.ID, userInput(&f)); err != nil {
		t.Fatal(err)
	}
	_ = u

	type try struct{ org, login, pw string }
	var first map[string]any
	for _, tr := range []try{
		{"acme", "pat", "wrong password"}, {"acme", "nobody", "wrong password"}, {"nope", "pat", userPassword},
		{"acme", "gone", userPassword}, {"primary", "pat", userPassword}, {"acme", "pat@example.com", "x"},
	} {
		b := e.browser(t)
		res, out := b.login(tr.org, tr.login, tr.pw)
		wantStatus(t, res, out, 401)
		if str(out, "error") != "The email address or password is incorrect." || str(out, "field") != "" {
			t.Fatalf("%+v: %v", tr, out)
		}
		if first == nil {
			first = out
		}
		if b.hasSession() {
			t.Fatalf("%+v created a session", tr)
		}
	}
	// validation errors that reveal nothing
	b := e.browser(t)
	res, out := b.login("acme", "", "")
	wantStatus(t, res, out, 422)
	res, out = b.post("/api/login/password", `{"org":"acme","email":"pat@example.com","password":"x","extra":1}`)
	wantStatus(t, res, out, 400)

	// Failures are audited with a reason, never the password.
	fails := e.audits(t, "login.failure")
	if len(fails) != 6 {
		t.Fatalf("failure audits: %d", len(fails))
	}
	reasons := map[string]int{}
	for _, a := range fails {
		reasons[a.Detail["reason"]]++
		for _, v := range a.Detail {
			if strings.Contains(v, "wrong password") {
				t.Fatal("password leaked into audit")
			}
		}
	}
	if reasons["bad password"] != 2 || reasons["unknown user"] != 2 || reasons["unknown org"] != 1 || reasons["inactive"] != 1 {
		t.Fatalf("reasons %v", reasons)
	}
}

// Unknown users cost a password hash like real ones, so response time does not give accounts away.
func TestUnknownUserCostsAHash(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0; c.Limits.LockoutAttempts = 0 })
	b := e.browser(t)
	measure := func(login string) time.Duration {
		var ds []time.Duration
		for range 7 {
			start := time.Now()
			b.login("primary", login, "wrong password")
			ds = append(ds, time.Since(start))
		}
		for i := range ds {
			for j := i + 1; j < len(ds); j++ {
				if ds[j] < ds[i] {
					ds[i], ds[j] = ds[j], ds[i]
				}
			}
		}
		return ds[len(ds)/2]
	}
	known, unknown := measure("admin"), measure("nobody-here")
	if unknown < known/3 {
		t.Fatalf("unknown user answered in %v, known user in %v: timing differs", unknown, known)
	}
	if unknown < 500*time.Microsecond {
		t.Fatalf("unknown user answered in %v: no hash spent", unknown)
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	body := map[string]any{"org": "primary", "email": "admin@example.com", "password": e.Password}

	cases := map[string]hdrs{
		"no token":          {"X-CSRF-Token": " "},
		"wrong token":       {"X-CSRF-Token": strings.Repeat("a", 32)},
		"cross-site origin": {"Origin": "https://evil.example"},
		"cross-site fetch":  {"Sec-Fetch-Site": "cross-site"},
		"same-site fetch":   {"Sec-Fetch-Site": "same-site"},
	}
	for name, h := range cases {
		if h["X-CSRF-Token"] == " " {
			h = hdrs{"X-CSRF-Token": ""}
		}
		res, out := b.do(http.MethodPost, "/api/login/password", body, h)
		if res.StatusCode != 403 || b.hasSession() {
			t.Fatalf("%s: status %d session=%v %v", name, res.StatusCode, b.hasSession(), out["_raw"])
		}
	}
	// a browser with the right header but without the cookie fails too
	other := e.client()
	req, _ := http.NewRequest("POST", e.URL+"/api/login/password", strings.NewReader(`{"org":"primary","email":"admin@example.com","password":"x"}`))
	req.Header.Set("X-CSRF-Token", b.csrf)
	res, err := other.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("token without cookie: %d", res.StatusCode)
	}
	// every anonymous endpoint checks it
	for _, p := range []string{"/api/login/password", "/api/login/totp", "/api/login/passkey/begin", "/api/login/passkey/finish",
		"/api/login/enrol/totp/begin", "/api/login/enrol/totp/confirm", "/api/login/enrol/passkey/begin",
		"/api/login/enrol/passkey/finish", "/api/password/forgot", "/api/password/reset"} {
		res, out := b.do(http.MethodPost, p, map[string]any{}, hdrs{"X-CSRF-Token": ""})
		if res.StatusCode != 403 {
			t.Fatalf("%s without token: %d %v", p, res.StatusCode, out["_raw"])
		}
	}
	// the right token works
	res2, out := b.post("/api/login/password", body)
	wantStatus(t, res2, out, 200)
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 5; c.Limits.LockoutAttempts = 0 })
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	for i := 1; i <= 5; i++ {
		res, out := b.login("primary", "admin", "wrong")
		if res.StatusCode != 401 {
			t.Fatalf("attempt %d: %d %v", i, res.StatusCode, out["_raw"])
		}
	}
	res, out := b.login("primary", "admin", e.Password) // even the right password is refused while limited
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") != "60" || b.hasSession() {
		t.Fatalf("429 details: retry-after=%q session=%v", res.Header.Get("Retry-After"), b.hasSession())
	}
	// limits are per organization
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
}

// A flood of junk sign-ins from the same address (an office NAT, a load balancer without trusted_proxies) does not
// keep out a browser that has signed in to the account before: its device cookie moves it onto the account's own
// budget. A browser without one, another account typed into that browser, or a tampered cookie stay limited by
// address, and the account's own budget is limited too.
func TestKnownDeviceSurvivesFlood(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 5; c.Limits.LockoutAttempts = 0 })
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	e.user(t, org, "sam", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	attacker := e.browser(t)
	for i := 0; i < 20; i++ { // past the per-org limit and the address-wide ceiling
		attacker.login([]string{"acme", "primary", "nope"}[i%3], "x@y.z", "x")
	}
	if res, out := e.browser(t).login("acme", "pat", userPassword); res.StatusCode != 429 {
		t.Fatalf("flood did not limit the address: %d %v", res.StatusCode, out["_raw"])
	}

	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	// the cookie is for pat: another account typed into the same browser is limited by address
	res, out = b.login("acme", "sam", userPassword)
	wantStatus(t, res, out, 429)

	// a tampered cookie is no cookie
	u, _ := url.Parse(e.URL)
	c := e.browser(t)
	for _, ck := range b.c.Jar.Cookies(u) {
		if ck.Name == "__Host-quisora_dev" {
			ck.Value = strings.Replace(ck.Value, ".", ".x", 1)
			c.c.Jar.SetCookies(u, []*http.Cookie{ck})
		}
	}
	res, out = c.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)

	// the device's own budget is limited like an address's
	for i := 0; i < 4; i++ {
		res, out = b.login("acme", "pat", "wrong")
		wantStatus(t, res, out, 401)
	}
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
}

func TestLockout(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LockoutAttempts = 3
		c.Limits.LockoutMinutes = 15
		c.Limits.LoginPerIPMin = 0
	})
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)

	b := e.browser(t)
	// Two failures, a success, two more failures: the success reset the count.
	b.login("acme", "pat", "bad1")
	b.login("acme", "pat", "bad2")
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	b = e.browser(t)
	b.login("acme", "pat", "bad3")
	b.login("acme", "pat", "bad4")
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	// Three in a row lock the account: even the right password is refused, with Retry-After.
	b = e.browser(t)
	for range 3 {
		res, _ = b.login("acme", "pat", "bad")
		if res.StatusCode != 401 {
			t.Fatalf("expected 401 before lockout, got %d", res.StatusCode)
		}
	}
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") != "900" || b.hasSession() {
		t.Fatalf("lockout details: %q session=%v", res.Header.Get("Retry-After"), b.hasSession())
	}
	// Another browser (another session) is locked out as well: it is per account.
	res, out = e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if n := len(e.audits(t, "login.lockout")); n != 1 {
		t.Fatalf("lockout audits: %d", n)
	}
	// Other accounts are unaffected.
	res, out = e.browser(t).login("primary", "admin", e.Password)
	wantStatus(t, res, out, 200)

	// No database writes: the lockout leaves the user record untouched.
	u, _ := e.Svc.FindUserByEmail(context.Background(), org.ID, "pat@example.com")
	if u == nil || u.Version != pat.Version {
		t.Fatalf("signing in or the lockout wrote to the user record: %+v", u)
	}
}

// An unknown login locks out after the same number of attempts, so lockout does not reveal which accounts exist.
// Someone who knows the email address can lock the account, but not its owner's browsers that have signed in to it
// before: they count failures of their own and lock after as many. A tampered device cookie is no cookie.
func TestKnownDeviceLockout(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LockoutAttempts = 3
		c.Limits.LockoutMinutes = 15
		c.Limits.LoginPerIPMin = 0
	})
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	stranger := e.browser(t)
	for range 3 {
		res, out = stranger.login("acme", "pat", "bad")
		wantStatus(t, res, out, 401)
	}
	res, out = stranger.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)

	u, _ := url.Parse(e.URL)
	c := e.browser(t)
	for _, ck := range b.c.Jar.Cookies(u) {
		if ck.Name == "__Host-quisora_dev" {
			ck.Value = strings.Replace(ck.Value, ".", ".x", 1)
			c.c.Jar.SetCookies(u, []*http.Cookie{ck})
		}
	}
	res, out = c.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)

	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	// the known browser's own failures lock it (and only it)
	for range 3 {
		res, out = b.login("acme", "pat", "bad")
		wantStatus(t, res, out, 401)
	}
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	res, out = e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
}

func TestLockoutDoesNotRevealAccounts(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LockoutAttempts = 2; c.Limits.LoginPerIPMin = 0 })
	b := e.browser(t)
	for _, login := range []string{"admin", "ghost"} {
		var codes []int
		for range 4 {
			res, _ := b.login("primary", login, "wrong")
			codes = append(codes, res.StatusCode)
		}
		if codes[0] != 401 || codes[1] != 401 || codes[2] != 429 || codes[3] != 429 {
			t.Fatalf("%s: status sequence %v", login, codes)
		}
	}
}

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
	res, out = b.post("/api/login/totp", map[string]any{"ticket": ticket, "code": "000000"})
	wantStatus(t, res, out, 401)
	if str(out, "field") != "code" || b.hasSession() {
		t.Fatalf("wrong code: %v", out)
	}
	// unknown ticket
	res, out = b.post("/api/login/totp", map[string]any{"ticket": "n1.unknown", "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 401)

	code := totpAt(secret, time.Now())
	res, out = b.post("/api/login/totp", map[string]any{"ticket": ticket, "code": code})
	wantStatus(t, res, out, 200)
	if str(out, "next") != "/account" || !b.hasSession() {
		t.Fatalf("totp success: %v", out)
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), u.ID)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "pwd,otp,mfa" {
		t.Fatalf("amr %+v", sess)
	}
	// the ticket is single use
	res, out = b.post("/api/login/totp", map[string]any{"ticket": ticket, "code": code})
	wantStatus(t, res, out, 401)

	// The same code cannot be used again on a fresh sign-in (replay protection)...
	b2 := e.browser(t)
	_, out = b2.login("primary", "pat", userPassword)
	res, out2 := b2.post("/api/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": code})
	wantStatus(t, res, out2, 401)
	if b2.hasSession() {
		t.Fatal("replayed code created a session")
	}
	// ...while the next time step still works.
	res, out2 = b2.post("/api/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": totpAt(secret, time.Now().Add(30*time.Second))})
	wantStatus(t, res, out2, 200)
	if si, _ := e.Svc.SignIns.Get(context.Background(), u.ID); si == nil || si.TOTPLastStep == 0 {
		t.Fatal("TOTPLastStep not stored")
	}
}

func TestTOTPTicketAttemptsAndLockout(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LockoutAttempts = 8; c.Limits.LoginPerIPMin = 0 })
	u := e.user(t, e.Primary, "pat", model.RoleUser)
	secret := e.giveTOTP(t, u)
	b := e.browser(t)
	_, out := b.login("primary", "pat", userPassword)
	ticket := str(out, "ticket")
	// five wrong codes burn the ticket; the right code no longer works with it
	for range 5 {
		res, _ := b.post("/api/login/totp", map[string]any{"ticket": ticket, "code": "111111"})
		if res.StatusCode != 401 {
			t.Fatalf("status %d", res.StatusCode)
		}
	}
	res, out := b.post("/api/login/totp", map[string]any{"ticket": ticket, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 401)
	if b.hasSession() {
		t.Fatal("ticket survived too many attempts")
	}
	// Wrong codes count toward the account lockout shared with passwords.
	e2 := newEnv(t, func(c *config.Config) { c.Limits.LockoutAttempts = 3; c.Limits.LoginPerIPMin = 0 })
	u2 := e2.user(t, e2.Primary, "pat", model.RoleUser)
	e2.giveTOTP(t, u2)
	b2 := e2.browser(t)
	_, o := b2.login("primary", "pat", userPassword)
	tk := str(o, "ticket")
	for range 3 {
		b2.post("/api/login/totp", map[string]any{"ticket": tk, "code": "222222"})
	}
	res, out = b2.login("primary", "pat", userPassword)
	wantStatus(t, res, out, 429)
}

func TestReauthShowsLoginAndReplacesSession(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("primary", "admin", e.Password)
	wantStatus(t, res, out, 200)
	oldSession := b.sessionID()

	res, body := b.get("/login/primary?reauth=1&next=/admin")
	if res.StatusCode != 200 || !strings.Contains(body, "sign in again") {
		t.Fatalf("reauth page: %d", res.StatusCode)
	}
	// The page still carries a working anonymous token even though a session exists.
	b.csrf = metaRe.FindStringSubmatch(body)[1]
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if b.sessionID() == oldSession {
		t.Fatal("session not replaced")
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), oldSession); err == nil {
		t.Fatal("old session still exists after re-authentication")
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), pat.ID)
	if len(sess) != 1 {
		t.Fatalf("sessions of pat: %d", len(sess))
	}
	res, body = b.get("/account")
	if !strings.Contains(body, "pat") || res.StatusCode != 200 {
		t.Fatalf("account after reauth: %d", res.StatusCode)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	e.member(t)
	b.login("primary", "member", userPassword)
	if !b.hasSession() {
		t.Fatal("no session")
	}
	sid := b.sessionID()

	// GET shows a confirmation and never signs out.
	res, body := b.get("/logout?next=/admin")
	if res.StatusCode != 200 || !strings.Contains(body, "Sign out") || !strings.Contains(body, `data-next="/admin"`) {
		t.Fatalf("logout page: %d", res.StatusCode)
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); err != nil {
		t.Fatal("GET /logout ended the session")
	}
	csrf := metaRe.FindStringSubmatch(body)[1]

	// POST without the CSRF token is refused and the session survives.
	req, _ := http.NewRequest("POST", e.URL+"/logout", nil)
	req.Header.Set("Accept", "application/json")
	res2, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != 403 {
		t.Fatalf("logout without csrf: %d", res2.StatusCode)
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); err != nil {
		t.Fatal("unauthenticated POST /logout ended the session")
	}
	// Cross-site POST refused.
	req, _ = http.NewRequest("POST", e.URL+"/logout", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Origin", "https://evil.example")
	res2, _ = b.c.Do(req)
	res2.Body.Close()
	if res2.StatusCode != 403 {
		t.Fatalf("cross-origin logout: %d", res2.StatusCode)
	}

	// fetch-style POST ends the session and answers JSON; hostile next is dropped.
	for next, want := range map[string]string{"/bye": "/bye", "//evil.example": "/", "": "/"} {
		b2 := e.browser(t)
		b2.login("primary", "member", userPassword)
		page, body := b2.get("/logout")
		_ = page
		tok := metaRe.FindStringSubmatch(body)[1]
		sid2 := b2.sessionID()
		res, out := b2.do(http.MethodPost, "/logout?next="+url.QueryEscape(next), nil, hdrs{"X-CSRF-Token": tok})
		wantStatus(t, res, out, 200)
		if str(out, "next") != want {
			t.Fatalf("logout next %q -> %q want %q", next, str(out, "next"), want)
		}
		if _, err := e.Svc.Sessions.Get(context.Background(), sid2); err == nil {
			t.Fatal("session survived logout")
		}
		if res, _ := b2.get("/account"); res.StatusCode != 303 {
			t.Fatalf("account after logout: %d", res.StatusCode)
		}
	}

	// plain form post (no JS): CSRF in the form field, redirect.
	b3 := e.browser(t)
	b3.login("primary", "member", userPassword)
	_, body = b3.get("/logout")
	tok := metaRe.FindStringSubmatch(body)[1]
	res3, err := b3.c.PostForm(e.URL+"/logout", url.Values{"csrf": {tok}, "next": {"/farewell"}})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res3.Body)
	res3.Body.Close()
	if res3.StatusCode != 303 || res3.Header.Get("Location") != "/farewell" {
		t.Fatalf("form logout: %d %q", res3.StatusCode, res3.Header.Get("Location"))
	}
	if res, _ := b3.get("/account"); res.StatusCode != 303 {
		t.Fatal("still signed in after form logout")
	}
	// form post with a bad token fails
	b4 := e.browser(t)
	b4.login("primary", "member", userPassword)
	res4, _ := b4.c.PostForm(e.URL+"/logout", url.Values{"csrf": {"nope"}})
	res4.Body.Close()
	if res4.StatusCode != 403 {
		t.Fatalf("form logout with bad token: %d", res4.StatusCode)
	}
	if res, _ := b4.get("/account"); res.StatusCode != 200 {
		t.Fatal("session ended by a rejected logout")
	}
	// signed-out POST is harmless
	b5 := e.browser(t)
	res5, out := b5.do(http.MethodPost, "/logout", nil, hdrs{"X-CSRF-Token": "x"})
	wantStatus(t, res5, out, 200)
}

// Case and whitespace variants of a real org name share one per-IP bucket; random unknown names share another.
func TestRateLimitOrgNormalisation(t *testing.T) {
	const limit = 50
	run := func(t *testing.T, name func(i int) string) *browser {
		e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = limit; c.Limits.LockoutAttempts = 100000 })
		e.org(t, "acme", nil)
		b := e.browser(t)
		first429 := 0
		for i := 1; i <= limit+10; i++ {
			org := name(i)
			res, _ := b.login(org, "pat", "wrong-password")
			if res.StatusCode == http.StatusTooManyRequests {
				first429 = i
				break
			}
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("attempt %d (%q): status %d", i, org, res.StatusCode)
			}
		}
		if first429 != limit+1 {
			t.Fatalf("first 429 at attempt %d, want %d", first429, limit+1)
		}
		return b
	}
	t.Run("case and whitespace variants", func(t *testing.T) {
		variants := []string{"acme", "acme ", " acme", "ACME", "Acme", "\tacme\n"}
		b := run(t, func(i int) string { return variants[i%len(variants)] })
		// The forgot-password form shares the buckets too.
		res, out := b.post("/api/password/forgot", map[string]any{"org": " ACME ", "email": "pat@example.com"})
		wantStatus(t, res, out, 429)
	})
	t.Run("random unknown org names", func(t *testing.T) {
		b := run(t, func(i int) string { return fmt.Sprintf("no-such-org-%d", i) })
		res, out := b.post("/api/password/forgot", map[string]any{"org": "yet-another", "email": "pat@example.com"})
		wantStatus(t, res, out, 429)
	})
}

// One IP cannot exceed three times the per-org limit by spreading attempts across organizations.
func TestRateLimitIPCeiling(t *testing.T) {
	const limit = 10
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = limit; c.Limits.LockoutAttempts = 100000 })
	orgs := []string{"a1", "a2", "a3", "a4", "a5"}
	for _, o := range orgs {
		e.org(t, o, nil)
	}
	b := e.browser(t)
	for i := 1; i <= 3*limit+5; i++ {
		res, _ := b.login(orgs[i%len(orgs)], "pat", "wrong-password")
		want := http.StatusUnauthorized
		if i > 3*limit {
			want = http.StatusTooManyRequests
		}
		if res.StatusCode != want {
			t.Fatalf("attempt %d: status %d, want %d", i, res.StatusCode, want)
		}
	}
}

// The username is not a sign-in name: with the right password it fails exactly like an unknown account (same
// message, same status, one password hash spent), while the email address (any case) signs in.
func TestUsernameCannotSignIn(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0; c.Limits.LockoutAttempts = 0 })
	org := e.org(t, "acme", nil)
	name, mailAddr := "pat-the-user", "Pat.Smith@Example.com"
	role := model.RoleUser
	u, err := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: &mailAddr, Role: &role})
	if err != nil {
		t.Fatal(err)
	}
	pw := userPassword
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, u.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	post := func(who string) (*http.Response, map[string]any, bool) {
		b := e.browser(t)
		res, out := b.post("/api/login/password", map[string]any{"org": "acme", "email": who, "password": userPassword})
		return res, out, b.hasSession()
	}
	res, unknown, _ := post("nobody-at-all")
	wantStatus(t, res, unknown, 401)
	for _, who := range []string{name, strings.ToUpper(name), "pat"} {
		res, out, sess := post(who)
		wantStatus(t, res, out, 401)
		if str(out, "_raw") != str(unknown, "_raw") || sess {
			t.Errorf("username %q: %v (session %v), want the unknown-account answer %v", who, out, sess, unknown)
		}
	}
	// The old JSON field is gone: "login" is an unknown field.
	b := e.browser(t)
	res, out := b.post("/api/login/password", map[string]any{"org": "acme", "login": name, "password": userPassword})
	wantStatus(t, res, out, 400)
	// Email addresses are case-insensitive.
	for _, who := range []string{"Pat.Smith@Example.com", "pat.smith@example.com", "PAT.SMITH@EXAMPLE.COM", "  pat.smith@example.com "} {
		res, out, sess := post(who)
		wantStatus(t, res, out, 200)
		if !sess {
			t.Errorf("%q: no session: %v", who, out)
		}
	}
	// A failed username attempt is audited as an unknown user, like any unknown account.
	reasons := map[string]int{}
	for _, a := range e.audits(t, "login.failure") {
		reasons[a.Detail["reason"]]++
	}
	if reasons["unknown user"] != 4 {
		t.Errorf("audit reasons %v", reasons)
	}
}

// login_hint is an email address that pre-fills the sign-in form.
func TestLoginHintPrefillsEmail(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	_, body := b.get("/login/primary?login_hint=ada%40example.com")
	if !strings.Contains(body, `data-hint="ada@example.com"`) {
		t.Fatalf("hint not carried: %.600s", body)
	}
}

// A sign-in continuing an authorization request that asked for a second factor (login.Options.StepUp) asks for one
// even where nothing else requires it.
func TestPasswordSignInStepUp(t *testing.T) {
	e := newEnv(t, nil)
	e.member(t)
	b := e.browser(t)
	res, out := b.post("/api/login/password", map[string]any{"org": "primary", "email": "member@example.com",
		"password": userPassword, "next": "/step-up"})
	wantStatus(t, res, out, 200)
	if str(out, "step") != "enrol" || b.hasSession() {
		t.Fatalf("step-up sign-in: %v session=%v", out, b.hasSession())
	}
	b2 := e.browser(t)
	res, out = b2.post("/api/login/password", map[string]any{"org": "primary", "email": "member@example.com",
		"password": userPassword, "next": "/x"})
	wantStatus(t, res, out, 200)
	if str(out, "step") != "" || !b2.hasSession() {
		t.Fatalf("plain sign-in: %v", out)
	}
}
