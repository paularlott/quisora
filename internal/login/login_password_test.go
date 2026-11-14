package login_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestLoginPagesAreAccessible(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	_, body := b.get("/o/primary/login")
	for _, want := range []string{`<label class="label" for="f-email">`, `aria-describedby="e-email"`, `:aria-invalid="invalid.email"`,
		`role="alert"`, `id="e-password"`, `<h1 class="page-title">`, `<main id="main"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %s", want)
		}
	}
	// no inline scripts or handlers (strict CSP) and no inline expressions with operators in directives
	for _, bad := range []string{"<script>", " onclick=", "javascript:"} {
		if strings.Contains(body, bad) {
			t.Errorf("login page contains %q", bad)
		}
	}
}

// The sign-in, enrolment, reset and invitation endpoints refuse a body that is not the JSON they take (and unknown
// fields), before anything else: no session and no mail result.
func TestAuthEndpointsRejectMalformedBodies(t *testing.T) {
	e := newEnv(t, withSMTP, noIPLimit)
	b := e.browser(t)
	for _, p := range []string{"login/password", "login/totp", "login/recovery", "login/email/send", "login/email", "login/passkey/begin",
		"login/passkey/finish", "login/enrol/totp/begin", "login/enrol/totp/confirm", "login/enrol/passkey/begin", "login/enrol/passkey/finish",
		"password/forgot", "password/reset", "invite/passkey/begin", "invite/complete"} {
		t.Run(p, func(t *testing.T) {
			for _, body := range []string{"{not json", `{"unknown_field":1}`} {
				res, out := b.post("/api-internal/"+p, body)
				if res.StatusCode != 400 {
					t.Errorf("%q: status %d, want 400: %v", body, res.StatusCode, out["_raw"])
				}
			}
			if b.hasSession() {
				t.Fatal("a session was created")
			}
		})
	}
	if e.mailCount() != 0 {
		t.Fatal("mail sent for a malformed body")
	}
}

// A user past their end date cannot sign in, even before the sweep disables them.
func TestValidUntilStopsSignIn(t *testing.T) {
	e := newEnv(t, nil)
	m := e.member(t)
	past := time.Now().Add(-time.Minute)
	m.ValidUntil = &past
	if err := e.Svc.Users.Update(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	res, out := e.browser(t).login("primary", "member", userPassword)
	if res.StatusCode != 401 {
		t.Fatalf("sign-in after the end date: %d %v", res.StatusCode, out)
	}
}

// A failed sign-in for an account that was not found records the address typed, never anything else typed in its
// place (a password in the address box would otherwise be in the audit trail and the structured log).
func TestFailedSignInDoesNotRecordAPasswordTypedAsTheLogin(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	e.org(t, "acme", nil)
	b := e.browser(t)
	b.post("/o/acme/api-internal/login/password", map[string]any{"email": "Hunter2-my-secret!", "password": "x"})
	b.post("/o/acme/api-internal/login/password", map[string]any{"email": "nobody@example.com", "password": "x"})
	var seen []string
	for _, a := range e.audits(t, "login.failure") {
		seen = append(seen, a.Target, a.Actor)
	}
	for _, v := range seen {
		if strings.Contains(v, "Hunter2") {
			t.Fatalf("the typed secret is in the audit trail: %v", seen)
		}
	}
	if !slices.Contains(seen, "nobody@example.com") {
		t.Fatalf("the address tried is not recorded: %v", seen)
	}
}

// The password forms say how long a password must be: limits.password_min_length.
func TestPasswordFormsStateTheMinimum(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.PasswordMinLength = 12 })
	org := e.org(t, "acme", nil)
	_, link := e.invitee(t, org, "newbie")
	res, body := e.browser(t).get(link)
	if res.StatusCode != 200 || !strings.Contains(body, "At least 12 characters.") {
		t.Fatalf("invitation page %d does not state the minimum", res.StatusCode)
	}
}

// A sign-in that continues an authorization request offers Cancel (the OIDC provider then sends access_denied to the
// application); other sign-ins do not.
func TestLoginPageCancel(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	_, body := b.get("/o/primary/login?next=" + url.QueryEscape(e.primaryBase()+"/oauth/authorize/resume?flow=abc"))
	if !strings.Contains(body, `href="`+e.primaryBase()+`/oauth/authorize/cancel?flow=abc"`) {
		t.Fatal("no Cancel link for an authorization request")
	}
	for _, path := range []string{"/o/primary/login", "/o/primary/login?next=" + url.QueryEscape(e.primaryBase()+"/account")} {
		if _, body := b.get(path); strings.Contains(body, "/oauth/authorize/cancel") {
			t.Fatalf("%s: Cancel link without an authorization request", path)
		}
	}
}

func TestPagesRender(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)

	// A plain visit is told to sign in through the application or the organization's link: nothing here says which
	// organization the visitor belongs to (a 200, not the 404 of a page that does not exist). Signed in, it is the
	// account page.
	for _, path := range []string{"/", "/?next=/oauth/authorize/resume"} {
		res, body := b.getAbs(path)
		if res.StatusCode != 200 || !strings.Contains(body, "Sign in through your application") || strings.Contains(body, "lead to a page here") {
			t.Fatalf("landing %s: %d %.300s", path, res.StatusCode, body)
		}
	}
	u := e.user(t, e.org(t, "landing", nil), "pat", model.RoleUser)
	if res, _ := e.signedIn(t, u).getAbs("/"); res.StatusCode != 303 || res.Header.Get("Location") != "/o/"+u.OrgID+"/account" {
		t.Fatalf("landing signed in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// The sign-in page, by the organization's name or its id: the same page, whose links are by id.
	for _, ref := range []string{"primary", e.Primary.ID} {
		res, body := b.get("/o/" + ref + "/login")
		if res.StatusCode != 200 || !strings.Contains(body, `data-org-base="`+e.primaryBase()+`"`) || !strings.Contains(body, `id="f-email"`) ||
			!strings.Contains(body, `autocomplete="username webauthn"`) {
			t.Fatalf("login page of %s: %d %.400s", ref, res.StatusCode, body)
		}
	}
	// An unknown organization: not found.
	res, body := b.get("/o/nope/login?next=" + url.QueryEscape(e.primaryBase()+"/oauth/authorize?flow=1"))
	if res.StatusCode != 404 {
		t.Fatalf("unknown org: %d %.300s", res.StatusCode, body)
	}
	// There are no routes outside an organization's address space.
	for _, p := range []string{"/login", "/login?org=primary", "/login/", "/login/primary", "/login/callback/x", "/account", "/logout", "/invite",
		"/reset", "/verify-email", "/api-internal/login/password"} {
		if res, _ = b.getAbs(p); res.StatusCode != 404 {
			t.Fatalf("%s: %d", p, res.StatusCode)
		}
	}
	// Pages that need a session go to the organization's sign-in page, back here afterwards.
	res, _ = b.get(e.primaryBase() + "/account")
	if res.StatusCode != 303 || res.Header.Get("Location") != e.primaryBase()+"/login?next="+url.QueryEscape(e.primaryBase()+"/account") {
		t.Fatalf("account signed out: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = b.get("/logout")
	if res.StatusCode != 303 || res.Header.Get("Location") != e.primaryBase()+"/login" {
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
	_, body := b.get("/o/acme/login")
	if !strings.Contains(body, "No sign-in method is enabled") || strings.Contains(body, `id="f-email"`) {
		t.Fatalf("no methods page: %.600s", body)
	}
	e.setSettings(t, org, func(s *model.OrgSettings) { s.PasswordLogin, s.PasskeyLogin = true, false })
	_, body = b.get("/o/acme/login")
	if !strings.Contains(body, `id="f-email"`) || strings.Contains(body, `data-passkey="1"`) {
		t.Fatalf("password-only page: %.600s", body)
	}
	// password login switched off is enforced by the endpoint too, with the generic failure
	e.setSettings(t, org, func(s *model.OrgSettings) { s.PasswordLogin = false })
	e.user(t, org, "pat", model.RoleUser)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 401)
	if str(out, "error") != msgBadLogin {
		t.Fatalf("disabled password sign-in: %v", out)
	}
	// an organization that does not exist has no endpoints at all
	res2, out2 := b.login("no-such-org", "pat", userPassword)
	wantStatus(t, res2, out2, 404)
}

const msgBadLogin = "The email address or password is incorrect."

func TestPasswordLogin(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	b := e.browser(t)
	m := e.member(t)

	res, out := b.login("primary", "member", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "next") != b.base+"/account" || !b.hasSession() {
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
	// Signed in: the login page redirects to next (a path of the organization or the console) or the account page.
	for path, want := range map[string]string{"/o/primary/login": e.primaryBase() + "/account",
		"/o/primary/login?next=" + url.QueryEscape(e.primaryBase()+"/oauth/authorize?x=1"): e.primaryBase() + "/oauth/authorize?x=1",
		"/o/primary/login?next=/admin":               "/admin",
		"/o/primary/login?next=/account":             e.primaryBase() + "/account",
		"/o/primary/login?next=//evil.example":       e.primaryBase() + "/account",
		"/o/primary/login?next=https://evil.example": e.primaryBase() + "/account"} {
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
	acct := e.primaryBase() + "/account"
	cases := map[string]string{
		e.primaryBase() + "/oauth/authorize?flow=abc": e.primaryBase() + "/oauth/authorize?flow=abc",
		"/admin":                                              "/admin",
		"/admin/orgs/acme/users":                              "/admin/orgs/acme/users",
		"//evil.example":                                      acct,
		"https://evil.example":                                acct,
		"/\\evil.example":                                     acct,
		"\\\\evil.example":                                    acct,
		"javascript:alert(1)":                                 acct,
		"/oauth/authorize?flow=abc":                           acct, // not in the organization's space
		"/%0d%0aSet-Cookie:x=1":                               acct,
		e.primaryBase() + "/a\r\nb":                           acct,
		e.primaryBase() + "/a\tb":                             acct,
		e.primaryBase() + "/%0d%0aSet-Cookie:x=1":             e.primaryBase() + "/%0d%0aSet-Cookie:x=1", // percent-encoded stays a path
		"/o/other/account":                                    acct,                                      // another organization's space
		"/o/" + model.NewID() + "/account":                    acct,
		"/o/primary/account":                                  "/o/primary/account", // by name: the same space
		e.primaryBase() + "/../" + model.NewID() + "/account": acct,
		"":     acct,
		"evil": acct,
	}
	for next, want := range cases {
		b := e.browser(t)
		res, out := b.post("/o/primary/api-internal/login/password", map[string]any{"email": "member@example.com", "password": userPassword, "next": next})
		wantStatus(t, res, out, 200)
		if str(out, "next") != want {
			t.Errorf("next %q -> %q, want %q", next, str(out, "next"), want)
		}
	}
	// And the provider redirect never carries a hostile next around.
	b := e.browser(t)
	res, _ := b.get("/o/primary/login/provider/nope?next=//evil.example")
	if res.StatusCode != 302 || strings.Contains(res.Header.Get("Location"), "evil") {
		t.Fatalf("provider redirect: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestGenericFailures(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	off := e.user(t, org, "gone", model.RoleUser)
	f := false
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, off.ID, service.UserInput{Active: &f}); err != nil {
		t.Fatal(err)
	}

	type try struct{ org, login, pw string }
	var first map[string]any
	for _, tr := range []try{
		{"acme", "pat", "wrong password"}, {"acme", "nobody", "wrong password"},
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
	res, out = b.post("/o/acme/api-internal/login/password", `{"email":"pat@example.com","password":"x","extra":1}`)
	wantStatus(t, res, out, 400)

	// Failures are audited with a reason, never the password: at most one a minute per account and reason (pat's
	// two wrong passwords are one event, the second held back), and per login that names no account in each
	// organization.
	fails := e.audits(t, "login.failure")
	if len(fails) != 4 {
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
	if reasons["bad password"] != 1 || reasons["unknown user"] != 2 || reasons["inactive"] != 1 {
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
	body := map[string]any{"email": "admin@example.com", "password": e.Password}

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
		res, out := b.do(http.MethodPost, "/api-internal/login/password", body, h)
		if res.StatusCode != 403 || b.hasSession() {
			t.Fatalf("%s: status %d session=%v %v", name, res.StatusCode, b.hasSession(), out["_raw"])
		}
	}
	// a browser with the right header but without the cookie fails too
	other := e.client()
	req, _ := http.NewRequest("POST", e.URL+e.primaryBase()+"/api-internal/login/password", strings.NewReader(`{"email":"admin@example.com","password":"x"}`))
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
	for _, p := range []string{"/api-internal/login/password", "/api-internal/login/totp", "/api-internal/login/passkey/begin", "/api-internal/login/passkey/finish",
		"/api-internal/login/enrol/totp/begin", "/api-internal/login/enrol/totp/confirm", "/api-internal/login/enrol/passkey/begin",
		"/api-internal/login/enrol/passkey/finish", "/api-internal/password/forgot", "/api-internal/password/reset"} {
		res, out := b.do(http.MethodPost, p, map[string]any{}, hdrs{"X-CSRF-Token": ""})
		if res.StatusCode != 403 {
			t.Fatalf("%s without token: %d %v", p, res.StatusCode, out["_raw"])
		}
	}
	// the right token works
	res2, out := b.post("/api-internal/login/password", body)
	wantStatus(t, res2, out, 200)
}

// The username is not a sign-in name: with the right password it fails exactly like an unknown account (same
// message, same status, one password hash spent), while the email address (any case) signs in.
func TestUsernameCannotSignIn(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0; c.Limits.LockoutAttempts = 0 })
	org := e.org(t, "acme", nil)
	name, mailAddr := "pat-the-user", "Pat.Smith@Example.com"
	role := model.RoleUser
	u, err := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{GivenName: ptr("T"), Username: &name, Email: &mailAddr, Role: &role})
	if err != nil {
		t.Fatal(err)
	}
	pw := userPassword
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, u.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	post := func(who string) (*http.Response, map[string]any, bool) {
		b := e.browser(t)
		res, out := b.post("/o/acme/api-internal/login/password", map[string]any{"email": who, "password": userPassword})
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
	res, out := b.post("/o/acme/api-internal/login/password", map[string]any{"login": name, "password": userPassword})
	wantStatus(t, res, out, 400)
	// Email addresses are case-insensitive.
	for _, who := range []string{"Pat.Smith@Example.com", "pat.smith@example.com", "PAT.SMITH@EXAMPLE.COM", "  pat.smith@example.com "} {
		res, out, sess := post(who)
		wantStatus(t, res, out, 200)
		if !sess {
			t.Errorf("%q: no session: %v", who, out)
		}
	}
	// A failed username attempt is audited as an unknown user, like any unknown account: once a minute per login,
	// whatever its case (the username in capitals is the same login, held back).
	reasons := map[string]int{}
	for _, a := range e.audits(t, "login.failure") {
		reasons[a.Detail["reason"]]++
	}
	if reasons["unknown user"] != 3 {
		t.Errorf("audit reasons %v", reasons)
	}
}

// login_hint is an email address that pre-fills the sign-in form.
func TestLoginHintPrefillsEmail(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	_, body := b.get("/o/primary/login?login_hint=ada%40example.com")
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
	res, out := b.post("/o/primary/api-internal/login/password", map[string]any{"email": "member@example.com",
		"password": userPassword, "next": "/step-up"})
	wantStatus(t, res, out, 200)
	if str(out, "step") != "enrol" || b.hasSession() {
		t.Fatalf("step-up sign-in: %v session=%v", out, b.hasSession())
	}
	b2 := e.browser(t)
	res, out = b2.post("/o/primary/api-internal/login/password", map[string]any{"email": "member@example.com",
		"password": userPassword, "next": "/x"})
	wantStatus(t, res, out, 200)
	if str(out, "step") != "" || !b2.hasSession() {
		t.Fatalf("plain sign-in: %v", out)
	}
}
