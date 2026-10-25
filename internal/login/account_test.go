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

func (b *browser) api(method, path string, body any) (*http.Response, map[string]any) {
	return b.do(method, path, body, nil)
}

func items(t testing.TB, out map[string]any) []map[string]any {
	t.Helper()
	raw, _ := out["items"].([]any)
	var r []map[string]any
	for _, x := range raw {
		r = append(r, x.(map[string]any))
	}
	return r
}

func TestAccountEndpointsNeedSessionAndCSRF(t *testing.T) {
	e := newEnv(t, nil)
	pat := e.user(t, e.Primary, "pat", model.RoleUser)
	anon := e.browser(t)
	signed := e.signedIn(t, pat)

	type ep struct{ method, path string }
	all := []ep{
		{"GET", "/api-internal/account"}, {"PATCH", "/api-internal/account"}, {"POST", "/api-internal/account/email/verify"}, {"POST", "/api-internal/account/password"},
		{"GET", "/api-internal/account/passkeys"}, {"PATCH", "/api-internal/account/passkeys/x"}, {"DELETE", "/api-internal/account/passkeys/x"},
		{"POST", "/api-internal/account/passkeys/register/begin"}, {"POST", "/api-internal/account/passkeys/register/finish"},
		{"POST", "/api-internal/account/totp/begin"}, {"POST", "/api-internal/account/totp/confirm"}, {"DELETE", "/api-internal/account/totp"},
		{"GET", "/api-internal/account/reauth"}, {"POST", "/api-internal/account/reauth"}, {"POST", "/api-internal/account/reauth/passkey/begin"},
		{"POST", "/api-internal/account/reauth/passkey/finish"}, {"GET", "/api-internal/account/sessions"}, {"DELETE", "/api-internal/account/sessions/x"},
		{"DELETE", "/api-internal/account/sessions"}, {"GET", "/api-internal/account/tokens"}, {"POST", "/api-internal/account/tokens"},
		{"DELETE", "/api-internal/account/tokens/x"}, {"POST", "/api-internal/account/tokens/x/regenerate"}, {"PATCH", "/api-internal/account/tokens/x"}, {"GET", "/api-internal/account/apps"},
		{"DELETE", "/api-internal/account/apps/x"},
	}
	for _, p := range all {
		res, out := anon.do(p.method, p.path, map[string]any{}, hdrs{"X-CSRF-Token": ""})
		if res.StatusCode != 401 {
			t.Errorf("%s %s without session: %d %v", p.method, p.path, res.StatusCode, out["_raw"])
		}
		if p.method != "GET" {
			res, out = signed.do(p.method, p.path, map[string]any{}, hdrs{"X-CSRF-Token": ""})
			if res.StatusCode != 403 {
				t.Errorf("%s %s without csrf: %d %v", p.method, p.path, res.StatusCode, out["_raw"])
			}
			res, out = signed.do(p.method, p.path, map[string]any{}, hdrs{"Origin": "https://evil.example"})
			if res.StatusCode != 403 {
				t.Errorf("%s %s cross-origin: %d", p.method, p.path, res.StatusCode)
			}
		}
	}
	// the anonymous CSRF token is not accepted for session endpoints
	res, out := signed.do("PATCH", "/api-internal/account", map[string]any{"given_name": "x"}, hdrs{"X-CSRF-Token": anon.csrf})
	wantStatus(t, res, out, 403)
	// and the session token is not accepted on anonymous endpoints
	res, out = anon.do("POST", "/api-internal/login/password", map[string]any{"org": "primary", "email": "pat@example.com", "password": userPassword},
		hdrs{"X-CSRF-Token": signed.csrf})
	wantStatus(t, res, out, 403)
}

func TestAccountProfile(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleManager)
	other := e.user(t, org, "other", model.RoleUser)
	b := e.signedIn(t, pat)

	res, out := b.api("GET", "/api-internal/account", nil)
	wantStatus(t, res, out, 200)
	user := out["user"].(map[string]any)
	sec := out["security"].(map[string]any)
	orgInfo := out["org"].(map[string]any)
	if user["username"] != "pat" || user["role"] != "manager" || user["email"] != "pat@example.com" || orgInfo["name"] != "acme" ||
		sec["has_password"] != true || sec["totp"] != false || sec["passkeys"] != float64(0) || sec["passkeys_available"] != true {
		t.Fatalf("account: %v", out["_raw"])
	}
	for _, leak := range []string{"password_hash", "PasswordHash", "$argon2", "totp_secret"} {
		if strings.Contains(str(out, "_raw"), leak) {
			t.Fatalf("response leaks %s", leak)
		}
	}

	res, out = b.api("PATCH", "/api-internal/account", map[string]any{"given_name": "Pat", "family_name": "Q",
		"locale": "en-GB"})
	wantStatus(t, res, out, 200)
	u := out["user"].(map[string]any)
	// job title and phone no longer exist: the strict decoder rejects them and the profile does not return them
	for _, f := range []string{"title", "phone"} {
		if r2, o2 := b.api("PATCH", "/api-internal/account", map[string]any{f: "x"}); r2.StatusCode != 400 && r2.StatusCode != 422 {
			t.Errorf("PATCH with %s: %d %v", f, r2.StatusCode, o2)
		}
		if _, has := u[f]; has {
			t.Errorf("profile returns %s", f)
		}
	}
	if u["name"] != "Pat Q" || u["locale"] != "en-GB" {
		t.Fatalf("patch: %v", out["_raw"])
	}
	fresh, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	if fresh.FullName() != "Pat Q" || fresh.Role != model.RoleManager {
		t.Fatalf("stored %+v", fresh)
	}

	// Fields a user may not change are not even accepted.
	for _, body := range []string{`{"role":"super_admin"}`, `{"username":"root"}`, `{"active":false}`, `{"email_verified":true}`,
		`{"external_id":"x"}`, `{"password":"hunter2hunter2"}`, `{"attributes":{"a":"b"}}`, `{"org_id":"x"}`, `not json`} {
		res, out = b.api("PATCH", "/api-internal/account", body)
		if res.StatusCode != 400 {
			t.Errorf("%s: %d %v", body, res.StatusCode, out["_raw"])
		}
	}
	if f, _ := e.Svc.Users.Get(context.Background(), pat.ID); f.Role != model.RoleManager || f.Username != "pat" {
		t.Fatal("forbidden field applied")
	}
	// validation errors carry the field
	res, out = b.api("PATCH", "/api-internal/account", map[string]any{"given_name": strings.Repeat("x", 300)})
	wantStatus(t, res, out, 422)
	// The address is never the user's to change (a manager's role included): refused on the email field, whatever
	// it is changed to (a valid one, a malformed one, another user's), and nothing is stored or reserved.
	b.markReauth()
	for _, addr := range []string{"new@example.com", "not-an-email", other.Email} {
		res, out = b.api("PATCH", "/api-internal/account", map[string]any{"email": addr})
		wantStatus(t, res, out, 422)
		if str(out, "field") != "email" {
			t.Fatalf("%s: field %v", addr, out)
		}
	}
	if f, _ := e.Svc.Users.Get(context.Background(), pat.ID); f.Email != pat.Email {
		t.Fatalf("address changed to %q", f.Email)
	}
}

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
	u, _ := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: &email})
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
	pk, _ := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{GivenName: gn("P"), Username: &name2, Email: &email2})
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
	np, _ := e.Svc.CreateUser(context.Background(), service.System, nopw.ID, service.UserInput{GivenName: gn("N"), Username: &name3, Email: &email3})
	d := e.signedIn(t, np)
	d.fresh()
	res, out = d.api("GET", "/api-internal/account", nil)
	if out["security"].(map[string]any)["passwords_allowed"] != false {
		t.Fatalf("passwords_allowed: %v", out["_raw"])
	}
	res, out = d.api("POST", "/api-internal/account/password", map[string]any{"new": "not allowed here!"})
	wantStatus(t, res, out, 409)
}

func TestAccountPasskeys(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	b := e.signedIn(t, pat)
	samB := e.signedIn(t, sam)

	b.registerPasskey("Laptop")
	samB.registerPasskey("Sam's key")

	res, out := b.api("GET", "/api-internal/account/passkeys", nil)
	wantStatus(t, res, out, 200)
	list := items(t, out)
	if len(list) != 1 || list[0]["name"] != "Laptop" || out["available"] != true {
		t.Fatalf("list: %v", out["_raw"])
	}
	for _, leak := range []string{"public_key", "PublicKey", "credential_id", "user_id", "sign_count"} {
		if strings.Contains(str(out, "_raw"), leak) {
			t.Fatalf("passkey list leaks %s: %s", leak, out["_raw"])
		}
	}
	id := str(list[0], "id")
	sams, _ := e.Svc.Passkeys.All(context.Background(), sam.ID)

	// Rename.
	res, out = b.api("PATCH", "/api-internal/account/passkeys/"+id, map[string]any{"name": "Work laptop"})
	wantStatus(t, res, out, 200)
	if out["name"] != "Work laptop" {
		t.Fatal(out)
	}
	for _, name := range []string{"", "   ", strings.Repeat("x", 101)} {
		res, out = b.api("PATCH", "/api-internal/account/passkeys/"+id, map[string]any{"name": name})
		wantStatus(t, res, out, 422)
		if str(out, "field") != "name" {
			t.Fatalf("field %v", out)
		}
	}
	// Someone else's passkey is invisible: not found for rename and delete, and nothing changes.
	res, out = b.api("PATCH", "/api-internal/account/passkeys/"+sams[0].ID, map[string]any{"name": "pwned"})
	wantStatus(t, res, out, 404)
	res, out = b.api("DELETE", "/api-internal/account/passkeys/"+sams[0].ID, nil)
	wantStatus(t, res, out, 404)
	res, out = b.api("PATCH", "/api-internal/account/passkeys/nope", map[string]any{"name": "x"})
	wantStatus(t, res, out, 404)
	if s, _ := e.Svc.Passkeys.Get(context.Background(), sams[0].ID); s == nil || s.Name != "Sam's key" {
		t.Fatal("another user's passkey was modified")
	}

	// The same authenticator cannot be registered twice.
	res, begin := b.api("POST", "/api-internal/account/passkeys/register/begin", nil)
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	if _, _, err := b.auth.Create(opts); err == nil {
		t.Fatal("excludeCredentials not honoured")
	}
	// Garbage and replay at finish.
	res, out = b.api("POST", "/api-internal/account/passkeys/register/finish", map[string]any{"challenge": begin["challenge"], "name": "x", "credential": map[string]any{}})
	wantStatus(t, res, out, 422)
	res, out = b.api("POST", "/api-internal/account/passkeys/register/finish", map[string]any{"challenge": begin["challenge"], "name": "x", "credential": map[string]any{}})
	wantStatus(t, res, out, 422)
	// A challenge begun by one user cannot be finished by another.
	res, begin = b.api("POST", "/api-internal/account/passkeys/register/begin", nil)
	opts, _ = json.Marshal(begin["options"])
	fresh := b.auth
	_ = fresh
	other2 := e.signedIn(t, sam)
	other2.markReauth()
	credJSON, _, err := other2.auth.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, out = other2.api("POST", "/api-internal/account/passkeys/register/finish", map[string]any{"challenge": begin["challenge"], "name": "steal",
		"credential": json.RawMessage(credJSON)})
	wantStatus(t, res, out, 422)
	if l, _ := e.Svc.Passkeys.All(context.Background(), sam.ID); len(l) != 1 {
		t.Fatal("registered through another user's challenge")
	}

	// Delete: fine while a password exists (and after a re-authentication).
	b.markReauth()
	res, out = b.api("DELETE", "/api-internal/account/passkeys/"+id, nil)
	wantStatus(t, res, out, 204)
	if l, _ := e.Svc.Passkeys.All(context.Background(), pat.ID); len(l) != 0 {
		t.Fatal("not deleted")
	}
	if n := len(e.audits(t, "account.passkey.delete")); n != 1 {
		t.Fatalf("audits %d", n)
	}
}

func TestAccountLastSignInMethodGuard(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	name, email := "fed", "fed@example.com"
	u, _ := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: &email})
	b := e.signedIn(t, u)
	b.registerPasskey("Only key")
	list, _ := e.Svc.Passkeys.All(context.Background(), u.ID)
	b.markReauth()
	res, out := b.api("DELETE", "/api-internal/account/passkeys/"+list[0].ID, nil)
	wantStatus(t, res, out, 409)
	// A linked upstream identity is another way in, so deleting is allowed.
	p, err := e.Svc.CreateProvider(context.Background(), service.System, org.ID, service.ProviderInput{Type: ptr(model.ProviderGitHub),
		Name: ptr("GH"), ClientID: ptr("x"), ClientSecret: ptr("y")})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Svc.Identities.Create(context.Background(), model.NewIdentity(u, p, "1", "", "admin")); err != nil {
		t.Fatal(err)
	}
	res, out = b.api("DELETE", "/api-internal/account/passkeys/"+list[0].ID, nil)
	wantStatus(t, res, out, 204)
	res, out = b.api("GET", "/api-internal/account", nil)
	if provs, _ := out["security"].(map[string]any)["providers"].([]any); len(provs) != 1 || provs[0] != "GH" {
		t.Fatalf("providers: %v", out["_raw"])
	}
}

func TestAccountTOTP(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)

	// confirm before begin
	res, out := b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": "123456"})
	wantStatus(t, res, out, 409)
	// nothing to disable yet and no reauth
	res, out = b.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 403)

	// even the first authenticator app needs a recent re-authentication
	res, out = b.api("POST", "/api-internal/account/totp/begin", nil)
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Fatalf("first enrolment without re-authentication: %v", out)
	}
	b.markReauth()
	res, out = b.api("POST", "/api-internal/account/totp/begin", nil)
	wantStatus(t, res, out, 200)
	secret := str(out, "secret")
	if len(secret) < 16 || !strings.HasPrefix(str(out, "uri"), "otpauth://totp/") || !strings.Contains(str(out, "uri"), "secret="+secret) ||
		!strings.Contains(str(out, "uri"), "issuer=") || !strings.HasPrefix(str(out, "qr"), "data:image/svg+xml;base64,") {
		t.Fatalf("begin: %v", out["_raw"])
	}
	res, out = b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": "000000"})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "code" {
		t.Fatalf("field %v", out)
	}
	if f, _ := e.Svc.Users.Get(context.Background(), pat.ID); f.HasTOTP() {
		t.Fatal("enabled by a wrong code")
	}
	res, out = b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)
	f, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	si, _ := e.Svc.SignIns.Get(context.Background(), pat.ID)
	if opened, _ := e.Svc.Sealer.OpenFor(service.TOTPBinding(f.ID), f.TOTPSecret); string(opened) != secret || si == nil || si.TOTPLastStep == 0 ||
		f.MFAEnrolledAt == nil || time.Since(*f.MFAEnrolledAt) > time.Minute {
		t.Fatalf("stored totp %+v", f)
	}
	// enabled: setting it up again (to add or change phones) needs a recent re-authentication first
	e.Mod.ClearReauth(b.sessionID())
	res, out = b.api("POST", "/api-internal/account/totp/begin", nil)
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Fatalf("begin again without reauth: %v", out)
	}
	// the pending secret is gone: confirm again
	res, out = b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": totpAt(secret, time.Now().Add(30*time.Second))})
	wantStatus(t, res, out, 409)

	// Disabling needs a recent re-authentication.
	res, out = b.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 403)
	res, out = b.api("GET", "/api-internal/account/reauth", nil)
	if out["valid"] != false {
		t.Fatal(out)
	}
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": "wrong"})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "password" {
		t.Fatal(out)
	}
	res, out = b.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 403)
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{})
	wantStatus(t, res, out, 422)
	// with the app set up, the password alone no longer re-authenticates: the code is asked for too
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "code" {
		t.Fatalf("password alone for an account with the app: %v", out)
	}
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword, "code": totpAt(secret, time.Now().Add(30*time.Second))})
	wantStatus(t, res, out, 200)
	res, out = b.api("GET", "/api-internal/account/reauth", nil)
	if out["valid"] != true {
		t.Fatal(out)
	}
	// Set up again: a new secret replaces the old one once confirmed (scan it on every phone to use).
	res, out = b.api("POST", "/api-internal/account/totp/begin", nil)
	wantStatus(t, res, out, 200)
	secret2 := str(out, "secret")
	if secret2 == "" || secret2 == secret {
		t.Fatal("set up again must issue a new secret")
	}
	res, out = b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": totpAt(secret, time.Now().Add(60*time.Second))})
	wantStatus(t, res, out, 422) // a code from the old secret does not confirm the new one
	res, out = b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": totpAt(secret2, time.Now())})
	wantStatus(t, res, out, 200)
	f, _ = e.Svc.Users.Get(context.Background(), pat.ID)
	if opened, _ := e.Svc.Sealer.OpenFor(service.TOTPBinding(f.ID), f.TOTPSecret); string(opened) != secret2 {
		t.Fatal("the new secret did not replace the old one")
	}
	if len(e.audits(t, "account.totp.replace")) != 1 {
		t.Fatal("replacement not audited")
	}
	// another session of the same user does not inherit the re-authentication
	other := e.signedIn(t, pat)
	res, out = other.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 403)

	res, out = b.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 204)
	if f, _ := e.Svc.Users.Get(context.Background(), pat.ID); f.HasTOTP() {
		t.Fatal("still enabled")
	}
	res, out = b.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 409)
	if n := len(e.audits(t, "account.totp.enable")) + len(e.audits(t, "account.totp.disable")); n != 2 {
		t.Fatalf("audits %d", n)
	}
}

func TestAccountTOTPDisableWithPasskeyReauthAndMFAOrg(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	pat := e.user(t, org, "pat", model.RoleUser)
	secret := e.giveTOTP(t, pat)
	b := e.signedIn(t, pat)

	// reauthenticate (password and code), but the org requires a second factor and there is no passkey: refused
	res, out := b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)
	res, out = b.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 409)

	// With a passkey the TOTP can go, and the passkey itself re-authenticates.
	b.registerPasskey("Key")
	b2 := e.signedIn(t, pat)
	b2.auth = b.auth
	res, begin := b2.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	assertion, _, err := b2.auth.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	// the assertion is bound to the session that began it
	res, out = b.api("POST", "/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(assertion)})
	wantStatus(t, res, out, 422)
	res, begin = b2.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
	opts, _ = json.Marshal(begin["options"])
	assertion, _, _ = b2.auth.Get(opts)
	res, out = b2.api("POST", "/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(assertion)})
	wantStatus(t, res, out, 200)
	res, out = b2.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 204)
	// a user without passkeys cannot begin a passkey reauth
	c := e.signedIn(t, e.user(t, org, "sam", model.RoleUser))
	res, out = c.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, out, 422)
}

func TestAccountSessions(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	cur := e.signedIn(t, pat)
	second := e.signedIn(t, pat)
	third := e.signedIn(t, pat)
	samB := e.signedIn(t, sam)

	res, out := cur.api("GET", "/api-internal/account/sessions", nil)
	wantStatus(t, res, out, 200)
	list := items(t, out)
	if len(list) != 3 || list[0]["current"] != true || list[1]["current"] == true {
		t.Fatalf("sessions: %v", out["_raw"])
	}
	// handles are not session ids: the id is the cookie secret
	all, _ := e.Svc.Sessions.All(context.Background(), pat.ID)
	for _, s := range all {
		if strings.Contains(str(out, "_raw"), s.ID) {
			t.Fatal("session id leaked to the page")
		}
		if strings.Contains(str(out, "_raw"), s.CSRF) {
			t.Fatal("session csrf leaked to the page")
		}
	}
	// a session handle taken from the list ends exactly that session
	victim := ""
	for _, s := range list[1:] {
		victim = str(s, "id")
	}
	res, out = cur.api("DELETE", "/api-internal/account/sessions/"+victim, nil)
	wantStatus(t, res, out, 204)
	if left, _ := e.Svc.Sessions.All(context.Background(), pat.ID); len(left) != 2 {
		t.Fatalf("sessions left %d", len(left))
	}
	// the current session cannot be revoked this way; unknown handles are 404
	res, out = cur.api("GET", "/api-internal/account/sessions", nil)
	curHandle := str(items(t, out)[0], "id")
	res, out = cur.api("DELETE", "/api-internal/account/sessions/"+curHandle, nil)
	wantStatus(t, res, out, 409)
	res, out = cur.api("DELETE", "/api-internal/account/sessions/nope", nil)
	wantStatus(t, res, out, 404)
	// another user's sessions are not reachable
	res, out = samB.api("GET", "/api-internal/account/sessions", nil)
	if len(items(t, out)) != 1 {
		t.Fatalf("sam sees %d sessions", len(items(t, out)))
	}
	res, out = samB.api("DELETE", "/api-internal/account/sessions/"+curHandle, nil)
	wantStatus(t, res, out, 404)
	if res, _ := cur.api("GET", "/api-internal/account", nil); res.StatusCode != 200 {
		t.Fatal("pat's session ended by sam")
	}

	// revoke all others
	res, out = cur.api("DELETE", "/api-internal/account/sessions", nil)
	wantStatus(t, res, out, 200)
	if out["revoked"] != float64(1) {
		t.Fatalf("revoked %v", out)
	}
	if res, _ := cur.api("GET", "/api-internal/account", nil); res.StatusCode != 200 {
		t.Fatal("current session ended")
	}
	if res, _ := second.api("GET", "/api-internal/account", nil); res.StatusCode != 401 {
		t.Fatalf("other session alive: %d", res.StatusCode)
	}
	_ = third
	if res, _ := samB.api("GET", "/api-internal/account", nil); res.StatusCode != 200 {
		t.Fatal("sam's session ended")
	}
}

func TestAccountTokens(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	mgr := e.user(t, org, "mia", model.RoleManager)
	b := e.signedIn(t, pat)
	m := e.signedInMFA(t, mgr)

	// a manager's session without a second factor cannot make a token (it would act as the manager and skip the
	// console's second-factor check)
	single := e.signedIn(t, mgr)
	single.markReauth()
	res, out := single.api("POST", "/api-internal/account/tokens", map[string]any{"name": "x", "scopes": []string{"api"}})
	wantStatus(t, res, out, 403)

	res, out = b.api("GET", "/api-internal/account/tokens", nil)
	wantStatus(t, res, out, 200)
	if sc, _ := out["scopes"].([]any); len(sc) != 1 || sc[0] != "api" {
		t.Fatalf("user scopes %v", out["scopes"])
	}
	res, out = m.api("GET", "/api-internal/account/tokens", nil)
	if sc, _ := out["scopes"].([]any); len(sc) != 3 {
		t.Fatalf("manager scopes %v", out["scopes"])
	}

	b.markReauth()
	res, out = b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}, "expires_days": 30})
	wantStatus(t, res, out, 201)
	token := str(out, "token")
	item := out["item"].(map[string]any)
	if !strings.HasPrefix(token, "qsr_"+str(item, "id")+"_") {
		t.Fatalf("token %q", token)
	}
	exp, _ := time.Parse(time.RFC3339, str(item, "expires"))
	if d := time.Until(exp); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("expiry %v", exp)
	}
	// the secret is shown once
	res, out = b.api("GET", "/api-internal/account/tokens", nil)
	if strings.Contains(str(out, "_raw"), token) || strings.Contains(str(out, "_raw"), "secret") || len(items(t, out)) != 1 {
		t.Fatalf("list: %v", out["_raw"])
	}
	// and works with the service
	if _, u, err := e.Svc.ValidateAPIToken(context.Background(), token); err != nil || u.ID != pat.ID {
		t.Fatalf("token invalid: %v", err)
	}

	// validation and role limits
	for name, body := range map[string]map[string]any{
		"no name": {"name": "", "scopes": []string{"api"}}, "no scopes": {"name": "x", "scopes": []string{}},
		"unknown scope": {"name": "x", "scopes": []string{"root"}}, "scim as user": {"name": "x", "scopes": []string{"scim"}},
		"admin as user": {"name": "x", "scopes": []string{"admin"}}, "too long": {"name": "x", "scopes": []string{"api"}, "expires_days": 100000},
		"negative": {"name": "x", "scopes": []string{"api"}, "expires_days": -1},
	} {
		res, out = b.api("POST", "/api-internal/account/tokens", body)
		if res.StatusCode != 422 {
			t.Errorf("%s: %d %v", name, res.StatusCode, out["_raw"])
		}
	}
	res, out = b.api("POST", "/api-internal/account/tokens", `{"name":"x","scopes":["api"],"user_id":"someone"}`)
	wantStatus(t, res, out, 400)
	m.markReauth()
	res, out = m.api("POST", "/api-internal/account/tokens", map[string]any{"name": "provisioning", "scopes": []string{"scim"}})
	wantStatus(t, res, out, 201)
	mgrTokenID := str(out["item"].(map[string]any), "id")

	// delete: own token only, even an administrator cannot delete someone else's through the account API
	admin := e.signedIn(t, e.Admin)
	res, out = admin.api("DELETE", "/api-internal/account/tokens/"+mgrTokenID, nil)
	wantStatus(t, res, out, 404)
	res, out = b.api("DELETE", "/api-internal/account/tokens/"+mgrTokenID, nil)
	wantStatus(t, res, out, 404)
	res, out = b.api("DELETE", "/api-internal/account/tokens/nope", nil)
	wantStatus(t, res, out, 404)
	if _, err := e.Svc.APITokens.Get(context.Background(), mgrTokenID); err != nil {
		t.Fatal("someone else's token deleted")
	}
	res, out = b.api("GET", "/api-internal/account/tokens", nil)
	id := str(items(t, out)[0], "id")
	res, out = b.api("DELETE", "/api-internal/account/tokens/"+id, nil)
	wantStatus(t, res, out, 204)
	if _, _, err := e.Svc.ValidateAPIToken(context.Background(), token); err == nil {
		t.Fatal("deleted token still valid")
	}
}

func TestAccountApps(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	c1, _, err := e.Svc.CreateClient(context.Background(), service.System, org.ID, service.ClientInput{Name: ptr("Wiki"),
		RedirectURIs: &[]string{"https://wiki.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	c2, _, _ := e.Svc.CreateClient(context.Background(), service.System, org.ID, service.ClientInput{Name: ptr("Chat"),
		RedirectURIs: &[]string{"https://chat.example/cb"}})
	mk := func(u *model.User, c *model.Client, scopes []string, mut func(*model.Grant)) *model.Grant {
		g := &model.Grant{ClientID: c.ID, UserID: u.ID, OrgID: org.ID, Scopes: scopes, Expires: time.Now().Add(time.Hour)}
		if mut != nil {
			mut(g)
		}
		if err := e.Svc.Grants.Create(context.Background(), g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	mk(pat, c1, []string{"openid", "email"}, nil)
	mk(pat, c1, []string{"openid", "profile"}, nil)
	mk(pat, c2, []string{"openid"}, nil)
	mk(pat, c2, []string{"admin"}, func(g *model.Grant) { g.Revoked = true })
	mk(pat, c2, []string{"admin"}, func(g *model.Grant) { g.Expires = time.Now().Add(-time.Hour) })
	mk(sam, c1, []string{"openid"}, nil)

	b := e.signedIn(t, pat)
	res, out := b.api("GET", "/api-internal/account/apps", nil)
	wantStatus(t, res, out, 200)
	list := items(t, out)
	if len(list) != 2 || list[0]["name"] != "Chat" || list[1]["name"] != "Wiki" {
		t.Fatalf("apps: %v", out["_raw"])
	}
	wiki := list[1]
	if wiki["grants"] != float64(2) {
		t.Fatalf("wiki grants %v", wiki["grants"])
	}
	if sc, _ := wiki["scopes"].([]any); len(sc) != 3 { // union of both grants
		t.Fatalf("wiki scopes %v", wiki["scopes"])
	}
	if sc, _ := list[0]["scopes"].([]any); len(sc) != 1 { // revoked and expired grants are not shown
		t.Fatalf("chat scopes %v", list[0]["scopes"])
	}
	for _, leak := range []string{"Secret", "Counter", "nonce", "session_id"} {
		if strings.Contains(str(out, "_raw"), leak) {
			t.Fatalf("leaks %s", leak)
		}
	}

	res, out = b.api("DELETE", "/api-internal/account/apps/"+c1.ID, nil)
	wantStatus(t, res, out, 204)
	res, out = b.api("GET", "/api-internal/account/apps", nil)
	if len(items(t, out)) != 1 {
		t.Fatalf("after revoke: %v", out["_raw"])
	}
	// the other user's grant for the same client is untouched
	if g, _ := e.Svc.Grants.All(context.Background(), sam.ID); len(g) != 1 {
		t.Fatal("another user's grant removed")
	}
	res, out = b.api("DELETE", "/api-internal/account/apps/"+c1.ID, nil)
	wantStatus(t, res, out, 404)
	res, out = b.api("DELETE", "/api-internal/account/apps/nope", nil)
	wantStatus(t, res, out, 404)
}

func TestAccountPageRenders(t *testing.T) {
	e := newEnv(t, nil)
	b := e.signedIn(t, e.Admin)
	res, body := b.get("/account")
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	for _, want := range []string{`x-data="accountProfile"`, `x-data="accountPassword"`, `x-data="accountPasskeys"`, `x-data="accountTotp"`, `id="password-dialog"`, `id="totp-dialog"`,
		`x-data="accountSessions"`, `x-data="accountTokens"`, `x-data="accountApps"`, `id="add-passkey-dialog"`, `id="token-dialog"`,
		`id="rename-passkey-dialog"`, `<meta name="csrf-token" content="` + b.csrf + `">`, `aria-describedby="e-given_name"`} {
		if !strings.Contains(body, want) {
			t.Errorf("account page lacks %s", want)
		}
	}
	// signed in with nav: the page uses the app shell
	if !strings.Contains(body, `aria-label="Primary"`) {
		t.Error("no app navigation")
	}
}

func TestLoginPagesAreAccessible(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	_, body := b.get("/login/primary")
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

func TestSensitiveActionsNeedReauth(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	b.registerPasskey("Key")
	list, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	auth := b.auth
	b = e.signedIn(t, pat) // a new session: the helper's re-authentication does not carry over
	b.auth = auth

	expect := func(what string, res *http.Response, out map[string]any, status int) {
		t.Helper()
		if res.StatusCode != status {
			t.Fatalf("%s: status %d, want %d: %v", what, res.StatusCode, status, out["_raw"])
		}
		if status == 403 && str(out, "field") != "reauth" {
			t.Fatalf("%s: field %v", what, out)
		}
	}
	tok := map[string]any{"name": "ci", "scopes": []string{"api"}}

	// Without a recent re-authentication all three are refused in the shape TOTP disable uses.
	// (an address change is never the user's own: refused at once, without asking to re-authenticate for nothing)
	res, out := b.api("PATCH", "/api-internal/account", map[string]any{"email": "changed@example.com"})
	expect("email change", res, out, 422)
	res, out = b.api("DELETE", "/api-internal/account/passkeys/"+list[0].ID, nil)
	expect("passkey delete", res, out, 403)
	res, out = b.api("POST", "/api-internal/account/tokens", tok)
	expect("token create", res, out, 403)
	res, out = b.api("POST", "/api-internal/account/passkeys/register/begin", nil)
	expect("passkey register begin", res, out, 403)
	res, out = b.api("POST", "/api-internal/account/passkeys/register/finish", map[string]any{"challenge": "x", "credential": map[string]any{}})
	expect("passkey register finish", res, out, 403)
	if l, _ := e.Svc.Passkeys.All(context.Background(), pat.ID); len(l) != 1 {
		t.Fatal("passkey deleted without re-authentication")
	}
	if u, _ := e.Svc.Users.Get(context.Background(), pat.ID); u.Email == "changed@example.com" {
		t.Fatal("email changed by the user")
	}
	// Profile edits that leave the email alone (or resend the current one) need no re-authentication.
	res, out = b.api("PATCH", "/api-internal/account", map[string]any{"given_name": "Pat"})
	expect("name change", res, out, 200)
	res, out = b.api("PATCH", "/api-internal/account", map[string]any{"email": strings.ToUpper(pat.Email), "given_name": "x"})
	expect("same email", res, out, 200)

	// The account's passkey is its second factor: the password alone does not re-authenticate it.
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword})
	expect("reauth with the password alone", res, out, 422)
	if str(out, "field") != "passkey" {
		t.Fatalf("password alone with a passkey: %v", out)
	}
	// After re-authenticating through the real endpoint (the passkey) all three go through.
	res, begin := b.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
	expect("reauth begin", res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	assertion, _, err := b.auth.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, out = b.api("POST", "/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(assertion)})
	expect("reauth", res, out, 200)
	res, out = b.api("PATCH", "/api-internal/account", map[string]any{"email": "changed@example.com"})
	expect("email change", res, out, 422) // re-authenticated or not, someone else changes the address
	res, out = b.api("POST", "/api-internal/account/tokens", tok)
	expect("token create", res, out, 201)
	res, out = b.api("POST", "/api-internal/account/passkeys/register/begin", nil)
	expect("passkey register begin", res, out, 200)
	res, out = b.api("DELETE", "/api-internal/account/passkeys/"+list[0].ID, nil)
	expect("passkey delete", res, out, 204)

	// Another session of the same user does not inherit it.
	other := e.signedIn(t, pat)
	res, out = other.api("POST", "/api-internal/account/tokens", tok)
	expect("other session", res, out, 403)
}

// A code alone re-authenticates only an account that has no password.
func TestReauthCodeOnlyWithoutPassword(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	secret := e.giveTOTP(t, pat)
	b := e.signedIn(t, pat)
	res, out := b.api("POST", "/api-internal/account/reauth", map[string]any{"code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 422)
	res, out = b.api("GET", "/api-internal/account/reauth", nil)
	if out["valid"] != false {
		t.Fatalf("code alone re-authenticated a password account: %v", out)
	}
}

// With the org requiring MFA, the last passkey of a user without an authenticator app cannot be deleted.
func TestPasskeyDeleteKeepsRequiredSecondFactor(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	b.registerPasskey("Only")
	list, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	res, out := b.api("DELETE", "/api-internal/account/passkeys/"+list[0].ID, nil)
	wantStatus(t, res, out, 409)
	// With an authenticator app set up the same deletion is fine.
	e.giveTOTP(t, pat)
	b2 := e.signedIn(t, pat)
	b2.markReauth()
	res, out = b2.api("DELETE", "/api-internal/account/passkeys/"+list[0].ID, nil)
	wantStatus(t, res, out, 204)
}

// A sign-in within the last few minutes counts as confirming it is you: an account with nothing to re-enter (signed
// in through a provider only) confirms a sensitive change by signing in again.
func TestRecentSignInCountsAsReauth(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	tok := map[string]any{"name": "ci", "scopes": []string{"api"}}
	res, out := b.api("POST", "/api-internal/account/tokens", tok)
	wantStatus(t, res, out, 403)
	b.fresh()
	res, out = b.api("POST", "/api-internal/account/tokens", tok)
	wantStatus(t, res, out, 201)
}

// A token's secret can be replaced: the new one works at once and the old one stops; the name, access and expiry stay.
// The same conditions as making a token (a recent re-authentication), and only for your own tokens.
func TestAccountTokenRegenerate(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	b := e.signedIn(t, pat)
	b.markReauth()
	res, out := b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}, "expires_days": 30})
	wantStatus(t, res, out, 201)
	old := str(out, "token")
	id := str(out["item"].(map[string]any), "id")
	exp := str(out["item"].(map[string]any), "expires")

	// someone else's token is not found, even with a fresh re-authentication
	other := e.signedIn(t, sam)
	other.markReauth()
	res, out = other.api("POST", "/api-internal/account/tokens/"+id+"/regenerate", nil)
	wantStatus(t, res, out, 404)

	res, out = b.api("POST", "/api-internal/account/tokens/"+id+"/regenerate", nil)
	wantStatus(t, res, out, 200)
	fresh := str(out, "token")
	item := out["item"].(map[string]any)
	if fresh == old || !strings.HasPrefix(fresh, "qsr_"+id+"_") || str(item, "name") != "ci" || !sameSecond(str(item, "expires"), exp) {
		t.Fatalf("regenerated: %q %v", fresh, item)
	}
	if _, _, err := e.Svc.ValidateAPIToken(context.Background(), old); err == nil {
		t.Fatal("the old secret still works")
	}
	if _, _, err := e.Svc.ValidateAPIToken(context.Background(), fresh); err != nil {
		t.Fatalf("the new secret: %v", err)
	}
	if len(e.audits(t, "apitoken.regenerate")) == 0 {
		t.Error("no audit entry")
	}
}

func sameSecond(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	return errA == nil && errB == nil && ta.Truncate(time.Second).Equal(tb.Truncate(time.Second))
}

// The token list offers the applications a token can be for, with their own scopes; editing a token changes its
// name, applications and scopes (checked as when it was made), and only for its owner.
func TestAccountTokenEdit(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	app, _, err := e.Svc.CreateClient(context.Background(), service.System, org.ID, service.ClientInput{Name: ptr("Orders"),
		GrantTypes: ptr([]string{"client_credentials"}), Scopes: ptr([]string{"orders:read", "orders:write"})})
	if err != nil {
		t.Fatal(err)
	}
	b := e.signedIn(t, pat)
	b.markReauth()
	res, out := b.api("GET", "/api-internal/account/tokens", nil)
	wantStatus(t, res, out, 200)
	apps, _ := out["apps"].([]any)
	if len(apps) != 1 || str(apps[0].(map[string]any), "id") != app.ID {
		t.Fatalf("apps: %v", out["apps"])
	}
	res, out = b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"},
		"audience": []string{app.ID}, "app_scopes": []string{"orders:read"}})
	wantStatus(t, res, out, 201)
	id := str(out["item"].(map[string]any), "id")

	res, out = b.api("PATCH", "/api-internal/account/tokens/"+id, map[string]any{"app_scopes": []string{"billing:read"}})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "app_scopes" {
		t.Fatalf("field %v", out)
	}
	res, out = b.api("PATCH", "/api-internal/account/tokens/"+id, map[string]any{"name": "ci (read/write)", "app_scopes": []string{"orders:read", "orders:write"}})
	wantStatus(t, res, out, 200)
	if it := out["item"].(map[string]any); str(it, "name") != "ci (read/write)" || len(it["app_scopes"].([]any)) != 2 {
		t.Fatalf("edited %v", it)
	}
	other := e.signedIn(t, sam)
	other.markReauth()
	res, out = other.api("PATCH", "/api-internal/account/tokens/"+id, map[string]any{"name": "mine"})
	wantStatus(t, res, out, 404)
}
