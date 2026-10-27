package login_test

import (
	"context"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

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
	res, out = anon.do("POST", "/o/primary/api-internal/login/password", map[string]any{"email": "pat@example.com", "password": userPassword},
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
		if r2, o2 := b.api("PATCH", "/api-internal/account", map[string]any{f: "x"}); r2.StatusCode != 400 {
			t.Errorf("PATCH with %s: %d, want 400: %v", f, r2.StatusCode, o2)
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

func TestAccountProfileOptions(t *testing.T) {
	e, org := accountEnv(t, 0)
	b := e.signedIn(t, e.user(t, org, "pat", model.RoleUser))
	res, out := b.api("GET", "/api-internal/account/profile-options", nil)
	wantStatus(t, res, out, 200)
	for _, k := range []string{"locales", "time_zones", "user_types"} {
		if l, _ := out[k].([]any); len(l) == 0 {
			t.Errorf("%s empty: %.200v", k, out["_raw"])
		}
	}
	if res.Header.Get("Cache-Control") == "" {
		t.Error("not cacheable")
	}
	if res, _ := e.browser(t).do("GET", "/api-internal/account/profile-options", nil, nil); res.StatusCode != 401 {
		t.Fatalf("anonymous: %d", res.StatusCode)
	}
}
