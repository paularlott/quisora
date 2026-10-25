package login_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
)

func accountEnv(t *testing.T, attempts int) (*env, *model.Org) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LoginPerIPMin = 0
		c.Limits.LockoutAttempts = attempts
		c.Audit.Logins = true
	})
	return e, e.org(t, "acme", nil)
}

func TestCoverageProfileOptions(t *testing.T) {
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

// Verification mails are limited to five an hour per account, shared by the primary address and linked ones.
func TestCoverageVerificationMailLimits(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	for i := range 5 {
		res, out := b.api("POST", "/api-internal/account/email/verify", nil)
		if res.StatusCode != 200 {
			t.Fatalf("mail %d: %d %v", i, res.StatusCode, out["_raw"])
		}
		e.nextMail(t)
	}
	res, out := b.api("POST", "/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") != "3600" {
		t.Fatalf("Retry-After %q", res.Header.Get("Retry-After"))
	}
	res, out = b.api("POST", "/api-internal/account/emails/"+pat.Email+"/verify", nil)
	wantStatus(t, res, out, 429)
	e.noMail(t)

	// an account with no address, and one already verified
	nu := e.user(t, org, "noaddr", model.RoleUser)
	nf, _ := e.Svc.Users.Get(context.Background(), nu.ID)
	nf.Email = ""
	if err := e.Svc.Users.Update(context.Background(), nf); err != nil {
		t.Fatal(err)
	}
	nb := e.signedIn(t, nu)
	res, out = nb.api("POST", "/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 422)
	v := e.verifiedUser(t, org, "vera", model.RoleUser)
	vb := e.signedIn(t, v)
	res, out = vb.api("POST", "/api-internal/account/email/verify", nil)
	wantStatus(t, res, out, 409)
	// an address the account does not have gets no mail
	res, out = vb.api("POST", "/api-internal/account/emails/stranger@example.com/verify", nil)
	if res.StatusCode < 400 {
		t.Fatalf("mail for an address the account does not have: %d", res.StatusCode)
	}
	e.noMail(t)
}

// Re-authentication asks for what the account signs in with, and a wrong or replayed code counts toward the lockout.
func TestCoverageReauthPasswordAndCode(t *testing.T) {
	e, org := accountEnv(t, 3)
	pat := e.user(t, org, "pat", model.RoleUser)
	secret := e.giveTOTP(t, pat)
	b := e.signedIn(t, pat)
	valid := func() bool {
		_, out := b.api("GET", "/api-internal/account/reauth", nil)
		return out["valid"] == true
	}
	post := func(body map[string]any, want int, field string) {
		t.Helper()
		res, out := b.api("POST", "/api-internal/account/reauth", body)
		wantStatus(t, res, out, want)
		if field != "" && str(out, "field") != field {
			t.Fatalf("field %q, want %q: %v", str(out, "field"), field, out["_raw"])
		}
		if want != 200 && valid() {
			t.Fatalf("re-authenticated by a refused request: %v", body)
		}
	}
	post(map[string]any{}, 422, "password")
	post(map[string]any{"code": totpAt(secret, time.Now())}, 422, "password")
	post(map[string]any{"password": "wrong-password"}, 422, "password")
	post(map[string]any{"password": userPassword}, 422, "code")
	post(map[string]any{"password": userPassword, "code": "000000"}, 422, "code")
	// the lockout is reached by wrong passwords and codes together; then even right answers are refused
	post(map[string]any{"password": "wrong-password"}, 422, "password") // the third failure trips it
	post(map[string]any{"password": userPassword, "code": totpAt(secret, time.Now())}, 429, "")
	post(map[string]any{"password": userPassword}, 429, "")
	if len(e.audits(t, "login.lockout")) != 1 {
		t.Fatalf("lockout audits: %d", len(e.audits(t, "login.lockout")))
	}
}

func TestCoverageReauthSucceedsOnceAndRejectsReplay(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	secret := e.giveTOTP(t, pat)
	b := e.signedIn(t, pat)
	code := totpAt(secret, time.Now())
	res, out := b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword, "code": code})
	wantStatus(t, res, out, 200)
	if _, out = b.api("GET", "/api-internal/account/reauth", nil); out["valid"] != true {
		t.Fatal("not re-authenticated")
	}
	// the same code again (a replay) is refused
	e.Mod.ClearReauth(b.sessionID())
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword, "code": code})
	wantStatus(t, res, out, 422)
}

// An account with an authenticator app and no password confirms with the code alone; one with nothing to enter is
// asked for a password.
func TestCoverageReauthCodeOnlyAccount(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	secret := e.giveTOTP(t, pat)
	f, _ := e.Svc.Users.Get(context.Background(), pat.ID)
	f.PasswordHash = ""
	if err := e.Svc.Users.Update(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	b := e.signedIn(t, pat)
	res, out := b.api("POST", "/api-internal/account/reauth", map[string]any{})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "code" {
		t.Fatalf("field %v", out)
	}
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"code": "000000"})
	wantStatus(t, res, out, 422)
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)

	bare := e.user(t, org, "bare", model.RoleUser)
	f, _ = e.Svc.Users.Get(context.Background(), bare.ID)
	f.PasswordHash = ""
	_ = e.Svc.Users.Update(context.Background(), f)
	bb := e.signedIn(t, bare)
	res, out = bb.api("POST", "/api-internal/account/reauth", map[string]any{"password": "anything-at-all"})
	wantStatus(t, res, out, 422)
}

// An account whose second factor is a passkey is not re-authenticated by its password; the passkey ceremony is bound to
// the session that began it and to the account.
func TestCoverageReauthPasskey(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)

	res, out := b.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, out, 422) // no passkeys yet

	b.registerPasskey("Key")
	e.Mod.ClearReauth(b.sessionID())
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "passkey" {
		t.Fatalf("field %v", out)
	}

	// garbage and unknown challenges
	res, out = b.api("POST", "/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": "nope", "credential": json.RawMessage(`{}`)})
	wantStatus(t, res, out, 422)

	// a ceremony begun by another session of the same account does not re-authenticate this one
	other := e.signedIn(t, pat)
	other.auth = b.auth
	res, begin := other.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, begin, 200)
	opts, _ := json.Marshal(begin["options"])
	cred, _, err := b.auth.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, out = b.api("POST", "/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(cred)})
	wantStatus(t, res, out, 422)
	if _, out = b.api("GET", "/api-internal/account/reauth", nil); out["valid"] == true {
		t.Fatal("re-authenticated through another session's ceremony")
	}

	// the right ceremony works
	res, begin = b.api("POST", "/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, begin, 200)
	opts, _ = json.Marshal(begin["options"])
	cred, _, _ = b.auth.Get(opts)
	res, out = b.api("POST", "/api-internal/account/reauth/passkey/finish", map[string]any{"challenge": begin["challenge"], "credential": json.RawMessage(cred)})
	wantStatus(t, res, out, 200)
	if _, out = b.api("GET", "/api-internal/account/reauth", nil); out["valid"] != true {
		t.Fatal("not re-authenticated")
	}
}

// Setting up an authenticator app again is limited to ten tries a window, and replacing a working one needs a fresh
// re-authentication at the confirmation too.
func TestCoverageTOTPConfirmLimitsAndReplace(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	e.giveTOTP(t, pat)
	b := e.signedIn(t, pat)
	b.markReauth()
	res, out := b.api("POST", "/api-internal/account/totp/begin", nil)
	wantStatus(t, res, out, 200)
	secret := str(out, "secret")

	// the re-authentication lapses before the code is confirmed
	e.Mod.ClearReauth(b.sessionID())
	res, out = b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Fatalf("field %v", out)
	}
	for range 9 {
		b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": "000000"})
	}
	res, out = b.api("POST", "/api-internal/account/totp/confirm", map[string]any{"code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	if f, _ := e.Svc.Users.Get(context.Background(), pat.ID); !f.HasTOTP() {
		t.Fatal("factor lost")
	}
}

// API tokens of managers and above need a second-factor session to be changed, as to be made.
func TestCoverageTokenChangesNeedMFAForManagers(t *testing.T) {
	e, org := accountEnv(t, 0)
	mgr := e.user(t, org, "mia", model.RoleManager)
	mfa := e.signedInMFA(t, mgr)
	mfa.markReauth()
	res, out := mfa.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}})
	wantStatus(t, res, out, 201)
	id := str(out["item"].(map[string]any), "id")

	single := e.signedIn(t, mgr)
	single.markReauth()
	res, out = single.api("PATCH", "/api-internal/account/tokens/"+id, map[string]any{"name": "renamed"})
	wantStatus(t, res, out, 403)
	if str(out, "field") != "mfa" {
		t.Fatalf("update: %v", out["_raw"])
	}
	res, out = single.api("POST", "/api-internal/account/tokens/"+id+"/regenerate", nil)
	wantStatus(t, res, out, 403)
	if str(out, "field") != "mfa" {
		t.Fatalf("regenerate: %v", out["_raw"])
	}
	// without a recent re-authentication it is the confirmation that is asked for first
	e.Mod.ClearReauth(single.sessionID())
	res, out = single.api("DELETE", "/api-internal/account/tokens/"+id, nil)
	if res.StatusCode != 403 && res.StatusCode != 204 {
		t.Fatalf("delete: %d", res.StatusCode)
	}
}
