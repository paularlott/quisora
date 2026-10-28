package login_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

func TestSensitiveActionsNeedReauth(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", allowAPITokens)
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

// A sign-in within the last few minutes counts as confirming it is you: an account with nothing to re-enter (signed
// in through a provider only) confirms a sensitive change by signing in again.
func TestRecentSignInCountsAsReauth(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", allowAPITokens)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	tok := map[string]any{"name": "ci", "scopes": []string{"api"}}
	res, out := b.api("POST", "/api-internal/account/tokens", tok)
	wantStatus(t, res, out, 403)
	b.fresh()
	res, out = b.api("POST", "/api-internal/account/tokens", tok)
	wantStatus(t, res, out, 201)
}

// Re-authentication asks for the account's second factor when it has one: the password alone confirms only an
// account that signs in with nothing else.
func TestReauthRequiresSecondFactor(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", allowAPITokens)

	plain := e.signedIn(t, e.user(t, org, "plain", model.RoleUser))
	res, out := plain.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword})
	wantStatus(t, res, out, 200)

	totpUser := e.user(t, org, "coder", model.RoleUser)
	secret := e.giveTOTP(t, totpUser)
	b := e.signedIn(t, totpUser)
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "code" {
		t.Fatalf("password alone with the app: %v", out)
	}
	if _, v := b.api("GET", "/api-internal/account/reauth", nil); v["valid"] != false {
		t.Fatalf("re-authenticated by the password alone: %v", v)
	}
	res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)

	keyUser := e.user(t, org, "keyed", model.RoleUser)
	k := e.signedIn(t, keyUser)
	k.registerPasskey("Key")
	k2 := e.signedIn(t, keyUser)
	res, out = k2.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "passkey" {
		t.Fatalf("password alone with a passkey: %v", out)
	}
	if _, v := k2.api("GET", "/api-internal/account/reauth", nil); v["valid"] != false {
		t.Fatalf("re-authenticated by the password alone: %v", v)
	}
}

// A code alone re-authenticates only an account that has no password, and an account with nothing to enter is asked
// for a password.
func TestReauthWithCodeOnly(t *testing.T) {
	e, org := accountEnv(t, 0)
	for i, tc := range []struct {
		name     string
		password bool
		totp     bool
		body     func(secret string) map[string]any
		field    string
	}{
		{"a password account is not confirmed by the code alone", true, true,
			func(secret string) map[string]any { return map[string]any{"code": totpAt(secret, time.Now())} }, "password"},
		{"no password: an empty body asks for the code", false, true,
			func(string) map[string]any { return map[string]any{} }, "code"},
		{"no password: a wrong code", false, true,
			func(string) map[string]any { return map[string]any{"code": "000000"} }, "code"},
		{"nothing to enter: a password is no use", false, false,
			func(string) map[string]any { return map[string]any{"password": "anything-at-all"} }, "password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := e.user(t, org, fmt.Sprintf("user%d", i), model.RoleUser)
			secret := ""
			if tc.totp {
				secret = e.giveTOTP(t, u)
			}
			if !tc.password {
				f, _ := e.Svc.Users.Get(context.Background(), u.ID)
				f.PasswordHash = ""
				if err := e.Svc.Users.Update(context.Background(), f); err != nil {
					t.Fatal(err)
				}
			}
			b := e.signedIn(t, u)
			res, out := b.api("POST", "/api-internal/account/reauth", tc.body(secret))
			wantStatus(t, res, out, 422)
			if str(out, "field") != tc.field {
				t.Fatalf("field %q, want %q: %v", str(out, "field"), tc.field, out["_raw"])
			}
			if _, v := b.api("GET", "/api-internal/account/reauth", nil); v["valid"] != false {
				t.Fatalf("re-authenticated by a refused request: %v", v)
			}
		})
	}
}

// Re-authentication asks for what the account signs in with, and a wrong or replayed code counts toward the lockout.
func TestReauthWithPasswordAndCode(t *testing.T) {
	t.Run("wrong answers count toward the lockout", func(t *testing.T) {
		e, org := accountEnv(t, 3)
		pat := e.user(t, org, "pat", model.RoleUser)
		secret := e.giveTOTP(t, pat)
		b := e.signedIn(t, pat)
		// the lockout is reached by wrong passwords and codes together; then even right answers are refused
		for _, step := range []struct {
			body  map[string]any
			want  int
			field string
		}{
			{map[string]any{}, 422, "password"},
			{map[string]any{"code": totpAt(secret, time.Now())}, 422, "password"},
			{map[string]any{"password": "wrong-password"}, 422, "password"},
			{map[string]any{"password": userPassword}, 422, "code"},
			{map[string]any{"password": userPassword, "code": "000000"}, 422, "code"},
			{map[string]any{"password": "wrong-password"}, 422, "password"}, // the third failure trips it
			{map[string]any{"password": userPassword, "code": totpAt(secret, time.Now())}, 429, ""},
			{map[string]any{"password": userPassword}, 429, ""},
		} {
			res, out := b.api("POST", "/api-internal/account/reauth", step.body)
			wantStatus(t, res, out, step.want)
			if step.field != "" && str(out, "field") != step.field {
				t.Fatalf("field %q, want %q: %v", str(out, "field"), step.field, out["_raw"])
			}
			if _, v := b.api("GET", "/api-internal/account/reauth", nil); v["valid"] == true {
				t.Fatalf("re-authenticated by a refused request: %v", step.body)
			}
		}
		if n := len(e.audits(t, "login.lockout")); n != 1 {
			t.Fatalf("lockout audits: %d", n)
		}
	})

	t.Run("a replayed code is refused", func(t *testing.T) {
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
		e.Mod.ClearReauth(b.sessionID())
		res, out = b.api("POST", "/api-internal/account/reauth", map[string]any{"password": userPassword, "code": code})
		wantStatus(t, res, out, 422)
	})
}

// An account whose second factor is a passkey is not re-authenticated by its password; the passkey ceremony is bound to
// the session that began it and to the account.
func TestReauthWithPasskey(t *testing.T) {
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
