package login_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

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
	// the app lists the account under its organization's name, not the site's
	if u, err := url.Parse(str(out, "uri")); err != nil || u.Query().Get("issuer") != org.DisplayName ||
		!strings.HasPrefix(u.Path, "/"+org.DisplayName+":") {
		t.Fatalf("issuer: %v %v", str(out, "uri"), err)
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

func TestAccountTOTPRemovalInOrgRequiringMFA(t *testing.T) {
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

	// With a passkey the TOTP can go (the passkey ceremony itself is TestReauthWithPasskey).
	b.registerPasskey("Key")
	b2 := e.signedIn(t, pat)
	b2.markReauth()
	res, out = b2.api("DELETE", "/api-internal/account/totp", nil)
	wantStatus(t, res, out, 204)
}

// Setting up an authenticator app again needs a fresh re-authentication at the confirmation too, and is limited to ten
// tries a window.
func TestAccountTOTPConfirmLimits(t *testing.T) {
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

// The account page makes recovery codes after a recent re-authentication, once the account has a second factor.
func TestAccountRecoveryCodes(t *testing.T) {
	e := newEnv(t, nil)
	u := e.user(t, e.Primary, "pat", model.RoleUser)
	b := e.signedIn(t, u)
	res, out := b.get("/api-internal/account")
	_ = res
	var acct map[string]any
	_ = json.Unmarshal([]byte(out), &acct)
	sec := acct["security"].(map[string]any)
	if sec["recovery_available"] != false || sec["recovery_created"] != nil {
		t.Fatalf("no second factor: %v", sec)
	}
	b.markReauth()
	res2, o := b.post("/api-internal/account/recovery-codes", nil)
	wantStatus(t, res2, o, 422)

	e.giveTOTP(t, u)
	b.markReauth()
	res2, o = b.post("/api-internal/account/recovery-codes", nil)
	wantStatus(t, res2, o, 200)
	if list, _ := o["codes"].([]any); len(list) != service.RecoveryCodeCount || res2.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("codes: %v %q", o, res2.Header.Get("Cache-Control"))
	}
	_, out = b.get("/api-internal/account")
	_ = json.Unmarshal([]byte(out), &acct)
	sec = acct["security"].(map[string]any)
	if sec["recovery_left"] != float64(10) || sec["recovery_created"] == nil || sec["recovery_available"] != true {
		t.Fatalf("after: %v", sec)
	}
}
