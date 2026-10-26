package login_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
	"github.com/paularlott/quisora/internal/service"
)

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
	// The length limit counts characters, not bytes.
	for _, name := range []string{"", "   ", strings.Repeat("x", 101), strings.Repeat("é", 101)} {
		res, out = b.api("PATCH", "/api-internal/account/passkeys/"+id, map[string]any{"name": name})
		wantStatus(t, res, out, 422)
		if str(out, "field") != "name" {
			t.Fatalf("field %v", out)
		}
	}
	res, out = b.api("PATCH", "/api-internal/account/passkeys/"+id, `{bad`)
	wantStatus(t, res, out, 400)
	res, out = b.api("PATCH", "/api-internal/account/passkeys/"+id, map[string]any{"name": "  Work  "})
	wantStatus(t, res, out, 200)
	if got, _ := e.Svc.Passkeys.Get(context.Background(), id); got.Name != "Work" {
		t.Fatalf("name %q, want it trimmed", got.Name)
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

	// A disabled passkey is listed with its problem.
	disabled, _ := e.Svc.Passkeys.Get(context.Background(), id)
	disabled.Disabled = true
	if err := e.Svc.Passkeys.Update(context.Background(), disabled); err != nil {
		t.Fatal(err)
	}
	res, out = b.api("GET", "/api-internal/account/passkeys", nil)
	if it := items(t, out); len(it) != 1 || it[0]["problem"] != "disabled" {
		t.Fatalf("list: %v", out["_raw"])
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
	u, _ := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{GivenName: ptr("T"), Username: &name, Email: &email})
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

// Deleting a passkey ends the sessions that signed in with it, but not the session deleting it.
func TestDeletingPasskeyEndsItsSessions(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	b.registerPasskey("Laptop")
	other := e.browser(t)
	other.auth = b.auth // the same authenticator, on another device
	if st, out := other.passkeyLogin(map[string]any{"org": "acme"}); st != 200 {
		t.Fatalf("passkey sign-in: %d %v", st, out)
	}
	if res, _ := other.api("GET", "/api-internal/account", nil); res.StatusCode != 200 {
		t.Fatalf("not signed in: %d", res.StatusCode)
	}
	// a session signed in another way is not touched
	pwd := e.signedIn(t, pat)
	list, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	b.markReauth()
	res, out := b.api("DELETE", "/api-internal/account/passkeys/"+list[0].ID, nil)
	wantStatus(t, res, out, 204)
	if res, _ := other.api("GET", "/api-internal/account", nil); res.StatusCode != 401 {
		t.Errorf("the passkey's session survived: %d", res.StatusCode)
	}
	for name, br := range map[string]*browser{"deleting": b, "password": pwd} {
		if res, _ := br.api("GET", "/api-internal/account", nil); res.StatusCode != 200 {
			t.Errorf("%s session ended: %d", name, res.StatusCode)
		}
	}
}

// Adding a passkey on the account page: a response that does not verify (no user verification, another origin, garbage,
// an unknown challenge) stores nothing, and the audit log only has the one that did.
func TestAccountPasskeyRegistrationRefused(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	begin := func() (any, []byte) {
		b.markReauth()
		res, out := b.post("/api-internal/account/passkeys/register/begin", nil)
		wantStatus(t, res, out, 200)
		opts, _ := json.Marshal(out["options"])
		return out["challenge"], opts
	}
	for _, tc := range []struct {
		name string
		// credential makes the authenticator's response from the begun ceremony's options; nil sends junk.
		credential func(opts []byte) []byte
		challenge  any // replaces the begun challenge when set
		msg        string
	}{
		{"no user verification", func(opts []byte) []byte {
			b.auth.UserVerified = false
			defer func() { b.auth.UserVerified = true }()
			cred, _, _ := b.auth.Create(opts)
			return cred
		}, nil, "could not be registered"},
		{"another origin", func(opts []byte) []byte {
			cred, _, _ := virtualauth.New("https://evil.example").Create(opts)
			return cred
		}, nil, "could not be registered"},
		{"junk credential", nil, nil, ""},
		{"expired challenge", func(opts []byte) []byte {
			cred, _, _ := b.auth.Create(opts)
			return cred
		}, "n1.expired", "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch, opts := begin()
			cred := []byte(`"junk"`)
			if tc.credential != nil {
				cred = tc.credential(opts)
			}
			if tc.challenge != nil {
				ch = tc.challenge
			}
			b.markReauth()
			res, out := b.post("/api-internal/account/passkeys/register/finish", map[string]any{"challenge": ch, "name": "Key", "credential": json.RawMessage(cred)})
			wantStatus(t, res, out, 422)
			if !strings.Contains(str(out, "error"), tc.msg) {
				t.Fatalf("message %q, want %q", str(out, "error"), tc.msg)
			}
		})
	}
	if l, _ := e.Svc.Passkeys.All(context.Background(), pat.ID); len(l) != 0 {
		t.Fatalf("passkeys stored by refused ceremonies: %d", len(l))
	}

	b.registerPasskey("First")
	if n := len(e.audits(t, "account.passkey.add")); n != 1 {
		t.Fatalf("audited additions: %d", n)
	}
}
