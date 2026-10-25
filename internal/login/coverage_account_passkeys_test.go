package login_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
)

// Adding a passkey on the account page: a response that does not verify (no user verification, another origin,
// garbage, a challenge begun for something else) stores nothing, and the audit log only has the one that did.
func TestCoverageAccountPasskeyRegistrationRefusals(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)
	b.markReauth()
	begin := func() (any, []byte) {
		b.markReauth()
		res, out := b.post("/api-internal/account/passkeys/register/begin", nil)
		wantStatus(t, res, out, 200)
		opts, _ := json.Marshal(out["options"])
		return out["challenge"], opts
	}
	finish := func(ch any, cred []byte, want int, msg string) {
		t.Helper()
		b.markReauth()
		res, out := b.post("/api-internal/account/passkeys/register/finish", map[string]any{"challenge": ch, "name": "Key", "credential": json.RawMessage(cred)})
		wantStatus(t, res, out, want)
		if msg != "" && !strings.Contains(str(out, "error"), msg) {
			t.Fatalf("message %q, want %q", str(out, "error"), msg)
		}
	}

	ch, opts := begin()
	b.auth.UserVerified = false
	cred, _, _ := b.auth.Create(opts)
	b.auth.UserVerified = true
	finish(ch, cred, 422, "could not be registered")

	ch, opts = begin()
	cred, _, _ = virtualauth.New("https://evil.example").Create(opts)
	finish(ch, cred, 422, "could not be registered")

	ch, _ = begin()
	finish(ch, []byte(`"junk"`), 422, "")

	// an unknown (expired) challenge says so
	_, opts = begin()
	cred, _, _ = b.auth.Create(opts)
	finish("n1.expired", cred, 422, "expired")

	// a ceremony begun for re-authentication cannot register a passkey
	b.registerPasskey("First")
	e.Mod.ClearReauth(b.sessionID())
	res, rb := b.post("/api-internal/account/reauth/passkey/begin", nil)
	wantStatus(t, res, rb, 200)
	_, opts = begin()
	cred, _, _ = virtualauth.New(e.Cfg.Server.PublicURL).Create(opts)
	finish(rb["challenge"], cred, 422, "")

	if l, _ := e.Svc.Passkeys.All(context.Background(), pat.ID); len(l) != 1 {
		t.Fatalf("passkeys stored: %d", len(l))
	}
	if n := len(e.audits(t, "account.passkey.add")); n != 1 {
		t.Fatalf("audited additions: %d", n)
	}
}

// Passkey names are checked, and one cannot rename or delete another account's passkey.
func TestCoverageAccountPasskeyNamesAndOwnership(t *testing.T) {
	e, org := accountEnv(t, 0)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	b := e.signedIn(t, pat)
	b.registerPasskey("Laptop")
	sb := e.signedIn(t, sam)
	l, _ := e.Svc.Passkeys.All(context.Background(), pat.ID)
	id := l[0].ID

	for _, name := range []string{"", "   ", strings.Repeat("é", 101)} {
		res, out := b.api("PATCH", "/api-internal/account/passkeys/"+id, map[string]any{"name": name})
		wantStatus(t, res, out, 422)
	}
	res, out := b.api("PATCH", "/api-internal/account/passkeys/"+id, `{bad`)
	wantStatus(t, res, out, 400)
	sb.markReauth()
	res, out = sb.api("PATCH", "/api-internal/account/passkeys/"+id, map[string]any{"name": "mine now"})
	wantStatus(t, res, out, 404)
	res, out = sb.api("DELETE", "/api-internal/account/passkeys/"+id, nil)
	wantStatus(t, res, out, 404)
	res, out = b.api("PATCH", "/api-internal/account/passkeys/"+id, map[string]any{"name": "  Work  "})
	wantStatus(t, res, out, 200)
	if got, _ := e.Svc.Passkeys.Get(context.Background(), id); got.Name != "Work" {
		t.Fatalf("name %q", got.Name)
	}
	// a disabled passkey is listed with its problem
	got, _ := e.Svc.Passkeys.Get(context.Background(), id)
	got.Disabled = true
	_ = e.Svc.Passkeys.Update(context.Background(), got)
	res, out = b.api("GET", "/api-internal/account/passkeys", nil)
	if it := items(t, out); len(it) != 1 || it[0]["problem"] != "disabled" {
		t.Fatalf("list: %v", out["_raw"])
	}
}
