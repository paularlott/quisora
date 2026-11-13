package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Whoever manages a user sees the applications they connected and the providers linked to them, and can end
// either for them; never on their own account (the account page does that, re-authenticated).
func TestUserConnectionsAPI(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	u := w.users["user"]
	cl, _, err := w.env.Svc.CreateClient(ctx, service.System, u.OrgID, service.ClientInput{Name: ptr("Knot"), RedirectURIs: &[]string{"https://knot.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"s1", "s2"} {
		g := &model.Grant{UserID: u.ID, OrgID: u.OrgID, ClientID: cl.ID, SessionID: sid, Scopes: []string{"openid", "email"}}
		if err := w.env.Svc.Grants.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	p := &model.Provider{OrgID: u.OrgID, Name: "GitHub", Type: model.ProviderGitHub, Enabled: true}
	if err := w.env.Svc.Providers.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := w.env.Svc.Identities.Create(ctx, model.NewIdentity(u, p, "gh-1", "alan@github.example", "connect")); err != nil {
		t.Fatal(err)
	}
	U := AU + "/" + u.ID
	mg := w.as("manager")

	r := mg.get(U + "/apps")
	want(t, r, 200)
	if it := first(r); r.total() != 1 || it["name"] != "Knot" || it["grants"] != float64(2) {
		t.Fatalf("apps: %s", r.Raw)
	}
	r = mg.get(U + "/providers")
	want(t, r, 200)
	if it := first(r); r.total() != 1 || it["name"] != "GitHub" || it["email"] != "alan@github.example" || it["via"] != "connect" {
		t.Fatalf("providers: %s", r.Raw)
	}

	// who may: managers of the user and the user themselves; not a manager on an admin, not another org
	want(t, w.as("user").get(U+"/apps"), 200)
	want(t, mg.get(AU+"/"+w.users["admin"].ID+"/apps"), 403)
	want(t, w.as("other").get(U+"/apps"), 404)
	want(t, w.as("admin").get(AU+"/"+w.users["admin"].ID+"/providers"), 200)
	want(t, w.as("admin").delete(AU+"/"+w.users["admin"].ID+"/apps/"+cl.ID), 404) // nothing granted

	// removing an application ends every grant to it; disconnecting a provider unlinks it
	want(t, mg.delete(U+"/apps/"+cl.ID), 200)
	if gs, _ := w.env.Svc.Grants.All(ctx, u.ID); len(gs) != 0 {
		t.Fatalf("grants left: %d", len(gs))
	}
	want(t, mg.delete(U+"/apps/"+cl.ID), 404)
	want(t, mg.delete(U+"/providers/"+p.ID), 200)
	if ids, _ := w.env.Svc.Identities.All(ctx, u.ID); len(ids) != 0 {
		t.Fatalf("identities left: %d", len(ids))
	}
	want(t, mg.delete(U+"/providers/"+p.ID), 404)
	for _, a := range []string{"user.app.revoke", "user.provider.disconnect"} {
		if len(auditActions(t, w, a)) == 0 {
			t.Errorf("no audit entry %s", a)
		}
	}
}

func first(r resp) map[string]any {
	if l := r.items(); len(l) > 0 {
		m, _ := l[0].(map[string]any)
		return m
	}
	return nil
}

// Sessions on the admin user page: listed by handle (never the session id), the current one marked; signing one out
// ends it; the session making the request is not ended here.
func TestUserSessionsAPI(t *testing.T) {
	w := newWorld(t)
	u := w.users["user"]
	U := AU + "/" + u.ID + "/sessions"
	w.as("user") // a session of the user's own
	mg := w.as("manager")
	r := mg.get(U)
	want(t, r, 200)
	if r.total() < 1 {
		t.Fatalf("sessions: %s", r.Raw)
	}
	it := first(r)
	h, _ := it["id"].(string)
	if list, _ := w.env.Svc.Sessions.All(context.Background(), u.ID); len(list) == 0 || h == list[0].ID || it["current"] != false {
		t.Fatalf("handle %q current %v", h, it["current"])
	}
	want(t, w.as("other").get(U), 404)
	want(t, mg.get(AU+"/"+w.users["admin"].ID+"/sessions"), 403)
	want(t, mg.delete(U+"/"+h), 200)
	want(t, mg.delete(U+"/"+h), 404)
	if len(auditActions(t, w, "user.session.revoke")) == 0 {
		t.Error("no audit entry")
	}
	// your own: the current session is listed first (ahead of a newer one), marked, and cannot be ended here
	me := w.as("admin")
	w.as("admin")
	r = me.get(AU + "/" + w.users["admin"].ID + "/sessions")
	cur, _ := first(r)["id"].(string)
	if r.total() != 2 || first(r)["current"] != true || r.items()[1].(map[string]any)["current"] != false {
		t.Fatalf("own sessions: %s", r.Raw)
	}
	want(t, me.delete(AU+"/"+w.users["admin"].ID+"/sessions/"+cur), 409)
}

// Passkeys on the admin user page: whoever manages a user sees them (never the credential) and can remove one, which
// ends the sessions that signed in with it. Your own last way to sign in cannot be removed here.
func TestUserPasskeysAPI(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	u := w.users["user"]
	pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: "Laptop", CredentialID: []byte("cred-1"), PublicKey: []byte("pk"), UserVerified: true}
	if err := w.env.Svc.Passkeys.Create(ctx, pk); err != nil {
		t.Fatal(err)
	}
	other := &model.Passkey{UserID: w.users["admin"].ID, OrgID: u.OrgID, Name: "Admin key", CredentialID: []byte("cred-2"), PublicKey: []byte("pk"), UserVerified: true}
	if err := w.env.Svc.Passkeys.Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	signedIn := &model.Session{UserID: u.ID, OrgID: u.OrgID, Passkey: pk.ID, AuthTime: time.Now(), Expires: time.Now().Add(time.Hour)}
	if err := w.env.Svc.Sessions.Create(ctx, signedIn); err != nil {
		t.Fatal(err)
	}
	U := AU + "/" + u.ID + "/passkeys"
	mg := w.as("manager")

	r := mg.get(U)
	want(t, r, 200)
	if it := first(r); r.total() != 1 || it["name"] != "Laptop" || it["id"] != pk.ID || it["problem"] != nil {
		t.Fatalf("passkeys: %s", r.Raw)
	}
	if strings.Contains(string(r.Raw), "public_key") || strings.Contains(string(r.Raw), "credential") {
		t.Fatalf("credential material listed: %s", r.Raw)
	}
	want(t, w.as("other").get(U), 404)
	want(t, mg.get(AU+"/"+w.users["admin"].ID+"/passkeys"), 403)
	want(t, mg.delete(U+"/"+other.ID), 404) // another user's passkey, through this user

	want(t, mg.delete(U+"/"+pk.ID), 200)
	if _, err := w.env.Svc.Passkeys.Get(ctx, pk.ID); err == nil {
		t.Fatal("passkey survived removal")
	}
	if _, err := w.env.Svc.Sessions.Get(ctx, signedIn.ID); err == nil {
		t.Fatal("the session signed in with the passkey survived its removal")
	}
	want(t, mg.delete(U+"/"+pk.ID), 404)
	if len(auditActions(t, w, "user.passkey.remove")) == 0 {
		t.Error("no audit entry")
	}

	// your own last way to sign in stays (someone else can remove it, and send you an invitation)
	me := w.users["admin"]
	me.PasswordHash = ""
	if err := w.env.Svc.Users.Update(ctx, me); err != nil {
		t.Fatal(err)
	}
	want(t, w.as("admin").delete(AU+"/"+me.ID+"/passkeys/"+other.ID), 409)
	if _, err := w.env.Svc.Passkeys.Get(ctx, other.ID); err != nil {
		t.Fatal("own last passkey removed")
	}
}

// Administrators can list and revoke another user's personal API tokens; the role limits still apply.
func TestUserAPITokensAPI(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	alan := w.users["user"]
	tok, plain, err := w.env.Svc.CreateAPIToken(ctx, service.ActorForUser(alan, ""), service.APITokenInput{Name: "ci", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	ad := w.as("admin")
	r := ad.get(AU + "/" + alan.ID + "/tokens")
	want(t, r, 200)
	if r.total() != 1 || r.items()[0].(map[string]any)["id"] != tok.ID || strings.Contains(string(r.Raw), plain) ||
		r.items()[0].(map[string]any)["name"] != "ci" {
		t.Fatalf("token list: %s", r.Raw)
	}
	// another user's token id under this user is not found; another org's user is not found
	want(t, ad.delete(AU+"/"+w.users["manager"].ID+"/tokens/"+tok.ID), 404)
	want(t, ad.get(G+"/users/"+w.users["other"].ID+"/tokens"), 404)
	// a manager cannot manage an admin's tokens
	want(t, w.as("manager").get(AU+"/"+w.users["admin"].ID+"/tokens"), 403)

	want(t, ad.delete(AU+"/"+alan.ID+"/tokens/"+tok.ID), 200)
	if _, _, err := w.env.Svc.ValidateAPIToken(ctx, plain); err == nil {
		t.Fatal("revoked token still valid")
	}
	if r := ad.get(AU + "/" + alan.ID + "/tokens"); r.total() != 0 {
		t.Fatalf("after revoke: %s", r.Raw)
	}
	if len(auditActions(t, w, "apitoken.delete")) != 1 {
		t.Fatal("revocation not audited")
	}
}

// Whoever manages a user can remove their authenticator app (a lost phone): the recovery codes go with it when it
// was the last second factor, the password stays. Never your own here (the account page does that), and a manager's
// or administrator's only by a super admin.
func TestUserTOTPAPI(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	giveTOTP := func(u *model.User) *model.User {
		t.Helper()
		fresh, err := w.env.Svc.Users.Get(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		fresh.TOTPSecret = w.env.Svc.Sealer.SealFor(service.TOTPBinding(fresh.ID), []byte("JBSWY3DPEHPK3PXP"))
		now := time.Now().UTC()
		fresh.MFAEnrolledAt = &now
		if err := w.env.Svc.Users.Update(ctx, fresh); err != nil {
			t.Fatal(err)
		}
		return fresh
	}
	u := giveTOTP(w.users["user"])
	if _, err := w.env.Svc.CreateRecoveryCodes(ctx, service.System, u); err != nil {
		t.Fatal(err)
	}
	U := AU + "/" + u.ID + "/totp"
	mg := w.as("manager")

	want(t, w.as("other").delete(U), 404) // another organization's user
	want(t, mg.delete(AU+"/"+giveTOTP(w.users["admin"]).ID+"/totp"), 403)
	want(t, mg.delete(U), 204)
	after, err := w.env.Svc.Users.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.HasTOTP() || after.MFAEnrolledAt != nil || len(after.RecoveryCodes) != 0 || after.PasswordHash == "" {
		t.Fatalf("after removal: totp %v, enrolled %v, codes %d, password %v", after.HasTOTP(), after.MFAEnrolledAt, len(after.RecoveryCodes), after.PasswordHash != "")
	}
	if after.SecurityGen == u.SecurityGen {
		t.Fatal("security generation not moved on")
	}
	if len(auditActions(t, w, "user.totp.remove")) != 1 {
		t.Error("no audit entry")
	}
	want(t, mg.delete(U), 409) // nothing left to remove

	// a manager's: a super admin only
	mgr := giveTOTP(w.users["manager"])
	want(t, w.as("admin").delete(AU+"/"+mgr.ID+"/totp"), 422)
	want(t, w.as("super").delete(AU+"/"+mgr.ID+"/totp"), 204)
}

// Removing another user's passkey or linked provider takes away a way they sign in, as removing their password or
// authenticator app does: it needs a recent re-authentication, so a stolen API token or an old session cannot strip
// a user's sign-in methods.
func TestRemovingSignInMethodsNeedsStepUp(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	u := w.users["user"]
	pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: "Laptop", CredentialID: []byte("cred-1"), PublicKey: []byte("pk"), UserVerified: true}
	if err := w.env.Svc.Passkeys.Create(ctx, pk); err != nil {
		t.Fatal(err)
	}
	p := &model.Provider{OrgID: u.OrgID, Name: "GitHub", Type: model.ProviderGitHub, Enabled: true}
	if err := w.env.Svc.Providers.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := w.env.Svc.Identities.Create(ctx, model.NewIdentity(u, p, "gh-1", "alan@github.example", "connect")); err != nil {
		t.Fatal(err)
	}
	fresh := false
	w.env.Server.Reauthed = func(*http.Request) bool { return fresh }
	U := AU + "/" + u.ID
	tok, ad := w.withBearer("admin", "admin"), w.as("admin")
	for _, c := range []*caller{tok, ad} {
		wantField(t, c.delete(U+"/passkeys/"+pk.ID), 403, "reauth")
		wantField(t, c.delete(U+"/providers/"+p.ID), 403, "reauth")
	}
	if _, err := w.env.Svc.Passkeys.Get(ctx, pk.ID); err != nil {
		t.Fatal("passkey removed without a re-authentication")
	}
	if ids, _ := w.env.Svc.Identities.All(ctx, u.ID); len(ids) != 1 {
		t.Fatal("provider unlinked without a re-authentication")
	}
	fresh = true
	want(t, ad.delete(U+"/passkeys/"+pk.ID), 200)
	want(t, ad.delete(U+"/providers/"+p.ID), 200)
}

// Signing out one's own other sessions through the management API needs a recent re-authentication, as on the
// account page (one or all: a stolen session alone must not sign its owner out); someone else's need none.
func TestOwnSessionsSignOutNeedsReauth(t *testing.T) {
	w := newWorld(t)
	fresh := false
	w.env.Server.Reauthed = func(*http.Request) bool { return fresh }
	me := w.as("admin")
	w.as("admin") // another session of the admin's own
	S := AU + "/" + w.users["admin"].ID + "/sessions"
	r := me.get(S)
	want(t, r, 200)
	other, _ := r.items()[1].(map[string]any)["id"].(string)
	wantField(t, me.delete(S+"/"+other), 403, "reauth")
	wantField(t, me.delete(S), 403, "reauth")
	if r := me.get(S); r.total() != 2 {
		t.Fatalf("a session ended without re-authentication: %s", r.Raw)
	}
	// someone else's need none
	w.as("user")
	U := AU + "/" + w.users["user"].ID + "/sessions"
	h, _ := first(w.as("manager").get(U))["id"].(string)
	want(t, me.delete(U+"/"+h), 200)
	want(t, me.delete(U), 200)
	fresh = true
	want(t, me.delete(S+"/"+other), 200)
}
