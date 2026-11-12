package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// A personal API token sent with a session cookie acts as the token alone: the cookie's session (whoever's it is)
// must not count as the token holder's recent re-authentication.
func TestBearerIgnoresTheSessionCookieForStepUp(t *testing.T) {
	w := newWorld(t)
	// as the login module's: a request whose session re-authenticated (or signed in) recently
	w.env.Server.Reauthed = func(r *http.Request) bool { return web.Session(r) != nil }
	tok := w.withBearer("admin", "admin")
	target := AU + "/" + w.users["user"].ID
	wantField(t, tok.patch(target, map[string]any{"role": "admin"}), 403, "reauth")
	for _, cookie := range []*caller{w.asSingleFactor("user"), w.as("other"), w.as("admin")} {
		mixed := &caller{w: w, c: cookie.c, bearer: tok.bearer}
		wantField(t, mixed.patch(target, map[string]any{"role": "admin"}), 403, "reauth")
	}
	if u, _ := w.env.Svc.Users.Get(context.Background(), w.users["user"].ID); u.Role != model.RoleUser {
		t.Fatalf("role became %s", u.Role)
	}
	// the cookie alone, re-authenticated, still may
	want(t, w.as("admin").patch(target, map[string]any{"role": "admin"}), 200)
}

// Service accounts hold their scopes for good: a person creates, changes or rotates one only after a recent
// re-authentication, and a personal API token never does; a service account with the scope still may.
func TestServiceAccountChangesNeedStepUp(t *testing.T) {
	w := newWorld(t)
	fresh := false
	w.env.Server.Reauthed = func(*http.Request) bool { return fresh }
	body := map[string]any{"name": "x", "scopes": []string{"users", "manage_admins"}}
	tok := w.withBearer("admin", "admin")
	wantField(t, tok.post(A+"/service-accounts", body), 403, "reauth")
	ad := w.as("admin")
	wantField(t, ad.post(A+"/service-accounts", body), 403, "reauth")
	fresh = true
	r := ad.post(A+"/service-accounts", body)
	want(t, r, 201)
	id := r.str("id")
	fresh = false
	wantField(t, ad.patch(A+"/service-accounts/"+id, map[string]any{"scopes": []string{"users"}}), 403, "reauth")
	wantField(t, ad.post(A+"/service-accounts/"+id+"/secret", nil), 403, "reauth")
	wantField(t, tok.post(A+"/service-accounts/"+id+"/secret", nil), 403, "reauth")
	sa := w.asServiceAccount(w.acme, service.ScopeServiceAccounts, service.ScopeUsers)
	want(t, sa.post(A+"/service-accounts", map[string]any{"name": "y", "scopes": []string{"users"}}), 201)
}

// An invitation a service account sent is judged again when it is used, as a person's is: the invited user made an
// administrator since (which the account may not manage), or the account deleted, and it opens nothing.
func TestServiceAccountInvitationIsJudgedAgain(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sa := w.asServiceAccount(w.acme, service.ScopeUsers)
	invite := func(uid string) string {
		r := sa.post(AU+"/"+uid+"/invite", nil)
		want(t, r, 200)
		link := r.str("url")
		return link[strings.Index(link, "token=")+len("token="):]
	}
	// unchanged: it opens
	tok := invite(w.users["user"].ID)
	if _, _, err := w.env.Svc.PeekLink(ctx, tok, service.LinkInvite); err != nil {
		t.Fatalf("a fresh invitation: %v", err)
	}
	// the user promoted to administrator: the account (users, without manage_admins) may not invite them now
	uid := w.users["user"].ID
	if _, err := w.env.Svc.UpdateUser(ctx, service.ActorForUser(w.env.Admin, ""), uid, service.UserInput{Role: ptr(model.RoleAdmin)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.env.Svc.PeekLink(ctx, tok, service.LinkInvite); err == nil {
		t.Fatal("an invitation for a user since made an administrator still opens")
	}
	// the issuing account deleted: its invitation goes with it
	mu := w.users["manager"]
	if _, err := w.env.Svc.UpdateUser(ctx, service.ActorForUser(w.env.Admin, ""), mu.ID, service.UserInput{Role: ptr(model.RoleUser)}); err != nil {
		t.Fatal(err)
	}
	tok = invite(mu.ID)
	saID := strings.TrimPrefix(sa.bearer, "sa:")
	if err := w.env.Svc.Clients.Delete(ctx, saID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.env.Svc.PeekLink(ctx, tok, service.LinkInvite); err == nil {
		t.Fatal("an invitation from a deleted service account still opens")
	}
}

// Pointing a client elsewhere (its redirect URIs) or changing how it redeems codes (its secret) moves its consent
// generation on, so what users allowed before does not let codes reach the new place or holder unasked. A change
// that does neither leaves it.
func TestClientCredentialChangesResetConsent(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	ad := w.as("admin")
	r := ad.post(A+"/clients", map[string]any{"name": "Portal", "redirect_uris": []string{"https://p.example/cb"}})
	want(t, r, 201)
	id := r.str("id")
	gen := func() int64 {
		c, err := w.env.Svc.Clients.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return c.RememberGen
	}
	g0 := gen()
	want(t, ad.patch(A+"/clients/"+id, map[string]any{"description": "the portal"}), 200)
	if gen() != g0 {
		t.Fatal("a description change reset consent")
	}
	want(t, ad.patch(A+"/clients/"+id, map[string]any{"redirect_uris": []string{"https://p.example/cb", "https://attacker.example/cb"}}), 200)
	g1 := gen()
	if g1 == g0 {
		t.Fatal("adding a redirect URI kept consent")
	}
	want(t, ad.post(A+"/clients/"+id+"/secret", nil), 200)
	if gen() == g1 {
		t.Fatal("rotating the secret kept consent")
	}
}

// A console session's backup download needs the CSRF header: the GET a link on another site could start leaves a
// copy of the store in the administrator's downloads.
func TestBackupFromSessionNeedsCSRF(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")
	const pw = "X-Backup-Password"
	want(t, su.do("GET", "/api/backup", nil, pw, "correct horse battery", "X-CSRF-Token", ""), 403)
	want(t, su.do("GET", "/api/backup", nil, pw, "correct horse battery", "Sec-Fetch-Site", "cross-site"), 403)
	want(t, su.do("GET", "/api/backup", nil, pw, "correct horse battery"), 200)
}

// A service account with orgs:create gets the default settings of a new organization: choosing them is a super admin's.
func TestServiceAccountCreatesOrgsWithDefaultSettings(t *testing.T) {
	w := newWorld(t)
	oc := w.asServiceAccount(w.env.Primary, service.ScopeOrgsCreate)
	wantField(t, oc.post("/api/orgs", map[string]any{"name": "withmcp", "settings": map[string]any{"mcp_server": true}}), 422, "settings")
	want(t, oc.post("/api/orgs", map[string]any{"name": "plain"}), 201)
}
