package admin_test

import (
	"context"
	"testing"

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
	// your own: the current session is marked and cannot be ended here
	me := w.as("admin")
	r = me.get(AU + "/" + w.users["admin"].ID + "/sessions")
	var cur string
	for _, x := range r.items() {
		if s := x.(map[string]any); s["current"] == true {
			cur, _ = s["id"].(string)
		}
	}
	if cur == "" {
		t.Fatalf("no current session: %s", r.Raw)
	}
	want(t, me.delete(AU+"/"+w.users["admin"].ID+"/sessions/"+cur), 409)
}
