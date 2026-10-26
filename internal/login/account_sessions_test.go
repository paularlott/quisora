package login_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestAccountSessions(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	cur := e.signedIn(t, pat)
	second := e.signedIn(t, pat)
	e.signedIn(t, pat) // a third session
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
	if res, _ := samB.api("GET", "/api-internal/account", nil); res.StatusCode != 200 {
		t.Fatal("sam's session ended")
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
