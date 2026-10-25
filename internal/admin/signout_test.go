package admin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"golang.org/x/crypto/bcrypt"
)

// An organization's administrator signs everyone in it out: every session stops at once (theirs is kept), other
// organizations carry on, API tokens end only when asked, and the console shows the last pull.
func TestEmergencySignOut(t *testing.T) {
	w := newWorld(t)
	ada, grace, otto := w.as("admin"), w.as("manager"), w.as("other")
	tok := w.withBearer("manager", "admin")
	want(t, grace.get(AU), 200)
	want(t, tok.get(AU), 200)

	// who may, and what it needs
	want(t, grace.post("/api/orgs/acme/sign-out", map[string]any{"reason": "x"}), 403)
	want(t, otto.post("/api/orgs/acme/sign-out", map[string]any{"reason": "x"}), 404)
	want(t, ada.post("/api/sign-out", map[string]any{"reason": "x"}), 403)
	wantField(t, ada.post("/api/orgs/acme/sign-out", map[string]any{"reason": ""}), 422, "reason")
	want(t, tok.post("/api/orgs/acme/sign-out", map[string]any{"reason": "x"}), 403) // an API token never can
	want(t, grace.get(AU), 200)

	r := ada.post("/api/orgs/acme/sign-out", map[string]any{"reason": "phishing"})
	want(t, r, 200)
	if r.str("by") != "ada" || r.str("reason") != "phishing" || r.JSON["api_tokens"] != false {
		t.Errorf("event: %s", r.Raw)
	}
	want(t, grace.get(AU), 401)
	want(t, ada.get(AU), 200)
	want(t, otto.get("/api/orgs/globex/users"), 200)
	want(t, tok.get(AU), 200) // API tokens were not included

	org := ada.get("/api/orgs/acme")
	want(t, org, 200)
	if last, _ := org.JSON["last_sign_out"].(map[string]any); last["reason"] != "phishing" {
		t.Errorf("last sign-out: %s", org.Raw)
	}

	// signing in again works; this time API tokens go too
	grace = w.as("manager")
	want(t, grace.get(AU), 200)
	want(t, ada.post("/api/orgs/acme/sign-out", map[string]any{"reason": "token leak", "api_tokens": true}), 200)
	want(t, tok.get(AU), 401)
	want(t, grace.get(AU), 401)
	want(t, ada.get(AU), 200)

	// the background sweep removes the ended sessions
	w.env.Svc.WaitBackground()
	s := ada.get(AU + "/" + w.users["manager"].ID + "/sessions")
	want(t, s, 200)
	if s.total() != 0 {
		t.Errorf("the manager's ended sessions are still listed: %s", s.Raw)
	}
}

// A super admin signs the whole server out.
func TestEmergencySignOutServer(t *testing.T) {
	w := newWorld(t)
	su, ada, otto := w.as("super"), w.as("admin"), w.as("other")
	want(t, su.post("/api/sign-out", map[string]any{"reason": "breach"}), 200)
	want(t, ada.get(AU), 401)
	want(t, otto.get("/api/orgs/globex/users"), 401)
	want(t, su.get("/api/orgs"), 200)
}

// Locking a user out from the console: they are signed out at once and disabled. The rules are those of resetting
// someone's sign-in: never yourself, and an established manager or administrator only by a super admin (otherwise an
// administrator could lock a colleague out, invite them again and take the account). The user page offers it for
// others only.
func TestLockOutEndpoint(t *testing.T) {
	w := newWorld(t)
	su, ada, grace := w.as("super"), w.as("admin"), w.as("manager")
	want(t, grace.get(AU), 200)
	want(t, grace.post(AU+"/"+w.users["admin"].ID+"/lock-out", map[string]any{"reason": "x"}), 403)
	wantField(t, ada.post(AU+"/"+w.users["admin"].ID+"/lock-out", map[string]any{}), 422, "reason")
	wantField(t, ada.post(AU+"/"+w.users["manager"].ID+"/lock-out", map[string]any{"reason": "x"}), 422, "reason")
	want(t, grace.get(AU), 200)

	r := su.post(AU+"/"+w.users["manager"].ID+"/lock-out", map[string]any{"reason": "left the company"})
	want(t, r, 200)
	if r.JSON["active"] != false || r.JSON["has_password"] != false {
		t.Errorf("not disabled, or the password kept: %s", r.Raw)
	}
	// every session is gone (the console's per-node session cache is evicted by the cluster's change notices, which
	// this test server has none of)
	if n, err := w.env.Svc.Sessions.Count(context.Background(), w.users["manager"].ID); err != nil || n != 0 {
		t.Errorf("sessions left: %d %v", n, err)
	}
	r = ada.post(AU+"/"+w.users["user"].ID+"/lock-out", map[string]any{})
	want(t, r, 200)

	page := func(c *caller, id string) string {
		r := c.do("GET", "/admin/orgs/acme/users/"+id, nil)
		want(t, r, 200)
		return string(r.Raw)
	}
	if b := page(ada, w.users["user"].ID); !strings.Contains(b, `id="lockout-open"`) {
		t.Error("no lock-out on another user's page")
	}
	if b := page(ada, w.users["admin"].ID); strings.Contains(b, `id="lockout-open"`) {
		t.Error("lock-out offered on your own page")
	}
}

// Importing users with a bcrypt hash over the API: a super admin's token needs the import scope as well as admin; an
// organization's admin cannot; an update never takes a hash.
func TestImportUserAPI(t *testing.T) {
	w := newWorld(t)
	bc, err := bcrypt.GenerateFromPassword([]byte("old system password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	body := func(name string) map[string]any {
		return map[string]any{"email": name + "@x.example", "given_name": "I", "password_hash": string(bc)}
	}
	wantField(t, w.withBearer("super", "admin").post(AU, body("i1")), 422, "password_hash")
	wantField(t, w.as("admin").post(AU, body("i2")), 422, "password_hash")
	r := w.withBearer("super", "admin", "import").post(AU, body("imported"))
	want(t, r, 201)
	if r.JSON["has_password"] != true {
		t.Errorf("no password: %s", r.Raw)
	}
	id, _ := r.JSON["id"].(string)
	u, err := w.env.Svc.Users.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := w.env.Svc.VerifyPassword(context.Background(), "", u, "old system password"); !ok || err != nil {
		t.Errorf("the imported password does not verify: %v", err)
	}
	// the update body has no such field: the hash the sign-in made (argon2id) stays
	w.withBearer("super", "admin", "import").patch(AU+"/"+id, map[string]any{"password_hash": string(bc)})
	again, _ := w.env.Svc.Users.Get(context.Background(), id)
	inner, _ := w.env.Svc.Sealer.OpenFor(service.PasswordBinding(id), again.PasswordHash)
	if !strings.HasPrefix(string(inner), "$argon2id$") {
		t.Errorf("an update changed the hash: %q", inner)
	}
	// only super admins can make an import token
	if _, _, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(w.users["admin"], ""),
		service.APITokenInput{Name: "t", Scopes: []string{"admin", "import"}}); err == nil {
		t.Error("an organization's admin made an import token")
	}
}
