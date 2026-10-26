package admin_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"golang.org/x/crypto/bcrypt"
)

func TestUsers(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")

	r := ad.get(AU)
	want(t, r, 200)
	if r.total() != 3 {
		t.Fatalf("list: %s", r.Raw)
	}
	for _, it := range r.items() {
		m := it.(map[string]any)
		if _, leaked := m["password_hash"]; leaked || m["PasswordHash"] != nil {
			t.Fatal("password hash in response")
		}
	}

	// create, with bulk data to exercise paging
	for i := 0; i < 30; i++ {
		want(t, ad.post(AU, map[string]any{"given_name": "T", "username": fmt.Sprintf("bulk%02d", i), "email": fmt.Sprintf("bulk%02d@x.example", i)}), 201)
	}
	r = ad.get(AU + "?limit=10&offset=20&sort=username")
	if r.total() != 33 || len(r.items()) != 10 {
		t.Fatalf("page: total %d items %d", r.total(), len(r.items()))
	}
	r = ad.get(AU + "?sort=username&desc=1&limit=2")
	if r.items()[0].(map[string]any)["username"] != "grace" {
		t.Fatalf("sort desc: %s", r.Raw)
	}
	r = ad.get(AU + "?q=BULK1")
	if r.total() != 10 {
		t.Fatalf("search: %d", r.total())
	}
	r = ad.get(AU + "?role=manager")
	if r.total() != 1 {
		t.Fatalf("role filter: %s", r.Raw)
	}
	wantField(t, ad.get(AU+"?role=wizard"), 422, "role")
	want(t, ad.get(AU+"?sort=password_hash"), 422)
	if n := ad.get(AU + "?limit=500").items(); len(n) != 33 {
		t.Fatalf("limit is clamped to 100, got %d", len(n))
	}

	// create validation
	wantField(t, ad.post(AU, map[string]any{"given_name": "T", "username": "!!", "email": "!!@x.example"}), 422, "username")
	// passwords are not part of the API: users set them through their invitation link
	want(t, ad.post(AU, map[string]any{"given_name": "T", "username": "withpw", "email": "withpw@x.example", "password": "correct horse battery"}), 400)
	want(t, ad.patch(AU+"/"+w.users["user"].ID, map[string]any{"password": "correct horse battery"}), 400)
	wantField(t, ad.post(AU, map[string]any{"given_name": "T", "username": "bulk00", "email": "bulk00@x.example"}), 409, "username")
	wantField(t, ad.post(AU, map[string]any{"given_name": "T", "username": "inv", "invite": map[string]any{"email": true}}), 422, "email")
	// email is required, whatever else is sent; the username is optional and defaults to the email
	wantField(t, ad.post(AU, map[string]any{"given_name": "T"}), 422, "email")
	wantField(t, ad.post(AU, map[string]any{"given_name": "T", "username": "nomail"}), 422, "email")
	wantField(t, ad.post(AU, map[string]any{"given_name": "T", "username": "nomail", "email": "  "}), 422, "email")
	r = ad.post(AU, map[string]any{"given_name": "T", "email": "defaults@x.example"})
	want(t, r, 201)
	if r.str("username") != "defaults@x.example" || r.str("email") != "defaults@x.example" {
		t.Fatalf("username should default to the email: %s", r.Raw)
	}
	wantField(t, ad.patch(AU+"/"+r.str("id"), map[string]any{"email": ""}), 422, "email")

	// a new user has no password; asking for an invitation returns the link (copyable right away)
	r = ad.post(AU, map[string]any{"given_name": "T", "username": "inv0", "email": "inv0@x.example", "invite": map[string]any{}})
	want(t, r, 201)
	inv := r.JSON["invite"].(map[string]any)
	if r.JSON["has_password"] != false || !strings.Contains(inv["url"].(string), "/invite?token=") || inv["expires"] == "" || inv["emailed"] != false {
		t.Fatalf("invite link: %s", r.Raw)
	}
	r = ad.post(AU, map[string]any{"given_name": "T", "username": "plain", "email": "plain@x.example"})
	want(t, r, 201)
	if _, has := r.JSON["invite"]; has {
		t.Fatalf("no invite requested: %s", r.Raw)
	}

	// emailing goes through the Mailer; the default one is disabled, so the user and link exist and a warning is returned
	r = ad.post(AU, map[string]any{"given_name": "T", "username": "inv", "email": "inv@x.example", "invite": map[string]any{"email": true}})
	want(t, r, 201)
	inv = r.JSON["invite"].(map[string]any)
	if inv["emailed"] != false || inv["email_warning"] == "" || inv["url"] == "" {
		t.Fatalf("invite: %s", r.Raw)
	}
	m := &fakeMailer{}
	w.mod.Mailer = m
	r = ad.post(AU, map[string]any{"given_name": "T", "username": "inv2", "email": "inv2@x.example", "invite": map[string]any{"email": true}})
	want(t, r, 201)
	inv = r.JSON["invite"].(map[string]any)
	if inv["emailed"] != true || len(m.sent) != 1 || m.sent[0] != "inv2 "+inv["url"].(string) {
		t.Fatalf("invite sent: %s %v", r.Raw, m.sent)
	}

	// get / update
	id := w.users["user"].ID
	r = ad.get(AU + "/" + id)
	want(t, r, 200)
	if r.str("username") != "alan" || r.JSON["has_password"] != true || r.JSON["passkeys"] != float64(0) {
		t.Fatal(string(r.Raw))
	}
	if _, leaked := r.JSON["password_hash"]; leaked {
		t.Fatal("password hash in response")
	}
	r = ad.patch(AU+"/"+id, map[string]any{"role": "manager", "family_name": "Alan T"})
	want(t, r, 200)
	if r.str("role") != "manager" || r.str("name") != "T Alan T" {
		t.Fatal(string(r.Raw))
	}
	want(t, ad.patch(AU+"/"+id, map[string]any{"active": false}), 200)
	r = ad.get(AU + "?active=0")
	if r.total() != 1 {
		t.Fatalf("active filter: %s", r.Raw)
	}
	wantField(t, ad.patch(AU+"/"+id, map[string]any{"email": "nope"}), 422, "email")
	want(t, ad.patch(AU+"/"+id, map[string]any{"role": "overlord"}), 422)

	// guards: not yourself, not the last admin
	adminID := w.users["admin"].ID
	want(t, ad.delete(AU+"/"+adminID), 422)
	want(t, ad.patch(AU+"/"+adminID, map[string]any{"role": "user"}), 422)

	// delete
	want(t, ad.delete(AU+"/"+id), 200)
	want(t, ad.get(AU+"/"+id), 404)
	want(t, ad.delete(AU+"/"+id), 404)

	// users of another organization are not reachable through this org's path
	want(t, ad.get(AU+"/"+w.users["other"].ID), 404)
	want(t, ad.get(G+"/users"), 404)
}

func TestUserRolePermissions(t *testing.T) {
	w := newWorld(t)
	mg := w.as("manager")
	// managers manage plain users but never admins or roles above user
	want(t, mg.get(AU), 200)
	want(t, mg.post(AU, map[string]any{"given_name": "T", "username": "new1", "email": "new1@x.example"}), 201)
	want(t, mg.post(AU, map[string]any{"given_name": "T", "username": "new2", "email": "new2@x.example", "role": "admin"}), 403)
	want(t, mg.post(AU, map[string]any{"given_name": "T", "username": "new3", "email": "new3@x.example", "role": "manager"}), 403)
	want(t, mg.patch(AU+"/"+w.users["admin"].ID, map[string]any{"family_name": "x"}), 403)
	want(t, mg.delete(AU+"/"+w.users["admin"].ID), 403)
	want(t, mg.delete(AU+"/"+w.users["admin"].ID+"/password"), 403)
	want(t, mg.post(AU+"/"+w.users["admin"].ID+"/invite", map[string]any{}), 403)
	want(t, mg.patch(AU+"/"+w.users["user"].ID, map[string]any{"family_name": "Al"}), 200)
	want(t, mg.get(A+"/groups"), 200)
	// managers do not see admin-only resources
	want(t, mg.post(A+"/groups", map[string]any{"display_name": "g"}), 403)
	want(t, mg.get(A+"/clients"), 403)
	want(t, mg.get(A+"/providers"), 403)
	want(t, mg.get(A+"/audit"), 403)

	us := w.as("user")
	for _, p := range []string{AU, A + "/groups", A + "/clients", A + "/providers", A + "/audit"} {
		want(t, us.get(p), 403)
	}
	want(t, us.post(AU, map[string]any{"given_name": "T", "username": "z", "email": "z@x.example"}), 403)
	// a plain user reads their own record through the user routes, and nobody above their role
	me := AU + "/" + w.users["user"].ID
	for _, p := range []string{"", "/sessions", "/passkeys", "/tokens"} {
		want(t, us.get(me+p), 200)
	}
	want(t, us.get(AU+"/"+w.users["manager"].ID), 404)

	// another organization's admin cannot reach acme at all
	ot := w.as("other")
	for _, p := range []string{AU, A + "/groups", A} {
		want(t, ot.get(p), 404)
	}
	want(t, ot.get("/api/keys"), 403)
	// and acme's admin does not reach that organization's user through acme's path, by any of the user routes
	ad := w.as("admin")
	for _, p := range []string{"", "/apps", "/providers", "/sessions", "/passkeys", "/tokens"} {
		want(t, ad.get(AU+"/"+w.users["other"].ID+p), 404)
	}

	// only super admins grant super_admin, and only in the primary org
	su := w.as("super")
	want(t, su.post("/api/orgs/primary/users", map[string]any{"given_name": "T", "username": "boss", "email": "boss@x.example", "role": "super_admin"}), 201)
	want(t, su.post(AU, map[string]any{"given_name": "T", "username": "boss", "email": "boss@x.example", "role": "super_admin"}), 403)
	want(t, ad.post(AU, map[string]any{"given_name": "T", "username": "boss2", "email": "boss2@x.example", "role": "super_admin"}), 403)
}

func TestPasswordAndSessions(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	id := w.users["user"].ID

	// the old "set a password" endpoint is gone
	want(t, ad.post(AU+"/"+id+"/password", map[string]any{}), 404)

	// removing a password: 204, has_password turns false, sessions end, idempotent
	victim := w.as("user")
	want(t, victim.get("/api/orgs"), 200)
	want(t, ad.delete(AU+"/"+id+"/password"), 204)
	u, _ := w.env.Svc.Users.Get(context.Background(), id)
	if u.PasswordHash != "" {
		t.Fatal("password not removed")
	}
	if r := ad.get(AU + "/" + id); r.JSON["has_password"] != false {
		t.Fatalf("has_password: %s", r.Raw)
	}
	w.env.Server.Sessions.Evict("", id)
	want(t, victim.get("/api/orgs"), 401)
	want(t, ad.delete(AU+"/"+id+"/password"), 204)

	// revoking sessions signs the user out (the next API call is 401)
	victim = w.as("user")
	want(t, victim.get("/api/orgs"), 200)
	want(t, ad.delete(AU+"/"+id+"/sessions"), 200)
	w.env.Server.Sessions.Evict("", id)
	want(t, victim.get("/api/orgs"), 401)
	want(t, ad.delete(AU+"/nope/sessions"), 404)
}

// Job title, phone and free-form attributes no longer exist: the strict decoder rejects them.
func TestRemovedUserFieldsRejected(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	for _, f := range []string{"title", "phone", "attributes"} {
		var v any = "x"
		if f == "attributes" {
			v = map[string]string{"a": "b"}
		}
		if r := ad.post(AU, map[string]any{"given_name": "T", "email": "rm-" + f + "@x.example", f: v}); r.Status != 400 {
			t.Errorf("create with %s: %d %s", f, r.Status, r.Raw)
		}
		if r := ad.patch(AU+"/"+w.users["user"].ID, map[string]any{f: v}); r.Status != 400 {
			t.Errorf("update with %s: %d %s", f, r.Status, r.Raw)
		}
	}
	r := ad.get(AU + "/" + w.users["user"].ID)
	for _, f := range []string{"title", "phone", "attributes"} {
		if _, has := r.JSON[f]; has {
			t.Errorf("user still returns %s", f)
		}
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
	want(t, w.withBearer("super", "admin", "import").patch(AU+"/"+id, map[string]any{"password_hash": string(bc)}), 400)
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
