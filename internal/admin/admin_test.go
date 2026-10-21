package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/store"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

func ptr[T any](v T) *T { return &v }

// world is a test environment with an org "acme" holding one admin, manager and user, and an org "globex".
type world struct {
	t     *testing.T
	env   *webtest.Env
	acme  *model.Org
	other *model.Org
	users map[string]*model.User // admin, manager, user (acme); other (globex admin)
	mod   *admin.Module
}

func newWorld(t *testing.T) *world { t.Helper(); return newWorldWith(t, nil) }

// newWorldWith is newWorld with a configuration hook.
func newWorldWith(t *testing.T, cfgFn func(*config.Config)) *world {
	t.Helper()
	w := &world{t: t, mod: admin.New(), users: map[string]*model.User{}}
	w.env = webtest.New(t, webtest.Options{Configure: cfgFn, Modules: func(s *web.Server) []web.Module {
		s.Mux.Handle("/", admin.NotFound(s))
		return []web.Module{w.mod}
	}})
	// Sessions here count as recently re-authenticated (the dangerous changes need it: stepUp); tests of the
	// re-authentication itself set their own.
	w.env.Server.Reauthed = func(*http.Request) bool { return true }
	ctx := context.Background()
	sys := service.System
	var err error
	if w.acme, err = w.env.Svc.CreateOrg(ctx, sys, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")}); err != nil {
		t.Fatal(err)
	}
	if w.other, err = w.env.Svc.CreateOrg(ctx, sys, service.OrgInput{Name: ptr("globex"), DisplayName: ptr("Globex")}); err != nil {
		t.Fatal(err)
	}
	mk := func(key string, org *model.Org, name string, role model.Role) {
		u, err := w.env.Svc.CreateUser(ctx, sys, org.ID, service.UserInput{GivenName: gn("T"), Username: ptr(name), Email: ptr(name + "@x.example"),
			Role: ptr(role), Password: ptr("correct horse battery")})
		if err != nil {
			t.Fatal(err)
		}
		w.users[key] = u
	}
	mk("admin", w.acme, "ada", model.RoleAdmin)
	mk("manager", w.acme, "grace", model.RoleManager)
	mk("user", w.acme, "alan", model.RoleUser)
	mk("other", w.other, "otto", model.RoleAdmin)
	return w
}

// caller performs requests as one identity.
type caller struct {
	w      *world
	c      *http.Client
	csrf   string
	bearer string
}

func (w *world) as(key string) *caller {
	u := w.env.Admin
	if key != "super" {
		u = w.users[key]
	}
	c, csrf := w.env.SessionAMR(u, []string{"pwd", "otp", "mfa"}) // the console needs a second factor
	return &caller{w: w, c: detach(c), csrf: csrf}
}

// asSingleFactor signs in as key with a password only.
func (w *world) asSingleFactor(key string) *caller {
	u := w.env.Admin
	if key != "super" {
		u = w.users[key]
	}
	c, csrf := w.env.Session(u)
	return &caller{w: w, c: detach(c), csrf: csrf}
}

// detach copies a webtest client so later webtest.Client()/Session() calls (which reuse one shared *http.Client and
// replace its cookie jar) cannot change which identity this caller uses.
func detach(c *http.Client) *http.Client {
	return &http.Client{Transport: c.Transport, Jar: c.Jar, CheckRedirect: c.CheckRedirect}
}

func (w *world) anon() *caller { return &caller{w: w, c: detach(w.env.Client())} }

// withBearer returns a caller that authenticates with an API token of the given scopes for user key.
func (w *world) withBearer(key string, scopes ...string) *caller {
	u := w.env.Admin
	if key != "super" {
		u = w.users[key]
	}
	_, tok, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(u, ""), service.APITokenInput{Name: "t", Scopes: scopes})
	if err != nil {
		w.t.Fatal(err)
	}
	w.env.Server.Bearer = func(ctx context.Context, r *http.Request, token string) (*service.Actor, error) {
		t, u, err := w.env.Svc.ValidateAPIToken(ctx, token)
		if err != nil {
			return nil, err
		}
		return service.ActorForToken(t, u, web.ClientIP(r)), nil
	}
	return &caller{w: w, c: detach(w.env.Client()), bearer: tok}
}

type resp struct {
	Status int
	Header http.Header
	Raw    []byte
	JSON   map[string]any
}

func (r resp) items() []any        { l, _ := r.JSON["items"].([]any); return l }
func (r resp) total() int          { n, _ := r.JSON["total"].(float64); return int(n) }
func (r resp) str(k string) string { s, _ := r.JSON[k].(string); return s }

func (c *caller) do(method, path string, body any, hdr ...string) resp {
	c.w.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.w.env.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	} else if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	res, err := c.c.Do(req)
	if err != nil {
		c.w.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Header: res.Header, Raw: raw}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

func (c *caller) get(path string) resp             { return c.do("GET", path, nil) }
func (c *caller) post(path string, body any) resp  { return c.do("POST", path, body) }
func (c *caller) patch(path string, body any) resp { return c.do("PATCH", path, body) }
func (c *caller) put(path string, body any) resp   { return c.do("PUT", path, body) }
func (c *caller) delete(path string) resp          { return c.do("DELETE", path, nil) }

func want(t *testing.T, r resp, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status %d, want %d: %s", r.Status, status, r.Raw)
	}
}

func wantField(t *testing.T, r resp, status int, field string) {
	t.Helper()
	want(t, r, status)
	if r.str("field") != field || r.str("error") == "" {
		t.Fatalf("error body %s, want field %q", r.Raw, field)
	}
}

const (
	A  = "/api/orgs/acme"
	G  = "/api/orgs/globex"
	AU = A + "/users"
)

// ---------------------------------------------------------------------------------------------------------------

func TestOrgs(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")

	r := su.get("/api/orgs")
	want(t, r, 200)
	if r.total() != 3 || len(r.items()) != 3 { // primary, acme, globex
		t.Fatalf("list: %s", r.Raw)
	}
	if r.Header.Get("Api-Version") != web.APIVersionLatest {
		t.Error("Api-Version not echoed")
	}
	first := r.items()[0].(map[string]any)
	if first["users"] == nil || first["settings"] == nil || first["id"] == "" {
		t.Errorf("org shape: %v", first)
	}

	// search, sort, pagination
	r = su.get("/api/orgs?q=glob")
	if r.total() != 1 || r.items()[0].(map[string]any)["name"] != "globex" {
		t.Fatalf("search: %s", r.Raw)
	}
	r = su.get("/api/orgs?sort=name&desc=1")
	if r.items()[0].(map[string]any)["name"] != "primary" {
		t.Fatalf("sort desc: %s", r.Raw)
	}
	r = su.get("/api/orgs?sort=name&limit=2&offset=2")
	if r.total() != 3 || len(r.items()) != 1 {
		t.Fatalf("page: %s", r.Raw)
	}
	wantField(t, su.get("/api/orgs?sort=password"), 422, "")

	// create
	r = su.post("/api/orgs", map[string]any{"name": "initech", "display_name": "Initech"})
	want(t, r, 201)
	wantField(t, su.post("/api/orgs", map[string]any{"name": "Bad Name"}), 422, "name")
	wantField(t, su.post("/api/orgs", map[string]any{"name": "admin"}), 422, "name") // reserved
	want(t, su.post("/api/orgs", map[string]any{"name": "initech"}), 409)
	want(t, su.post("/api/orgs", map[string]any{"name": "x1", "bogus": 1}), 400)

	// read + update
	want(t, su.get("/api/orgs/initech"), 200)
	r = su.patch("/api/orgs/initech", map[string]any{"display_name": "Initech Ltd"})
	want(t, r, 200)
	if r.str("display_name") != "Initech Ltd" {
		t.Fatal(string(r.Raw))
	}
	want(t, su.get("/api/orgs/nope"), 404)

	// delete: refuses a non-empty org without cascade, primary is protected
	want(t, su.delete("/api/orgs/globex"), 409)
	want(t, su.delete("/api/orgs/primary"), 409)
	want(t, su.delete("/api/orgs/globex?cascade=1"), 200)
	want(t, su.get("/api/orgs/globex"), 404)
	want(t, su.delete("/api/orgs/initech"), 200)

	// permissions
	ad := w.as("admin")
	r = ad.get("/api/orgs")
	if r.total() != 1 || r.items()[0].(map[string]any)["name"] != "acme" {
		t.Fatalf("admin sees %s", r.Raw)
	}
	if r.items()[0].(map[string]any)["users"] != nil {
		t.Error("user counts are for super admins only")
	}
	want(t, ad.post("/api/orgs", map[string]any{"name": "mine"}), 403)
	want(t, ad.delete("/api/orgs/acme"), 403)
	want(t, ad.get("/api/orgs/primary"), 404)
	want(t, ad.patch("/api/orgs/acme", map[string]any{"display_name": "Acme Inc"}), 403) // super admins only
	want(t, w.as("manager").patch("/api/orgs/acme", map[string]any{"display_name": "x"}), 403)
}

func TestAuthAndCSRF(t *testing.T) {
	w := newWorld(t)
	want(t, w.anon().get("/api/orgs"), 401)
	want(t, w.anon().post("/api/orgs", map[string]any{"name": "x"}), 401)

	ad := w.as("admin")
	c := &caller{w: w, c: ad.c} // session cookie without CSRF header
	want(t, c.post(A+"/groups", map[string]any{"display_name": "g"}), 403)
	want(t, c.get(A+"/groups"), 200) // safe methods need no token
	bad := &caller{w: w, c: ad.c, csrf: "wrong"}
	want(t, bad.post(A+"/groups", map[string]any{"display_name": "g"}), 403)
	// cross-origin
	want(t, ad.do("POST", A+"/groups", map[string]any{"display_name": "g"}, "Origin", "https://evil.example"), 403)
	want(t, ad.do("POST", A+"/groups", map[string]any{"display_name": "g"}, "Sec-Fetch-Site", "cross-site"), 403)
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "g"}), 201)
}

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

type fakeMailer struct{ sent []string }

func (m *fakeMailer) SendInviteLink(_ context.Context, _ *model.Org, u *model.User, url string, _ time.Time) error {
	m.sent = append(m.sent, u.Username+" "+url)
	return nil
}

func (m *fakeMailer) SendVerifyAddress(_ context.Context, _ *model.Org, u *model.User, address string) error {
	m.sent = append(m.sent, "verify "+u.Username+" "+address)
	return nil
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

	// another organization's admin cannot reach acme at all
	ot := w.as("other")
	for _, p := range []string{AU, A + "/groups", A} {
		want(t, ot.get(p), 404)
	}
	want(t, ot.get("/api/keys"), 403)

	// only super admins grant super_admin, and only in the primary org
	su := w.as("super")
	want(t, su.post("/api/orgs/primary/users", map[string]any{"given_name": "T", "username": "boss", "email": "boss@x.example", "role": "super_admin"}), 201)
	want(t, su.post(AU, map[string]any{"given_name": "T", "username": "boss", "email": "boss@x.example", "role": "super_admin"}), 403)
	want(t, w.as("admin").post(AU, map[string]any{"given_name": "T", "username": "boss2", "email": "boss2@x.example", "role": "super_admin"}), 403)
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

func TestGroups(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	r := ad.post(A+"/groups", map[string]any{"display_name": "Engineering", "external_id": "eng"})
	want(t, r, 201)
	gid := r.str("id")
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "Design"}), 201)
	wantField(t, ad.post(A+"/groups", map[string]any{"display_name": "engineering"}), 409, "display_name")
	wantField(t, ad.post(A+"/groups", map[string]any{}), 422, "display_name")

	r = ad.get(A + "/groups?sort=display_name")
	if r.total() != 2 || r.items()[0].(map[string]any)["display_name"] != "Design" {
		t.Fatal(string(r.Raw))
	}
	if ad.get(A+"/groups?q=eng").total() != 1 {
		t.Fatal("search")
	}
	want(t, ad.patch(A+"/groups/"+gid, map[string]any{"display_name": "Eng"}), 200)

	// members
	uid := w.users["user"].ID
	want(t, ad.put(A+"/groups/"+gid+"/members/"+uid, nil), 200)
	want(t, ad.put(A+"/groups/"+gid+"/members/"+uid, nil), 200) // idempotent
	want(t, ad.put(A+"/groups/"+gid+"/members/"+w.users["manager"].ID, nil), 200)
	wantField(t, ad.put(A+"/groups/"+gid+"/members/"+w.users["other"].ID, nil), 422, "members")
	r = ad.get(A + "/groups/" + gid + "/members")
	if r.total() != 2 || len(r.items()) != 2 {
		t.Fatal(string(r.Raw))
	}
	if len(ad.get(A+"/groups/"+gid+"/members?limit=1&offset=1").items()) != 1 {
		t.Fatal("member paging")
	}
	g := ad.get(AU + "/" + uid)
	if gs, _ := g.JSON["groups"].([]any); len(gs) != 1 {
		t.Fatalf("user groups: %s", g.Raw)
	}
	want(t, ad.delete(A+"/groups/"+gid+"/members/"+uid), 200)
	if ad.get(A+"/groups/"+gid+"/members").total() != 1 {
		t.Fatal("remove member")
	}
	want(t, ad.delete(A+"/groups/"+gid), 200)
	want(t, ad.get(A+"/groups/"+gid+"/members"), 404)
	// groups of another org are invisible
	gr := w.as("other").post(G+"/groups", map[string]any{"display_name": "Theirs"})
	want(t, gr, 201)
	want(t, ad.patch(A+"/groups/"+gr.str("id"), map[string]any{"display_name": "x"}), 404)
}

func TestClients(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	r := ad.post(A+"/clients", map[string]any{"name": "Portal", "redirect_uris": []string{"https://p.example/cb"}})
	want(t, r, 201)
	secret, id := r.str("secret"), r.str("id")
	if !strings.HasPrefix(secret, "qsrs_") || id == "" {
		t.Fatalf("create: %s", r.Raw)
	}
	r = ad.get(A + "/clients")
	if strings.Contains(string(r.Raw), secret) || strings.Contains(string(r.Raw), "secret_hash") || strings.Contains(string(r.Raw), "SecretHash") {
		t.Fatal("secret leaked in the list")
	}
	if r.total() != 1 {
		t.Fatal(string(r.Raw))
	}
	wantField(t, ad.post(A+"/clients", map[string]any{"name": "Bad", "redirect_uris": []string{"ftp://x"}}), 422, "redirect_uris")
	wantField(t, ad.post(A+"/clients", map[string]any{"redirect_uris": []string{"https://p.example/cb"}}), 422, "name")
	want(t, ad.post(A+"/clients", map[string]any{"name": "SA", "grant_types": []string{"client_credentials"}}), 201)
	// super-only flag: SCIM
	want(t, ad.post(A+"/clients", map[string]any{"name": "SA2", "scim": true, "grant_types": []string{"client_credentials"}}), 403)
	want(t, w.as("super").post(A+"/clients", map[string]any{"name": "SA3", "scim": true, "grant_types": []string{"client_credentials"}}), 201)
	// the former "serves every organization" flag is gone: the strict decoder refuses it
	want(t, ad.patch(A+"/clients/"+id, map[string]any{"all_orgs": true}), 400)

	r = ad.patch(A+"/clients/"+id, map[string]any{"name": "Portal 2", "enabled": false})
	want(t, r, 200)
	if r.str("name") != "Portal 2" || r.JSON["enabled"] != false || r.str("secret") != "" {
		t.Fatal(string(r.Raw))
	}

	r = ad.post(A+"/clients/"+id+"/secret", nil)
	want(t, r, 200)
	if r.str("secret") == "" || r.str("secret") == secret || r.str("client_id") != id {
		t.Fatal(string(r.Raw))
	}

	// public clients: no secret is issued and there is nothing to rotate
	r = ad.post(A+"/clients", map[string]any{"name": "SPA", "token_endpoint_auth_method": "none", "redirect_uris": []string{"com.example.app:/callback"}})
	want(t, r, 201)
	if r.str("secret") != "" {
		t.Fatalf("public client got a secret: %s", r.Raw)
	}
	wantField(t, ad.post(A+"/clients/"+r.str("id")+"/secret", nil), 422, "token_endpoint_auth_method")
	wantField(t, ad.post(A+"/clients", map[string]any{"name": "Bad SPA", "token_endpoint_auth_method": "none", "grant_types": []string{"client_credentials"}}), 422, "grant_types")

	want(t, ad.delete(A+"/clients/"+id), 200)
	want(t, ad.delete(A+"/clients/"+id), 404)
	if ad.get(A+"/clients?q=zzz").total() != 0 {
		t.Fatal("search")
	}
	if ad.get(A + "/clients?sort=name&desc=1").items()[0].(map[string]any)["name"] != "SPA" {
		t.Fatal("sort")
	}
}

func TestTenants(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	T := A + "/tenants"

	// every org starts with its default tenant
	r := ad.get(T)
	want(t, r, 200)
	if r.total() != 1 || r.items()[0].(map[string]any)["name"] != "default" {
		t.Fatalf("default tenant: %s", r.Raw)
	}
	defID := r.items()[0].(map[string]any)["id"].(string)

	// create with settings
	prov := ad.post(A+"/providers", map[string]any{"type": "oidc", "name": "SSO", "issuer": "https://sso.example", "client_id": "c", "client_secret": "s"})
	want(t, prov, 201)
	r = ad.post(T, map[string]any{"name": "staff", "display_name": "Staff", "description": "Internal", "settings": map[string]any{
		"password_login": false, "passkey_login": true, "all_providers": false, "providers": []string{prov.str("id")}, "require_mfa": true}})
	want(t, r, 201)
	id := r.str("id")
	set, _ := r.JSON["settings"].(map[string]any)
	if r.str("name") != "staff" || set["password_login"] != false || set["require_mfa"] != true || r.JSON["clients"] != float64(0) {
		t.Fatalf("create: %s", r.Raw)
	}
	// defaults: everything the org allows
	r = ad.post(T, map[string]any{"name": "plain", "display_name": "Plain"})
	want(t, r, 201)
	set, _ = r.JSON["settings"].(map[string]any)
	if set["password_login"] != true || set["all_providers"] != true {
		t.Fatalf("default settings: %s", r.Raw)
	}
	wantField(t, ad.post(T, map[string]any{"name": "staff", "display_name": "Dup"}), 409, "name")
	wantField(t, ad.post(T, map[string]any{"name": "Bad Name", "display_name": "x"}), 422, "name")
	wantField(t, ad.post(T, map[string]any{"display_name": "x"}), 422, "name")
	wantField(t, ad.post(T, map[string]any{"name": "nodisplay", "display_name": " "}), 422, "display_name")
	wantField(t, ad.post(T, map[string]any{"name": "x1", "display_name": "x", "settings": map[string]any{"providers": []string{"nope"}}}), 422, "settings")

	// a provider of another organization cannot be allowed
	gp := w.as("other").post(G+"/providers", map[string]any{"type": "oidc", "name": "Theirs", "issuer": "https://t.example", "client_id": "c", "client_secret": "s"})
	want(t, gp, 201)
	wantField(t, ad.post(T, map[string]any{"name": "x2", "display_name": "x", "settings": map[string]any{"providers": []string{gp.str("id")}}}), 422, "settings")

	// get, list, search, sort, paging
	r = ad.get(T + "/" + id)
	want(t, r, 200)
	if r.str("display_name") != "Staff" {
		t.Fatal(string(r.Raw))
	}
	if ad.get(T).total() != 3 || ad.get(T+"?q=staf").total() != 1 || ad.get(T+"?q=zzz").total() != 0 {
		t.Fatal("list / search")
	}
	if ad.get(T + "?sort=name&desc=1").items()[0].(map[string]any)["name"] != "staff" {
		t.Fatal("sort")
	}
	if r = ad.get(T + "?limit=1&offset=1"); len(r.items()) != 1 || r.total() != 3 {
		t.Fatal("paging")
	}

	// patch
	r = ad.patch(T+"/"+id, map[string]any{"display_name": "Staff tools", "settings": map[string]any{"password_login": true, "passkey_login": true, "all_providers": true}})
	want(t, r, 200)
	set, _ = r.JSON["settings"].(map[string]any)
	if r.str("display_name") != "Staff tools" || set["all_providers"] != true || r.str("name") != "staff" {
		t.Fatal(string(r.Raw))
	}
	wantField(t, ad.patch(T+"/"+id, map[string]any{"name": "plain"}), 409, "name")
	want(t, ad.patch(T+"/"+id, map[string]any{"bogus": 1}), 400)

	// clients: tenant_id is accepted, returned, validated and filterable
	r = ad.post(A+"/clients", map[string]any{"name": "Portal", "tenant_id": id, "redirect_uris": []string{"https://p.example/cb"}})
	want(t, r, 201)
	cid := r.str("id")
	if r.str("tenant_id") != id {
		t.Fatalf("client tenant: %s", r.Raw)
	}
	r = ad.post(A+"/clients", map[string]any{"name": "Untenanted", "redirect_uris": []string{"https://u.example/cb"}})
	want(t, r, 201)
	if r.str("tenant_id") != defID {
		t.Fatalf("client without tenant gets the default tenant: %s", r.Raw)
	}
	wantField(t, ad.post(A+"/clients", map[string]any{"name": "Bad", "tenant_id": "nope", "redirect_uris": []string{"https://b.example/cb"}}), 422, "tenant_id")
	ot := w.as("other").post(G+"/tenants", map[string]any{"name": "theirs", "display_name": "Theirs"})
	want(t, ot, 201)
	wantField(t, ad.post(A+"/clients", map[string]any{"name": "Bad", "tenant_id": ot.str("id"), "redirect_uris": []string{"https://b.example/cb"}}), 422, "tenant_id")
	wantField(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": ot.str("id")}), 422, "tenant_id")
	if r = ad.get(A + "/clients?tenant=" + id); r.total() != 1 || r.items()[0].(map[string]any)["id"] != cid {
		t.Fatalf("tenant filter: %s", r.Raw)
	}
	if ad.get(A+"/clients?tenant="+defID).total() != 1 || ad.get(A+"/clients").total() != 2 || ad.get(A+"/clients?tenant=nope").total() != 0 {
		t.Fatal("tenant filter counts")
	}
	want(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": defID}), 200)
	if ad.get(A+"/clients?tenant="+defID).total() != 2 {
		t.Fatal("moving a client between tenants")
	}
	want(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": id}), 200)

	// clients count; delete in use -> 409
	r = ad.get(T + "/" + id)
	if r.JSON["clients"] != float64(1) {
		t.Fatalf("clients count: %s", r.Raw)
	}
	for _, it := range ad.get(T + "?q=staff").items() {
		if it.(map[string]any)["clients"] != float64(1) {
			t.Fatal("list clients count")
		}
	}
	r = ad.delete(T + "/" + id)
	want(t, r, 409)
	if !strings.Contains(r.str("error"), "clients") {
		t.Fatal(string(r.Raw))
	}
	want(t, ad.delete(A+"/clients/"+cid), 200)
	want(t, ad.delete(T+"/"+id), 200)
	want(t, ad.get(T+"/"+id), 404)
	want(t, ad.delete(T+"/"+id), 404)

	// tenants of another organization are invisible
	want(t, ad.get(T+"/"+ot.str("id")), 404)
	want(t, ad.patch(T+"/"+ot.str("id"), map[string]any{"display_name": "x"}), 404)
	want(t, ad.delete(T+"/"+ot.str("id")), 404)
	want(t, w.as("other").get(T+"/"+defID), 404)
}

func TestTenantPermissions(t *testing.T) {
	w := newWorld(t)
	T := A + "/tenants"
	made := w.as("admin").post(T, map[string]any{"name": "t1", "display_name": "T1"})
	want(t, made, 201)
	id := made.str("id")

	// admins and super admins: full access; super may act in any org
	su := w.as("super")
	want(t, su.get(T), 200)
	want(t, su.post(T, map[string]any{"name": "bysuper", "display_name": "By super"}), 201)
	want(t, su.patch(T+"/"+id, map[string]any{"description": "d"}), 200)
	want(t, su.get(G+"/tenants"), 200)

	// managers and users: forbidden everywhere
	for _, who := range []string{"manager", "user"} {
		c := w.as(who)
		want(t, c.get(T), 403)
		want(t, c.post(T, map[string]any{"name": "x", "display_name": "x"}), 403)
		// a single tenant is invisible to those who may not administer the org
		want(t, c.get(T+"/"+id), 404)
		want(t, c.patch(T+"/"+id, map[string]any{"description": "x"}), 404)
		want(t, c.delete(T+"/"+id), 404)
	}

	// another organization's admin: acme does not exist for them
	ot := w.as("other")
	want(t, ot.get(T), 404)
	want(t, ot.post(T, map[string]any{"name": "x", "display_name": "x"}), 404)
	want(t, ot.get(T+"/"+id), 404)
	want(t, ot.patch(T+"/"+id, map[string]any{"description": "x"}), 404)
	want(t, ot.delete(T+"/"+id), 404)
	want(t, ot.get(G+"/tenants"), 200)

	// anonymous
	want(t, w.anon().get(T), 401)

	// bearer tokens: the role still limits the call; the admin scope is required
	at := w.withBearer("admin", service.ScopeAdmin)
	want(t, at.get(T), 200)
	want(t, at.post(T, map[string]any{"name": "viatoken", "display_name": "Via token"}), 201)
	want(t, at.get(T+"/"+id), 200)
	want(t, at.patch(T+"/"+id, map[string]any{"description": "tok"}), 200)
	want(t, at.get(G+"/tenants"), 404)
	mt := w.withBearer("manager", service.ScopeAdmin)
	want(t, mt.get(T), 403)
	want(t, mt.post(T, map[string]any{"name": "x", "display_name": "x"}), 403)
	api := w.withBearer("admin", service.ScopeAPI)
	want(t, api.get(T), 403)
	want(t, at.delete(T+"/"+id), 200)
}

func TestProviders(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	in := map[string]any{"type": "oidc", "name": "SSO", "issuer": "https://login.example.com", "client_id": "cid", "client_secret": "hunter2-secret"}
	r := ad.post(A+"/providers", in)
	want(t, r, 201)
	if r.JSON["has_secret"] != true || strings.Contains(string(r.Raw), "hunter2") || r.JSON["client_secret"] != nil {
		t.Fatalf("secret handling: %s", r.Raw)
	}
	id := r.str("id")
	wantField(t, ad.post(A+"/providers", in), 409, "name")
	wantField(t, ad.post(A+"/providers", map[string]any{"type": "oidc", "name": "X", "issuer": "http://x", "client_id": "a", "client_secret": "b"}), 422, "issuer")
	wantField(t, ad.post(A+"/providers", map[string]any{"type": "oidc", "name": "Y", "issuer": "https://x.example", "client_id": "a"}), 422, "client_secret")

	// link_by_email defaults to on and can be switched off
	if r.JSON["link_by_email"] != true {
		t.Fatalf("link_by_email default: %s", r.Raw)
	}
	r = ad.patch(A+"/providers/"+id, map[string]any{"link_by_email": false})
	want(t, r, 200)
	if r.JSON["link_by_email"] != false || ad.get(A + "/providers/" + id).JSON["link_by_email"] != false {
		t.Fatalf("link_by_email off: %s", r.Raw)
	}
	r = ad.patch(A+"/providers/"+id, map[string]any{"name": "SSO 2", "client_secret": ""}) // blank keeps the secret
	want(t, r, 200)
	if r.JSON["has_secret"] != true || r.str("name") != "SSO 2" {
		t.Fatal(string(r.Raw))
	}
	r = ad.get(A + "/providers?sort=type")
	if r.total() != 1 || strings.Contains(string(r.Raw), "hunter2") {
		t.Fatal(string(r.Raw))
	}
	want(t, w.as("other").patch(A+"/providers/"+id, map[string]any{"name": "hax"}), 404)
	want(t, ad.delete(A+"/providers/"+id), 200)
	want(t, ad.delete(A+"/providers/"+id), 404)
}

func TestSettings(t *testing.T) {
	w := newWorld(t)
	su, ad := w.as("super"), w.as("admin")
	// the organization's own administrators read its settings (the tenant pages show them) but do not change them
	r := ad.get(A)
	want(t, r, 200)
	if r.JSON["settings"] == nil {
		t.Fatalf("settings missing: %s", r.Raw)
	}
	want(t, ad.patch(A, map[string]any{"settings": map[string]any{"password_login": true}}), 403)
	r = su.patch(A, map[string]any{"settings": map[string]any{"password_login": true, "password_reset": true, "passkey_login": false,
		"require_mfa": true, "session_ttl": 3600, "session_idle": 600}})
	want(t, r, 200)
	o, _ := w.env.Svc.Orgs.Get(context.Background(), w.acme.ID)
	if !o.Settings.RequireMFA || o.Settings.PasskeyLogin || !o.Settings.PasswordReset || o.Settings.SessionTTL != 3600 {
		t.Fatalf("not saved: %+v", o.Settings)
	}
	want(t, su.patch(A, map[string]any{"settings": map[string]any{"session_ttl": -1}}), 422)
	wantField(t, su.patch(A, map[string]any{"name": "Not Valid"}), 422, "name")
	r = su.patch(A, map[string]any{"name": "acme2", "display_name": "Acme Two"})
	want(t, r, 200)
	want(t, su.get("/api/orgs/acme"), 404) // renamed: the URL name changed
	want(t, su.get("/api/orgs/acme2"), 200)
}

func TestAudit(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "First"}), 201)
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "Second"}), 201)
	r := ad.get(A + "/audit")
	want(t, r, 200)
	if r.total() < 2 {
		t.Fatal(string(r.Raw))
	}
	if first := r.items()[0].(map[string]any); first["action"] != "group.create" || first["target"] != "Second" {
		t.Fatalf("newest first expected: %v", first)
	}
	r = ad.get(A + "/audit?q=First")
	if r.total() != 1 {
		t.Fatalf("search: %s", r.Raw)
	}
	r = ad.get(A + "/audit?sort=created&desc=0&limit=1")
	if first := r.items()[0].(map[string]any); first["action"] == "group.create" && first["target"] == "Second" {
		t.Fatalf("ascending sort should start with the oldest: %v", first)
	}
	want(t, ad.get(A+"/audit?sort=ip"), 422)
	if n := len(ad.get(A + "/audit?limit=1").items()); n != 1 {
		t.Fatal("limit")
	}
	// the other org's events are not visible here
	w.as("other").post(G+"/groups", map[string]any{"display_name": "Theirs"})
	if ad.get(A+"/audit?q=Theirs").total() != 0 {
		t.Fatal("cross-org audit leak")
	}

	// filters: a family of actions, one action, an outcome, a time range; the search covers the IP address
	r = ad.get(A + "/audit?action_group=GROUP.")
	want(t, r, 200)
	if r.total() < 2 {
		t.Fatalf("action group: %s", r.Raw)
	}
	for _, it := range r.items() {
		if a := it.(map[string]any)["action"].(string); !strings.HasPrefix(a, "group.") {
			t.Fatalf("action group returned %s", a)
		}
	}
	if n := ad.get(A + "/audit?action=group.create&q=First").total(); n != 1 {
		t.Fatalf("action and search: %d", n)
	}
	if n := ad.get(A + "/audit?action=group.delete").total(); n != 0 {
		t.Fatalf("an action that did not happen: %d", n)
	}
	for _, it := range ad.get(A + "/audit?outcome=success").items() {
		if o := it.(map[string]any)["outcome"]; o != "success" {
			t.Fatalf("outcome filter returned %v", o)
		}
	}
	all := ad.get(A + "/audit").total()
	past, future := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if n := ad.get(A + "/audit?from=" + past + "&to=" + future).total(); n != all {
		t.Fatalf("the last hour: %d of %d", n, all)
	}
	if n := ad.get(A + "/audit?from=" + future).total(); n != 0 {
		t.Fatalf("from the future: %d", n)
	}
	if ip, _ := ad.get(A + "/audit").items()[0].(map[string]any)["ip"].(string); ip != "" {
		if n := ad.get(A + "/audit?q=" + url.QueryEscape(ip)).total(); n == 0 {
			t.Fatalf("search by IP address %s found nothing", ip)
		}
	}
	want(t, ad.get(A+"/audit?outcome=maybe"), 422)
	want(t, ad.get(A+"/audit?from=yesterday"), 422)
	want(t, ad.get(A+"/audit?from="+future+"&to="+past), 422)
	// every organization (super admins), narrowed to one
	su := w.as("super")
	if n := su.get("/api/audit?org=globex&q=Theirs").total(); n != 1 {
		t.Fatalf("all organizations, narrowed to one: %d", n)
	}
}

func TestKeys(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")
	now := time.Now()
	for _, k := range []*model.SigningKey{
		{Meta: model.Meta{ID: "k-prev"}, Alg: "ES256", NotBefore: now.Add(-60 * 24 * time.Hour), RetireAt: now.Add(-time.Hour), Expires: now.Add(time.Hour)},
		{Meta: model.Meta{ID: "k-sign"}, Alg: "ES256", NotBefore: now.Add(-time.Hour), RetireAt: now.Add(29 * 24 * time.Hour), Expires: now.Add(30 * 24 * time.Hour)},
		{Meta: model.Meta{ID: "k-next"}, Alg: "ES256", NotBefore: now.Add(10 * time.Minute), RetireAt: now.Add(40 * 24 * time.Hour), Expires: now.Add(41 * 24 * time.Hour)},
	} {
		if err := w.env.Svc.Keys.Create(context.Background(), k); err != nil {
			t.Fatal(err)
		}
	}
	r := su.get("/api/keys")
	want(t, r, 200)
	states := map[string]string{}
	for _, it := range r.items() {
		m := it.(map[string]any)
		states[m["id"].(string)] = m["state"].(string)
		if _, leaked := m["private_key"]; leaked {
			t.Fatal("private key in the listing")
		}
	}
	if states["k-sign"] != "signing" || states["k-next"] != "next" || states["k-prev"] != "previous" {
		t.Fatalf("states: %v", states)
	}
	if first := r.items()[0].(map[string]any)["id"]; first != "k-next" {
		t.Fatalf("not newest first: %v", first)
	}
	want(t, su.post("/api/keys/rotate", nil), 501)
	want(t, w.as("admin").get("/api/keys"), 403)
	want(t, w.as("admin").post("/api/keys/rotate", nil), 403)
}

// GET /api/backup streams a complete backup of the live store; super admins only. It is encrypted with the
// password in X-Backup-Password, or unencrypted with ?plain=1; one or the other must be asked for.
func TestBackupDownload(t *testing.T) {
	w := newWorld(t)
	want(t, w.as("super").get("/api/backup"), 400)
	want(t, w.as("super").do("GET", "/api/backup", nil, "X-Backup-Password", "short"), 400)
	enc := w.as("super").do("GET", "/api/backup", nil, "X-Backup-Password", "correct horse battery")
	want(t, enc, 200)
	if !backup.PasswordProtected(enc.Raw) || enc.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("encrypted download: %v", enc.Header)
	}
	if _, err := backup.Verify(bytes.NewReader(enc.Raw), w.env.Svc.Sealer, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	r := w.as("super").get("/api/backup?plain=1")
	want(t, r, 200)
	if r.Header.Get("Content-Type") != "application/gzip" || !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("headers %v", r.Header)
	}
	stats, err := backup.Verify(bytes.NewReader(r.Raw), w.env.Svc.Sealer, "")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := w.env.Svc.Users.Count(context.Background(), ""); stats[model.KindUser] != n {
		t.Fatalf("backup has %d users, the store %d", stats[model.KindUser], n)
	}
	want(t, w.as("admin").get("/api/backup"), 403)
	// a token needs the backup scope (admin is not enough); only super admins get it, and it expires within 30 days
	want(t, w.withBearer("super", "admin").get("/api/backup"), 403)
	want(t, w.withBearer("super", "api").get("/api/backup"), 403)
	_, tok, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(w.env.Admin, ""),
		service.APITokenInput{Name: "b", Scopes: []string{"backup"}, Expires: 7})
	if err != nil {
		t.Fatal(err)
	}
	c := w.withBearer("super", "api")
	c.bearer = tok
	want(t, c.get("/api/backup?plain=1"), 200)
	for name, in := range map[string]service.APITokenInput{
		"no expiry": {Name: "b", Scopes: []string{"backup"}},
		"too long":  {Name: "b", Scopes: []string{"backup"}, Expires: 31},
	} {
		if _, _, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(w.env.Admin, ""), in); err == nil {
			t.Errorf("backup token %s: accepted", name)
		}
	}
	if _, _, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(w.users["admin"], ""),
		service.APITokenInput{Name: "b", Scopes: []string{"backup"}, Expires: 7}); err == nil {
		t.Error("an organization admin got a backup token")
	}
	// a node that is not ready (catching up, cut off) refuses rather than back up a partial store
	w.env.Server.Health = notReady{}
	want(t, w.as("super").get("/api/backup?plain=1"), 503)
	w.env.Server.Health = nil
	if n := len(auditActions(t, w, "backup.download")); n < 2 {
		t.Fatalf("backup downloads audited: %d", n)
	}
}

type notReady struct{}

func (notReady) Ready() (bool, string) { return false, "catching up" }

func auditActions(t *testing.T, w *world, action string) []*model.Audit {
	t.Helper()
	l, _, err := w.env.Svc.Audits.List(context.Background(), store.ListQuery{Filters: []store.Filter{{Field: "action", Value: action}}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestBearerAndVersioning(t *testing.T) {
	w := newWorld(t)
	// manager token with admin scope: same limits as the manager's session
	mt := w.withBearer("manager", service.ScopeAdmin)
	r := mt.get(AU)
	want(t, r, 200)
	if r.Header.Get("Api-Version") != web.APIVersionLatest {
		t.Error("version not echoed")
	}
	want(t, mt.post(AU, map[string]any{"given_name": "T", "username": "viabearer", "email": "viabearer@x.example"}), 201)
	want(t, mt.post(AU, map[string]any{"given_name": "T", "username": "viabearer2", "email": "viabearer2@x.example", "role": "admin"}), 403)
	want(t, mt.get(A+"/clients"), 403)
	want(t, mt.get("/api/orgs/globex/users"), 404)
	want(t, mt.get("/api/keys"), 403)

	// admin token: no CSRF needed, can administer its org but not create orgs
	at := w.withBearer("admin", service.ScopeAdmin)
	want(t, at.post(A+"/groups", map[string]any{"display_name": "viatoken"}), 201)
	want(t, at.post("/api/orgs", map[string]any{"name": "nope"}), 403)
	want(t, at.get("/api/orgs/primary"), 404)

	// super admin token
	st := w.withBearer("super", service.ScopeAdmin)
	want(t, st.post("/api/orgs", map[string]any{"name": "viabearer"}), 201)
	want(t, st.get("/api/keys"), 200)
	want(t, st.get("/api/orgs/globex/users"), 200)

	// wrong scope, bad token, missing token
	api := w.withBearer("super", service.ScopeAPI)
	want(t, api.get("/api/orgs"), 403)
	bad := &caller{w: w, c: detach(w.env.Client()), bearer: "qsr_nope_nope"}
	want(t, bad.get("/api/orgs"), 401)
	want(t, w.anon().get("/api/orgs"), 401)

	// version negotiation
	want(t, st.do("GET", "/api/orgs", nil, "Api-Version", web.APIVersionLatest), 200)
	r = st.do("GET", "/api/orgs", nil, "Api-Version", "2000-01-01")
	wantField(t, r, 400, "")
	if r.Header.Get("Api-Version") != web.APIVersionLatest {
		t.Error("an unsupported version is answered with the latest supported one")
	}
	// session callers may send the header too, and the old /api/admin paths are gone
	want(t, w.as("admin").do("GET", AU, nil, "Api-Version", web.APIVersionLatest), 200)
	want(t, w.as("admin").get("/api/admin/orgs"), 404)
}

func TestPages(t *testing.T) {
	w := newWorld(t)
	ad, su, mg := w.as("admin"), w.as("super"), w.as("manager")
	html := func(c *caller, path string, status int) string {
		t.Helper()
		req, _ := http.NewRequest("GET", w.env.URL+path, nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != status {
			t.Fatalf("%s: status %d want %d\n%s", path, res.StatusCode, status, b)
		}
		return string(b)
	}
	for _, p := range []struct{ path, comp string }{
		{"/admin/orgs/acme/users", "adminUsers"}, {"/admin/orgs/acme/groups", "adminGroups"},
		{"/admin/orgs/acme/tenants", "adminTenants"}, {"/admin/orgs/acme/providers", "adminProviders"}, {"/admin/orgs/acme/audit", "adminAudit"},
		{"/admin/orgs/acme/users/" + w.users["user"].ID, "adminUser"},
	} {
		body := html(ad, p.path, 200)
		for _, s := range []string{`x-data="` + p.comp + `"`, `<meta name="csrf-token" content="`, `aria-label="Primary"`, `class="skip-link"`,
			`<h1 `, `/api/orgs/acme`, `theme-boot-`, `lang="en"`} {
			if !strings.Contains(body, s) {
				t.Errorf("%s missing %q", p.path, s)
			}
		}
		if strings.Contains(body, "<script>") || strings.Contains(body, " onclick=") {
			t.Errorf("%s: inline script", p.path)
		}
	}
	if b := html(su, "/admin/orgs", 200); !strings.Contains(b, `x-data="adminOrgs"`) || !strings.Contains(b, `href="/admin/orgs" aria-current="page"`) {
		t.Error("orgs page")
	}
	// the organization block: for administrators the link to its overview (current on that page); for managers a
	// label; the organizations list is a System link, for super admins only
	if b := html(ad, "/admin/orgs/acme", 200); !strings.Contains(b, `class="nav-link nav-org-link" href="/admin/orgs/acme" aria-current="page"`) ||
		strings.Contains(b, `href="/admin/orgs"`) {
		t.Error("admin: organization block")
	}
	if b := html(mg, "/admin/orgs/acme/users", 200); strings.Contains(b, "nav-org-link") || !strings.Contains(b, `class="nav-org"`) {
		t.Error("manager: organization block")
	}
	if b := html(su, "/admin/orgs/acme/users", 200); !strings.Contains(b, `href="/admin/orgs"`) || !strings.Contains(b, `href="/admin/audit"`) {
		t.Error("super admin: System links")
	}
	// the audit log of every organization is reached from the menu, not from an organization's audit log
	if b := html(su, "/admin/orgs/acme/audit", 200); strings.Count(b, `href="/admin/audit"`) != 1 {
		t.Error("an organization's audit log links to every organization's besides the menu")
	}
	// current-page marker in the navigation
	if b := html(ad, "/admin/orgs/acme/groups", 200); !strings.Contains(b, `href="/admin/orgs/acme/groups" aria-current="page"`) {
		t.Error("aria-current")
	}
	// super admin administering another org: the nav shows that org
	if b := html(su, "/admin/orgs/globex/users", 200); !strings.Contains(b, "Globex") || !strings.Contains(b, `/api/orgs/globex`) {
		t.Error("super admin on another org")
	}

	// the system overview (the server as a whole: cluster, signing keys, emergency sign-out): super admins only, in the
	// menu's System group, which keeps the organization last administered
	if b := html(su, "/admin/system", 200); !strings.Contains(b, `x-data="adminSystem"`) ||
		!strings.Contains(b, `href="/admin/system" aria-current="page"`) || !strings.Contains(b, `id="signout-dialog"`) ||
		!strings.Contains(b, `id="rotate-keys"`) || !strings.Contains(b, `aria-label="Cluster nodes table"`) {
		t.Error("system overview")
	}
	if b := html(su, "/admin/orgs/acme/users", 200); !strings.Contains(b, `href="/admin/system"`) {
		t.Error("no system link for a super admin")
	}
	if b := html(su, "/admin/system", 200); !strings.Contains(b, `href="/admin/orgs/acme/users"`) {
		t.Error("the system overview does not keep the organization last administered")
	}
	html(su, "/admin/orgs/globex/users", 200)
	if b := html(su, "/admin/system", 200); !strings.Contains(b, `href="/admin/orgs/globex/users"`) {
		t.Error("the system overview does not follow the organization last administered")
	}
	for _, path := range []string{"/admin/system", "/admin/system/master-key"} {
		html(ad, path, 404)
		html(mg, path, 404)
	}
	if b := html(ad, "/admin/orgs/acme/users", 200); strings.Contains(b, "/admin/system") {
		t.Error("system link for an organization admin")
	}
	w.env.Server.Site.Clustered = true
	html(su, "/admin/orgs/primary/settings", 404) // organization settings are edited from the organizations list
	w.env.Server.Site.Clustered = false

	// permissions
	html(ad, "/admin/orgs", 403)
	html(mg, "/admin/orgs/acme/users", 200)
	b := html(mg, "/admin/orgs/acme/tenants", 403)
	if !strings.Contains(b, "Not allowed") || !strings.Contains(b, "<h1") {
		t.Error("403 page")
	}
	html(w.as("user"), "/admin/orgs/acme/users", 403)
	html(ad, "/admin/orgs/globex/users", 404)
	html(ad, "/admin/orgs/nope/users", 404)
	html(ad, "/admin/orgs/acme/users/not-a-user", 200) // the page loads; the API reports the missing user
	// an organization's overview, with its emergency sign-out: its administrators and super admins; managers go to users
	if b := html(ad, "/admin/orgs/acme", 200); !strings.Contains(b, `x-data="adminOrg"`) ||
		!strings.Contains(b, `href="/admin/orgs/acme" aria-current="page"`) || !strings.Contains(b, `id="signout-dialog"`) {
		t.Error("organization overview")
	}
	html(su, "/admin/orgs/globex", 200)
	html(ad, "/admin/orgs/globex", 404)
	html(mg, "/admin/orgs/acme", 303)
	if b := html(mg, "/admin/orgs/acme/users", 200); strings.Contains(b, `href="/admin/orgs/acme" `) {
		t.Error("overview link for a manager")
	}

	// redirects
	loc := func(c *caller, path string) string {
		req, _ := http.NewRequest("GET", w.env.URL+path, nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.Header.Get("Location")
	}
	// signed out: an organization's pages go to its sign-in page (and back); the rest to the help page
	if l := loc(w.anon(), "/admin/orgs"); l != "/" {
		t.Errorf("anonymous redirect %q", l)
	}
	if l := loc(w.anon(), "/admin/orgs/acme/users?q=x"); l != "/login/acme?next="+url.QueryEscape("/admin/orgs/acme/users?q=x") {
		t.Errorf("anonymous redirect from an organization's page %q", l)
	}
	if l := loc(su, "/admin"); l != "/admin/system" {
		t.Errorf("super /admin -> %q", l)
	}
	if l := loc(ad, "/admin"); l != "/admin/orgs/acme" {
		t.Errorf("admin /admin -> %q", l)
	}
	if l := loc(mg, "/admin"); l != "/admin/orgs/acme/users" {
		t.Errorf("manager /admin -> %q", l)
	}
	if l := loc(mg, "/admin/orgs/acme"); l != "/admin/orgs/acme/users" {
		t.Errorf("org home for a manager -> %q", l)
	}
	html(w.as("user"), "/admin", 403)
	// clients live under tenants: the old page redirects to the tenants list
	if l := loc(ad, "/admin/orgs/acme/clients"); l != "/admin/orgs/acme/tenants" {
		t.Errorf("clients -> %q", l)
	}
}

// The tenant page: same RBAC as the tenants list, 404 for unknown tenants and tenants of other organizations.
func TestTenantPage(t *testing.T) {
	w := newWorld(t)
	ad, su, mg, us := w.as("admin"), w.as("super"), w.as("manager"), w.as("user")
	get := func(c *caller, path string) (int, string, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", w.env.URL+path, nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b), res.Header.Get("Location")
	}
	st := ad.post("/api/orgs/acme/tenants", map[string]any{"name": "staff", "display_name": "Staff tools"})
	want(t, st, 201)
	want(t, su.post("/api/orgs/globex/tenants", map[string]any{"name": "theirs", "display_name": "Theirs"}), 201)

	code, body, _ := get(ad, "/admin/orgs/acme/tenants/staff")
	if code != 200 {
		t.Fatalf("tenant page: %d", code)
	}
	for _, s := range []string{`x-data="adminTenant"`, `aria-label="Breadcrumb"`, `aria-current="page"`, "Tenant: Staff tools", `data-tenant="` + st.str("id") + `"`,
		`/api/orgs/acme`, `href="/admin/orgs/acme/tenants"`} {
		if !strings.Contains(body, s) {
			t.Errorf("tenant page missing %q", s)
		}
	}
	if strings.Contains(body, `href="/admin/orgs/acme/clients"`) {
		t.Error("the navigation must not link to a top-level Clients page")
	}
	if code, _, _ = get(ad, "/admin/orgs/acme/tenants/default"); code != 200 {
		t.Errorf("default tenant page: %d", code)
	}
	if code, _, _ = get(su, "/admin/orgs/acme/tenants/staff"); code != 200 {
		t.Errorf("super admin: %d", code)
	}
	if code, _, _ = get(su, "/admin/orgs/globex/tenants/theirs"); code != 200 {
		t.Errorf("super admin, other org: %d", code)
	}
	// unknown tenant, tenant of another organization, unknown organization
	for _, p := range []string{"/admin/orgs/acme/tenants/nope", "/admin/orgs/acme/tenants/theirs", "/admin/orgs/globex/tenants/staff", "/admin/orgs/nope/tenants/staff"} {
		if code, _, _ = get(su, p); code != 404 {
			t.Errorf("%s (super): %d want 404", p, code)
		}
	}
	if code, _, _ = get(ad, "/admin/orgs/globex/tenants/theirs"); code != 404 {
		t.Errorf("admin of another org: %d want 404", code)
	}
	// RBAC as the tenants list: managers and users are refused, anonymous visitors go to sign-in
	for _, c := range []*caller{mg, us} {
		if code, _, _ = get(c, "/admin/orgs/acme/tenants/staff"); code != 403 {
			t.Errorf("non-admin: %d want 403", code)
		}
	}
	if code, _, l := get(w.anon(), "/admin/orgs/acme/tenants/staff"); code != 303 || !strings.HasPrefix(l, "/login/acme?next=") {
		t.Errorf("anonymous: %d %q", code, l)
	}
	// old clients URL redirects (302) for everyone who can sign in; anonymous users are sent to sign-in first
	if code, _, l := get(ad, "/admin/orgs/acme/clients"); code != 302 || l != "/admin/orgs/acme/tenants" {
		t.Errorf("clients redirect: %d %q", code, l)
	}
}

// Single-record GETs used by the live-update dialogs, and client operations stay scoped to the organization and its
// tenants.
func TestClientScopeAndGets(t *testing.T) {
	w := newWorld(t)
	ad, su := w.as("admin"), w.as("super")
	A, G := "/api/orgs/acme", "/api/orgs/globex"
	ta := ad.post(A+"/tenants", map[string]any{"name": "a1", "display_name": "A1"})
	tb := ad.post(A+"/tenants", map[string]any{"name": "a2", "display_name": "A2"})
	tg := su.post(G+"/tenants", map[string]any{"name": "g1", "display_name": "G1"})
	want(t, ta, 201)
	want(t, tb, 201)
	want(t, tg, 201)
	c := ad.post(A+"/clients", map[string]any{"name": "One", "tenant_id": ta.str("id"), "redirect_uris": []string{"https://o.example/cb"}})
	want(t, c, 201)
	cid := c.str("id")
	gc := su.post(G+"/clients", map[string]any{"name": "Theirs", "tenant_id": tg.str("id"), "redirect_uris": []string{"https://t.example/cb"}})
	want(t, gc, 201)

	// the list for a tenant holds only that tenant's clients
	if r := ad.get(A + "/clients?tenant=" + ta.str("id")); r.total() != 1 {
		t.Fatalf("tenant a1 clients: %s", r.Raw)
	}
	if r := ad.get(A + "/clients?tenant=" + tb.str("id")); r.total() != 0 {
		t.Fatalf("tenant a2 clients: %s", r.Raw)
	}
	// another organization's tenant id yields nothing, never its clients
	if r := ad.get(A + "/clients?tenant=" + tg.str("id")); r.total() != 0 {
		t.Fatalf("foreign tenant filter leaked: %s", r.Raw)
	}
	// moving a client to a tenant of the same org works; to another org's tenant it does not
	want(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": tb.str("id")}), 200)
	if ad.get(A+"/clients?tenant="+ta.str("id")).total() != 0 || ad.get(A+"/clients?tenant="+tb.str("id")).total() != 1 {
		t.Fatal("client did not move between tenants")
	}
	wantField(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": tg.str("id")}), 422, "tenant_id")
	// GET one client: own org only; another org's client is a 404 through either org path
	if r := ad.get(A + "/clients/" + cid); r.str("name") != "One" || r.str("tenant_id") != tb.str("id") {
		t.Fatalf("get client: %s", r.Raw)
	}
	want(t, ad.get(A+"/clients/"+gc.str("id")), 404)
	want(t, ad.get(G+"/clients/"+cid), 404)
	want(t, ad.patch(A+"/clients/"+gc.str("id"), map[string]any{"name": "x"}), 404)
	want(t, ad.delete(A+"/clients/"+gc.str("id")), 404)
	want(t, ad.post(A+"/clients/"+gc.str("id")+"/secret", nil), 404)
	// groups and providers can be read one by one too (dialogs compare against the stored record)
	g := ad.post(A+"/groups", map[string]any{"display_name": "Ops"})
	want(t, g, 201)
	if ad.get(A+"/groups/"+g.str("id")).str("display_name") != "Ops" {
		t.Fatal("get group")
	}
	want(t, ad.get(G+"/groups/"+g.str("id")), 404)
	p := ad.post(A+"/providers", map[string]any{"type": "oidc", "name": "SSO", "issuer": "https://sso.example", "client_id": "x", "client_secret": "y"})
	want(t, p, 201)
	if ad.get(A+"/providers/"+p.str("id")).str("name") != "SSO" {
		t.Fatal("get provider")
	}
	want(t, ad.get(G+"/providers/"+p.str("id")), 404)
}

func TestNotFound(t *testing.T) {
	w := newWorld(t)
	anon := w.anon()
	res, err := anon.c.Get(w.env.URL + "/no/such/page")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	// signed out: how to sign in, as a 404
	if res.StatusCode != 404 || !strings.Contains(string(b), "Sign in through your application") || !strings.Contains(string(b), "does not exist") ||
		!strings.Contains(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("html 404 signed out: %d %s", res.StatusCode, b)
	}
	// signed in: the ordinary not-found page
	in, err := w.as("admin").c.Get(w.env.URL + "/no/such/page")
	if err != nil {
		t.Fatal(err)
	}
	ib, _ := io.ReadAll(in.Body)
	in.Body.Close()
	if in.StatusCode != 404 || !strings.Contains(string(ib), "Page not found") {
		t.Fatalf("html 404 signed in: %d %.300s", in.StatusCode, ib)
	}
	r := anon.get("/api/nothing")
	want(t, r, 404)
	if r.str("error") == "" {
		t.Fatal("json 404 body")
	}
}

func TestErrorPageTemplates(t *testing.T) {
	// every status the error page is used for renders
	w := newWorld(t)
	for _, p := range []string{"/admin/orgs", "/admin/nope"} {
		res, err := w.as("admin").c.Get(w.env.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode < 400 || !strings.Contains(string(b), "Error ") {
			t.Fatalf("%s: %d", p, res.StatusCode)
		}
	}
}

func TestInviteEndpoint(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	id := w.users["user"].ID
	m := &fakeMailer{}
	w.mod.Mailer = m

	// plain link: url + expiry, nothing emailed
	r := ad.post(AU+"/"+id+"/invite", map[string]any{})
	want(t, r, 200)
	first := r.str("url")
	exp, err := time.Parse(time.RFC3339, r.str("expires"))
	if !strings.Contains(first, "/invite?token=") || err != nil || time.Until(exp) < 6*24*time.Hour || len(m.sent) != 0 {
		t.Fatalf("invite: %s", r.Raw)
	}
	// no body at all works too
	want(t, ad.do("POST", AU+"/"+id+"/invite", nil), 200)

	// emailing; a newer link replaces the older one
	r = ad.post(AU+"/"+id+"/invite", map[string]any{"email": true})
	want(t, r, 200)
	second := r.str("url")
	if second == first || r.JSON["emailed"] != true || len(m.sent) != 1 || m.sent[0] != "alan "+second {
		t.Fatalf("emailed invite: %s %v", r.Raw, m.sent)
	}
	tok := func(u string) string { return u[strings.Index(u, "token=")+6:] }
	if _, _, err := w.env.Svc.PeekLink(context.Background(), tok(first), service.LinkInvite); err == nil {
		t.Error("the first link still works")
	}
	if _, _, err := w.env.Svc.PeekLink(context.Background(), tok(second), service.LinkInvite); err != nil {
		t.Errorf("the newest link does not work: %v", err)
	}

	// unknown fields are rejected; a user without an address cannot be emailed (and no link is spent)
	want(t, ad.post(AU+"/"+id+"/invite", map[string]any{"password": "x"}), 400)

	// disabled users cannot be invited; you cannot invite or de-password yourself here
	want(t, ad.patch(AU+"/"+id, map[string]any{"active": false}), 200)
	want(t, ad.post(AU+"/"+id+"/invite", map[string]any{}), 422)
	self := w.users["admin"].ID
	want(t, ad.post(AU+"/"+self+"/invite", map[string]any{}), 422)
	want(t, ad.delete(AU+"/"+self+"/password"), 422)

	// unknown user, other organization
	want(t, ad.post(AU+"/nope/invite", map[string]any{}), 404)
	want(t, ad.delete(AU+"/nope/password"), 404)
	want(t, ad.post(AU+"/"+w.users["other"].ID+"/invite", map[string]any{}), 404)
	want(t, ad.delete(AU+"/"+w.users["other"].ID+"/password"), 404)
}

func TestInvitePermissions(t *testing.T) {
	w := newWorld(t)
	uid, mid, aid := w.users["user"].ID, w.users["manager"].ID, w.users["admin"].ID
	inv := func(c *caller, id string) int { return c.post(AU+"/"+id+"/invite", map[string]any{}).Status }
	rm := func(c *caller, id string) int { return c.delete(AU + "/" + id + "/password").Status }

	// super admin and admin: anyone below them (admins can also manage managers), not themselves
	su := w.as("super")
	for _, id := range []string{uid, mid, aid} {
		if s := inv(su, id); s != 200 {
			t.Errorf("super invites %s: %d", id, s)
		}
		if s := rm(su, id); s != 204 {
			t.Errorf("super removes password of %s: %d", id, s)
		}
	}
	ad := w.as("admin")
	// the manager holds the super admin's unused invitation: an admin cannot replace it (and accept the new one as
	// the manager); its issuer can
	if s := inv(ad, mid); s != 422 {
		t.Errorf("admin replaces the super admin's pending invitation: %d", s)
	}
	if s := inv(su, mid); s != 200 {
		t.Errorf("super replaces its own invitation: %d", s)
	}
	if s := rm(ad, mid); s != 204 {
		t.Errorf("admin removes manager password: %d", s)
	}

	// managers: plain users only
	mg := w.as("manager")
	if s := inv(mg, uid); s != 200 {
		t.Errorf("manager invites user: %d", s)
	}
	if s := rm(mg, uid); s != 204 {
		t.Errorf("manager removes user password: %d", s)
	}
	for _, id := range []string{aid} {
		if s := inv(mg, id); s != 403 {
			t.Errorf("manager invites admin: %d", s)
		}
		if s := rm(mg, id); s != 403 {
			t.Errorf("manager removes admin password: %d", s)
		}
	}
	if s := inv(mg, mid); s != 422 && s != 403 {
		t.Errorf("manager invites self: %d", s)
	}
	if s := rm(mg, mid); s != 422 && s != 403 {
		t.Errorf("manager removes own password: %d", s)
	}

	// plain users and other organizations
	us := w.as("user")
	if s := inv(us, uid); s != 403 && s != 404 { // the service hides users from those who cannot manage any
		t.Errorf("user invites: %d", s)
	}
	if s := rm(us, uid); s != 403 && s != 404 {
		t.Errorf("user removes password: %d", s)
	}
	ot := w.as("other")
	if s := inv(ot, uid); s != 404 {
		t.Errorf("other org invites: %d", s)
	}
	if s := rm(ot, uid); s != 404 {
		t.Errorf("other org removes password: %d", s)
	}

	// bearer tokens: the owner's role limits them; admin scope is required
	bt := w.withBearer("manager", service.ScopeAdmin)
	if s := inv(bt, uid); s != 200 {
		t.Errorf("bearer invite: %d", s)
	}
	if s := rm(bt, aid); s != 403 {
		t.Errorf("bearer remove admin password: %d", s)
	}
	if s := w.anon().post(AU+"/"+uid+"/invite", map[string]any{}).Status; s != 401 {
		t.Errorf("anonymous invite: %d", s)
	}
}

func TestTagsAPI(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	strs := func(m map[string]any) []string {
		var out []string
		l, ok := m["tags"].([]any)
		if !ok {
			t.Fatalf("tags is not a list: %v", m["tags"])
		}
		for _, v := range l {
			out = append(out, v.(string))
		}
		return out
	}

	// users: create, update, get, list, validation
	r := ad.post(AU, map[string]any{"given_name": "T", "username": "tagme", "email": "tagme@x.example", "tags": []string{"b", "dept:finance", "b"}})
	want(t, r, 201)
	if got := strs(r.JSON); !slices.Equal(got, []string{"b", "dept:finance"}) {
		t.Fatalf("create tags %v", got)
	}
	id := r.str("id")
	r = ad.post(AU, map[string]any{"given_name": "T", "username": "plain", "email": "plain@x.example"})
	want(t, r, 201)
	if got := strs(r.JSON); len(got) != 0 {
		t.Fatalf("untagged user tags %v", got)
	}
	other := r.str("id")
	wantField(t, ad.patch(AU+"/"+id, map[string]any{"tags": []string{"x y"}}), 422, "tags")
	wantField(t, ad.post(AU, map[string]any{"given_name": "T", "username": "bad", "email": "bad@x.example", "tags": []string{"-nope"}}), 422, "tags")
	r = ad.patch(AU+"/"+id, map[string]any{"tags": []string{"sales", "dept:finance"}})
	want(t, r, 200)
	if got := strs(r.JSON); !slices.Equal(got, []string{"dept:finance", "sales"}) {
		t.Fatalf("update tags %v", got)
	}
	// untouched by an update without tags
	r = ad.patch(AU+"/"+id, map[string]any{"family_name": "x"})
	if got := strs(r.JSON); len(got) != 2 {
		t.Fatalf("tags lost: %v", got)
	}
	r = ad.get(AU + "/" + id)
	if got := strs(r.JSON); len(got) != 2 {
		t.Fatalf("get tags %v", got)
	}
	// ?tag filter: exact match, combines with paging, search finds tags
	r = ad.get(AU + "?tag=sales")
	want(t, r, 200)
	if r.total() != 1 || r.items()[0].(map[string]any)["id"] != id {
		t.Fatalf("tag filter: %s", r.Raw)
	}
	if r = ad.get(AU + "?tag=sale"); r.total() != 0 {
		t.Fatalf("tag filter must be exact: %s", r.Raw)
	}
	if r = ad.get(AU + "?tag=" + url.QueryEscape("dept:finance") + "&limit=1"); r.total() != 1 || len(r.items()) != 1 {
		t.Fatalf("namespaced tag: %s", r.Raw)
	}
	if r = ad.get(AU + "?q=dept:fin"); r.total() != 1 {
		t.Fatalf("search by tag: %s", r.Raw)
	}
	if r = ad.get(AU + "?tag=sales&offset=1"); r.total() != 1 || len(r.items()) != 0 {
		t.Fatalf("offset past the matches: %s", r.Raw)
	}
	// clear
	r = ad.patch(AU+"/"+other, map[string]any{"tags": []string{}})
	want(t, r, 200)
	// a manager may tag a plain user
	if r = w.as("manager").patch(AU+"/"+other, map[string]any{"tags": []string{"by-manager"}}); r.Status != 200 {
		t.Fatalf("manager tag: %d %s", r.Status, r.Raw)
	}

	// groups
	r = ad.post(A+"/groups", map[string]any{"display_name": "Tagged", "tags": []string{"team:b", "team:a"}})
	want(t, r, 201)
	if got := strs(r.JSON); !slices.Equal(got, []string{"team:a", "team:b"}) {
		t.Fatalf("group create tags %v", got)
	}
	gid := r.str("id")
	wantField(t, ad.patch(A+"/groups/"+gid, map[string]any{"tags": []string{"a b"}}), 422, "tags")
	r = ad.patch(A+"/groups/"+gid, map[string]any{"tags": []string{"only"}})
	want(t, r, 200)
	if got := strs(r.JSON); !slices.Equal(got, []string{"only"}) {
		t.Fatalf("group update tags %v", got)
	}
	r = ad.get(A + "/groups/" + gid)
	if got := strs(r.JSON); !slices.Equal(got, []string{"only"}) {
		t.Fatalf("group get tags %v", got)
	}
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "Untagged"}), 201)
	r = ad.get(A + "/groups?sort=display_name")
	for _, it := range r.items() {
		strs(it.(map[string]any)) // never null
	}
	if ad.get(A+"/groups?q=only").total() != 1 {
		t.Fatal("group search by tag")
	}
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
		if r := ad.post(AU, map[string]any{"given_name": "T", "email": "rm-" + f + "@x.example", f: v}); r.Status != 400 && r.Status != 422 {
			t.Errorf("create with %s: %d %s", f, r.Status, r.Raw)
		}
		if r := ad.patch(AU+"/"+w.users["user"].ID, map[string]any{f: v}); r.Status != 400 && r.Status != 422 {
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

func TestClientListFieldsRoundTrip(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	A := "/api/orgs/acme"
	body := map[string]any{"name": "Lists", "redirect_uris": []string{"https://a.example/cb", " ", "com.example.app:/callback", "https://a.example/cb2"},
		"post_logout_redirect_uris": []string{"https://a.example/bye", "https://a.example/bye2"},
		"backchannel_logout_uri":    "https://a.example/logout",
		"scopes":                    []string{"openid", "email", "orders:read", "billing.write"}}
	c := ad.post(A+"/clients", body)
	want(t, c, 201)
	got := ad.get(A + "/clients/" + c.str("id"))
	for k, wantJSON := range map[string]string{
		"redirect_uris":             `["https://a.example/cb","com.example.app:/callback","https://a.example/cb2"]`,
		"post_logout_redirect_uris": `["https://a.example/bye","https://a.example/bye2"]`,
		"scopes":                    `["openid","email","orders:read","billing.write"]`,
	} {
		b, _ := json.Marshal(got.JSON[k])
		if string(b) != wantJSON {
			t.Errorf("%s = %s, want %s", k, b, wantJSON)
		}
	}
	if got.str("backchannel_logout_uri") != "https://a.example/logout" {
		t.Errorf("backchannel: %s", got.Raw)
	}
	// a bad row is reported on its field with the offending value first; nothing is stored
	r := ad.patch(A+"/clients/"+c.str("id"), map[string]any{"redirect_uris": []string{"https://a.example/cb", "http://nope.example/cb"}})
	wantField(t, r, 422, "redirect_uris")
	if !strings.HasPrefix(r.str("error"), "http://nope.example/cb ") {
		t.Errorf("message should start with the value: %s", r.Raw)
	}
	wantField(t, ad.patch(A+"/clients/"+c.str("id"), map[string]any{"scopes": []string{"openid", "bad scope"}}), 422, "scopes")
	if g := ad.get(A + "/clients/" + c.str("id")); len(g.JSON["redirect_uris"].([]any)) != 3 {
		t.Errorf("failed update changed the client: %s", g.Raw)
	}
}

func TestTenantAccessAPI(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	made := ad.post(A+"/tenants", map[string]any{"name": "staff", "display_name": "Staff"})
	want(t, made, 201)
	if set, _ := made.JSON["settings"].(map[string]any); set["members_only"] != true {
		t.Fatalf("a new tenant is members-only: %s", made.Raw)
	}
	T := A + "/tenants/" + made.str("id") + "/access"
	cl := ad.post(A+"/clients", map[string]any{"name": "app", "tenant_id": made.str("id"), "redirect_uris": []string{"https://app.example/cb"}})
	want(t, cl, 201)
	alan := w.users["user"]

	r := ad.post(T, map[string]any{"subject_type": "user", "subject_id": alan.ID, "roles": []string{"editor"}, "tags": []string{"t1"},
		"all_clients": false, "clients": []string{cl.str("id")}, "expires": "2099-01-01"})
	want(t, r, 201)
	if r.str("name") == "" || r.str("detail") != alan.Email || r.JSON["all_clients"] != false || r.JSON["expired"] != false ||
		!strings.HasPrefix(r.str("expires"), "2099-01-01T00:00:00") {
		t.Fatalf("add: %s", r.Raw)
	}
	aid := r.str("id")
	want(t, ad.post(T, map[string]any{"subject_type": "user", "subject_id": alan.ID}), 409)
	want(t, ad.post(T, map[string]any{"subject_type": "user", "subject_id": w.users["other"].ID}), 422)

	r = ad.get(T + "?q=" + url.QueryEscape(alan.Email))
	want(t, r, 200)
	if r.total() != 1 {
		t.Fatalf("search: %s", r.Raw)
	}
	r = ad.patch(T+"/"+aid, map[string]any{"all_clients": true, "expires": ""})
	want(t, r, 200)
	if r.JSON["all_clients"] != true || r.JSON["expires"] != nil {
		t.Fatalf("update: %s", r.Raw)
	}
	want(t, ad.get(T+"/"+aid), 200)

	// managers, users and other organizations cannot see or change access
	for _, who := range []string{"manager", "user"} {
		want(t, w.as(who).get(T), 404)
		want(t, w.as(who).post(T, map[string]any{"subject_type": "user", "subject_id": alan.ID}), 404)
	}
	want(t, w.as("other").get(T), 404)

	want(t, ad.delete(T+"/"+aid), 200)
	want(t, ad.get(T+"/"+aid), 404)
	if r := ad.get(T); r.total() != 0 {
		t.Fatalf("after delete: %s", r.Raw)
	}
}

// Without an SMTP server nothing offers to email: the user dialog says a link will be shown, the invitation dialog has
// no "Send by email", and asking the API to email an invitation still returns the link with a note.
func TestEmailOffersFollowSMTP(t *testing.T) {
	page := func(w *world) string {
		req, _ := http.NewRequest("GET", w.env.URL+"/admin/orgs/acme/users", nil)
		res, err := w.as("admin").c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	off := newWorld(t)
	b := page(off)
	if strings.Contains(b, "Email the invitation") || strings.Contains(b, "Send by email") || !strings.Contains(b, `data-mail="0"`) ||
		!strings.Contains(b, "email is not set up on this server") {
		t.Error("mail off: the page still offers email")
	}
	r := off.as("admin").post(A+"/users/"+off.users["user"].ID+"/invite", map[string]any{"email": true})
	want(t, r, 200)
	if r.str("url") == "" || r.JSON["emailed"] != false || !strings.Contains(r.str("email_warning"), "not configured") {
		t.Errorf("mail off invite: %s", r.Raw)
	}

	on := newWorldWith(t, func(c *config.Config) { c.Mail.SMTPHost = "mail.example" })
	b = page(on)
	if !strings.Contains(b, "Email the invitation") || !strings.Contains(b, "Send by email") || !strings.Contains(b, `data-mail="1"`) {
		t.Error("mail on: the page does not offer email")
	}
}

func TestClientRequirePKCE(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	r := ad.post(A+"/clients", map[string]any{"name": "Legacy", "redirect_uris": []string{"https://l.example/cb"}, "require_pkce": false})
	want(t, r, 201)
	if r.JSON["require_pkce"] != false || r.str("secret") == "" {
		t.Fatalf("create: %s", r.Raw)
	}
	id := r.str("id")
	if g := ad.get(A + "/clients/" + id); g.JSON["require_pkce"] != false {
		t.Fatalf("get: %s", g.Raw)
	}
	if p := ad.patch(A+"/clients/"+id, map[string]any{"require_pkce": true}); p.JSON["require_pkce"] != true {
		t.Fatalf("patch: %s", p.Raw)
	}
	r = ad.post(A+"/clients", map[string]any{"name": "Default", "redirect_uris": []string{"https://d.example/cb"}})
	if r.JSON["require_pkce"] != true {
		t.Fatalf("default: %s", r.Raw)
	}
	want(t, ad.post(A+"/clients", map[string]any{"name": "SPA", "redirect_uris": []string{"https://s.example/cb"},
		"token_endpoint_auth_method": "none", "require_pkce": false}), 422)
}

// The console needs a session that used a second factor, whatever the organization requires: a password-only (or
// provider-only) sign-in of a manager or administrator is refused, pages and API alike.
func TestConsoleNeedsSecondFactor(t *testing.T) {
	w := newWorld(t)
	for _, who := range []string{"admin", "manager", "super"} {
		c := w.asSingleFactor(who)
		r := c.get(A + "/users")
		if r.Status != 403 || r.str("field") != "mfa" {
			t.Errorf("%s API: %d %s", who, r.Status, r.Raw)
		}
		req, _ := http.NewRequest("GET", w.env.URL+"/admin/orgs/acme/users", nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 403 || !strings.Contains(string(b), "second factor") {
			t.Errorf("%s page: %d", who, res.StatusCode)
		}
	}
	// a plain user's account page is not the console
	c := w.asSingleFactor("user")
	req, _ := http.NewRequest("GET", w.env.URL+"/admin/orgs/acme/users", nil)
	if res, _ := c.c.Do(req); res.StatusCode != 403 {
		t.Errorf("user: %d", res.StatusCode)
	}
	want(t, w.as("admin").get(A+"/users"), 200)
}

// Dangerous changes need a recent re-authentication of the browser session (403 with field "reauth" otherwise, which
// the console answers with its dialog), and an API token can never make them.
func TestDangerousChangesNeedStepUp(t *testing.T) {
	w := newWorld(t)
	w.mod.RotateKeys = func(context.Context) error { return nil }
	w.mod.RemoveKey = func(context.Context, string) error { return nil }
	fresh := false
	w.env.Server.Reauthed = func(*http.Request) bool { return fresh }
	su, tok := w.as("super"), w.withBearer("super", "admin")
	primary, _ := w.env.Svc.PrimaryOrg(context.Background())
	settings := primary.Settings
	settings.SessionIdle = 600
	victim := w.users["manager"].ID
	for name, call := range map[string]func(c *caller) resp{
		"delete an organization":        func(c *caller) resp { return c.delete("/api/orgs/globex?cascade=1") },
		"rotate the signing keys":       func(c *caller) resp { return c.post("/api/keys/rotate", nil) },
		"remove a signing key":          func(c *caller) resp { return c.delete("/api/keys/old") },
		"primary org sign-in settings":  func(c *caller) resp { return c.patch("/api/orgs/primary", map[string]any{"settings": settings}) },
		"make someone an administrator": func(c *caller) resp { return c.patch(AU+"/"+victim, map[string]any{"role": "admin"}) },
		"create an administrator": func(c *caller) resp {
			return c.post(AU, map[string]any{"username": "boss", "email": "boss@x.example", "given_name": "B", "role": "admin"})
		},
		"remove another user's password": func(c *caller) resp { return c.delete(AU + "/" + victim + "/password") },
		"sign an organization out": func(c *caller) resp {
			return c.post("/api/orgs/acme/sign-out", map[string]any{"reason": "test"})
		},
		"sign the server out": func(c *caller) resp { return c.post("/api/sign-out", map[string]any{"reason": "test"}) },
		"lock a user out": func(c *caller) resp {
			return c.post(AU+"/"+w.users["user"].ID+"/lock-out", map[string]any{"reason": "test"})
		},
	} {
		fresh = false
		if r := call(su); r.Status != 403 || r.str("field") != "reauth" {
			t.Errorf("%s without re-authentication: %d %s", name, r.Status, r.Raw)
		}
		if r := call(tok); r.Status != 403 {
			t.Errorf("%s with an API token: %d %s", name, r.Status, r.Raw)
		}
		fresh = true
		if r := call(su); r.Status/100 != 2 {
			t.Errorf("%s after re-authentication: %d %s", name, r.Status, r.Raw)
		}
	}
	// ordinary changes need none
	fresh = false
	want(t, su.patch("/api/orgs/acme", map[string]any{"display_name": "Acme Ltd"}), 200)
}

// A tenant is addressed by its id or by its name (the console shows and links by name); another organization's
// tenant name never resolves.
func TestTenantByName(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	T := A + "/tenants"
	r := ad.post(T, map[string]any{"name": "mcp", "display_name": "MCP", "resources": []string{"https://mcp.example.com/mcp"},
		"settings": map[string]any{"password_login": true, "passkey_login": true, "all_providers": true, "self_registration": true}})
	want(t, r, 201)
	id := r.str("id")
	byName := ad.get(T + "/mcp")
	want(t, byName, 200)
	if byName.str("id") != id {
		t.Fatalf("by name: %s", byName.Raw)
	}
	want(t, ad.patch(T+"/mcp", map[string]any{"display_name": "MCP servers"}), 200)
	want(t, ad.get(T+"/mcp/self-registered"), 200)
	want(t, ad.get(T+"/no-such-tenant"), 404)
	want(t, w.as("other").get(G+"/tenants/mcp"), 404) // globex has no tenant named mcp
	want(t, w.as("other").get(A+"/tenants/mcp"), 404) // and acme's is not theirs
}
