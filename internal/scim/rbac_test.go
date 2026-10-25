package scim_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

func TestSCIMRBAC(t *testing.T) {
	e := newEnv(t)
	plain := e.mk("plain", nil)
	admUser := e.users["adm-a"]
	mgrUser := e.users["mgr-a"]
	bUser := e.mkUser(e.orgB, "b-plain", model.RoleUser)

	// Manager token: plain users only; of groups, only the membership of plain users.
	if r := e.createUser("acme", e.mgrA, map[string]any{"userName": "by-mgr"}); r.Status != 201 {
		t.Errorf("manager creates user: %d %s", r.Status, r.Raw)
	}
	for _, role := range []string{"manager", "admin", "super_admin"} {
		if r := e.createUser("acme", e.mgrA, map[string]any{"userName": "mgr-" + role, quisoraURN: map[string]any{"role": role}}); r.Status != 403 {
			t.Errorf("manager creates %s: %d", role, r.Status)
		}
	}
	if r := e.do("PATCH", "/scim/v2/acme/Users/"+plain, e.mgrA, patchBody(op("replace", "name.familyName", "by manager"))); r.Status != 200 {
		t.Errorf("manager patches plain: %d %s", r.Status, r.Raw)
	}
	if r := e.do("PATCH", "/scim/v2/acme/Users/"+plain, e.mgrA, patchBody(op("replace", quisoraURN+":role", "manager"))); r.Status != 403 {
		t.Errorf("manager promotes: %d %s", r.Status, r.Raw)
	}
	// An administrator does not exist for a manager's SCIM token (SCIM shows only users seen in full); another manager
	// is seen but cannot be changed.
	otherMgr := e.mkUser(e.orgA, "other-mgr", model.RoleManager)
	for name, c := range map[string]struct {
		u    *model.User
		want int
	}{"admin": {admUser, 404}, "manager": {otherMgr, 403}} {
		u := c.u
		if r := e.do("PATCH", "/scim/v2/acme/Users/"+u.ID, e.mgrA, patchBody(op("replace", "name.familyName", "x"))); r.Status != c.want {
			t.Errorf("manager patches %s: %d", name, r.Status)
		}
		if r := e.do("PUT", "/scim/v2/acme/Users/"+u.ID, e.mgrA, map[string]any{"userName": u.Username, "emails": mail(u.Email), "name": map[string]any{"givenName": "Changed"}}); r.Status != c.want {
			t.Errorf("manager puts %s: %d", name, r.Status)
		}
		if r := e.do("DELETE", "/scim/v2/acme/Users/"+u.ID, e.mgrA, nil); r.Status != c.want {
			t.Errorf("manager deletes %s: %d", name, r.Status)
		}
	}
	if r := e.do("GET", "/scim/v2/acme/Users/"+admUser.ID, e.mgrA, nil); r.Status != 404 {
		t.Errorf("manager reads admin: %d", r.Status)
	}
	if r := e.do("GET", "/scim/v2/acme/Groups", e.mgrA, nil); r.Status != 200 {
		t.Errorf("manager lists groups: %d", r.Status)
	}
	gid := e.group("rbac-group", plain)
	if r := e.do("POST", "/scim/v2/acme/Groups", e.mgrA, map[string]any{"displayName": "nope"}); r.Status != 403 {
		t.Errorf("manager creates group: %d", r.Status)
	}
	if r := e.do("PATCH", "/scim/v2/acme/Groups/"+gid, e.mgrA, patchBody(op("replace", "displayName", "renamed"))); r.Status != 403 {
		t.Errorf("manager renames group: %d", r.Status)
	}
	for _, u := range []string{admUser.ID, mgrUser.ID} {
		if r := e.do("PATCH", "/scim/v2/acme/Groups/"+gid, e.mgrA, patchBody(op("add", "members", []any{map[string]any{"value": u}}))); r.Status != 403 {
			t.Errorf("manager adds %s to group: %d %s", u, r.Status, r.Raw)
		}
	}
	if r := e.do("PATCH", "/scim/v2/acme/Groups/"+gid, e.mgrA, patchBody(op("remove", "members", nil))); r.Status != 200 {
		t.Errorf("manager removes plain users: %d %s", r.Status, r.Raw)
	}
	if r := e.do("PATCH", "/scim/v2/acme/Groups/"+gid, e.mgrA, patchBody(op("add", "members", []any{map[string]any{"value": plain}}))); r.Status != 200 {
		t.Errorf("manager adds a plain user: %d %s", r.Status, r.Raw)
	}
	if r := e.do("DELETE", "/scim/v2/acme/Groups/"+gid, e.mgrA, nil); r.Status != 403 {
		t.Errorf("manager deletes group: %d", r.Status)
	}
	if g := e.do("GET", "/scim/v2/acme/Groups/"+gid, e.admA, nil); len(g.list("members")) != 1 {
		t.Error("forbidden group patches changed the group")
	}
	// An administrator in a group does not stop a manager changing its plain users, and is never taken out by them:
	// a manager's token does not see the administrator, so removing every member it sees, or a PUT of the members
	// it sees, leaves them.
	mixed := e.group("rbac-mixed", plain, admUser.ID)
	if r := e.do("PATCH", "/scim/v2/acme/Groups/"+mixed, e.mgrA, patchBody(op("remove", "members", nil))); r.Status != 200 {
		t.Errorf("manager empties a group with an administrator: %d %s", r.Status, r.Raw)
	}
	plain2 := e.mk("plain2", nil)
	if r := e.do("PUT", "/scim/v2/acme/Groups/"+mixed, e.mgrA, map[string]any{"displayName": "rbac-mixed",
		"members": []any{map[string]any{"value": plain2}}}); r.Status != 200 {
		t.Errorf("manager puts a group with an administrator: %d %s", r.Status, r.Raw)
	}
	got := map[string]bool{}
	for _, m := range e.do("GET", "/scim/v2/acme/Groups/"+mixed, e.admA, nil).list("members") {
		got[m.(map[string]any)["value"].(string)] = true
	}
	if len(got) != 2 || !got[admUser.ID] || !got[plain2] {
		t.Errorf("members of the mixed group: %v", got)
	}
	if r := e.do("DELETE", "/scim/v2/acme/Users/"+plain, e.mgrA, nil); r.Status != 204 {
		t.Errorf("manager deletes plain: %d", r.Status)
	}

	// Admin token: full control of its org's users and managers; administrator roles are granted in the admin
	// console after a re-authentication, never with a token.
	if r := e.createUser("acme", e.admA, map[string]any{"userName": "by-adm-manager", quisoraURN: map[string]any{"role": "manager"}}); r.Status != 201 {
		t.Errorf("admin creates manager: %d %s", r.Status, r.Raw)
	}
	for _, role := range []string{"admin", "super_admin"} {
		if r := e.createUser("acme", e.admA, map[string]any{"userName": "by-adm-" + role, quisoraURN: map[string]any{"role": role}}); r.Status != 403 {
			t.Errorf("admin creates %s: %d", role, r.Status)
		}
	}
	super2 := e.mkUser(e.primary(), "super2", model.RoleSuperAdmin)
	// Another org, even when naming a real id: not found. Same answer as for an org that does not exist.
	for _, path := range []string{"/scim/v2/globex/Users", "/scim/v2/globex/Groups", "/scim/v2/primary/Users", "/scim/v2/nonexistent/Users",
		"/scim/v2/globex/Users/" + bUser.ID, "/scim/v2/primary/Users/" + super2.ID} {
		if r := e.do("GET", path, e.admA, nil); r.Status != 404 {
			t.Errorf("admin A GET %s: %d", path, r.Status)
		}
	}
	if r := e.do("POST", "/scim/v2/globex/Users", e.admA, map[string]any{"userName": "intruder"}); r.Status != 404 {
		t.Errorf("admin A creates in B: %d", r.Status)
	}
	if r := e.do("DELETE", "/scim/v2/globex/Users/"+bUser.ID, e.admA, nil); r.Status != 404 {
		t.Errorf("admin A deletes in B: %d", r.Status)
	}
	// The user's id under the wrong org of the same actor is not found either.
	if r := e.do("GET", "/scim/v2/acme/Users/"+bUser.ID, e.admA, nil); r.Status != 404 {
		t.Errorf("foreign id in own org: %d", r.Status)
	}
	if r := e.do("GET", "/scim/v2/globex/Users/"+bUser.ID, e.admB, nil); r.Status != 200 {
		t.Errorf("admin B reads own: %d", r.Status)
	}
	// Super admins can work in every org but not read an org's user through another org's URL, and they are
	// the only ones that can touch super admins.
	for _, path := range []string{"/scim/v2/acme/Users", "/scim/v2/globex/Users", "/scim/v2/primary/Users", "/scim/v2/acme/Groups"} {
		if r := e.do("GET", path, e.super, nil); r.Status != 200 {
			t.Errorf("super GET %s: %d", path, r.Status)
		}
	}
	if r := e.do("GET", "/scim/v2/acme/Users/"+bUser.ID, e.super, nil); r.Status != 404 {
		t.Errorf("super reading B's user via acme: %d", r.Status)
	}
	if r := e.do("PATCH", "/scim/v2/primary/Users/"+super2.ID, e.super, patchBody(op("replace", "displayName", "boss"))); r.Status != 200 {
		t.Errorf("super patches super: %d", r.Status)
	}
	if r := e.createUser("globex", e.super, map[string]any{"userName": "made-by-super"}); r.Status != 201 {
		t.Errorf("super creates in B: %d", r.Status)
	}

	// Guards through SCIM: the super admins the server keeps (two here, as in a gossip cluster), self.
	e.Svc.MinSuperAdmins = 2
	if r := e.do("DELETE", "/scim/v2/primary/Users/"+super2.ID, e.super, nil); r.Status != 409 {
		t.Errorf("delete a super admin the server needs: %d %s", r.Status, r.Raw)
	}
	if r := e.do("PATCH", "/scim/v2/primary/Users/"+super2.ID, e.super, patchBody(op("replace", "active", false))); r.Status != 409 {
		t.Errorf("disable a super admin the server needs: %d %s", r.Status, r.Raw)
	}
	if r := e.do("PATCH", "/scim/v2/primary/Users/"+super2.ID, e.super, patchBody(op("replace", quisoraURN+":role", "user"))); r.Status != 409 {
		t.Errorf("demote a super admin the server needs: %d %s", r.Status, r.Raw)
	}
	e.Svc.MinSuperAdmins = 0
	// an organization's last administrator is not guarded: super admins administer every organization
	if r := e.do("PATCH", "/scim/v2/globex/Users/"+e.users["adm-b"].ID, e.super, patchBody(op("replace", "active", false))); r.Status != 200 {
		t.Errorf("disable an organization's last admin: %d %s", r.Status, r.Raw)
	}
	if r := e.do("DELETE", "/scim/v2/acme/Users/"+admUser.ID, e.admA, nil); r.Status != 400 {
		t.Errorf("delete self: %d %s", r.Status, r.Raw)
	}
	if r := e.do("PATCH", "/scim/v2/acme/Users/"+admUser.ID, e.admA, patchBody(op("replace", "active", false))); r.Status != 400 {
		t.Errorf("disable self: %d %s", r.Status, r.Raw)
	}
	if r := e.do("PATCH", "/scim/v2/acme/Users/"+admUser.ID, e.admA, patchBody(op("replace", quisoraURN+":role", "user"))); r.Status != 400 {
		t.Errorf("demote self: %d %s", r.Status, r.Raw)
	}
	// Editing one's own profile through SCIM works for the fields that are allowed.
	if r := e.do("PATCH", "/scim/v2/acme/Users/"+mgrUser.ID, e.mgrA, patchBody(op("replace", "displayName", "me"))); r.Status != 200 {
		t.Errorf("manager edits self: %d %s", r.Status, r.Raw)
	}
	// Disabling a user ends their API tokens' validity.
	victim := e.mkUser(e.orgA, "victim", model.RoleManager)
	vt := e.token(victim, "scim")
	if r := e.do("GET", "/scim/v2/acme/Users", vt, nil); r.Status != 200 {
		t.Fatal(r.Status)
	}
	e.do("PATCH", "/scim/v2/acme/Users/"+victim.ID, e.admA, patchBody(op("replace", "active", false)))
	if r := e.do("GET", "/scim/v2/acme/Users", vt, nil); r.Status != 401 {
		t.Errorf("token of disabled user: %d", r.Status)
	}
}

func (e *env) primary() *model.Org { return e.Env.Primary }

func TestOrganizationsResource(t *testing.T) {
	e := newEnv(t)
	// Super admins only.
	for _, tok := range []string{e.admA, e.mgrA, e.admB} {
		if r := e.do("GET", "/scim/v2/Organizations", tok, nil); r.Status != 403 {
			t.Errorf("non-super list: %d", r.Status)
		}
		if r := e.do("POST", "/scim/v2/Organizations", tok, map[string]any{"name": "sneaky"}); r.Status != 403 {
			t.Errorf("non-super create: %d", r.Status)
		}
		if r := e.do("DELETE", "/scim/v2/Organizations/"+e.orgB.ID, tok, nil); r.Status != 403 {
			t.Errorf("non-super delete: %d", r.Status)
		}
	}
	if r := e.do("GET", "/scim/v2/Organizations", "", nil); r.Status != 401 {
		t.Errorf("anonymous: %d", r.Status)
	}
	// List, filter, sort.
	r := e.do("GET", "/scim/v2/Organizations?sortBy=name", e.super, nil)
	if r.Status != 200 || r.total() != 3 || !slicesEqual(r.names("name"), []string{"acme", "globex", "primary"}) {
		t.Errorf("list: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/Organizations?filter="+qs(`name eq "GLOBEX"`), e.super, nil); r.total() != 1 {
		t.Errorf("filter eq: %s", r.Raw)
	}
	if r := e.do("GET", "/scim/v2/Organizations?filter="+qs(`primary eq true`), e.super, nil); r.total() != 1 || r.names("name")[0] != "primary" {
		t.Errorf("filter primary: %s", r.Raw)
	}
	if r := e.do("GET", "/scim/v2/Organizations?count=1&startIndex=2&sortBy=name", e.super, nil); r.total() != 3 || r.names("name")[0] != "globex" {
		t.Errorf("paging: %s", r.Raw)
	}
	// Create.
	c := e.do("POST", "/scim/v2/Organizations", e.super, map[string]any{"schemas": []string{schemaOrgURN}, "name": "initech", "displayName": "Initech",
		"settings": map[string]any{"requireMfa": true, "sessionTtl": 3600}})
	if c.Status != 201 || c.str("name") != "initech" || c.str("meta", "resourceType") != "Organization" || c.Header.Get("ETag") == "" ||
		c.Header.Get("Location") != e.URL+"/scim/v2/Organizations/"+c.str("id") {
		t.Fatalf("create: %d %v %s", c.Status, c.Header, c.Raw)
	}
	st := c.Body["settings"].(map[string]any)
	if st["requireMfa"] != true || st["sessionTtl"].(float64) != 3600 || st["passwordLogin"] != true {
		t.Errorf("settings: %v", st)
	}
	id := c.str("id")
	o, err := e.Svc.OrgByName(e.ctx, "initech")
	if err != nil || o.ID != id || !o.Settings.RequireMFA {
		t.Errorf("stored org: %v", err)
	}
	// Errors.
	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		typ    string
	}{
		"duplicate":  {map[string]any{"name": "acme"}, 409, "uniqueness"},
		"reserved":   {map[string]any{"name": "admin"}, 400, "invalidValue"},
		"bad name":   {map[string]any{"name": "Has Space"}, 400, "invalidValue"},
		"no name":    {map[string]any{"displayName": "x"}, 400, "invalidValue"},
		"bad ttl":    {map[string]any{"name": "ttl", "settings": map[string]any{"sessionTtl": -5}}, 400, "invalidValue"},
		"ttl string": {map[string]any{"name": "ttl2", "settings": map[string]any{"sessionTtl": "soon"}}, 400, "invalidValue"},
	} {
		if r := e.do("POST", "/scim/v2/Organizations", e.super, tc.body); r.Status != tc.status || r.str("scimType") != tc.typ {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	// GET, PATCH, PUT.
	if g := e.do("GET", "/scim/v2/Organizations/"+id, e.super, nil); g.Status != 200 || g.str("displayName") != "Initech" {
		t.Errorf("get: %s", g.Raw)
	}
	if e.do("GET", "/scim/v2/Organizations/nope", e.super, nil).Status != 404 {
		t.Error("unknown org")
	}
	p := e.do("PATCH", "/scim/v2/Organizations/"+id, e.super, patchBody(op("replace", "displayName", "Initech Inc"), op("replace", "settings.passkeyLogin", false),
		op("replace", "primary", true), op("replace", "settings.sessionIdle", 120)))
	if p.Status != 200 || p.str("displayName") != "Initech Inc" || p.Body["primary"] != false ||
		p.Body["settings"].(map[string]any)["passkeyLogin"] != false || p.Body["settings"].(map[string]any)["sessionIdle"].(float64) != 120 {
		t.Errorf("patch: %d %s", p.Status, p.Raw)
	}
	if p := e.do("PATCH", "/scim/v2/Organizations/"+id, e.super, patchBody(op("replace", "name", "admin"))); p.Status != 400 {
		t.Errorf("patch reserved: %d", p.Status)
	}
	if p := e.do("PATCH", "/scim/v2/Organizations/"+id, e.super, patchBody(op("replace", "name", "acme"))); p.Status != 409 {
		t.Errorf("patch clash: %d", p.Status)
	}
	put := e.do("PUT", "/scim/v2/Organizations/"+id, e.super, map[string]any{"name": "initech-2", "displayName": "Initech 2"})
	if put.Status != 200 || put.str("name") != "initech-2" || put.Body["settings"].(map[string]any)["passkeyLogin"] != false {
		t.Errorf("put: %d %s", put.Status, put.Raw)
	}
	// The renamed org's SCIM endpoint follows the name.
	if r := e.do("GET", "/scim/v2/initech-2/Users", e.super, nil); r.Status != 200 {
		t.Errorf("renamed org endpoint: %d", r.Status)
	}
	// Deleting an organization takes a super admin's re-authentication in the admin console, as in the management
	// API: a token cannot, empty or not, cascading or not (deletion itself is tested in the service).
	for _, q := range []string{"", "?cascade=true"} {
		if r := e.do("DELETE", "/scim/v2/Organizations/"+e.orgA.ID+q, e.super, nil); r.Status != 403 {
			t.Errorf("delete%s: %d %s", q, r.Status, r.Raw)
		}
	}
	if r := e.do("DELETE", "/scim/v2/Organizations/"+id, e.super, nil); r.Status != 403 {
		t.Errorf("delete empty: %d", r.Status)
	}
	if _, err := e.Svc.Orgs.Get(e.ctx, e.orgA.ID); err != nil {
		t.Errorf("organization deleted through SCIM: %v", err)
	}
	if r := e.do("PUT", "/scim/v2/Organizations", e.super, nil); r.Status != 405 {
		t.Errorf("PUT collection: %d", r.Status)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
