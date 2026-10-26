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

	// Guards through SCIM: a super admin cannot curb themselves, and only a super admin curbs a super admin.
	for name, r := range map[string]resp{
		"delete self":                  e.do("DELETE", "/scim/v2/primary/Users/"+e.Admin.ID, e.super, nil),
		"disable self":                 e.do("PATCH", "/scim/v2/primary/Users/"+e.Admin.ID, e.super, patchBody(op("replace", "active", false))),
		"demote self":                  e.do("PATCH", "/scim/v2/primary/Users/"+e.Admin.ID, e.super, patchBody(op("replace", quisoraURN+":role", "user"))),
		"admin deletes a super admin":  e.do("DELETE", "/scim/v2/primary/Users/"+super2.ID, e.admA, nil),
		"admin disables a super admin": e.do("PATCH", "/scim/v2/primary/Users/"+super2.ID, e.admA, patchBody(op("replace", "active", false))),
	} {
		if r.Status < 400 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
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

// An administrator role is granted in the admin console after a re-authentication, never with a token (as the
// management API): not by creating a user, nor by changing one's role. Role changes downwards go through the service
// guards.
func TestSuperAdminRoleThroughSCIM(t *testing.T) {
	e := newEnv(t)
	for _, role := range []string{"admin", "super_admin"} {
		if r := e.createUser("primary", e.super, map[string]any{"userName": "new-" + role, quisoraURN: map[string]any{"role": role}}); r.Status != 403 {
			t.Errorf("%s through SCIM: %d %s", role, r.Status, r.Raw)
		}
	}
	r := e.createUser("primary", e.super, map[string]any{"userName": "plain"})
	if p := e.do("PATCH", "/scim/v2/primary/Users/"+r.str("id"), e.super, patchBody(op("replace", quisoraURN+":role", "admin"))); p.Status != 403 {
		t.Errorf("promotion to admin through SCIM: %d %s", p.Status, p.Raw)
	}
	id := e.mkUser(e.primary(), "sa2", model.RoleSuperAdmin).ID
	if p := e.do("PATCH", "/scim/v2/primary/Users/"+id, e.admA, patchBody(op("replace", quisoraURN+":role", "user"))); p.Status != 404 {
		t.Errorf("other org's admin patching primary: %d", p.Status)
	}
	if p := e.do("PATCH", "/scim/v2/primary/Users/"+id, e.super, patchBody(op("replace", quisoraURN+":role", "user"))); p.Status != 200 || p.str(quisoraURN, "role") != "user" {
		t.Errorf("demote: %d %s", p.Status, p.Raw)
	}
	// The token's owner cannot disable itself.
	if p := e.do("PATCH", "/scim/v2/primary/Users/"+e.Admin.ID, e.super, patchBody(op("replace", "active", false))); p.Status != 400 {
		t.Errorf("self-disable: %d %s", p.Status, p.Raw)
	}
}
