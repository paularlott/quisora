package admin_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Who sees whom, in the primary organization (where super admins are): a manager sees an administrator as a directory
// entry (name, role, status) and no super admin at all; an administrator sees no super admin; a super admin sees
// everyone. Nothing hidden leaks through a total, a search, a tag filter, a group's members or a tenant's access list.
func TestVisibility(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	primary, _ := w.env.Svc.PrimaryOrg(ctx)
	sys := service.System
	mk := func(name, given string, role model.Role, tags ...string) *model.User {
		u, err := w.env.Svc.CreateUser(ctx, sys, primary.ID, service.UserInput{GivenName: ptr(given), Username: ptr(name),
			Email: ptr(name + "@p.example"), Role: &role, Password: ptr("correct horse battery"), Tags: &tags,
			Phone: ptr("+441234567890")})
		if err != nil {
			t.Fatal(err)
		}
		w.users[name] = u
		return u
	}
	mk("pmgr", "Mona", model.RoleManager)
	boss := mk("boss", "Pat", model.RoleAdmin, "vip")
	pu := mk("pu", "Uma", model.RoleUser, "vip")
	super := w.env.Admin
	g, err := w.env.Svc.CreateGroup(ctx, sys, primary.ID, service.GroupInput{DisplayName: ptr("Everyone")})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{super.ID, boss.ID, pu.ID} {
		if err := w.env.Svc.SetMembership(ctx, sys, g.ID, id, true); err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := w.env.Svc.Tenants.GetByUnique(ctx, model.TenantNameKey(primary.ID, model.DefaultTenantName))
	if err != nil {
		t.Fatal(err)
	}
	superAccess, err := w.env.Svc.AddAccess(ctx, sys, tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: super.ID})
	if err != nil {
		t.Fatal(err)
	}
	api := "/api/orgs/" + primary.Name
	rows := func(c *caller, query string) (map[string]map[string]any, resp) {
		r := c.get(api + "/users?limit=100" + query)
		want(t, r, 200)
		out := map[string]map[string]any{}
		for _, it := range r.items() {
			row := it.(map[string]any)
			out[row["id"].(string)] = row
		}
		if r.total() != len(out) {
			t.Errorf("%s: total %d for %d rows", query, r.total(), len(out))
		}
		return out, r
	}

	// a manager
	mgr := w.as("pmgr")
	list, _ := rows(mgr, "")
	if list[super.ID] != nil {
		t.Error("manager: a super admin is listed")
	}
	if b := list[boss.ID]; b == nil || b["directory"] != true || b["email"] != "" || b["username"] != "" || b["name"] != "Pat" ||
		b["phone_number"] != nil || len(b["tags"].([]any)) != 0 {
		t.Errorf("manager: the administrator's row: %v", list[boss.ID])
	}
	if p := list[pu.ID]; p == nil || p["directory"] != nil || p["email"] != "pu@p.example" {
		t.Errorf("manager: a user's row: %v", p)
	}
	want(t, mgr.get(api+"/users/"+super.ID), 404)
	want(t, mgr.delete(api+"/users/"+super.ID+"/sessions"), 404) // not 403: nothing to confirm it exists
	r := mgr.get(api + "/users/" + boss.ID)
	want(t, r, 200)
	if r.JSON["directory"] != true || r.JSON["email"] != "" || r.JSON["groups"] != nil || r.JSON["passkeys"] != nil ||
		r.JSON["linked_emails"] == nil || len(r.JSON["linked_emails"].([]any)) != 0 {
		t.Errorf("manager: the administrator: %s", r.Raw)
	}
	if found, _ := rows(mgr, "&q="+url.QueryEscape("boss@")); found[boss.ID] != nil {
		t.Error("manager: a search by the administrator's address finds them")
	}
	if found, _ := rows(mgr, "&q=Pat"); found[boss.ID] == nil {
		t.Error("manager: a search by the administrator's name does not find them")
	}
	if found, _ := rows(mgr, "&tag=vip"); found[boss.ID] != nil || found[pu.ID] == nil {
		t.Errorf("manager: tag filter: %v", found)
	}
	if found, _ := rows(mgr, "&sort=username&desc=1"); found[boss.ID] == nil || found[super.ID] != nil {
		t.Errorf("manager: sorted by username: %v", found)
	}
	members := mgr.get(api + "/groups/" + g.ID + "/members")
	want(t, members, 200)
	if members.total() != 2 || strings.Contains(string(members.Raw), super.ID) || strings.Contains(string(members.Raw), "boss@p.example") {
		t.Errorf("manager: group members: %s", members.Raw)
	}
	if gr := mgr.get(api + "/groups/" + g.ID); gr.JSON["members"] != float64(2) {
		t.Errorf("manager: member count %v", gr.JSON["members"])
	}

	// an administrator
	adm := w.as("boss")
	list, _ = rows(adm, "")
	if list[super.ID] != nil || list[boss.ID] == nil || list[w.users["pmgr"].ID]["email"] != "pmgr@p.example" {
		t.Errorf("administrator: listed %v", list)
	}
	want(t, adm.get(api+"/users/"+super.ID), 404)
	if gr := adm.get(api + "/groups/" + g.ID); gr.JSON["members"] != float64(2) {
		t.Errorf("administrator: member count %v", gr.JSON["members"])
	}
	acc := adm.get(api + "/tenants/" + tenant.ID + "/access?limit=100")
	want(t, acc, 200)
	if strings.Contains(string(acc.Raw), super.ID) {
		t.Errorf("administrator: a super admin's access is listed: %s", acc.Raw)
	}
	want(t, adm.get(api+"/tenants/"+tenant.ID+"/access/"+superAccess.ID), 404)
	want(t, adm.delete(api+"/tenants/"+tenant.ID+"/access/"+superAccess.ID), 404)
	wantField(t, adm.post(api+"/tenants/"+tenant.ID+"/access", map[string]any{"subject_type": "user", "subject_id": super.ID}), 422, "subject_id")
	want(t, adm.put(api+"/groups/"+g.ID+"/members/"+super.ID, nil), 404)

	// a super admin sees everyone
	list, _ = rows(w.as("super"), "")
	if list[super.ID] == nil || list[boss.ID]["email"] != "boss@p.example" {
		t.Errorf("super admin: listed %v", list)
	}
}

// The users list's role filter offers the viewer's own role and lower: super admin only to super admins on the primary
// organization.
func TestRoleFilterOptions(t *testing.T) {
	w := newWorld(t)
	page := func(c *caller, path string) string {
		r := c.do("GET", path, nil)
		want(t, r, 200)
		b := string(r.Raw)
		start := strings.Index(b, `id="filter-role"`)
		return b[start : start+strings.Index(b[start:], "</select>")]
	}
	for _, c := range []struct {
		who, path string
		want      []string
		not       []string
	}{
		{"manager", "/admin/orgs/acme/users", []string{`"user"`, `"manager"`}, []string{`"admin"`, `"super_admin"`}},
		{"admin", "/admin/orgs/acme/users", []string{`"user"`, `"manager"`, `"admin"`}, []string{`"super_admin"`}},
		{"super", "/admin/orgs/acme/users", []string{`"admin"`}, []string{`"super_admin"`}},
		{"super", "/admin/orgs/primary/users", []string{`"admin"`, `"super_admin"`}, nil},
	} {
		sel := page(w.as(c.who), c.path)
		for _, v := range c.want {
			if !strings.Contains(sel, `value=`+v) {
				t.Errorf("%s on %s: no %s option", c.who, c.path, v)
			}
		}
		for _, v := range c.not {
			if strings.Contains(sel, `value=`+v) {
				t.Errorf("%s on %s: %s offered", c.who, c.path, v)
			}
		}
	}
}
