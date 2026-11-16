package service_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestTenantAccessLifecycle(t *testing.T) {
	c := newCast(t)
	admin := actor(c.aAdmin)
	def, _ := c.svc.DefaultTenant(c.ctx, c.a.ID)
	if def.Settings.MembersOnly {
		t.Fatal("the default tenant must be open to everyone")
	}
	ten, err := c.svc.CreateTenant(c.ctx, admin, c.a.ID, service.TenantInput{Name: ptr("staff")})
	if err != nil || !ten.Settings.MembersOnly {
		t.Fatalf("a new tenant is members-only: %v %+v", err, ten)
	}
	cl, _, err := c.svc.CreateClient(c.ctx, admin, c.a.ID, service.ClientInput{Name: ptr("app"), TenantID: &ten.ID,
		RedirectURIs: ptr([]string{"https://app.example/cb"})})
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := c.svc.CreateClient(c.ctx, admin, c.a.ID, service.ClientInput{Name: ptr("elsewhere"),
		RedirectURIs: ptr([]string{"https://else.example/cb"})}) // in the default tenant
	g, err := c.svc.CreateGroup(c.ctx, admin, c.a.ID, service.GroupInput{DisplayName: ptr("Ops")})
	if err != nil {
		t.Fatal(err)
	}
	// a group of another organization never gets access here, so its members (whoever adds them, a provisioning
	// client included) never reach this tenant through it
	bg, err := c.svc.CreateGroup(c.ctx, service.System, c.b.ID, service.GroupInput{DisplayName: ptr("Elsewhere")})
	if err != nil {
		t.Fatal(err)
	}

	// Only the org's admins (and super admins) manage access.
	for name, a := range map[string]*service.Actor{"manager": actor(c.aManager), "user": actor(c.aUser), "other org": actor(c.bAdmin)} {
		if _, err := c.svc.AddAccess(c.ctx, a, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aUser.ID}); err == nil {
			t.Errorf("%s added access", name)
		}
		if _, _, err := c.svc.ListAccess(c.ctx, a, ten.ID, store.ListQuery{}); err == nil {
			t.Errorf("%s listed access", name)
		}
	}

	// Validation: the subject must exist in the org; clients must be the tenant's; roles and tags are identifiers.
	bad := map[string]service.AccessInput{
		"bad type":          {SubjectType: "robot", SubjectID: c.aUser.ID},
		"other org user":    {SubjectType: model.SubjectUser, SubjectID: c.bAdmin.ID},
		"missing group":     {SubjectType: model.SubjectGroup, SubjectID: "nope"},
		"other org group":   {SubjectType: model.SubjectGroup, SubjectID: bg.ID},
		"foreign client":    {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, AllClients: ptr(false), Clients: &[]string{other.ID}},
		"no clients":        {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, AllClients: ptr(false), Clients: &[]string{}},
		"bad role":          {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, Roles: &[]string{"has space"}},
		"bad tag":           {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, Tags: &[]string{"-x"}},
		"bad expiry":        {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, Expires: ptr("next week")},
		"date only":         {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, Expires: ptr("2099-01-01")},
		"no offset":         {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, Expires: ptr("2099-01-01T10:00:00")},
		"ended already":     {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, Expires: ptr(time.Now().Add(-time.Minute).Format(time.RFC3339))},
		"long reason":       {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, Reason: ptr(strings.Repeat("x", 501))},
		"unknown client id": {SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, AllClients: ptr(false), Clients: &[]string{"nope"}},
	}
	for name, in := range bad {
		if _, err := c.svc.AddAccess(c.ctx, admin, ten.ID, in); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Add a user and a group; a duplicate is a conflict.
	u, err := c.svc.AddAccess(c.ctx, admin, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aUser.ID,
		Roles: &[]string{"viewer", "editor", "viewer"}, AllClients: ptr(false), Clients: &[]string{cl.ID}})
	if err != nil || !slices.Equal(u.Roles, []string{"editor", "viewer"}) || u.Name == "" || u.Detail != c.aUser.Email || u.AllClients {
		t.Fatalf("add user: %v %+v", err, u)
	}
	if _, err := c.svc.AddAccess(c.ctx, admin, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aUser.ID}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate: %v", err)
	}
	ga, err := c.svc.AddAccess(c.ctx, admin, ten.ID, service.AccessInput{SubjectType: model.SubjectGroup, SubjectID: g.ID, Tags: &[]string{"team:ops"}})
	if err != nil || !ga.AllClients || ga.Name != "Ops" {
		t.Fatalf("add group: %v %+v", err, ga)
	}

	// List: names resolved, search and sort.
	l, n, err := c.svc.ListAccess(c.ctx, admin, ten.ID, store.ListQuery{})
	if err != nil || n != 2 || strings.ToLower(l[0].Name) > strings.ToLower(l[1].Name) {
		t.Fatalf("list: %v %d", err, n)
	}
	if l, n, _ := c.svc.ListAccess(c.ctx, admin, ten.ID, store.ListQuery{Search: "ops"}); n != 1 || l[0].SubjectType != model.SubjectGroup {
		t.Errorf("search: %d", n)
	}
	if l, _, _ := c.svc.ListAccess(c.ctx, admin, ten.ID, store.ListQuery{Sort: "type"}); l[0].SubjectType != model.SubjectUser {
		t.Errorf("sort by type: users first")
	}
	if _, _, err := c.svc.ListAccess(c.ctx, admin, ten.ID, store.ListQuery{Sort: "secret"}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("bad sort: %v", err)
	}

	// Update: an end that has passed is refused (remove the entry instead); one that passes shows as such.
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	if _, err := c.svc.UpdateAccess(c.ctx, admin, ten.ID, u.ID, service.AccessInput{Expires: &past}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("an end in the past: %v", err)
	}
	// An end given in Perth time is the same instant, kept in UTC.
	perth := time.Now().Add(time.Hour).In(time.FixedZone("AWST", 8*3600)).Truncate(time.Second)
	if e, err := c.svc.UpdateAccess(c.ctx, admin, ten.ID, u.ID, service.AccessInput{Expires: ptr(perth.Format(time.RFC3339))}); err != nil ||
		!e.Expires.Equal(perth) || e.Expires.Location() != time.UTC {
		t.Fatalf("end in +08:00: %v %+v", err, e)
	}
	endEntry(t, c.svc, u.ID)
	if e, err := c.svc.GetAccess(c.ctx, admin, ten.ID, u.ID); err != nil || !e.Expired {
		t.Fatalf("expire: %v %+v", err, e)
	}
	if e, err := c.svc.UpdateAccess(c.ctx, admin, ten.ID, u.ID, service.AccessInput{AllClients: ptr(true), Expires: ptr("")}); err != nil || e.Expired || !e.AllClients || len(e.Clients) != 0 {
		t.Fatalf("all clients, no end: %v %+v", err, e)
	}
	// The entry must belong to the tenant in the path.
	if _, err := c.svc.UpdateAccess(c.ctx, admin, def.ID, u.ID, service.AccessInput{}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("update through another tenant: %v", err)
	}

	// Remove, then add again (the id is reused).
	if err := c.svc.RemoveAccess(c.ctx, admin, ten.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.AddAccess(c.ctx, admin, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aUser.ID}); err != nil {
		t.Fatalf("add again: %v", err)
	}

	// Deleting the group removes its access; deleting the user removes theirs.
	if err := c.svc.DeleteGroup(c.ctx, admin, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, n, _ := c.svc.ListAccess(c.ctx, admin, ten.ID, store.ListQuery{}); n != 1 {
		t.Errorf("after group delete: %d", n)
	}
	if err := c.svc.DeleteUser(c.ctx, actor(c.super), c.aUser.ID); err != nil {
		t.Fatal(err)
	}
	if _, n, _ := c.svc.ListAccess(c.ctx, admin, ten.ID, store.ListQuery{}); n != 0 {
		t.Errorf("after user delete: %d", n)
	}
}

func TestClientAccessDecision(t *testing.T) {
	c := newCast(t)
	admin := actor(c.aAdmin)
	ten, _ := c.svc.CreateTenant(c.ctx, admin, c.a.ID, service.TenantInput{Name: ptr("staff")})
	cl, _, _ := c.svc.CreateClient(c.ctx, admin, c.a.ID, service.ClientInput{Name: ptr("app"), TenantID: &ten.ID,
		RedirectURIs: ptr([]string{"https://app.example/cb"})})
	g, _ := c.svc.CreateGroup(c.ctx, admin, c.a.ID, service.GroupInput{DisplayName: ptr("Ops")})
	u := c.aUser

	dec := func(groups ...string) *service.AppAccess {
		t.Helper()
		a, err := c.svc.ClientAccess(c.ctx, ten, cl, u, groups)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if dec().Allowed {
		t.Fatal("members-only tenant allowed a non-member")
	}
	// A user of another organization is never allowed, whatever the tenant's setting.
	if a, _ := c.svc.ClientAccess(c.ctx, ten, cl, c.bAdmin, nil); a.Allowed {
		t.Error("other-org user allowed")
	}
	if _, err := c.svc.AddAccess(c.ctx, admin, ten.ID, service.AccessInput{SubjectType: model.SubjectGroup, SubjectID: g.ID,
		Roles: &[]string{"viewer"}, Tags: &[]string{"g"}}); err != nil {
		t.Fatal(err)
	}
	if dec().Allowed {
		t.Error("group access without membership")
	}
	if a := dec(g.ID); !a.Allowed || !slices.Equal(a.Roles, []string{"viewer"}) || !slices.Equal(a.Tags, []string{"g"}) {
		t.Errorf("through group: %+v", a)
	}
	// A direct entry for another client only adds nothing here; one that has expired is ignored.
	soon := time.Now().Add(time.Hour).Format(time.RFC3339)
	ue, err := c.svc.AddAccess(c.ctx, admin, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID,
		Roles: &[]string{"editor"}, Expires: &soon})
	if err != nil {
		t.Fatal(err)
	}
	endEntry(t, c.svc, ue.ID)
	if a := dec(g.ID); !slices.Equal(a.Roles, []string{"viewer"}) {
		t.Errorf("expired entry counted: %+v", a)
	}
	// Open the tenant: everyone may sign in, and the entries are not used (no roles or tags from them).
	ten.Settings.MembersOnly = false
	if a := dec(g.ID); !a.Allowed || len(a.Roles) != 0 || len(a.Tags) != 0 {
		t.Errorf("open tenant: %+v", a)
	}
}

// An access list sorts by name, type, expiry (none last) and creation, searches by name and address, pages, and never
// takes a super admin as a subject; only the organization's admins change it, and changes are audited.
func TestListAccessSortSearchAndPaging(t *testing.T) {
	c := newCast(t)
	sys := service.System
	ten, err := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("staff")})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := c.svc.CreateGroup(c.ctx, sys, c.a.ID, service.GroupInput{DisplayName: ptr("Operations")})
	if err != nil {
		t.Fatal(err)
	}
	add := func(typ, id string, in service.AccessInput) *service.AccessEntry {
		in.SubjectType, in.SubjectID = typ, id
		e, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, in)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	exp := time.Now().Add(48 * time.Hour).Format(time.RFC3339)
	add(model.SubjectUser, c.aUser.ID, service.AccessInput{Expires: &exp})
	add(model.SubjectUser, c.aManager.ID, service.AccessInput{})
	g := add(model.SubjectGroup, grp.ID, service.AccessInput{Expires: &exp, Roles: &[]string{"Viewer"}})
	endEntry(t, c.svc, g.ID)
	if g, err = c.svc.GetAccess(c.ctx, actor(c.aAdmin), ten.ID, g.ID); err != nil || !g.Expired || g.Roles[0] != "Viewer" {
		t.Errorf("group entry %+v", g.TenantAccess)
	}
	// a super admin's access cannot be added
	if _, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.super.ID}); !isInvalid(err) {
		t.Errorf("super admin subject: %v", err)
	}
	names := func(q store.ListQuery) []string {
		l, _, err := c.svc.ListAccess(c.ctx, actor(c.aAdmin), ten.ID, q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range l {
			out = append(out, e.Name)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		q    store.ListQuery
		want []string
	}{
		{"by name", store.ListQuery{}, []string{"amanager", "auser", "Operations"}},
		{"by name, descending", store.ListQuery{Sort: "name", Desc: true}, []string{"Operations", "auser", "amanager"}},
		{"by type, users first", store.ListQuery{Sort: "type"}, []string{"amanager", "auser", "Operations"}},
		{"by expiry, none last", store.ListQuery{Sort: "expires"}, []string{"Operations", "auser", "amanager"}},
		{"by address", store.ListQuery{Search: "AUSER@example"}, []string{"auser"}},
		{"second page", store.ListQuery{Offset: 1, Limit: 1}, []string{"auser"}},
		{"offset past the end", store.ListQuery{Offset: 9}, nil},
	} {
		if got := names(tc.q); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := names(store.ListQuery{Sort: "created"}); len(got) != 3 {
		t.Errorf("by created: %v", got)
	}
	// Anyone but the organization's admins is told nothing, and changes nothing.
	for name, u := range map[string]*model.User{"manager": c.aManager, "foreign admin": c.bAdmin} {
		if _, err := c.svc.UpdateAccess(c.ctx, actor(u), ten.ID, g.ID, service.AccessInput{Roles: &[]string{"x"}}); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s update: %v", name, err)
		}
		if err := c.svc.RemoveAccess(c.ctx, actor(u), ten.ID, g.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s remove: %v", name, err)
		}
	}
	if got := names(store.ListQuery{}); len(got) != 3 {
		t.Errorf("access changed by denied callers: %v", got)
	}
	// update and remove are audited
	if _, err := c.svc.UpdateAccess(c.ctx, actor(c.aAdmin), ten.ID, g.ID, service.AccessInput{Expires: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.RemoveAccess(c.ctx, actor(c.aAdmin), ten.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	if len(c.audited(c.a.ID, "tenant.access.update")) != 1 || len(c.audited(c.a.ID, "tenant.access.remove")) != 1 {
		t.Error("access update/remove not audited")
	}
	// removed and re-added: a new generation, not a conflict
	if _, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, service.AccessInput{SubjectType: model.SubjectGroup, SubjectID: grp.ID}); err != nil {
		t.Errorf("re-adding: %v", err)
	}
}

// endEntry moves access entry id's end into the past, as time passing would: the API refuses to set one there.
func endEntry(t *testing.T, svc *service.Service, id string) {
	t.Helper()
	ctx := context.Background()
	acc, err := svc.Access.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	acc.Expires = time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if err := svc.Access.Update(ctx, acc); err != nil {
		t.Fatal(err)
	}
}

// The sweep removes entries past their end (and only those), recording each in the organization's audit log as the
// system's; the reason given when one was added is in that entry's audit record.
func TestExpireAccess(t *testing.T) {
	c := newCast(t)
	sys := service.System
	ten, err := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("staff")})
	if err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(time.Hour).Format(time.RFC3339)
	ue, err := c.svc.AddAccess(c.ctx, sys, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aUser.ID,
		Expires: &soon, Reason: ptr("INC-42")})
	if err != nil {
		t.Fatal(err)
	}
	if ev := c.audited(c.a.ID, "tenant.access.add"); len(ev) != 1 || ev[0].Detail["reason"] != "INC-42" || ev[0].Detail["expires"] == "" {
		t.Fatalf("add audit: %+v", ev)
	}
	me, err := c.svc.AddAccess(c.ctx, sys, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aManager.ID, Expires: &soon})
	if err != nil {
		t.Fatal(err)
	}
	standing, err := c.svc.AddAccess(c.ctx, sys, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aAdmin.ID})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := c.svc.ExpireAccess(c.ctx); err != nil || n != 0 {
		t.Fatalf("nothing due yet: %d %v", n, err)
	}
	endEntry(t, c.svc, ue.ID)
	endEntry(t, c.svc, me.ID)
	if n, err := c.svc.ExpireAccess(c.ctx); err != nil || n != 2 {
		t.Fatalf("expire: %d %v", n, err)
	}
	for _, id := range []string{ue.ID, me.ID} {
		if _, err := c.svc.Access.Get(c.ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s still there: %v", id, err)
		}
	}
	if _, err := c.svc.Access.Get(c.ctx, standing.ID); err != nil {
		t.Errorf("an entry without an end went: %v", err)
	}
	ev := c.audited(c.a.ID, "tenant.access.expire")
	if len(ev) != 2 || ev[0].Actor != "system" || ev[0].Detail["expires"] == "" {
		t.Fatalf("expire audit: %+v", ev)
	}
	// Added again after the sweep: a new generation, not refused.
	if _, err := c.svc.AddAccess(c.ctx, sys, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aUser.ID, Expires: &soon}); err != nil {
		t.Fatalf("add again after expiry: %v", err)
	}
}
