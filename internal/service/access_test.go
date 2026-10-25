package service_test

import (
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

	// Update: expiry, then all clients.
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	if e, err := c.svc.UpdateAccess(c.ctx, admin, ten.ID, u.ID, service.AccessInput{Expires: &past}); err != nil || !e.Expired {
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
	soon := time.Now().Add(-time.Second).Format(time.RFC3339)
	if _, err := c.svc.AddAccess(c.ctx, admin, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID,
		Roles: &[]string{"editor"}, Expires: &soon}); err != nil {
		t.Fatal(err)
	}
	if a := dec(g.ID); !slices.Equal(a.Roles, []string{"viewer"}) {
		t.Errorf("expired entry counted: %+v", a)
	}
	// Open the tenant: everyone may sign in, and the entries are not used (no roles or tags from them).
	ten.Settings.MembersOnly = false
	if a := dec(g.ID); !a.Allowed || len(a.Roles) != 0 || len(a.Tags) != 0 {
		t.Errorf("open tenant: %+v", a)
	}
}
