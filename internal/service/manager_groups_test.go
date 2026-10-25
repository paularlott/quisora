package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A manager adds plain users to groups and takes them out, and does nothing else to a group: no new groups, no
// renames, tags or external ids, no deletions, and no membership change of a manager or an administrator (themself
// included).
func TestManagerChangesMembershipOfPlainUsersOnly(t *testing.T) {
	c := newCast(t)
	mgr := actor(c.aManager)
	otherMgr := c.user(c.a.ID, "amanager2", model.RoleManager)
	g, err := c.svc.CreateGroup(c.ctx, service.System, c.a.ID, service.GroupInput{DisplayName: ptr("staff"), Tags: ptr([]string{"t1"})})
	if err != nil {
		t.Fatal(err)
	}
	members := func() []string {
		t.Helper()
		ids, err := c.svc.GroupMembers(c.ctx, service.System, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}

	// Plain users: in and out.
	if err := c.svc.SetMembership(c.ctx, mgr, g.ID, c.aUser.ID, true); err != nil {
		t.Fatalf("manager adds a user: %v", err)
	}
	if ids := members(); len(ids) != 1 || ids[0] != c.aUser.ID {
		t.Fatalf("members %v", ids)
	}
	if err := c.svc.SetMembership(c.ctx, mgr, g.ID, c.aUser.ID, false); err != nil {
		t.Fatalf("manager removes a user: %v", err)
	}

	// Equal or higher roles: neither in nor out, the manager themself included.
	for _, u := range []*model.User{c.aManager, otherMgr, c.aAdmin} {
		c.check(t, "add "+u.Username, c.svc.SetMembership(c.ctx, mgr, g.ID, u.ID, true), "forbidden")
		if err := c.svc.SetMembership(c.ctx, service.System, g.ID, u.ID, true); err != nil {
			t.Fatal(err)
		}
		c.check(t, "remove "+u.Username, c.svc.SetMembership(c.ctx, mgr, g.ID, u.ID, false), "forbidden")
	}

	// One change is checked in full: a plain user alongside an administrator is refused as a whole.
	cur, err := c.svc.GetGroup(c.ctx, service.System, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.svc.ChangeGroup(c.ctx, mgr, cur, service.GroupInput{}, []string{c.aUser.ID}, []string{c.aAdmin.ID})
	c.check(t, "mixed change", err, "forbidden")
	if ids := members(); len(ids) != 3 {
		t.Fatalf("members after a refused change: %v", ids)
	}

	// The group itself: no change of any field, even together with an allowed membership change.
	for name, in := range map[string]service.GroupInput{
		"rename":      {DisplayName: ptr("renamed")},
		"external id": {ExternalID: ptr("ext-1")},
		"tags":        {Tags: ptr([]string{"t1", "t2"})},
	} {
		_, err := c.svc.ChangeGroup(c.ctx, mgr, cur, in, []string{c.aUser.ID}, nil)
		c.check(t, "change "+name, err, "forbidden")
		_, err = c.svc.UpdateGroup(c.ctx, mgr, g.ID, in)
		c.check(t, "update "+name, err, "forbidden")
	}
	_, err = c.svc.CreateGroup(c.ctx, mgr, c.a.ID, service.GroupInput{DisplayName: ptr("new")})
	c.check(t, "create", err, "forbidden")
	_, err = c.svc.CreateGroupWithMembers(c.ctx, mgr, c.a.ID, service.GroupInput{DisplayName: ptr("new")}, []string{c.aUser.ID})
	c.check(t, "create with members", err, "forbidden")
	c.check(t, "delete", c.svc.DeleteGroup(c.ctx, mgr, g.ID), "forbidden")
	after, err := c.svc.GetGroup(c.ctx, service.System, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.DisplayName != "staff" || after.ExternalID != "" || len(after.Tags) != 1 {
		t.Fatalf("group changed: %+v", after)
	}

	// Another organization's groups are out of reach.
	gb, err := c.svc.CreateGroup(c.ctx, service.System, c.b.ID, service.GroupInput{DisplayName: ptr("b-staff")})
	if err != nil {
		t.Fatal(err)
	}
	c.check(t, "other org", c.svc.SetMembership(c.ctx, mgr, gb.ID, c.aUser.ID, true), "denied")
}

// Administrators and super admins in a group do not stop a manager adding and removing plain users: only the users
// the change touches are checked, and the others stay as they are.
func TestManagerChangesGroupsHoldingAdministrators(t *testing.T) {
	c := newCast(t)
	for _, tc := range []struct {
		org          string
		mgr, user    *model.User
		higherRanked []*model.User
	}{
		{c.primary.ID, c.pManager, c.pUser, []*model.User{c.super, c.pAdmin}},
		{c.a.ID, c.aManager, c.aUser, []*model.User{c.aAdmin}},
	} {
		g, err := c.svc.CreateGroup(c.ctx, service.System, tc.org, service.GroupInput{DisplayName: ptr(c.next("mixed"))})
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range tc.higherRanked {
			if err := c.svc.SetMembership(c.ctx, service.System, g.ID, u.ID, true); err != nil {
				t.Fatal(err)
			}
		}
		mgr := actor(tc.mgr)
		if err := c.svc.SetMembership(c.ctx, mgr, g.ID, tc.user.ID, true); err != nil {
			t.Fatalf("%s adds a user: %v", tc.mgr.Username, err)
		}
		if ids, _ := c.svc.GroupMembers(c.ctx, service.System, g.ID); len(ids) != len(tc.higherRanked)+1 {
			t.Fatalf("members after the add: %v", ids)
		}
		if err := c.svc.SetMembership(c.ctx, mgr, g.ID, tc.user.ID, false); err != nil {
			t.Fatalf("%s removes a user: %v", tc.mgr.Username, err)
		}
		if ids, _ := c.svc.GroupMembers(c.ctx, service.System, g.ID); len(ids) != len(tc.higherRanked) {
			t.Fatalf("members after the removal: %v", ids)
		}
	}
}
