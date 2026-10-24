package service_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestGroupMembershipIdempotentAndScoped(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	g, err := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("devs"), ExternalID: ptr("ext-g")})
	if err != nil {
		t.Fatal(err)
	}
	u1 := c.user(c.a.ID, "m1", model.RoleUser)
	u2 := c.user(c.a.ID, "m2", model.RoleUser)

	for range 3 { // adding repeatedly is a no-op
		if err := c.svc.SetMembership(c.ctx, a, g.ID, u1.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, u2.ID, true); err != nil {
		t.Fatal(err)
	}
	ids, err := c.svc.GroupMembers(c.ctx, a, g.ID)
	slices.Sort(ids)
	want := []string{u1.ID, u2.ID}
	slices.Sort(want)
	if err != nil || !slices.Equal(ids, want) {
		t.Fatalf("members %v %v", ids, err)
	}
	if n, _ := c.svc.Store.Count(c.ctx, model.KindMember, c.a.ID); n != 2 {
		t.Errorf("%d member records, want one per member", n)
	}
	// Removing repeatedly (and removing a non-member) is a no-op.
	for range 3 {
		if err := c.svc.SetMembership(c.ctx, a, g.ID, u1.ID, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, c.aUser.ID, false); err != nil {
		t.Fatalf("remove non-member: %v", err)
	}
	ids, _ = c.svc.GroupMembers(c.ctx, a, g.ID)
	if len(ids) != 1 || ids[0] != u2.ID {
		t.Errorf("after removal: %v", ids)
	}
	// Re-adding after removal works.
	if err := c.svc.SetMembership(c.ctx, a, g.ID, u1.ID, true); err != nil {
		t.Fatal(err)
	}
	gs, err := c.svc.UserGroups(c.ctx, u1)
	if err != nil || len(gs) != 1 || gs[0].ID != g.ID {
		t.Errorf("UserGroups: %v %v", gs, err)
	}

	// Cross-org membership is rejected, as is an unknown user or group.
	other := c.user(c.b.ID, "outsider", model.RoleUser)
	err = c.svc.SetMembership(c.ctx, a, g.ID, other.ID, true)
	var fe *service.FieldError
	if !errors.As(err, &fe) || fe.Field != "members" {
		t.Errorf("cross-org member: %v", err)
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, "ghost", true); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("unknown user: %v", err)
	}
	if err := c.svc.SetMembership(c.ctx, a, "ghost", u1.ID, true); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown group: %v", err)
	}
	// The super admin cannot slip a primary-org user into org A's group either.
	if err := c.svc.SetMembership(c.ctx, actor(c.super), g.ID, c.pUser.ID, true); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("super cross-org member: %v", err)
	}
	// An admin of another org cannot manage the group.
	if err := c.svc.SetMembership(c.ctx, actor(c.bAdmin), g.ID, u1.ID, true); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("other org admin: %v", err)
	}

	// Deleting the group removes its memberships.
	if err := c.svc.DeleteGroup(c.ctx, a, g.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.svc.Store.Count(c.ctx, model.KindMember, c.a.ID); n != 0 {
		t.Errorf("%d memberships left", n)
	}
	if gs, _ := c.svc.UserGroups(c.ctx, u1); len(gs) != 0 {
		t.Errorf("user still in deleted group")
	}
}

func TestGroupValidationAndConflicts(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	if _, err := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("no name: %v", err)
	}
	for _, n := range []string{"", "   ", strings.Repeat("g", 201)} {
		if _, err := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr(n)}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("name %q: %v", n, err)
		}
	}
	g1, err := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("Ops"), ExternalID: ptr("x1")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("ops")})
	var fe *service.FieldError
	if !errors.As(err, &fe) || fe.Field != "display_name" || !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
	_, err = c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("Other"), ExternalID: ptr("x1")})
	if !errors.As(err, &fe) || fe.Field != "external_id" || !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate external id should name external_id: %v", err)
	}
	// Same name in another org.
	if _, err := c.svc.CreateGroup(c.ctx, actor(c.bAdmin), c.b.ID, service.GroupInput{DisplayName: ptr("Ops")}); err != nil {
		t.Errorf("same name in other org: %v", err)
	}
	g2, _ := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("Dev")})
	if _, err := c.svc.UpdateGroup(c.ctx, a, g2.ID, service.GroupInput{DisplayName: ptr("OPS")}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("rename clash: %v", err)
	}
	upd, err := c.svc.UpdateGroup(c.ctx, a, g1.ID, service.GroupInput{DisplayName: ptr("Operations"), ExternalID: ptr("")})
	if err != nil || upd.DisplayName != "Operations" || upd.ExternalID != "" {
		t.Errorf("update: %v %+v", err, upd)
	}
	if _, err := c.svc.GetGroup(c.ctx, actor(c.bAdmin), g1.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-org get: %v", err)
	}
	gs, total, err := c.svc.ListGroups(c.ctx, a, c.a.ID, store.ListQuery{Sort: "display_name"})
	if err != nil || total != 2 || gs[0].DisplayName != "Dev" {
		t.Errorf("list: %v %d", err, total)
	}
}

// An organization with many groups: UserGroups answers from the user's own memberships, not the groups.
func TestUserGroupsManyGroups(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	u := c.user(c.a.ID, "many", model.RoleUser)
	var mine []string
	for i := range 70 {
		g, err := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("g" + string(rune('a'+i/26)) + string(rune('a'+i%26)))})
		if err != nil {
			t.Fatal(err)
		}
		if i%23 == 0 {
			if err := c.svc.SetMembership(c.ctx, a, g.ID, u.ID, true); err != nil {
				t.Fatal(err)
			}
			mine = append(mine, g.ID)
		}
	}
	gs, err := c.svc.UserGroups(c.ctx, u)
	if err != nil || len(gs) != len(mine) {
		t.Fatalf("%d groups, want %d (%v)", len(gs), len(mine), err)
	}
	for _, g := range gs {
		if !slices.Contains(mine, g.ID) {
			t.Errorf("unexpected group %s", g.DisplayName)
		}
	}
}
