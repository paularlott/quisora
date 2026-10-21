package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// End dates count against the last-super-admin guard: two super admins cannot end-date each other (none would be left
// once the dates pass), and one past their end date is not usable.
func TestLastAdminMutualEndDatesRefused(t *testing.T) {
	c := newCast(t)
	root := c.super
	other := c.user(c.primary.ID, "esa", model.RoleSuperAdmin)
	next := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)

	if _, err := c.svc.UpdateUser(c.ctx, actor(root), other.ID, service.UserInput{ValidUntil: ptr(next)}); err != nil {
		t.Fatalf("end-date the other while one without an end date remains: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(other), root.ID, service.UserInput{ValidUntil: ptr(next)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("mutual end-dating: want ErrLastAdmin, got %v", err)
	}
	// Disabling the only one without an end date next to an end-dated one is refused too.
	if _, err := c.svc.UpdateUser(c.ctx, actor(other), root.ID, service.UserInput{Active: ptr(false)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("disable the last lasting super admin: want ErrLastAdmin, got %v", err)
	}
	// Moving the end date later, or clearing it, is always fine.
	later := time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := c.svc.UpdateUser(c.ctx, actor(root), other.ID, service.UserInput{ValidUntil: ptr(later)}); err != nil {
		t.Fatalf("extend end date: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(root), other.ID, service.UserInput{ValidUntil: ptr("")}); err != nil {
		t.Fatalf("clear end date: %v", err)
	}

	// One past their end date is not usable: with only such a colleague, the remaining one is the last.
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := c.svc.UpdateUser(c.ctx, actor(root), other.ID, service.UserInput{ValidUntil: ptr(past)}); err != nil {
		t.Fatalf("end-date the other in the past: %v", err)
	}
	ghost := &service.Actor{UserID: "someone-else", OrgID: c.primary.ID, Role: model.RoleSuperAdmin, Name: "ghost"}
	if _, err := c.svc.UpdateUser(c.ctx, ghost, root.ID, service.UserInput{Active: ptr(false)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("disable next to an expired super admin: want ErrLastAdmin, got %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, ghost, root.ID, service.UserInput{Role: ptr(model.RoleUser)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("demote next to an expired super admin: want ErrLastAdmin, got %v", err)
	}
}

// Super admins are guarded the same way.
func TestLastSuperAdminEndDateRefused(t *testing.T) {
	c := newCast(t)
	ghost := &service.Actor{UserID: "someone-else", OrgID: c.primary.ID, Role: model.RoleSuperAdmin, Name: "ghost"}
	next := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := c.svc.UpdateUser(c.ctx, ghost, c.super.ID, service.UserInput{ValidUntil: ptr(next)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("end-date the last super admin: want ErrLastAdmin, got %v", err)
	}
}

// A provisioning client acts as an admin of its organization but never reaches administrators: not through group
// membership, nor through the tags (or deletion) of a group they belong to.
func TestClientCannotManageAdminsThroughGroups(t *testing.T) {
	c := newCast(t)
	cl, _, err := c.svc.CreateClient(c.ctx, actor(c.super), c.a.ID, service.ClientInput{Name: ptr("scim"), SCIM: ptr(true),
		RedirectURIs: ptr([]string{"https://x.example.com/cb"})})
	if err != nil {
		t.Fatal(err)
	}
	a := service.ActorForClient(cl, "1.2.3.4")
	g, err := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("staff")})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, c.aUser.ID, true); err != nil {
		t.Fatalf("client adds a user: %v", err)
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, c.aAdmin.ID, true); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("client adds an admin: %v", err)
	}
	// An admin puts themselves in the group: the client can neither remove them nor retag or delete the group.
	if err := c.svc.SetMembership(c.ctx, actor(c.aAdmin), g.ID, c.aAdmin.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, c.aAdmin.ID, false); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("client removes an admin: %v", err)
	}
	if _, err := c.svc.UpdateGroup(c.ctx, a, g.ID, service.GroupInput{Tags: ptr([]string{"elevated"})}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("client tags an admin's group: %v", err)
	}
	if err := c.svc.DeleteGroup(c.ctx, a, g.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("client deletes an admin's group: %v", err)
	}
	// Renaming without touching tags is still fine, and so is everything for a group of plain users.
	if _, err := c.svc.UpdateGroup(c.ctx, a, g.ID, service.GroupInput{DisplayName: ptr("staff2")}); err != nil {
		t.Fatalf("client renames: %v", err)
	}
	plain, _ := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("plain")})
	_ = c.svc.SetMembership(c.ctx, a, plain.ID, c.aManager.ID, true)
	if _, err := c.svc.UpdateGroup(c.ctx, a, plain.ID, service.GroupInput{Tags: ptr([]string{"x"})}); err != nil {
		t.Fatalf("client tags a plain group: %v", err)
	}
	// An administrator is not limited.
	if err := c.svc.SetMembership(c.ctx, actor(c.aAdmin), plain.ID, c.aAdmin.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateGroup(c.ctx, actor(c.aAdmin), plain.ID, service.GroupInput{Tags: ptr([]string{"y"})}); err != nil {
		t.Fatalf("admin tags: %v", err)
	}
}
