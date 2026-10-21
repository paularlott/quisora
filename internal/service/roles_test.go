package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Role changes and the last super admin: a promotion is never refused, administrators can always be demoted (super
// admins administer every organization), and the last super admin cannot be.
func TestRoleChangesAndLastAdmin(t *testing.T) {
	e := newEnv(t)
	super := actor(e.super)
	role := func(r model.Role) *model.Role { return &r }

	// the user's case: in the primary organization, the super admin and one administrator
	x := e.user(e.primary.ID, "x", model.RoleUser)
	if _, err := e.svc.UpdateUser(e.ctx, super, x.ID, service.UserInput{Role: role(model.RoleAdmin)}); err != nil {
		t.Fatalf("user -> admin: %v", err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, super, x.ID, service.UserInput{Role: role(model.RoleSuperAdmin)}); err != nil {
		t.Fatalf("admin -> super admin: %v", err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, super, x.ID, service.UserInput{Role: role(model.RoleAdmin)}); err != nil {
		t.Fatalf("super admin -> admin, another super admin remaining: %v", err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, super, x.ID, service.UserInput{Role: role(model.RoleManager)}); err != nil {
		t.Fatalf("admin -> manager, a super admin remaining: %v", err)
	}

	// the last super admin stays one
	if _, err := e.svc.UpdateUser(e.ctx, service.System, e.super.ID, service.UserInput{Role: role(model.RoleAdmin)}); outcome(err) != "lastadmin" {
		t.Errorf("demoting the last super admin: %v", err)
	}

	// another organization may be left without an administrator: super admins administer it
	acme := e.org("acme")
	a := e.user(acme.ID, "a", model.RoleAdmin)
	if _, err := e.svc.UpdateUser(e.ctx, super, a.ID, service.UserInput{Role: role(model.RoleManager)}); err != nil {
		t.Errorf("demoting acme's last administrator: %v", err)
	}
}
