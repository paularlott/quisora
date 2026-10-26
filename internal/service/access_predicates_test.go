package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

// Who administers an organization, who manages its users, and which users one may manage: managers manage plain users
// only, admins everyone but super admins, super admins every organization.
func TestAccessPredicates(t *testing.T) {
	c := newCast(t)
	for _, tc := range []struct {
		name                 string
		u                    *model.User
		admin, users, manage bool // admin/manage users of org a; manage c.aUser
	}{
		{"super", c.super, true, true, true},
		{"a-admin", c.aAdmin, true, true, true},
		{"a-manager", c.aManager, false, true, true},
		{"a-user", c.aUser, false, false, false},
		{"b-admin", c.bAdmin, false, false, false},
		{"primary-admin", c.pAdmin, false, false, false},
	} {
		a := actor(tc.u)
		if got := c.svc.CanAdminOrg(a, c.a.ID); got != tc.admin {
			t.Errorf("%s CanAdminOrg %v", tc.name, got)
		}
		if got := c.svc.CanManageUsers(a, c.a.ID); got != tc.users {
			t.Errorf("%s CanManageUsers %v", tc.name, got)
		}
		if got := c.svc.CanManageUser(a, c.aUser); got != tc.manage {
			t.Errorf("%s CanManageUser %v", tc.name, got)
		}
	}
	// managers manage plain users only, admins everyone but super admins; provisioning clients stop at managers
	if c.svc.CanManageUser(actor(c.aManager), c.aAdmin) || c.svc.CanManageUser(actor(c.aManager), c.aManager) {
		t.Error("manager manages a manager or admin")
	}
	if !c.svc.CanManageUser(actor(c.aAdmin), c.aManager) {
		t.Error("admin cannot manage a manager")
	}
}
