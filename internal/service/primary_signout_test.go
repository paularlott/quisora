package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// The primary organization holds the super admins: only a super admin pulls its emergency sign-out, so one of its
// administrators cannot sign out (and end the API tokens of) those above them. Other organizations' administrators
// still pull their own.
func TestPrimarySignOutIsSuperAdminsOnly(t *testing.T) {
	c := newCast(t)
	opt := service.SignOutOptions{Reason: "test", APITokens: true}
	if _, err := c.svc.SignOutOrg(c.ctx, actor(c.pAdmin), c.primary.ID, opt); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("a primary-organization administrator signed it out: %v", err)
	}
	if _, err := c.svc.SignOutOrg(c.ctx, actor(c.aAdmin), c.a.ID, opt); err != nil {
		t.Fatalf("an administrator could not sign out their own organization: %v", err)
	}
	if _, err := c.svc.SignOutOrg(c.ctx, actor(c.super), c.primary.ID, opt); err != nil {
		t.Fatalf("a super admin could not sign out the primary organization: %v", err)
	}
}
