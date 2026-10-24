package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestDeepReviewPrivilegedLinkedEmailCannotBypassResetGuard(t *testing.T) {
	e := newEnv(t)
	org := e.org("deepreview")
	admin := e.user(org.ID, "issuer", model.RoleAdmin)
	target := e.user(org.ID, "target", model.RoleManager)
	password := "correct horse battery staple 9"
	if _, err := e.svc.UpdateUser(e.ctx, service.System, target.ID, service.UserInput{Password: &password}); err != nil {
		t.Fatal(err)
	}
	address := "attacker@controlled.example"
	if _, err := e.svc.AddLinkedEmail(e.ctx, actor(admin), target.ID, address, true); err == nil {
		t.Fatal("control: guarded email API unexpectedly allowed the change")
	}
	_, err := e.svc.UpdateUser(e.ctx, actor(admin), target.ID, service.UserInput{LinkedEmails: &[]string{address}})
	if err == nil {
		matched, lookupErr := e.svc.UsersByVerifiedEmail(e.ctx, org.ID, []string{address})
		t.Fatalf("bulk email update bypassed privileged reset guard; verified upstream matches=%d lookup error=%v", len(matched), lookupErr)
	}
}
