package scim_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestDeepReviewSCIMCannotLinkAttackerEmailToEstablishedAdmin(t *testing.T) {
	e := newEnv(t)
	target := e.mkUser(e.orgA, "privileged-target", model.RoleAdmin)
	password := "correct horse battery staple 9"
	if _, err := e.Svc.UpdateUser(e.ctx, service.System, target.ID, service.UserInput{Password: &password}); err != nil {
		t.Fatal(err)
	}
	address := "attacker@controlled.example"
	r := e.do("PATCH", "/scim/v2/acme/Users/"+target.ID, e.admA, patchBody(op("add", "emails", []any{map[string]any{"value": address, "type": "other"}})))
	if r.Status == 200 {
		matched, err := e.Svc.UsersByVerifiedEmail(e.ctx, e.orgA.ID, []string{address})
		t.Fatalf("admin SCIM token added verified sign-in address to established peer: status=%d upstream matches=%d err=%v", r.Status, len(matched), err)
	}
	if r.Status != 400 && r.Status != 403 {
		t.Fatalf("unexpected response: %d %s", r.Status, r.Raw)
	}
}
