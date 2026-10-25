package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Deleting a user leaves its materialized membership for the orphan sweep, but
// that membership must stop appearing as a user in group counts and pagination.
func TestFresh5DeletedUserStopsCountingAsGroupMemberImmediately(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-deleted-member")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Group"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteUser(e.ctx, service.System, u.ID); err != nil {
		t.Fatal(err)
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.GroupMemberCount(e.ctx, service.System, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 || n != 0 {
		t.Fatalf("deleted user still appears before sweep: member IDs %v, count %d", ids, n)
	}
}
