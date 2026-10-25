package service_test

import (
	"fmt"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A quorum read that settles a user's membership in a group stands while the group is at the change it was read
// against: the next token of the user reads nothing again, and a later change of the group (one that names the user
// or not) is read afresh.
func TestUserGroupsRemembersQuorumDecisions(t *testing.T) {
	e := newEnv(t)
	org := e.org("member-confirm")
	u := e.user(org.ID, "member", model.RoleUser)
	other := e.user(org.ID, "other", model.RoleUser)
	var gs []*model.Group
	for i := range 4 {
		name := fmt.Sprintf("Group %d", i)
		g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
		if err != nil {
			t.Fatal(err)
		}
		// a change that does not name the user: their membership record stays at an older change
		if err := e.svc.SetMembership(e.ctx, service.System, g.ID, other.ID, true); err != nil {
			t.Fatal(err)
		}
		gs = append(gs, g)
	}
	counter := &fresh4ReadCounter{Store: e.svc.Store}
	e.svc.Store = counter
	if got, err := e.svc.UserGroups(e.ctx, u); err != nil || len(got) != len(gs) {
		t.Fatalf("first: %d groups, %v", len(got), err)
	}
	first := counter.calls.Load()
	if first == 0 {
		t.Fatal("the stale memberships were not read from a quorum")
	}
	if got, err := e.svc.UserGroups(e.ctx, u); err != nil || len(got) != len(gs) {
		t.Fatalf("second: %d groups, %v", len(got), err)
	}
	if n := counter.calls.Load(); n != first {
		t.Fatalf("the second token read the same memberships again: %d quorum reads after %d", n, first)
	}
	// The user leaves one group: the group moves to a later change, and the answer follows it.
	if err := e.svc.SetMembership(e.ctx, service.System, gs[0].ID, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.UserGroups(e.ctx, u); err != nil || len(got) != len(gs)-1 {
		t.Fatalf("after leaving one: %d groups, %v", len(got), err)
	}
}
