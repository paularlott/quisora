package service_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

type userGroupsResult struct {
	groups []*model.Group
	err    error
}

// userGroupsAsync reads the user's groups in the background.
func (e *env) userGroupsAsync(u *model.User) <-chan userGroupsResult {
	done := make(chan userGroupsResult, 1)
	go func() {
		gs, err := e.svc.UserGroups(e.ctx, u)
		done <- userGroupsResult{gs, err}
	}()
	return done
}

// holdsTag reports whether any of the groups is g carrying tag.
func holdsTag(groups []*model.Group, g *model.Group, tag string) bool {
	return slices.ContainsFunc(groups, func(x *model.Group) bool { return x.ID == g.ID && slices.Contains(x.Tags, tag) })
}

// A group update atomically removes a user while granting the group a new tag. A concurrent lookup of the user's
// groups never combines membership from before the commit with tags from after it: the user never held that tag.
func TestUserGroupsNeverCombineMembershipAndTagsFromDifferentCommits(t *testing.T) {
	e := newEnv(t)
	org := e.org("snapshot")
	u := e.user(org.ID, "member", model.RoleUser)
	g := e.group(org.ID, "Group", u)
	gt := newGate(t)
	e.svc.Members.S = &faultStore{Store: e.svc.Store, afterList: func(kind model.Kind) {
		if kind == model.KindMember {
			gt.stall()
		}
	}}
	done := e.userGroupsAsync(u)
	gt.waitEntered(t, "the reader's membership list")
	tags := []string{"admin"}
	_, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, nil, []string{u.ID})
	gt.release()
	r := <-done
	if err != nil {
		t.Fatal(err)
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	if holdsTag(r.groups, g, "admin") {
		t.Fatalf("a removed user received the newly privileged group: %+v", r.groups)
	}
}

// The recheck matches the group version whose tags it authorizes: a newer active membership cannot authorize a group
// snapshot under which it was removed.
func TestUserGroupsRecheckMatchesTheGroupVersionItAuthorizes(t *testing.T) {
	e := newEnv(t)
	org := e.org("recheck")
	u := e.user(org.ID, "member", model.RoleUser)
	g := e.group(org.ID, "Group", u)
	membersRead, groupsRead := newGate(t), newGate(t)
	fs := &faultStore{
		Store: e.svc.Store,
		afterList: func(kind model.Kind) {
			if kind == model.KindMember {
				membersRead.stall()
			}
		},
		afterGetMany: func(kind model.Kind) {
			if kind == model.KindGroup {
				groupsRead.stall()
			}
		},
	}
	e.svc.Members.S, e.svc.Groups.S = fs, fs
	done := e.userGroupsAsync(u)
	membersRead.waitEntered(t, "the reader's membership list") // the reader holds the initial membership, seq 1
	tags := []string{"admin"}
	g, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, nil, []string{u.ID})
	membersRead.release()
	if err != nil {
		t.Fatal(err)
	}
	groupsRead.waitEntered(t, "the reader's group read") // the reader holds group seq 2: admin tag, user removed
	tags = nil
	_, err = e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, []string{u.ID}, nil)
	groupsRead.release() // the recheck sees membership seq 3: user re-added, admin tag gone
	r := <-done
	if err != nil {
		t.Fatal(err)
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	if holdsTag(r.groups, g, "admin") {
		t.Fatalf("the user received a privilege they never held: %+v", r.groups)
	}
}

// A quorum read that settles a user's membership in a group stands while the group is at the change it was read
// against: groups where other members changed since leave the user's membership at an older change, they are read
// together in one round, and the next lookup reads nothing again. A later change of one group is read afresh.
func TestUserGroupsRemembersQuorumDecisions(t *testing.T) {
	e := newEnv(t)
	org := e.org("quorum-memory")
	u := e.user(org.ID, "member", model.RoleUser)
	other := e.user(org.ID, "other", model.RoleUser)
	const groups = 12
	var gs []*model.Group
	for i := range groups {
		g := e.group(org.ID, fmt.Sprintf("Group %02d", i), u)
		// a change that does not name the user: their membership record stays at an older change
		if err := e.svc.SetMembership(e.ctx, service.System, g.ID, other.ID, true); err != nil {
			t.Fatal(err)
		}
		gs = append(gs, g)
	}
	quorum := newerOnQuorum(e.svc.Store)
	e.svc.Store = quorum
	if got, err := e.svc.UserGroups(e.ctx, u); err != nil || len(got) != groups {
		t.Fatalf("first: %d groups, %v", len(got), err)
	}
	if n := quorum.calls.Load(); n != 1 { // one round: the memberships to read again, read together
		t.Fatalf("%d quorum reads for the first lookup, want 1", n)
	}
	if got, err := e.svc.UserGroups(e.ctx, u); err != nil || len(got) != groups {
		t.Fatalf("second: %d groups, %v", len(got), err)
	}
	if n := quorum.calls.Load(); n != 1 {
		t.Fatalf("the second lookup read the same memberships again: %d quorum reads", n)
	}
	// The user leaves one group: the group moves to a later change, and the answer follows it.
	if err := e.svc.SetMembership(e.ctx, service.System, gs[0].ID, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.UserGroups(e.ctx, u); err != nil || len(got) != groups-1 {
		t.Fatalf("after leaving one: %d groups, %v", len(got), err)
	}
}
