package service_test

import (
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
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

// The groups of several users are what each user's own lookup returns, including a group change committed but not yet
// written to the memberships (a pending add), and the organization's groups with pending changes are read once for
// all of them, not once per user.
func TestUserGroupsOfSeveralUsersMatchesEachUsersOwn(t *testing.T) {
	b := newBrokenMembership(t, "bulk-groups", false)
	e := b.e
	if err := <-b.addBoth(); err != nil {
		t.Fatal(err) // committed, with the second user's membership still to be written
	}
	third := e.user(b.first.OrgID, "third", model.RoleUser)
	other := e.group(b.first.OrgID, "Other", third)
	loner := e.user(b.first.OrgID, "loner", model.RoleUser)
	pendingReads := 0
	e.svc.Groups.S = &faultStore{Store: e.svc.Store, beforeList: func(kind model.Kind, q store.ListQuery) error {
		if kind == model.KindGroup && len(q.Filters) == 1 && q.Filters[0].Field == "pending" {
			pendingReads++
		}
		return nil
	}}
	users := []*model.User{b.first, b.second, third, loner}
	got, err := e.svc.UserGroupsOf(e.ctx, users)
	if err != nil {
		t.Fatal(err)
	}
	if pendingReads != 1 {
		t.Errorf("the pending groups were read %d times for %d users, want once", pendingReads, len(users))
	}
	ids := func(gs []*model.Group) []string {
		out := []string{}
		for _, g := range gs {
			out = append(out, g.ID)
		}
		return out
	}
	want := map[string][]string{b.first.ID: {b.g.ID}, b.second.ID: {b.g.ID}, third.ID: {other.ID}, loner.ID: {}}
	for _, u := range users {
		own, err := e.svc.UserGroups(e.ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(ids(got[u.ID]), ids(own)) || !slices.Equal(ids(own), want[u.ID]) {
			t.Errorf("%s: groups of several %v, of their own %v, want %v", u.Username, ids(got[u.ID]), ids(own), want[u.ID])
		}
	}
}
