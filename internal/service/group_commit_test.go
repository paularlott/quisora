package service_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// stallMemberWrite pauses the first compare-and-swap of one membership record (memberID) until the test resumes it,
// modelling a writer that stalled between its commit and the write (a slow store or RPC, a paused node).
type stallMemberWrite struct {
	store.Store
	memberID        string
	stalled         atomic.Bool
	entered, resume chan struct{}
}

func (g *stallMemberWrite) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindMember && r.ID == g.memberID && g.stalled.CompareAndSwap(false, true) {
		close(g.entered)
		<-g.resume
	}
	return g.Store.CompareAndPut(ctx, r, expect)
}

// A writer stalled on a removal must not apply it after a later change made the user a member again: the
// membership record's sequence fences the stale write (the mirror image of the add-then-remove case in
// fresh_replication_review_test.go).
func TestGroupStaleRemovalCannotUndoLaterAdd(t *testing.T) {
	e := newEnv(t)
	org := e.org("fence-remove")
	u := e.user(org.ID, "u", model.RoleUser)
	name := "G"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	gate := &stallMemberWrite{Store: e.svc.Store, memberID: model.MemberID(g.ID, u.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Members.S = gate
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, nil, []string{u.ID}) // seq 2: remove
		done <- err
	}()
	<-gate.entered // committed, stalled before the membership write
	fresh, err := e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Finishes the removal (seq 2), then commits and materializes the add (seq 3).
	if _, err := e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{}, []string{u.ID}, nil); err != nil {
		t.Fatal(err)
	}
	close(gate.resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID))
	if err != nil || !m.Active() || m.Seq != 3 {
		t.Fatalf("stale removal overwrote the later add: %v %+v", err, m)
	}
	if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 1 {
		t.Fatalf("user's groups: %v %v", gs, err)
	}
}

// A group created with members is one commit: the record is created carrying the change, so readers see the
// members at once, and a group whose creation is refused has nothing written for it.
func TestCreateGroupWithMembersIsOneCommit(t *testing.T) {
	e := newEnv(t)
	org := e.org("create-commit")
	a, b := e.user(org.ID, "a", model.RoleUser), e.user(org.ID, "b", model.RoleUser)
	other := e.org("other")
	stranger := e.user(other.ID, "s", model.RoleUser)
	name := "Team"
	if _, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{a.ID, stranger.ID}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("stranger accepted: %v", err)
	}
	if _, err := e.svc.Groups.GetByUnique(e.ctx, model.GroupNameKey(org.ID, name)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("group written by a refused create: %v", err)
	}
	if gs, _ := e.svc.UserGroups(e.ctx, a); len(gs) != 0 {
		t.Fatal("membership written by a refused create")
	}
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{a.ID, b.ID, a.ID})
	if err != nil {
		t.Fatal(err)
	}
	if g.Seq != 1 || len(g.Pending) != 0 {
		t.Fatalf("created group: %+v", g)
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil || !slices.Equal(ids, sortedIDs(a.ID, b.ID)) {
		t.Fatalf("members: %v %v", ids, err)
	}
	if n, err := e.svc.GroupMemberCount(e.ctx, service.System, g); err != nil || n != 2 {
		t.Fatalf("count: %d %v", n, err)
	}
	// A duplicate name with members: refused at the record, nothing written.
	if _, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{a.ID}); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if gs, _ := e.svc.UserGroups(e.ctx, a); len(gs) != 1 {
		t.Fatalf("a's groups: %v", gs)
	}
}

// Changes larger than MaxMembersPerChange are refused before anything is written.
func TestGroupChangeTooLarge(t *testing.T) {
	e := newEnv(t)
	org := e.org("too-large")
	name := "Big"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, service.MaxMembersPerChange+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("u%d", i)
	}
	if _, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, ids, nil); !errors.Is(err, service.ErrTooLarge) {
		t.Fatalf("add: %v", err)
	}
	if _, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, ids[:600], ids[600:]); !errors.Is(err, service.ErrTooLarge) {
		t.Fatalf("add and remove: %v", err)
	}
	if _, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr("Bigger")}, ids); !errors.Is(err, service.ErrTooLarge) {
		t.Fatalf("create: %v", err)
	}
	if cur, _ := e.svc.Groups.Get(e.ctx, g.ID); cur.Version != g.Version {
		t.Fatal("a refused change wrote the group")
	}
}

// Housekeeping finishes a change whose writer died after committing it, once it is older than the grace period,
// and leaves a fresh one to its writer.
func TestHousekeepingFinishesAbandonedGroupChange(t *testing.T) {
	e := newEnv(t)
	org := e.org("housekeeping")
	u := e.user(org.ID, "u", model.RoleUser)
	name := "G"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	// A writer that died right after its commit: the record carries the entry, no membership exists.
	g.Seq, g.Pending = 1, []model.GroupChange{{Op: "op", Seq: 1, At: time.Now().Add(-time.Minute), Add: []string{u.ID}}}
	if err := e.svc.Groups.Update(e.ctx, g); err != nil {
		t.Fatal(err)
	}
	if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 1 {
		t.Fatalf("committed change not seen before it is materialized: %v %v", gs, err)
	}
	if n, err := e.svc.FinishGroupChanges(e.ctx, time.Hour); err != nil || n != 0 {
		t.Fatalf("finished within grace: %d %v", n, err)
	}
	if n, err := e.svc.FinishGroupChanges(e.ctx, 30*time.Second); err != nil || n != 1 {
		t.Fatalf("finished: %d %v", n, err)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || !m.Active() || m.Seq != 1 {
		t.Fatalf("membership: %v %+v", err, m)
	}
	cur, err := e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil || len(cur.Pending) != 0 {
		t.Fatalf("record: %v %+v", err, cur)
	}
	if n, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil || n != 0 {
		t.Fatalf("nothing left, finished %d: %v", n, err)
	}
}

// Deleting a group commits the removal of every member first: a deletion that cannot finish leaves an empty group
// (no membership grants anything), and a retry removes it.
func TestDeleteGroupCommitsRemovalFirst(t *testing.T) {
	e := newEnv(t)
	org := e.org("delete-commit")
	a, b := e.user(org.ID, "a", model.RoleUser), e.user(org.ID, "b", model.RoleUser)
	name := "Doomed"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{a.ID, b.ID})
	if err != nil {
		t.Fatal(err)
	}
	inner := e.svc.Members.S
	e.svc.Members.S = failRecord{Store: inner, suffix: b.ID}
	if err := e.svc.DeleteGroup(e.ctx, service.System, g.ID); err == nil {
		t.Fatal("deletion finished with a membership it could not write")
	}
	cur, err := e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil {
		t.Fatalf("the group must still exist: %v", err)
	}
	if len(cur.Pending) != 1 || !cur.Pending[0].Clear {
		t.Fatalf("record: %+v", cur)
	}
	for _, u := range []*model.User{a, b} {
		if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 0 {
			t.Fatalf("%s still granted the group: %v %v", u.Username, gs, err)
		}
	}
	if ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID); err != nil || len(ids) != 0 {
		t.Fatalf("members: %v %v", ids, err)
	}
	if n, err := e.svc.GroupMemberCount(e.ctx, service.System, cur); err != nil || n != 0 {
		t.Fatalf("count: %d %v", n, err)
	}
	e.svc.Members.S = inner
	if err := e.svc.DeleteGroup(e.ctx, service.System, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Groups.Get(e.ctx, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("group: %v", err)
	}
	// b's record, removed by this deletion, went with the group; a's, removed by the first attempt, is kept out of
	// every index until it expires (model.RemovedMemberRetention), like any removed membership.
	if _, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, b.ID)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("b's membership: %v", err)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, a.ID)); err != nil || m.Active() || m.Index().Expires.IsZero() {
		t.Fatalf("a's membership: %v %+v", err, m)
	}
	if _, n, err := e.svc.Members.List(e.ctx, store.ListQuery{Scope: org.ID, Filters: []store.Filter{{Field: "group_id", Value: g.ID}}}); err != nil || n != 0 {
		t.Fatalf("memberships of the deleted group still indexed: %d %v", n, err)
	}
}

// A removed membership's record is kept (fencing stalled writers) but is out of every index and expires.
func TestRemovedMembershipLeavesIndexes(t *testing.T) {
	e := newEnv(t)
	org := e.org("removed")
	u := e.user(org.ID, "u", model.RoleUser)
	name := "G"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetMembership(e.ctx, service.System, g.ID, u.ID, false); err != nil {
		t.Fatal(err)
	}
	m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID))
	if err != nil || m.Active() || m.Seq != 2 {
		t.Fatalf("record: %v %+v", err, m)
	}
	ix := m.Index()
	if ix.Fields["group_id"] != "" || ix.Fields["user_id"] != "" || ix.Expires.IsZero() {
		t.Fatalf("index of a removed membership: %+v", ix)
	}
	if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 0 {
		t.Fatalf("user's groups: %v %v", gs, err)
	}
	if n, err := e.svc.GroupMemberCount(e.ctx, service.System, g); err != nil || n != 0 {
		t.Fatalf("count: %d %v", n, err)
	}
	// Added back: the same record, live again.
	if err := e.svc.SetMembership(e.ctx, service.System, g.ID, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if m, err = e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || !m.Active() || m.Seq != 3 {
		t.Fatalf("record: %v %+v", err, m)
	}
	if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 1 {
		t.Fatalf("user's groups: %v %v", gs, err)
	}
}

// Concurrent changes of one group from the same copy: exactly one commits, the other is stale, and the record ends
// consistent with the memberships.
func TestConcurrentGroupChangesSerialiseOnTheRecord(t *testing.T) {
	e := newEnv(t)
	org := e.org("concurrent")
	users := make([]string, 6)
	for i := range users {
		users[i] = e.user(org.ID, fmt.Sprintf("u%d", i), model.RoleUser).ID
	}
	name := "G"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, len(users))
	for _, uid := range users {
		go func() {
			_, err := e.svc.ChangeGroup(context.Background(), service.System, g, service.GroupInput{}, []string{uid}, nil)
			errs <- err
		}()
	}
	okCount := 0
	for range users {
		switch err := <-errs; {
		case err == nil:
			okCount++
		case !errors.Is(err, service.ErrStale):
			t.Fatal(err)
		}
	}
	if okCount != 1 {
		t.Fatalf("%d changes from one copy committed", okCount)
	}
	for _, uid := range users { // the rest, retried from the current record
		if err := e.svc.SetMembership(e.ctx, service.System, g.ID, uid, true); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil || len(ids) != len(users) {
		t.Fatalf("members: %v %v", ids, err)
	}
	cur, _ := e.svc.Groups.Get(e.ctx, g.ID)
	if len(cur.Pending) != 0 || cur.Seq != uint64(len(users)) {
		t.Fatalf("record: %+v", cur)
	}
	if n, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil || n != 0 {
		t.Fatalf("housekeeping found work: %d %v", n, err)
	}
}
