package service_test

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// These tests were written against the lease design (a per-group lock, member writes one by one, an undo on
// failure). Groups now commit on their record (service.ChangeGroup): a change is committed by one compare-and-swap of
// the group's record and its membership records are written afterwards, fenced by sequence. The setups below keep
// each test's invariant and are adapted only where the lease made them meaningful:
//   - there is no lease to outlive, so the first test stalls the writer between its commit and its membership write
//     (where the lease used to lapse) and no longer sleeps out a 30 s lease: the fence is the sequence, not time;
//   - a membership write cannot fail a change any more (the change is committed before it), so "a failed change"
//     is one whose commit fails: the second test injects the failure there, and also checks the other half of the
//     invariant: a committed change whose membership write fails is seen whole, not half;
//   - the third test's metadata update now commits on the same record: the member change it races is committed,
//     never undone, so the invariant checked is that the update neither loses it nor leaves it half-applied.

type freshLeaseStall struct {
	store.Store
	groupID, memberID string
	parentWritten     atomic.Bool
	blocked           atomic.Bool
	entered, resume   chan struct{}
}

func (g *freshLeaseStall) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	err := g.Store.CompareAndPut(ctx, r, expected)
	if err == nil && r.Kind == model.KindGroup && r.ID == g.groupID {
		g.parentWritten.Store(true)
	}
	return err
}
func (g *freshLeaseStall) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	r, err := g.Store.Get(ctx, kind, id)
	if kind == model.KindMember && id == g.memberID && g.parentWritten.Load() && g.blocked.CompareAndSwap(false, true) {
		close(g.entered)
		<-g.resume
	}
	return r, err
}

// A membership operation that committed, then stalled before writing the membership, must not write it after
// another operation committed and materialized a conflicting change (the stalled write is fenced by sequence).
func TestFreshGroupWriteCannotOutliveItsLease(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-lease")
	user := e.user(org.ID, "member", model.RoleUser)
	original := "Original"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &original})
	if err != nil {
		t.Fatal(err)
	}
	gate := &freshLeaseStall{Store: e.svc.Store, groupID: group.ID, memberID: model.MemberID(group.ID, user.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	firstDone := make(chan error, 1)
	firstName := "First operation"
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{DisplayName: &firstName}, []string{user.ID}, nil)
		firstDone <- err
	}()
	<-gate.entered // the first operation is committed and about to write the membership: a delayed store/RPC call
	fresh, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		close(gate.resume)
		<-firstDone
		t.Fatal(err)
	}
	secondName := "Second operation"
	// The second operation finishes the first's pending entry (the user becomes a member), then commits and
	// materializes the removal.
	_, secondErr := e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &secondName}, nil, []string{user.ID})
	close(gate.resume)
	firstErr := <-firstDone
	if secondErr != nil {
		t.Fatalf("replacement operation could not complete: %v", secondErr)
	}
	if firstErr != nil {
		t.Fatalf("the first operation was committed; it must not report failure: %v", firstErr)
	}
	final, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.DisplayName != secondName || len(final.Pending) != 0 {
		t.Fatalf("final group: %+v", final)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(group.ID, user.ID)); err != nil || m.Active() {
		t.Fatalf("stalled operation committed membership after the replacement revoked it: %v %+v", err, m)
	}
	if ids, err := e.svc.GroupMembers(e.ctx, service.System, group.ID); err != nil || len(ids) != 0 {
		t.Fatalf("members: %v %v", ids, err)
	}
}

// freshFaultGate fails every compare-and-swap of a record (failID) while failing is set, pausing the first one
// until the test lets it go.
type freshFaultGate struct {
	store.Store
	failID          string
	failing, paused atomic.Bool
	entered, resume chan struct{}
}

func (g *freshFaultGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.ID == g.failID && g.failing.Load() {
		if g.paused.CompareAndSwap(false, true) {
			close(g.entered)
			<-g.resume
		}
		return errors.New("review: injected write failure")
	}
	return g.Store.CompareAndPut(ctx, r, expected)
}

// Permission lookups must never observe a member of a change that fails: a change fails only at its commit (the
// group record's compare-and-swap), before which nothing is written. A change whose membership write fails after
// the commit is committed: readers see every member of it, never only those written so far.
func TestFreshFailedGroupChangeIsInvisibleToPermissionReaders(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-visibility")
	first := e.user(org.ID, "first", model.RoleUser)
	second := e.user(org.ID, "second", model.RoleUser)
	name := "Privileged group"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	inGroup := func(u *model.User) bool {
		t.Helper()
		gs, err := e.svc.UserGroups(e.ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(gs, func(g *model.Group) bool { return g.ID == group.ID })
	}

	// The commit fails: nothing is visible, during or after.
	gate := &freshFaultGate{Store: e.svc.Store, failID: group.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	gate.failing.Store(true)
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, []string{first.ID, second.ID}, nil)
		done <- err
	}()
	<-gate.entered
	during := inGroup(first)
	close(gate.resume)
	if err := <-done; err == nil {
		t.Fatal("fault did not fail the change")
	}
	if during || inGroup(first) || inGroup(second) {
		t.Fatal("permission reader observed membership from a group change that failed")
	}
	gate.failing.Store(false)

	// A membership write fails after the commit: the change is committed, and seen whole.
	gate2 := &freshFaultGate{Store: e.svc.Store, failID: model.MemberID(group.ID, second.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	gate2.failing.Store(true)
	e.svc.Groups.S = gate2
	e.svc.Members.S = gate2
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, []string{first.ID, second.ID}, nil)
		done <- err
	}()
	<-gate2.entered // first's membership is written, second's write is failing
	firstSeen, secondSeen := inGroup(first), inGroup(second)
	close(gate2.resume)
	if err := <-done; err != nil {
		t.Fatalf("a committed change reported failure: %v", err)
	}
	if !firstSeen || !secondSeen {
		t.Fatalf("committed change seen in part by permission readers: first=%v second=%v", firstSeen, secondSeen)
	}
	gate2.failing.Store(false)
	if n, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil || n != 1 {
		t.Fatalf("housekeeping: %d %v", n, err)
	}
	if g, _ := e.svc.Groups.Get(e.ctx, group.ID); len(g.Pending) != 0 {
		t.Fatalf("still pending: %+v", g.Pending)
	}
	if !inGroup(first) || !inGroup(second) {
		t.Fatal("members lost once materialized")
	}
}

// A metadata edit commits on the same record as a member change: it can neither undo one nor leave it
// half-applied. Racing a member change whose membership write fails, the edit carries the committed change forward,
// and the change stays visible whole until it is materialized.
func TestFreshMetadataUpdateCannotPreventFailedMembershipRollback(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-metadata")
	first := e.user(org.ID, "first", model.RoleUser)
	second := e.user(org.ID, "second", model.RoleUser)
	name := "Original"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	gate := &freshFaultGate{Store: e.svc.Store, failID: model.MemberID(group.ID, second.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	gate.failing.Store(true)
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, []string{first.ID, second.ID}, nil)
		done <- err
	}()
	<-gate.entered
	newName := "Concurrent metadata edit"
	_, metadataErr := e.svc.UpdateGroup(e.ctx, service.System, group.ID, service.GroupInput{DisplayName: &newName})
	close(gate.resume)
	changeErr := <-done
	if metadataErr != nil {
		t.Fatalf("concurrent metadata edit: %v", metadataErr)
	}
	if changeErr != nil {
		t.Fatalf("the committed member change reported failure: %v", changeErr)
	}
	g, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.DisplayName != newName {
		t.Fatalf("metadata edit lost: %q", g.DisplayName)
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, group.ID)
	if err != nil || !slices.Equal(ids, sortedIDs(first.ID, second.ID)) {
		t.Fatalf("committed member change not seen whole after the metadata edit: %v %v (pending %+v)", ids, err, g.Pending)
	}
	for _, u := range []*model.User{first, second} {
		gs, err := e.svc.UserGroups(e.ctx, u)
		if err != nil || len(gs) != 1 || gs[0].ID != group.ID {
			t.Fatalf("user %s groups: %v %v", u.Username, gs, err)
		}
	}
	gate.failing.Store(false)
	if _, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil {
		t.Fatal(err)
	}
	if g, _ = e.svc.Groups.Get(e.ctx, group.ID); len(g.Pending) != 0 {
		t.Fatalf("still pending after housekeeping: %+v", g.Pending)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(group.ID, second.ID)); err != nil || !m.Active() {
		t.Fatalf("second's membership not materialized: %v", err)
	}
}

func sortedIDs(ids ...string) []string {
	slices.Sort(ids)
	return ids
}
