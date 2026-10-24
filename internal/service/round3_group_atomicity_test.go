package service_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// round3GroupRollbackGate fails every write of one membership (failedMemberID) and pauses the first request once
// its commit (the first write of the group's record) has succeeded, before it writes any membership.
//
// Written against the lease design, where the pause came after the second group write (the undo of a failed
// change). A change now commits on the group's record and is never undone, so the request paused here is committed
// and the later, successful request must materialize it first; the invariant is unchanged: nothing the later
// request explicitly set is erased by the earlier one finishing (or not).
type round3GroupRollbackGate struct {
	store.Store
	groupID, failedMemberID string
	groupWrites             atomic.Int32
	entered, resume         chan struct{}
	resumeOnce              sync.Once
}

func (g *round3GroupRollbackGate) letResume() { g.resumeOnce.Do(func() { close(g.resume) }) }

func (g *round3GroupRollbackGate) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindMember && r.ID == g.failedMemberID {
		return errors.New("review: membership storage failure")
	}
	return g.Store.Put(ctx, r)
}

func (g *round3GroupRollbackGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.Kind == model.KindMember && r.ID == g.failedMemberID {
		return errors.New("review: membership storage failure")
	}
	err := g.Store.CompareAndPut(ctx, r, expected)
	if r.Kind == model.KindGroup && r.ID == g.groupID && err == nil && g.groupWrites.Add(1) == 1 {
		close(g.entered)
		<-g.resume
	}
	return err
}

func TestRound3GroupRollbackCannotEraseLaterSuccessfulMembership(t *testing.T) {
	for _, adding := range []bool{true, false} {
		name := "retain-added-membership"
		if !adding {
			name = "retain-revocation"
		}
		t.Run(name, func(t *testing.T) { round3GroupRollback(t, adding) })
	}
}

func round3GroupRollback(t *testing.T, adding bool) {
	e := newEnv(t)
	org := e.org("rollback-window")
	first := e.user(org.ID, "first", model.RoleUser)
	second := e.user(org.ID, "second", model.RoleUser)
	name := "Original"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	if !adding {
		for _, user := range []*model.User{first, second} {
			if err := e.svc.SetMembership(e.ctx, service.System, group.ID, user.ID, true); err != nil {
				t.Fatal(err)
			}
		}
		group, err = e.svc.Groups.Get(e.ctx, group.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	gate := &round3GroupRollbackGate{Store: e.svc.Store, groupID: group.ID, failedMemberID: model.MemberID(group.ID, second.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	done := make(chan error, 1)
	go func() {
		add, remove := []string{first.ID, second.ID}, []string(nil)
		if !adding {
			add, remove = nil, add
		}
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, add, remove)
		done <- err
	}()
	<-gate.entered // the first request is committed; none of its memberships is written yet
	fresh, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		gate.letResume()
		<-done
		t.Fatal(err)
	}
	renamed := "Concurrent success"
	add, remove := []string{first.ID}, []string(nil)
	if !adding {
		add, remove = nil, add
	}
	_, concurrentErr := e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &renamed}, add, remove)
	gate.letResume()
	failedErr := <-done
	if concurrentErr != nil {
		t.Fatal(concurrentErr)
	}
	if failedErr != nil {
		t.Fatalf("the first request was committed before its membership write failed; it must not report failure: %v", failedErr)
	}
	m, err := e.svc.Members.Get(e.ctx, model.MemberID(group.ID, first.ID))
	if adding && (err != nil || !m.Active()) {
		t.Fatalf("membership explicitly retained by later successful update was erased: %v", err)
	}
	if !adding && err == nil && m.Active() {
		t.Fatal("membership explicitly revoked by later successful update was restored")
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{}; adding {
		want = sortedIDs(first.ID, second.ID) // second is committed, seen until materialized
		if !equalIDs(ids, want) {
			t.Fatalf("members %v, want %v", ids, want)
		}
	} else if len(ids) != 0 {
		t.Fatalf("members %v, want none", ids)
	}
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
