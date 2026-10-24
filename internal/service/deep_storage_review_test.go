package service_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// deepGroupGate pauses the first write of a group's record (the commit of a change; written against the lease
// design it paused the taking of the group's lock, the equivalent point: nothing is written yet).
type deepGroupGate struct {
	store.Store
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (s *deepGroupGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindGroup && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.resume
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A request that loses the commit to a concurrent successful request fails as stale and touches nothing the
// successful request set.
func TestDeepGroupRollbackPreservesConcurrentSuccess(t *testing.T) {
	e := newEnv(t)
	org := e.org("deep-group")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Original"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	gate := &deepGroupGate{Store: e.svc.Groups.S, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Groups.S = gate
	gate.armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, []string{u.ID}, nil)
		done <- err
	}()
	<-gate.entered // the first request is about to commit; nothing written yet
	fresh, err := e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil {
		close(gate.resume)
		<-done
		t.Fatal(err)
	}
	renamed := "Committed"
	_, err = e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &renamed}, []string{u.ID}, nil)
	close(gate.resume)
	firstErr := <-done
	if err != nil {
		t.Fatalf("concurrent update failed: %v", err)
	}
	if !errors.Is(firstErr, service.ErrStale) {
		t.Fatalf("first update should be stale: %v", firstErr)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || !m.Active() {
		t.Fatalf("successful concurrent change lost its requested membership to a stale request: %v", err)
	}
	if cur, _ := e.svc.Groups.Get(e.ctx, g.ID); cur.DisplayName != renamed || len(cur.Pending) != 0 {
		t.Fatalf("group: %+v", cur)
	}
}

// failRecord fails every compare-and-swap of records whose id ends in suffix.
type failRecord struct {
	store.Store
	suffix string
}

func (s failRecord) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if strings.HasSuffix(r.ID, s.suffix) {
		return errors.New("disk on fire")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A change that fails leaves the group as it was: it can only fail at its commit, the group record's
// compare-and-swap, before which nothing is written (written against the lease design, this failed a membership
// write and checked the undo; a membership write no longer fails a change, see below).
func TestGroupChangeFailingPartWayIsUndone(t *testing.T) {
	e := newEnv(t)
	org := e.org("undo-group")
	ok := e.user(org.ID, "ok", model.RoleUser)
	bad := e.user(org.ID, "bad", model.RoleUser)
	name := "Before"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Groups.S = failRecord{Store: e.svc.Groups.S, suffix: g.ID}
	renamed := "After"
	if _, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{DisplayName: &renamed}, []string{ok.ID, bad.ID}, nil); err == nil {
		t.Fatal("a change whose commit failed succeeded")
	}
	for _, u := range []*model.User{ok, bad} {
		if _, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a membership was written by a change that failed: %v", err)
		}
	}
	if cur, err := e.svc.Groups.Get(e.ctx, g.ID); err != nil || cur.DisplayName != "Before" || len(cur.Pending) != 0 {
		t.Errorf("the group's record changed: %v %+v", err, cur)
	}
}

// A change whose membership write fails after its commit is committed: every reader sees it whole from the record,
// and the membership is written later (the next change of the group, or housekeeping).
func TestGroupChangeCommittedDespiteMembershipWriteFailure(t *testing.T) {
	e := newEnv(t)
	org := e.org("commit-group")
	ok := e.user(org.ID, "ok", model.RoleUser)
	bad := e.user(org.ID, "bad", model.RoleUser)
	name := "Before"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	inner := e.svc.Members.S
	e.svc.Members.S = failRecord{Store: inner, suffix: bad.ID}
	renamed := "After"
	res, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{DisplayName: &renamed}, []string{ok.ID, bad.ID}, nil)
	if err != nil {
		t.Fatalf("a committed change reported failure: %v", err)
	}
	if res.DisplayName != renamed || len(res.Pending) != 1 {
		t.Fatalf("returned group: %+v", res)
	}
	if ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID); err != nil || !equalIDs(ids, sortedIDs(ok.ID, bad.ID)) {
		t.Fatalf("members seen: %v %v", ids, err)
	}
	if gs, err := e.svc.UserGroups(e.ctx, bad); err != nil || len(gs) != 1 {
		t.Fatalf("bad's groups: %v %v", gs, err)
	}
	if _, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, bad.ID)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bad's membership record: %v", err)
	}
	// The next change of the group finishes it.
	e.svc.Members.S = inner
	if err := e.svc.SetMembership(e.ctx, service.System, g.ID, ok.ID, true); err != nil { // a no-op change
		t.Fatal(err)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, bad.ID)); err != nil || !m.Active() {
		t.Fatalf("bad's membership not materialized by the next change: %v", err)
	}
	if cur, _ := e.svc.Groups.Get(e.ctx, g.ID); len(cur.Pending) != 0 {
		t.Fatalf("still pending: %+v", cur.Pending)
	}
}
