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

type deepGroupGate struct {
	store.Store
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (s *deepGroupGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindLock && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.resume
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A failed request must not roll back membership a concurrent successful request explicitly retains.
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
	e.svc.Locks.S = gate
	gate.armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, []string{u.ID}, nil)
		done <- err
	}()
	<-gate.entered // the first request is about to take the group's lock; nothing written yet
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
	if _, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil {
		t.Fatalf("successful concurrent change lost its requested membership during another request's rollback: %v", err)
	}
}

type failMemberFor struct {
	store.Store
	userID string
}

func (s failMemberFor) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindMember && strings.HasSuffix(r.ID, s.userID) {
		return errors.New("disk on fire")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A change whose member writes fail part-way is undone: the members written so far go, and the group's record goes
// back to what it was.
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
	e.svc.Members.S = failMemberFor{Store: e.svc.Members.S, userID: bad.ID}
	renamed := "After"
	if _, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{DisplayName: &renamed}, []string{ok.ID, bad.ID}, nil); err == nil {
		t.Fatal("a change whose member write failed succeeded")
	}
	if _, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, ok.ID)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the member written before the failure stayed: %v", err)
	}
	if cur, err := e.svc.Groups.Get(e.ctx, g.ID); err != nil || cur.DisplayName != "Before" {
		t.Errorf("the group's record was not put back: %v %+v", err, cur)
	}
}
