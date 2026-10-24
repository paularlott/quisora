package service_test

import (
	"context"
	"errors"
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
	if r.Kind == model.KindGroup && s.armed.CompareAndSwap(true, false) {
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
	gate.armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, []string{u.ID}, nil)
		done <- err
	}()
	<-gate.entered // membership already written; parent group update is pending
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
