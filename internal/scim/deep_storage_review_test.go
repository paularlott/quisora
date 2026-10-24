package scim_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

type deepSCIMGroupGate struct {
	store.Store
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (s *deepSCIMGroupGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindGroup && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.resume
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A conditional PATCH racing another node must not undo the other node's successful desired membership.
func TestDeepConditionalSCIMRollbackPreservesConcurrentSuccess(t *testing.T) {
	e := newEnv(t)
	uid := e.mk("deep-member", nil)
	id := e.group("Original")
	path := "/scim/v2/acme/Groups/" + id
	tag := e.do("GET", path, e.admA, nil).Header.Get("ETag")
	gate := &deepSCIMGroupGate{Store: e.Svc.Groups.S, entered: make(chan struct{}), resume: make(chan struct{})}
	e.Svc.Groups.S = gate
	gate.armed.Store(true)
	done := make(chan resp, 1)
	go func() {
		done <- e.do("PATCH", path, e.admA, patchBody(op("add", "members", []any{map[string]any{"value": uid}})), "If-Match", tag)
	}()
	<-gate.entered
	g, err := e.Svc.Groups.Get(e.ctx, id)
	if err != nil {
		close(gate.resume)
		<-done
		t.Fatal(err)
	}
	// Another node has its own SCIM lock; call the same service operation directly to model its concurrent PATCH.
	name := "Concurrent success"
	_, err = e.Svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{DisplayName: &name}, []string{uid}, nil)
	close(gate.resume)
	first := <-done
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != 412 {
		t.Fatalf("first conditional request: %d %s", first.Status, first.Raw)
	}
	got := e.do("GET", path, e.admA, nil)
	if len(got.list("members")) != 1 {
		t.Fatalf("concurrent successful change lost member after failed conditional PATCH: %s", got.Raw)
	}
}
