package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// fakeForceNode is a node with a forced start pending.
type fakeForceNode struct {
	writable atomic.Bool
	audited  atomic.Int64
}

func (f *fakeForceNode) ID() string     { return "node-1" }
func (f *fakeForceNode) Writable() bool { return f.writable.Load() }
func (f *fakeForceNode) PendingForceStart() (time.Time, string, bool) {
	return time.Now().Add(-time.Minute), "forced", true
}
func (f *fakeForceNode) ForceStartAudited() { f.audited.Add(1) }

// auditFailing fails every write of an audit event with err (nil: they succeed).
type auditFailing struct {
	store.Store
	err   error
	tries atomic.Int64
}

func (s *auditFailing) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindAudit {
		s.tries.Add(1)
		if s.err != nil {
			return s.err
		}
	}
	return s.Store.Put(ctx, r)
}

func forceAuditService(t *testing.T, st store.Store) *service.Service {
	t.Helper()
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Server.DataDir = t.TempDir()
	svc := service.New(c, st, sealer)
	if err := svc.Orgs.Create(context.Background(), &model.Org{Name: "primary", Primary: true}); err != nil {
		t.Fatal(err)
	}
	return svc
}

func forceStartEvents(t *testing.T, svc *service.Service) int {
	t.Helper()
	items, _, err := svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range items {
		if e.Action == "cluster.force_start" {
			n++
		}
	}
	return n
}

// A forced start stays pending until its audit event is confirmed stored: one the store refuses, or a stop before the
// node could write, leaves the record pending for the next start.
func TestForcedStartClearedOnlyOnceAudited(t *testing.T) {
	// stored: cleared once, one event
	st := &auditFailing{Store: memstore.New()}
	svc := forceAuditService(t, st)
	node := &fakeForceNode{}
	node.writable.Store(true)
	auditForcedStart(context.Background(), node, svc, 10*time.Millisecond)
	if node.audited.Load() != 1 || forceStartEvents(t, svc) != 1 || st.tries.Load() != 1 {
		t.Fatalf("cleared %d times, %d events, %d tries", node.audited.Load(), forceStartEvents(t, svc), st.tries.Load())
	}

	// refused by the store: not cleared
	st = &auditFailing{Store: memstore.New(), err: errors.New("disk full")}
	svc = forceAuditService(t, st)
	node = &fakeForceNode{}
	node.writable.Store(true)
	auditForcedStart(context.Background(), node, svc, 10*time.Millisecond)
	if node.audited.Load() != 0 || forceStartEvents(t, svc) != 0 {
		t.Fatalf("a refused audit event cleared the pending forced start (%d)", node.audited.Load())
	}

	// not writable until stopped: nothing written, not cleared
	node = &fakeForceNode{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	auditForcedStart(ctx, node, forceAuditService(t, memstore.New()), 10*time.Millisecond)
	if node.audited.Load() != 0 {
		t.Fatal("cleared while the node was never writable")
	}

	// writable, but no primary organization known (not set up, or not copied yet): nothing written, not cleared
	node = &fakeForceNode{}
	node.writable.Store(true)
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	empty := service.New(config.Default(), memstore.New(), sealer)
	auditForcedStart(ctx, node, empty, 10*time.Millisecond)
	if node.audited.Load() != 0 || forceStartEvents(t, empty) != 0 {
		t.Fatal("cleared with no primary organization to record it in")
	}
}
