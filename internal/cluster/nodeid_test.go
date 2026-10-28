package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// idNode is a node over the shared database st that is configured with node id id (not started), with its own data
// directory as two machines have.
func idNode(t *testing.T, st store.Store, id string) *Node {
	t.Helper()
	cfg := tempConfig(t)
	cfg.Storage.Backend = "postgres"
	cfg.Cluster.NodeID = id
	n, err := New(cfg, st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// fastLease shortens the lease timing so that a record runs out within a test.
func fastLease(t *testing.T) {
	ttl, renew := leaseTTL, leaseRenew
	leaseTTL, leaseRenew = 600*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { leaseTTL, leaseRenew = ttl, renew })
}

// Two nodes with one node id on one database (a cloned data directory, or one configured id) would each deliver every
// queued item: the second to start refuses, naming the id, while the first keeps serving.
func TestSecondNodeWithTheSameIDRefusesToStart(t *testing.T) {
	fastLease(t)
	st := memstore.New()
	id := uuid.NewString()
	first := idNode(t, st, id)
	if err := first.Start(bg); err != nil {
		t.Fatal(err)
	}
	second := idNode(t, st, id)
	err := second.Start(bg)
	if !errors.Is(err, ErrNodeIDInUse) || !strings.Contains(err.Error(), id) {
		t.Fatalf("the second node with the same id: %v", err)
	}
	time.Sleep(2 * leaseTTL) // the first has renewed its record all the while
	if ok, why := first.Ready(); !ok && strings.Contains(why, "node's id") {
		t.Fatalf("the first node was stopped: %s", why)
	}
	if other := idNode(t, st, uuid.NewString()); other.Start(bg) != nil {
		t.Fatal("a node with another id was refused")
	}
}

// A node that restarts is not refused by its own earlier record: one that shut down released it, and one that was
// killed leaves it to run out (the restart waits for that).
func TestRestartedNodeIsNotRefusedByItsOwnRecord(t *testing.T) {
	fastLease(t)
	st := memstore.New()
	id := uuid.NewString()
	first := idNode(t, st, id)
	if err := first.Start(bg); err != nil {
		t.Fatal(err)
	}
	first.Close()
	began := time.Now()
	if err := idNode(t, st, id).Start(bg); err != nil || time.Since(began) > leaseTTL/2 {
		t.Fatalf("restart after a clean shutdown: %v after %v", err, time.Since(began))
	}

	// a process that was killed: its record stays until it expires
	st = memstore.New()
	rec := &model.Ephemeral{Meta: model.Meta{ID: nodeIDPrefix + id}, Value: []byte("killed-process"), Expires: time.Now().Add(leaseTTL / 2)}
	if err := store.NewTable[model.Ephemeral](st).Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	if err := idNode(t, st, id).Start(bg); err != nil {
		t.Fatalf("restart after a kill: %v", err)
	}
}

// A running node whose id is taken by another process stops serving, and serves again once that has passed.
func TestRunningNodeStopsServingWhileItsIDIsTaken(t *testing.T) {
	st := memstore.New()
	id := uuid.NewString()
	n := idNode(t, st, id)
	n.checkID(bg)
	tbl := n.lease.st
	e, err := tbl.Get(bg, nodeIDPrefix+id)
	if err != nil {
		t.Fatal(err)
	}
	e.Value = []byte("another-process")
	if err := tbl.Update(bg, e); err != nil {
		t.Fatal(err)
	}
	n.checkID(bg)
	if ok, why := n.Ready(); ok || !strings.Contains(why, id) {
		t.Fatalf("a node whose id another process holds: ready %v %q", ok, why)
	}
	if err := tbl.S.CompareAndPut(bg, store.Tombstone(model.KindEphemeral, nodeIDPrefix+id), e.Version); err != nil {
		t.Fatal(err)
	}
	n.checkID(bg)
	if n.foreign.Load() != nil {
		t.Fatal("the node still refuses once the other process is gone")
	}
}
