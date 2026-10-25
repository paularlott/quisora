package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// snode is a node sharing a database server (not opened: the failing store is given), not started.
func snode(t *testing.T, st store.Store) *Node {
	t.Helper()
	cfg := tempConfig(t)
	cfg.Storage.Backend = "postgres"
	n, err := New(cfg, st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func TestLeaseTickOutcomes(t *testing.T) {
	cs := &covStore{Store: memstore.New()}
	n := snode(t, cs)
	l := n.lease
	if l.reachable() {
		t.Fatal("reachable before any answer")
	}
	if ok, why := n.Ready(); ok || !strings.Contains(why, "not answering") {
		t.Fatalf("a shared node that has not reached its database: %v %q", ok, why)
	}

	// The database fails: no lease, not reachable, the error is reported.
	cs.get = errors.New("db down")
	if err := l.tick(bg); err == nil || l.until.Load() != 0 || l.reachable() {
		t.Fatalf("db down: %v until %d reachable %v", err, l.until.Load(), l.reachable())
	}
	cs.get = nil

	// Another node got there first (the create loses), which is not an error and shows the database answers.
	cs.cas = store.ErrConflict
	if err := l.tick(bg); err != nil || l.held() || !l.reachable() {
		t.Fatalf("lost the race: %v held %v reachable %v", err, l.held(), l.reachable())
	}
	// Any other failure of the write is an error.
	cs.cas = errors.New("disk full")
	if err := l.tick(bg); err == nil {
		t.Fatal("a failing lease write was not reported")
	}
	cs.cas = nil

	// Free: this node takes it, with a fencing token; renewing keeps the token.
	if err := l.tick(bg); err != nil || !l.held() || l.token.Load() == 0 {
		t.Fatalf("take: %v held %v token %d", err, l.held(), l.token.Load())
	}
	token := l.token.Load()
	if !n.IsLeader() {
		t.Fatal("the holder is not the leader")
	}
	if err := l.tick(bg); err != nil || l.token.Load() != token {
		t.Fatalf("renew: %v token %d (was %d)", err, l.token.Load(), token)
	}
	// A renewal that loses to a write by another node is not an error either.
	cs.cas = store.ErrStale
	if err := l.tick(bg); err != nil || l.held() {
		t.Fatalf("stale renewal: %v held %v", err, l.held())
	}
	cs.cas = nil
	if err := l.tick(bg); err != nil || !l.held() {
		t.Fatalf("take again: %v", err)
	}

	// Someone else holds it: this node leads no more.
	e, err := l.st.Get(bg, leaseID)
	if err != nil {
		t.Fatal(err)
	}
	e.Value = []byte("another-node")
	if err := l.st.Update(bg, e); err != nil {
		t.Fatal(err)
	}
	if err := l.tick(bg); err != nil || l.held() || !l.reachable() {
		t.Fatalf("another holder: %v held %v", err, l.held())
	}
	if n.IsLeader() {
		t.Fatal("a node without the lease leads")
	}
}

// A lease record this node cannot read back (or one without a creation version) gives no fencing token, so no lease.
func TestLeaseTickWithoutToken(t *testing.T) {
	cs := &covStore{Store: memstore.New()}
	n := snode(t, cs)
	calls := 0
	cs.getHook = func(r *store.Record, err error) (*store.Record, error) {
		calls++
		if calls == 2 { // the read of the record just created
			cp := *r
			cp.Created = 0
			return &cp, nil
		}
		return r, err
	}
	if err := n.lease.tick(bg); err != nil || n.lease.held() || n.lease.token.Load() != 0 {
		t.Fatalf("%v held %v token %d", err, n.lease.held(), n.lease.token.Load())
	}
}

func TestLeaseReleaseAndFence(t *testing.T) {
	shared := memstore.New()
	a, b := snode(t, shared), snode(t, shared)
	// Not held: nothing to release.
	a.lease.release(bg)
	if err := a.lease.tick(bg); err != nil || !a.IsLeader() {
		t.Fatal(err)
	}
	ctx := a.fence(bg)
	if err := a.fenced(ctx); err != nil {
		t.Fatalf("the holder: %v", err)
	}
	if err := a.fenced(bg); err != nil {
		t.Fatalf("an unfenced context: %v", err)
	}
	a.lease.release(bg)
	if a.IsLeader() {
		t.Fatal("still leader after releasing")
	}
	if err := a.fenced(ctx); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("a fenced write after the release: %v", err)
	}
	// The other node takes over at once.
	if err := b.lease.tick(bg); err != nil || !b.IsLeader() {
		t.Fatalf("b: %v", err)
	}
	// A node that is not the holder keeps its hands off housekeeping: purging is the leader's.
	old := store.Tombstone(dataKind, "t")
	old.Version = store.Clock.Now() - 1
	if _, _, err := shared.PutReplicated(bg, old); err != nil {
		t.Fatal(err)
	}
	a.purgeOnce(bg, time.Now().Add(48*time.Hour))
	if _, err := shared.Lookup(bg, dataKind, "t"); err != nil {
		t.Fatalf("a node without the lease purged: %v", err)
	}
	// A leader whose lease record was taken over since is fenced out of purging too.
	e, _ := b.lease.st.Get(bg, leaseID)
	e.Value = []byte("another-node")
	if err := b.lease.st.Update(bg, e); err != nil {
		t.Fatal(err)
	}
	b.purgeOnce(bg, time.Now().Add(48*time.Hour))
	if _, err := shared.Lookup(bg, dataKind, "t"); err != nil {
		t.Fatalf("a fenced-out leader purged: %v", err)
	}
	// The real holder purges (tombstones are kept an hour on a shared database).
	c := snode(t, shared)
	e.Value = []byte(c.ID())
	if err := b.lease.st.Update(bg, e); err != nil {
		t.Fatal(err)
	}
	if err := c.lease.tick(bg); err != nil || !c.IsLeader() {
		t.Fatalf("c: %v", err)
	}
	c.purgeOnce(bg, time.Now().Add(48*time.Hour))
	if _, err := shared.Lookup(bg, dataKind, "t"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the holder did not purge: %v", err)
	}
}

func TestGossipNodeDatabaseOwnerAndMarkers(t *testing.T) {
	n, cs := gnode(t)
	owner := func() string {
		e, err := store.NewTable[model.Ephemeral](cs.Store).Get(bg, ownerID)
		if err != nil {
			return ""
		}
		return string(e.Value)
	}
	// A database without an owner becomes this node's.
	n.checkOwner(bg)
	if owner() != n.ID() || n.foreign.Load() != nil {
		t.Fatalf("owner %q", owner())
	}
	n.checkOwner(bg) // and stays so
	// One that names another node is refused, and not touched.
	e, _ := store.NewTable[model.Ephemeral](cs.Store).Get(bg, ownerID)
	e.Value = []byte("another-node")
	if err := store.NewTable[model.Ephemeral](cs.Store).Put(bg, e); err != nil {
		t.Fatal(err)
	}
	n.checkOwner(bg)
	if why := n.foreign.Load(); why == nil || !strings.Contains(*why, "another-node") {
		t.Fatalf("foreign database not refused: %v", why)
	}
	// Once it names this node again the refusal lifts.
	e, _ = store.NewTable[model.Ephemeral](cs.Store).Get(bg, ownerID)
	e.Value = []byte(n.ID())
	if err := store.NewTable[model.Ephemeral](cs.Store).Put(bg, e); err != nil {
		t.Fatal(err)
	}
	n.checkOwner(bg)
	if n.foreign.Load() != nil {
		t.Fatal("the refusal stayed")
	}
	// Failing reads and writes of the owner record are logged, not fatal.
	cs.get = errors.New("db down")
	n.checkOwner(bg)
	cs.get = nil
	if err := store.NewTable[model.Ephemeral](cs.Store).Delete(bg, ownerID); err != nil {
		t.Fatal(err)
	}
	cs.put = errors.New("disk full")
	n.checkOwner(bg)
	n.markGossip(bg) // its markers cannot be written either
	cs.put = nil

	// A node without gossip's lease in this database refuses; its lapse lifts the refusal.
	l := store.NewTable[model.Ephemeral](cs.Store)
	if err := l.Put(bg, &model.Ephemeral{Meta: model.Meta{ID: leaseID}, Value: []byte("plain-node"), Expires: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	n.markGossip(bg)
	if why := n.mixed.Load(); why == nil || !strings.Contains(*why, "plain-node") {
		t.Fatalf("mixed database not refused: %v", why)
	}
	if err := l.Delete(bg, leaseID); err != nil {
		t.Fatal(err)
	}
	n.markGossip(bg)
	if n.mixed.Load() != nil {
		t.Fatal("mixed refusal stayed")
	}

	// The other side: a node without gossip meeting a gossip node's marker.
	sh := snode(t, cs.Store)
	if err := l.Put(bg, &model.Ephemeral{Meta: model.Meta{ID: gossipMarkerID}, Value: []byte("gossip-node"), Expires: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	sh.checkNoGossip(bg)
	if why := sh.mixed.Load(); why == nil || !strings.Contains(*why, "gossip-node") {
		t.Fatalf("%v", why)
	}
	if err := l.Delete(bg, gossipMarkerID); err != nil {
		t.Fatal(err)
	}
	sh.checkNoGossip(bg)
	if sh.mixed.Load() != nil {
		t.Fatal("refusal stayed")
	}
}
