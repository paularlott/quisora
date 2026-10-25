package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// gnode is a gossip node over a failing store that is built but never started: its state is what New makes it, and
// nothing in the background changes it while a test drives the methods.
func gnode(t *testing.T) (*Node, *covStore) {
	t.Helper()
	cs := &covStore{Store: memstore.New()}
	c := newTCluster(t, 3, func(testing.TB, string) store.Store { return cs })
	tn := c.build(0, "", nil)
	t.Cleanup(func() { tn.n.Close() })
	return tn.n, cs
}

func TestStoreOptionalInterfacesOnPlainBackend(t *testing.T) {
	n, cs := hnode(t)
	st := n.Store()
	ids := []string{newID(), newID()}
	if err := st.Put(bg, newRec(ids[0], "")); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetMany(bg, dataKind, append(ids, "missing"))
	if err != nil || len(got) != 1 || got[0].ID != ids[0] {
		t.Fatalf("GetMany without MultiGetter: %v %v", got, err)
	}
	cs.get = errors.New("disk")
	if _, err := st.GetMany(bg, dataKind, ids); err == nil {
		t.Fatal("GetMany swallowed a store error")
	}
	cs.get = nil
	if _, err := st.ListDue(bg, dataKind, time.Now(), 10); !errors.Is(err, store.ErrNoDueIndex) {
		t.Fatalf("ListDue: %v", err)
	}
	if _, err := st.Snapshot(bg); !errors.Is(err, store.ErrNoSnapshot) {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.Inner() != store.Store(cs) {
		t.Fatal("Inner")
	}
}

func TestStoreOptionalInterfacesOnBadger(t *testing.T) {
	st := badgerBackend(t, t.TempDir())
	n, err := New(tempConfig(t), st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { n.Close(); st.Close() }()
	s := n.Store()
	id := newID()
	if err := s.Put(bg, newRec(id, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMany(bg, dataKind, []string{id, "missing"}); err != nil || len(got) != 1 {
		t.Fatalf("GetMany: %v %v", got, err)
	}
	if _, err := s.ListDue(bg, dataKind, time.Now().Add(time.Hour), 10); err != nil {
		t.Fatalf("ListDue: %v", err)
	}
	if view, err := s.Snapshot(bg); err == nil {
		view.Close()
	} else if !errors.Is(err, store.ErrNoSnapshot) {
		t.Fatalf("Snapshot: %v", err)
	}
	if recs, next, err := s.Changes(bg, 0, 10); err != nil || len(recs) == 0 || next == 0 {
		t.Fatalf("Changes: %d %d %v", len(recs), next, err)
	}
	// PutReplicated applies locally and fires the hooks, as a replica from a peer does.
	fired := 0
	n.OnChange(func(*store.Record, bool) { fired++ })
	rec := newRec(newID(), "")
	if applied, _, err := s.PutReplicated(bg, rec); err != nil || !applied || fired != 1 {
		t.Fatalf("PutReplicated: %v %v %d", applied, err, fired)
	}
	if applied, _, err := s.PutReplicated(bg, rec); err != nil || applied || fired != 1 {
		t.Fatalf("the same version again: %v %v %d", applied, err, fired)
	}
	if _, err := s.Purge(bg, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
}

// A write the backend refuses leaves nothing noted for the hooks, and is reported as it is.
func TestStoreWriteFailureIsReported(t *testing.T) {
	n, cs := hnode(t)
	cs.put = errors.New("disk full")
	fired := 0
	n.OnChange(func(*store.Record, bool) { fired++ })
	rec := newRec(newID(), "")
	if err := n.Store().Put(bg, rec); err == nil || fired != 0 {
		t.Fatalf("%v, hooks %d", err, fired)
	}
	del := &store.Record{Kind: dataKind, ID: rec.ID, Version: store.Clock.Now(), Deleted: true}
	if err := n.Store().Put(bg, del); err == nil {
		t.Fatal("a failing deletion was reported done")
	}
}

func TestApplyBatchWithoutBatchBackend(t *testing.T) {
	n, cs := hnode(t)
	s := n.Store()
	a, b := newRec(newID(), ""), newRec(newID(), "")
	if err := s.applyBatch(bg, []*store.Record{a, b}); err != nil {
		t.Fatal(err)
	}
	if !has(s, a.ID) || !has(s, b.ID) {
		t.Fatal("records of the page not applied")
	}
	cs.putRepl = errors.New("disk")
	if err := s.applyBatch(bg, []*store.Record{newRec(newID(), "")}); err == nil {
		t.Fatal("a failing apply was not reported")
	}
	cs.putRepl = nil
	// Node-local kinds that reached a feed are never applied.
	loc := &store.Record{Kind: model.KindEphemeral, ID: "e", Version: store.Clock.Now(), Data: []byte("x")}
	if applied, err := s.applyReplica(bg, loc); err != nil || applied {
		t.Fatalf("%v %v", applied, err)
	}
}

func TestCreatedOf(t *testing.T) {
	u := newUser("org1", "created-of")
	rec := mustEncode(t, u)
	if c, ok := createdOf(rec); !ok || c.IsZero() {
		t.Fatalf("%v %v", c, ok)
	}
	if _, ok := createdOf(&store.Record{Kind: model.KindUser, Data: []byte("junk")}); ok {
		t.Fatal("undecodable data has a creation time")
	}
	if _, ok := createdOf(&store.Record{Kind: "bogus"}); ok {
		t.Fatal("unknown kind has a creation time")
	}
}

func TestRunPurgeRemovesOldTombstones(t *testing.T) {
	n, cs := hnode(t)
	old := store.Tombstone(dataKind, "old")
	old.Version = hlc.FromTime(time.Now().Add(-3 * time.Hour))
	if _, _, err := cs.Store.PutReplicated(bg, old); err != nil {
		t.Fatal(err)
	}
	fresh := store.Tombstone(dataKind, "fresh")
	if _, _, err := cs.Store.PutReplicated(bg, fresh); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { n.RunPurge(ctx, 10*time.Millisecond); close(done) }()
	waitFor(t, 5*time.Second, "the old tombstone to be purged", func() bool {
		_, err := cs.Store.Lookup(bg, dataKind, "old")
		return errors.Is(err, store.ErrNotFound)
	})
	if _, err := cs.Store.Lookup(bg, dataKind, "fresh"); err != nil {
		t.Fatalf("a tombstone within the retention was purged: %v", err)
	}
	cs.purge = errors.New("disk") // logged, not fatal
	n.purgeOnce(bg, time.Now())
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunPurge did not stop")
	}
}

// A gossip node purges only once it holds what its peers hold, and keeps tombstones for the retention.
func TestPurgeOnceWaitsForCatchUp(t *testing.T) {
	n, cs := gnode(t)
	tomb := func(id string, age time.Duration) {
		r := store.Tombstone(dataKind, id)
		r.Version = hlc.FromTime(time.Now().Add(-age))
		if _, _, err := cs.Store.PutReplicated(bg, r); err != nil {
			t.Fatal(err)
		}
	}
	gone := func(id string) bool {
		_, err := cs.Store.Lookup(bg, dataKind, id)
		return errors.Is(err, store.ErrNotFound)
	}
	tomb("old", 30*24*time.Hour)
	tomb("young", time.Hour)
	for name, set := range map[string]func(){
		"bootstrap":  func() { n.bootstrap.Store(true) },
		"catchingUp": func() { n.bootstrap.Store(false); n.catchingUp.Store(true) },
		"behind": func() {
			n.catchingUp.Store(false)
			why := "behind"
			n.behind.Store(&why)
		},
	} {
		set()
		n.purgeOnce(bg, time.Now())
		if gone("old") {
			t.Fatalf("purged while %s", name)
		}
	}
	n.behind.Store(nil)
	n.purgeOnce(bg, time.Now())
	if !gone("old") || gone("young") {
		t.Fatalf("old purged %v, young purged %v", gone("old"), gone("young"))
	}
}

func TestGossipNodeEphemeralWithoutOwner(t *testing.T) {
	n, _ := gnode(t)
	e := n.Ephemeral()
	// Nothing serves yet (this node has no quorum), so hash-routed state has no owner and everything fails closed.
	if _, err := e.Incr(bg, "rl", "k", 1, time.Minute); !errors.Is(err, errNoOwner) {
		t.Errorf("Incr: %v", err)
	}
	if err := e.Set(bg, "ns", "plain-id", []byte("v"), time.Minute); !errors.Is(err, errNoOwner) {
		t.Errorf("Set: %v", err)
	}
	if _, err := e.Get(bg, "ns", "plain-id"); !errors.Is(err, errNoOwner) {
		t.Errorf("Get: %v", err)
	}
	if _, err := e.Take(bg, "ns", "plain-id"); !errors.Is(err, errNoOwner) {
		t.Errorf("Take: %v", err)
	}
	if err := e.Delete(bg, "ns", "plain-id"); !errors.Is(err, errNoOwner) {
		t.Errorf("Delete: %v", err)
	}
	if id, local, dead := n.OwnerOf("ns", "plain-id"); id != "" || local || !dead {
		t.Errorf("OwnerOf: %q %v %v", id, local, dead)
	}
	// An id this node minted is owned by it, whatever the cluster looks like.
	id, err := e.New(bg, "ns", []byte("v1"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if owner, local, dead := n.OwnerOf("ns", id); owner != n.ID() || !local || dead {
		t.Errorf("OwnerOf own id: %q %v %v", owner, local, dead)
	}
	if err := e.Set(bg, "ns", id, []byte("v2"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, err := e.Get(bg, "ns", id); err != nil || string(v) != "v2" {
		t.Fatalf("%q %v", v, err)
	}
	if v, err := e.Take(bg, "ns", id); err != nil || string(v) != "v2" {
		t.Fatalf("%q %v", v, err)
	}
	if err := e.Delete(bg, "ns", id); err != nil {
		t.Fatal(err)
	}
}

func TestSetClusterKeysOnGossipNode(t *testing.T) {
	n, _ := gnode(t)
	current := n.cfg.Cluster.Key
	if changed, err := n.SetClusterKeys(current, nil); err != nil || changed {
		t.Fatalf("the keys in use: %v %v", changed, err)
	}
	if _, err := n.SetClusterKeys("not base64!", nil); err == nil {
		t.Error("a mistyped key was accepted")
	}
	if _, err := n.SetClusterKeys(testKey(), nil); err == nil {
		t.Error("keys that drop the key in use were accepted")
	}
	fresh := testKey()
	if changed, err := n.SetClusterKeys(fresh, []string{current}); err != nil || !changed {
		t.Fatalf("rotation step: %v %v", changed, err)
	}
	if ids := n.ClusterKeyIDs(); len(ids) != 2 {
		t.Fatalf("key ids %v", ids)
	}
	// The next step drops the old key; the new one is in use now, so that is allowed.
	if changed, err := n.SetClusterKeys(fresh, nil); err != nil || !changed {
		t.Fatalf("rotation end: %v %v", changed, err)
	}
	if ids := n.ClusterKeyIDs(); len(ids) != 1 {
		t.Fatalf("key ids %v", ids)
	}
}
