package cluster

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func TestStandalonePassThrough(t *testing.T) {
	n, err := New(tempConfig(t), memstore.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	var hook atomic.Int64
	n.OnChange(func(*store.Record, bool) { hook.Add(1) })
	id := model.NewID()
	if err := n.Store().Put(bg, newRec(id, "")); err != nil || !has(n.Store(), id) || hook.Load() != 1 {
		t.Fatal("standalone put/get/hook")
	}
	eid, err := n.Ephemeral().New(bg, "x", []byte("1"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Ephemeral().Take(bg, "x", eid); err != nil {
		t.Fatal(err)
	}
	if v, _ := n.Ephemeral().Incr(bg, "rl", "k", 2, time.Minute); v != 2 {
		t.Fatal("incr")
	}
	ran := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	go n.RunHousekeeping(ctx, 10*time.Millisecond, func(context.Context) {
		select {
		case ran <- struct{}{}:
		default:
		}
	})
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("housekeeping did not run standalone")
	}
}

// The store passes the backend's optional interfaces through (store.MultiGetter, store.DueLister, store.Snapshotter),
// and falls back, or says it has none, where the backend has none. Standalone, PutReplicated applies a record locally and
// runs the hooks, once per version.
func TestStoreOptionalInterfaces(t *testing.T) {
	t.Run("plain backend", func(t *testing.T) {
		n, cs := hnode(t)
		st := n.Store()
		ids := []string{model.NewID(), model.NewID()}
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
	})
	for _, b := range localBackends() {
		t.Run(b.name, func(t *testing.T) {
			st := b.open(t, t.TempDir())
			n, err := New(tempConfig(t), st, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { n.Close(); st.Close() }()
			s := n.Store()
			id := model.NewID()
			if err := s.Put(bg, newRec(id, "")); err != nil {
				t.Fatal(err)
			}
			if got, err := s.GetMany(bg, dataKind, []string{id, "missing"}); err != nil || len(got) != 1 {
				t.Fatalf("GetMany: %v %v", got, err)
			}
			_, dues := st.(store.DueLister) // (BadgerDB keeps a due index; SQLite has none)
			if _, err := s.ListDue(bg, dataKind, time.Now().Add(time.Hour), 10); dues && err != nil ||
				!dues && !errors.Is(err, store.ErrNoDueIndex) {
				t.Fatalf("ListDue: %v", err)
			}
			_, snapshots := st.(store.Snapshotter) // (SQLite reads from a point in time; BadgerDB has no such view)
			if view, err := s.Snapshot(bg); snapshots && err == nil {
				view.Close()
			} else if snapshots || !errors.Is(err, store.ErrNoSnapshot) {
				t.Fatalf("Snapshot: %v", err)
			}
			fired := 0
			n.OnChange(func(*store.Record, bool) { fired++ })
			rec := newRec(model.NewID(), "")
			if applied, err := s.PutReplicated(bg, rec); err != nil || !applied || fired != 1 {
				t.Fatalf("PutReplicated: %v %v %d", applied, err, fired)
			}
			if applied, err := s.PutReplicated(bg, rec); err != nil || applied || fired != 1 {
				t.Fatalf("the same version again: %v %v %d", applied, err, fired)
			}
			if _, err := s.Purge(bg, time.Now(), time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Without gossip (standalone, or nodes sharing a database) the node's own database is the latest copy: a fresh read is
// a local one, tombstones included, with or without a partition key.
func TestFreshReadsWithoutGossip(t *testing.T) {
	for name, n := range map[string]*Node{"standalone": func() *Node { n, _ := hnode(t); return n }(),
		"shared database": snode(t, memstore.New())} {
		st := n.Store()
		live, gone := newRec(model.NewID(), ""), newRec(model.NewID(), "")
		for _, r := range []*store.Record{live, gone} {
			if err := st.Put(bg, r); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.Put(bg, store.Tombstone(dataKind, gone.ID)); err != nil {
			t.Fatal(err)
		}
		ids := []string{live.ID, gone.ID, "missing"}
		for _, key := range []string{"", "org1", "org-other"} {
			got, err := st.FreshIn(bg, dataKind, key, ids)
			if err != nil || len(got) != 2 || got[live.ID] == nil || got[live.ID].Deleted || got[gone.ID] == nil || !got[gone.ID].Deleted {
				t.Fatalf("%s, key %q: %v %v", name, key, got, err)
			}
		}
	}
}

// A write the backend refuses leaves nothing noted for the hooks, and is reported as it is.
func TestStoreWriteFailureIsReported(t *testing.T) {
	n, cs := hnode(t)
	cs.put = errors.New("disk full")
	fired := 0
	n.OnChange(func(*store.Record, bool) { fired++ })
	rec := newRec(model.NewID(), "")
	if err := n.Store().Put(bg, rec); err == nil || fired != 0 {
		t.Fatalf("%v, hooks %d", err, fired)
	}
	del := &store.Record{Kind: dataKind, ID: rec.ID, Version: store.Clock.Now(), Deleted: true}
	if err := n.Store().Put(bg, del); err == nil {
		t.Fatal("a failing deletion was reported done")
	}
}

func TestRunPurgeRemovesOldTombstones(t *testing.T) {
	n, cs := hnode(t)
	old := store.Tombstone(dataKind, "old")
	old.Version = hlc.FromTime(time.Now().Add(-3 * time.Hour))
	if _, err := cs.Store.PutReplicated(bg, old); err != nil {
		t.Fatal(err)
	}
	fresh := store.Tombstone(dataKind, "fresh")
	if _, err := cs.Store.PutReplicated(bg, fresh); err != nil {
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

func TestCheckResizeAndResizeStandalone(t *testing.T) {
	n, _ := hnode(t)
	if err := n.CheckResize(0, nil); err != nil {
		t.Error(err)
	}
	if err := n.CheckResize(3, nil); err == nil || !strings.Contains(err.Error(), "applies only with cluster.bind") {
		t.Errorf("%v", err)
	}
	if changed, err := n.Resize(0, nil); err != nil || changed {
		t.Errorf("%v %v", changed, err)
	}
	if changed, err := n.Resize(3, nil); err == nil || changed {
		t.Errorf("%v %v", changed, err)
	}
	if sign(-3) != -1 || sign(4) != 1 || sign(0) != 1 {
		t.Error("sign")
	}
	if _, err := n.SetClusterKeys(testKey(), nil); err == nil || !strings.Contains(err.Error(), "not clustering") {
		t.Errorf("%v", err)
	}
	if n.ClusterKeyIDs() != nil {
		t.Error("a standalone node has no cluster keys")
	}
}

func TestNodeAccessors(t *testing.T) {
	n, _ := hnode(t)
	if !n.Standalone() || n.cfg.Replicate() {
		t.Error("standalone or replicating")
	}
	if n.Prefix() == "" || n.Prefix() != PrefixOf(n.ID()) {
		t.Errorf("prefix %q", n.Prefix())
	}
	if n.EphemeralStore() != ephemeral.Store(n.Ephemeral()) || n.Ephemeral().Local() == nil {
		t.Error("ephemeral store")
	}
}
