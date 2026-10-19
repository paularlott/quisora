package cluster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

var backends = map[string]backend{"memstore": memBackend, "badger": badgerBackend}

func forBackends(t *testing.T, fn func(t *testing.T, mk backend)) {
	for name, mk := range backends {
		t.Run(name, func(t *testing.T) { fn(t, mk) })
	}
}

func TestConvergence(t *testing.T) {
	forBackends(t, func(t *testing.T, mk backend) {
		c := newTCluster(t, 3, mk)
		c.startAll()
		c.waitReady()

		var ids []string
		for i, tn := range c.nodes {
			for j := range 5 {
				id := newID()
				ids = append(ids, id)
				if err := tn.st().Put(bg, newRec(id, fmt.Sprintf("o|g%d-%d", i, j))); err != nil {
					t.Fatal(err)
				}
			}
		}
		waitFor(t, 15*time.Second, "all records everywhere", func() bool {
			for _, tn := range c.nodes {
				if countAll(tn.st()) != len(ids) {
					return false
				}
			}
			return true
		})
		// Fields keep their types across the wire.
		got, err := c.nodes[2].st().Get(bg, model.KindGroup, ids[0])
		if err != nil {
			t.Fatal(err)
		}
		if got.Fields["n"] != int64(7) || got.Fields["b"] != true || got.Origin != c.nodes[0].n.ID() {
			t.Fatalf("fields/origin not preserved: %#v origin %s", got.Fields, got.Origin)
		}
		if _, ok := got.Fields["created"].(time.Time); !ok {
			t.Fatalf("time field lost: %T", got.Fields["created"])
		}

		// Update on one node, delete on another.
		upd := newRec(ids[0], "o|g0-0")
		upd.Data = []byte("changed")
		if err := c.nodes[1].st().Put(bg, upd); err != nil {
			t.Fatal(err)
		}
		if err := c.nodes[2].st().Put(bg, store.Tombstone(model.KindGroup, ids[1])); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 15*time.Second, "update and delete everywhere", func() bool {
			for _, tn := range c.nodes {
				r, err := tn.st().Get(bg, model.KindGroup, ids[0])
				if err != nil || string(r.Data) != "changed" || has(tn.st(), ids[1]) {
					return false
				}
			}
			return true
		})
	})
}

// A2: records created concurrently on three nodes claiming one unique value converge on the record created first
// keeping it, everywhere; the others are kept (never deleted) without it, and reported (OnConflict).
func TestUniqueConflictConverges(t *testing.T) {
	forBackends(t, func(t *testing.T, mk backend) {
		c := newTCluster(t, 3, mk)
		c.startAll()
		c.waitReady()
		var conflicts atomic.Int64
		for _, tn := range c.nodes {
			tn.n.OnConflict(func(*store.Record) { conflicts.Add(1) })
		}
		ids := make([]string, 3)
		var wg sync.WaitGroup
		for i, tn := range c.nodes {
			ids[i] = newID()
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := tn.st().Put(bg, newRec(ids[i], "o|same-name")); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		waitFor(t, 15*time.Second, "one holder of the value everywhere, every record kept", func() bool {
			var winner string
			for _, tn := range c.nodes {
				r, err := tn.st().GetByUnique(bg, model.KindGroup, "o|same-name")
				if err != nil {
					return false
				}
				if winner == "" {
					winner = r.ID
				} else if winner != r.ID {
					return false
				}
				if countAll(tn.st()) != 3 {
					return false
				}
			}
			return true
		})
		if conflicts.Load() == 0 {
			t.Fatal("OnConflict never fired")
		}
		// The holder is the record created first (lowest Created), the same on every node.
		w, _ := c.nodes[0].st().GetByUnique(bg, model.KindGroup, "o|same-name")
		for _, id := range ids {
			r, _ := c.nodes[0].st().Get(bg, model.KindGroup, id)
			if r == nil {
				t.Fatalf("record %s was deleted over a unique clash", id)
			}
			if id != w.ID && store.KeepsUnique(r.Head(), w.Head(), r.ID, w.ID) {
				t.Fatalf("record %s was created before the holder %s but lost the value", id, w.ID)
			}
		}
	})
}

func TestRestartCatchesUpViaFeed(t *testing.T) {
	forBackends(t, func(t *testing.T, mk backend) {
		c := newTCluster(t, 3, mk)
		c.startAll()
		c.waitReady()
		first := newID()
		if err := c.nodes[0].st().Put(bg, newRec(first, "")); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 10*time.Second, "first record on C", func() bool { return has(c.nodes[2].st(), first) })

		// Stop C and write while it is down. Memstore loses its data on stop, so only the badger run proves the
		// resume; the memstore run proves the full re-pull.
		dir := c.nodes[2].dir
		var persisted store.Store
		if _, isMem := c.nodes[2].st().Inner().(*memstore.Store); isMem {
			persisted = c.nodes[2].st().Inner()
			c.nodes[2].n.Close() // keep the same in-memory store for the "restart"
		} else {
			stop(c.nodes[2])
		}
		var ids []string
		for i := range 20 {
			id := newID()
			ids = append(ids, id)
			if err := c.nodes[i%2].st().Put(bg, newRec(id, "")); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.nodes[1].st().Put(bg, store.Tombstone(model.KindGroup, first)); err != nil {
			t.Fatal(err)
		}

		cfg := c.config(2, dir)
		opt := fastOptions()
		var inner store.Store = persisted
		if inner == nil {
			inner = mk(t, dir)
		}
		n, err := New(cfg, inner, opt)
		if err != nil {
			t.Fatal(err)
		}
		tn := &tnode{n: n, dir: dir, addr: c.addrs[2], cfg: cfg}
		c.nodes[2] = tn
		if n.ID() != c.nodes[0].n.ID() && n.ID() == "" {
			t.Fatal("no node id")
		}
		c.start(tn)
		waitFor(t, 15*time.Second, "C caught up", func() bool {
			for _, id := range ids {
				if !has(tn.st(), id) {
					return false
				}
			}
			return !has(tn.st(), first)
		})
		// Cursors persisted and the node id is stable across restarts.
		tn.n.saveState()
		if _, err := os.Stat(filepath.Join(dir, "cluster-state.json")); err != nil {
			t.Fatal(err)
		}
		if id2, _ := loadNodeID(dir, ""); id2 != tn.n.ID() {
			t.Fatal("node id not persisted")
		}
	})
}

// A node whose disk was lost comes back empty (the documented replacement): it copies everything, deletions
// included, and serves once it has caught up.
func TestEmptyReplacementReceivesEverything(t *testing.T) {
	forBackends(t, func(t *testing.T, mk backend) {
		c := newTCluster(t, 3, mk)
		c.startAll()
		c.waitReady()
		var ids []string
		for i := range 60 {
			id := newID()
			ids = append(ids, id)
			if err := c.nodes[i%3].st().Put(bg, newRec(id, "")); err != nil {
				t.Fatal(err)
			}
		}
		_ = c.nodes[0].st().Put(bg, store.Tombstone(model.KindGroup, ids[0]))
		waitFor(t, 15*time.Second, "replicated", func() bool { return countAll(c.nodes[2].st()) == 59 })
		stop(c.nodes[2])
		c.nodes[2] = c.build(2, "", nil) // a new data directory: empty
		c.start(c.nodes[2])
		n3 := c.nodes[2]
		waitFor(t, 15*time.Second, "replacement has everything", func() bool { return countAll(n3.st()) == 59 })
		c.waitReady(n3)
		if has(n3.st(), ids[0]) {
			t.Fatal("deleted record present on the replacement")
		}
	})
}

func TestFeedIDReset(t *testing.T) {
	c := newTCluster(t, 2, memBackend)
	c.startAll()
	c.waitReady()
	for range 10 {
		if err := c.nodes[0].st().Put(bg, newRec(newID(), "")); err != nil {
			t.Fatal(err)
		}
	}
	a, b := c.nodes[0], c.nodes[1]
	waitFor(t, 10*time.Second, "B synced", func() bool { return countAll(b.st()) == 10 })
	oldFeed := a.st().FeedID()
	waitFor(t, 5*time.Second, "B cursor for A", func() bool { return curOf(b.n, a.n.ID()).Feed == oldFeed })

	// Replace A's store (a restore): new FeedID, same node id. B must restart its cursor from 0.
	dir := a.dir
	stop(a)
	fresh := memstore.New()
	if fresh.FeedID() == oldFeed {
		t.Fatal("feed id should differ")
	}
	n, err := New(c.config(0, dir), fresh, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	a2 := &tnode{n: n, dir: dir, addr: c.addrs[0]}
	c.nodes[0] = a2
	c.start(a2)
	waitFor(t, 15*time.Second, "B reset cursor to A's new feed", func() bool { return curOf(b.n, a2.n.ID()).Feed == fresh.FeedID() })
	// A restored everything from B.
	waitFor(t, 15*time.Second, "A refilled from B", func() bool { return countAll(a2.st()) == 10 })
}

func curOf(n *Node, peer string) cursor {
	p := n.peer(peer)
	p.running <- struct{}{}
	defer func() { <-p.running }()
	return p.cur
}

func TestDurableWrites(t *testing.T) {
	ctx := store.WithDurable(bg)
	t.Run("standalone succeeds immediately", func(t *testing.T) {
		cfg := tempConfig(t)
		n, err := New(cfg, memstore.New(), Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		if err := n.Start(bg); err != nil {
			t.Fatal(err)
		}
		if err := n.Store().Put(ctx, newRec(newID(), "")); err != nil {
			t.Fatal(err)
		}
		if ok, _ := n.Ready(); !ok || !n.Writable() || !n.IsLeader() {
			t.Fatal("standalone must be ready, writable and leader")
		}
	})
	t.Run("acknowledged by a peer", func(t *testing.T) {
		c := newTCluster(t, 3, memBackend)
		c.startAll()
		c.waitReady()
		id := newID()
		if err := c.nodes[0].st().Put(ctx, newRec(id, "")); err != nil {
			t.Fatal(err)
		}
		applied := 0
		for _, tn := range c.nodes[1:] {
			if has(tn.st(), id) {
				applied++
			}
		}
		if applied == 0 {
			t.Fatal("durable write returned without any peer holding the record")
		}
	})
	t.Run("no peer reachable: refused, nothing applied", func(t *testing.T) {
		c := newTCluster(t, 3, memBackend)
		// Only node 0 is started; its peers never answer. It cannot catch up with a majority, so it writes nothing.
		tn := c.build(0, "", nil)
		c.nodes = append(c.nodes, tn)
		c.opts = func(o *Options) { o.JoinWait = 200 * time.Millisecond }
		c.start(tn)
		t.Cleanup(c.closeAll)
		for _, ctx := range []context.Context{ctx, bg} {
			id := newID()
			if err := tn.st().Put(ctx, newRec(id, "")); !errors.Is(err, store.ErrNotWritable) {
				t.Fatalf("a write on a node that cannot reach a majority: %v", err)
			}
			if has(tn.st(), id) {
				t.Fatal("a refused write was applied")
			}
		}
		if tn.n.Status().Unconfirmed != 0 {
			t.Fatalf("unconfirmed writes: %d", tn.n.Status().Unconfirmed)
		}
	})
	t.Run("peers stopped: refused", func(t *testing.T) {
		c := newTCluster(t, 2, memBackend)
		c.startAll()
		c.waitReady()
		stop(c.nodes[1])
		waitFor(t, 15*time.Second, "minority", func() bool { return !c.nodes[0].n.Writable() })
		if err := c.nodes[0].st().Put(ctx, newRec(newID(), "")); !errors.Is(err, store.ErrNotWritable) {
			t.Fatalf("durable write with the peer stopped: %v", err)
		}
	})
	t.Run("majority in view, no acknowledgement: applied, unconfirmed", func(t *testing.T) {
		c := newTCluster(t, 3, memBackend)
		c.startAll()
		c.waitReady()
		c.dropPushes(0) // the peers stay in view but never acknowledge node 0's pushes
		id := newID()
		// applied here, counted as unconfirmed, not an error (the caller must not think it failed)
		if err := c.nodes[0].st().Put(ctx, newRec(id, "")); err != nil {
			t.Fatalf("an unconfirmed durable write returned %v", err)
		}
		if c.nodes[0].n.Status().Unconfirmed != 1 || !has(c.nodes[0].st(), id) {
			t.Fatalf("unconfirmed writes: %d", c.nodes[0].n.Status().Unconfirmed)
		}
		// it still reaches the peers (broadcast, anti-entropy)
		waitFor(t, 15*time.Second, "replicated", func() bool { return has(c.nodes[1].st(), id) && has(c.nodes[2].st(), id) })
	})
}

func TestOldRecordsMerge(t *testing.T) {
	n, err := New(tempConfig(t), memstore.New(), Options{TombstoneRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	s := n.Store()
	old := newRec(newID(), "")
	old.Version = hlc.FromTime(time.Now().Add(-48 * time.Hour))
	if _, err := s.applyReplica(bg, old); err != nil || !has(s, old.ID) {
		t.Fatal("an old record was not applied")
	}
	stale := *old
	stale.Version = hlc.FromTime(time.Now().Add(-72 * time.Hour))
	stale.Data = []byte("older")
	if _, err := s.applyReplica(bg, &stale); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Get(bg, model.KindGroup, old.ID); string(r.Data) == "older" {
		t.Fatal("an older version replaced a newer one")
	}
}

// A node that comes back after days away (within the retention) merges with the others: it receives what it missed
// and keeps (and shares) what it has. Nothing is deleted.
func TestReturningNodeMerges(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	// Nodes 0 and 1 run; node 2 comes back with state saying its last sync was 5 days ago (retention: 7).
	for i := range 2 {
		c.nodes = append(c.nodes, c.build(i, "", nil))
	}
	c.start(c.nodes...)
	t.Cleanup(c.closeAll)
	c.waitReady(c.nodes...)
	ids := writeN(t, c.nodes[0], 25)
	dir := t.TempDir()
	own := newID()
	st := badgerBackend(t, dir) // its database holds a record of its own
	if _, _, err := st.PutReplicated(bg, newRec(own, "")); err != nil {
		t.Fatal(err)
	}
	ps := fmt.Sprintf(`{"last_sync":%d,"cursors":{},"self":%q,"joined":true}`,
		time.Now().Add(-5*24*time.Hour).UnixNano(), st.FeedID())
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), []byte(ps), 0o600); err != nil {
		t.Fatal(err)
	}
	st.Close()
	back := c.build(2, dir, nil)
	c.nodes = append(c.nodes, back)
	c.start(back)
	waitFor(t, 20*time.Second, "returning node merged", func() bool {
		ok, _ := back.n.Ready()
		return ok && holdsAll(back, ids) && has(back.st(), own)
	})
	waitFor(t, 10*time.Second, "its own record shared", func() bool { return has(c.nodes[0].st(), own) && has(c.nodes[1].st(), own) })
}

func TestPrefix(t *testing.T) {
	a, b := PrefixOf(newID()), PrefixOf(newID())
	if len(a) != 8 || a == b {
		t.Fatalf("bad prefixes %q %q", a, b)
	}
	if ephemeral.Owner(a+".xyz") != a {
		t.Fatal("prefix must not contain a dot")
	}
}

func TestPrefixCollisionRefusesToStart(t *testing.T) {
	c := newTCluster(t, 2, memBackend)
	c.opts = func(o *Options) { o.prefix = func(string) string { return "samesame" } }
	c.nodes = []*tnode{c.build(0, "", nil), c.build(1, "", nil)}
	errs := make(chan error, 2)
	for _, tn := range c.nodes {
		go func() { errs <- tn.n.Start(bg) }()
	}
	failed := 0
	for range 2 {
		if err := <-errs; errors.Is(err, ErrPrefixCollision) {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("no node refused to start on a prefix collision")
	}
	t.Cleanup(c.closeAll)
}

func TestStandalonePassThrough(t *testing.T) {
	n, err := New(tempConfig(t), memstore.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	var hook atomic.Int64
	n.OnChange(func(*store.Record, bool) { hook.Add(1) })
	id := newID()
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

// tempConfig is the default configuration with a temporary data directory (not ./data in the source tree).
func tempConfig(t *testing.T) *config.Config {
	c := config.Default()
	c.Server.DataDir = t.TempDir()
	return c
}
