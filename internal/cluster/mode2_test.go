package cluster

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A restarted node serves only once it has caught up: whenever it first reports ready, every record written while
// it was down is already there.
func TestRestartCatchesUpBeforeServing(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.opts = func(o *Options) { o.PageSize = 5 } // a slow catch-up: many small pages
	c.startAll()
	c.waitReady()
	down := c.nodes[2]
	dir := down.dir
	stop(down)
	var ids []string
	for range 2000 {
		id := newID()
		if err := c.nodes[0].st().Put(bg, newRec(id, "")); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	back := c.build(2, dir, nil)
	c.nodes[2] = back
	go func() { _ = back.n.Start(bg) }()
	waitFor(t, 20*time.Second, "restarted node ready", func() bool { ok, _ := back.n.Ready(); return ok })
	for _, id := range ids {
		if !has(back.st(), id) {
			t.Fatal("ready before catching up: a record written while it was down is missing")
		}
	}
}

// A node whose database was replaced by hand (an older copy, of unknown age) refuses to start on it and keeps it.
// Forced ("quisora force-start") while the other nodes serve the cluster's data and synced more recently, it still
// refuses rather than merge a copy that may hold records deleted (and purged) since; emptied, it copies everything.
func TestReplacedDatabaseRefusedUnlessForced(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 100)
	waitFor(t, 10*time.Second, "replicated", func() bool { return holdsAll(c.nodes[2], ids) })
	time.Sleep(time.Second) // the state file records node 2's database
	dir := c.nodes[2].dir
	stop(c.nodes[2])
	if err := os.RemoveAll(filepath.Join(dir, "badger")); err != nil { // the database goes; cluster-state.json stays
		t.Fatal(err)
	}
	old := badgerBackend(t, dir)
	kept := newID()
	if _, _, err := old.PutReplicated(bg, newRec(kept, "")); err != nil {
		t.Fatal(err)
	}
	old.Close()
	back := c.build(2, dir, nil)
	c.nodes[2] = back
	if _, why := back.n.Ready(); !strings.Contains(why, "replaced") {
		t.Fatalf("replaced database: %s", why)
	}
	back.n.Close()
	back.n.Store().Close()
	c.opts = func(o *Options) { o.ForceStart = true }
	back = c.build(2, dir, nil)
	c.opts = nil
	c.nodes[2] = back
	c.start(back)
	// Forced, but the other nodes serve the cluster's data and synced more recently than this node's last sync:
	// its database (of unknown age) is not the newest copy, so it refuses after all instead of merging it in.
	waitFor(t, 20*time.Second, "forced node refuses", func() bool {
		_, why := back.n.Ready()
		return strings.Contains(why, "synced more recently")
	})
	time.Sleep(time.Second)
	if !has(back.st(), kept) || has(c.nodes[0].st(), kept) || has(c.nodes[1].st(), kept) || back.n.ServesTokens() {
		t.Fatal("the refused forced node lost its data, served, or handed it to the others")
	}
	// Emptied, it copies the cluster's data.
	stop(back)
	_ = os.RemoveAll(dir)
	_ = os.MkdirAll(dir, 0o700)
	back = c.build(2, dir, nil)
	c.nodes[2] = back
	c.start(back)
	waitFor(t, 20*time.Second, "emptied node ready with everything", func() bool {
		ok, _ := back.n.Ready()
		return ok && holdsAll(back, ids)
	})
}

// A new node started on a copy of a peer's database (a cloned volume) refuses to serve and wipes nothing — it cannot
// tell a copy from its own database under a lost node id — and offers the copy to nobody; the peer keeps serving.
// Once the operator empties the copy, the node joins and copies everything.
func TestClonedDatabaseRefusedNotWiped(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	for range 50 {
		if err := c.nodes[0].st().Put(bg, newRec(newID(), "")); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 10*time.Second, "replicated", func() bool { return countAll(c.nodes[1].st()) == 50 && countAll(c.nodes[2].st()) == 50 })
	src, dst := c.nodes[1], c.nodes[2]
	stop(src)
	stop(dst)
	if err := os.RemoveAll(filepath.Join(dst.dir, "badger")); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(filepath.Join(src.dir, "badger"), filepath.Join(dst.dir, "badger")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dst.dir, "cluster-state.json")); err != nil {
		t.Fatal(err)
	}
	c.nodes[1] = c.build(1, src.dir, nil)
	c.nodes[2] = c.build(2, dst.dir, nil)
	c.start(c.nodes[1], c.nodes[2])
	c.waitReady(c.nodes[0], c.nodes[1]) // the source and the others serve
	time.Sleep(time.Second)
	if ok, why := c.nodes[2].n.Ready(); ok || !(strings.Contains(why, "belongs to node") || strings.Contains(why, "same database")) {
		t.Fatalf("the node on a copied database: ready=%v %s", ok, why)
	}
	if countAll(c.nodes[2].st()) != 50 {
		t.Fatal("the copied database was changed")
	}
	// the operator empties the copy: the node joins as a new member
	stop(c.nodes[2])
	if err := os.RemoveAll(filepath.Join(dst.dir, "badger")); err != nil {
		t.Fatal(err)
	}
	c.nodes[2] = c.build(2, dst.dir, nil)
	c.start(c.nodes[2])
	c.waitReady()
	if countAll(c.nodes[2].st()) != 50 {
		t.Fatalf("after emptying, %d records copied", countAll(c.nodes[2].st()))
	}
}

func copyDir(from, to string) error {
	return filepath.WalkDir(from, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		target := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
}

// Two gossip nodes on one database: the one that finds the database recorded as the other's refuses to serve and
// offers nothing; nothing is wiped and the other keeps serving it.
func TestGossipNodesSharingADatabaseRefuse(t *testing.T) {
	shared := memstore.New()
	for range 20 {
		_ = shared.Put(bg, newRec(newID(), ""))
	}
	c := newTCluster(t, 2, func(testing.TB, string) store.Store { return shared })
	c.startAll()
	waitFor(t, 15*time.Second, "one refuses", func() bool {
		refusing := 0
		for _, tn := range c.nodes {
			if ok, why := tn.n.Ready(); !ok && (strings.Contains(why, "belongs to node") || strings.Contains(why, "same database")) &&
				!tn.n.Writable() && !tn.n.ServesTokens() {
				refusing++
			}
		}
		return refusing >= 1
	})
	if countAll(shared) != 20 {
		t.Fatalf("records lost: %d of 20", countAll(shared))
	}
}

// A gossip node and a node without gossip on one database both refuse, and serve again once the other has gone.
func TestMixedDatabaseRefused(t *testing.T) {
	oldTTL, oldRenew, oldMargin := leaseTTL, leaseRenew, leaseMargin
	leaseTTL, leaseRenew, leaseMargin = time.Second, 100*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { leaseTTL, leaseRenew, leaseMargin = oldTTL, oldRenew, oldMargin })
	shared := memstore.New()
	// A gossip node (its configured peer never starts) and a node without gossip, on one database.
	c := newTCluster(t, 2, func(testing.TB, string) store.Store { return shared })
	c.nodes = append(c.nodes, c.build(0, "", nil))
	c.start(c.nodes[0])
	t.Cleanup(c.closeAll)
	cfg := tempConfig(t)
	cfg.Storage.Backend = "postgres"
	plain, err := New(cfg, shared, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Start(bg); err != nil {
		t.Fatal(err)
	}
	g := c.nodes[0].n
	waitFor(t, 5*time.Second, "both refuse", func() bool {
		ok1, why1 := g.Ready()
		ok2, why2 := plain.Ready()
		return !ok1 && !ok2 && strings.Contains(why1, "without gossip") && strings.Contains(why2, "with gossip") &&
			!g.Writable() && !plain.Writable()
	})
	plain.Close() // the node without gossip goes (its lease is released)
	waitFor(t, 5*time.Second, "gossip node serves again", func() bool { return g.mixed.Load() == nil })
}

// A durable write returns only once a majority holds it: with five nodes, two peers besides the writer.
func TestDurableWriteReachesMajority(t *testing.T) {
	c := newTCluster(t, 5, memBackend)
	c.startAll()
	c.waitReady()
	for range 5 {
		id := newID()
		if err := c.nodes[0].st().Put(store.WithDurable(bg), newRec(id, "")); err != nil {
			t.Fatal(err)
		}
		held := 0
		for _, tn := range c.nodes[1:] {
			if has(tn.st(), id) {
				held++
			}
		}
		if held < 2 {
			t.Fatalf("durable write returned with %d peers holding it, a majority needs 2", held)
		}
	}
}

// Cut off from the majority, a node keeps serving tokens for cluster.minority_grace, then stops.
func TestMinorityGrace(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	for i := range c.addrs {
		c.nodes = append(c.nodes, c.build(i, "", func(cfg *config.Config) { cfg.Cluster.MinorityGrace = 2 }))
	}
	c.start(c.nodes...)
	t.Cleanup(c.closeAll)
	c.waitReady()
	alone := c.nodes[0].n
	if !alone.ServesTokens() {
		t.Fatal("a healthy node must serve tokens")
	}
	stop(c.nodes[1])
	stop(c.nodes[2])
	waitFor(t, 15*time.Second, "minority", func() bool { return !alone.Writable() })
	lost := time.Now()
	if !alone.ServesTokens() {
		t.Fatal("tokens refused at once; the grace period should apply")
	}
	waitFor(t, 6*time.Second, "grace over", func() bool { return !alone.ServesTokens() })
	if d := time.Since(lost); d < time.Second {
		t.Fatalf("grace ended after %v, want about 2s", d)
	}
}

// A durable write whose request is cancelled (the client went away) mid-write is still a write: it reports success,
// it still waits for the majority, and the majority holds it.
func TestDurableWriteSurvivesCancelledRequest(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	ctx, cancel := context.WithCancel(store.WithDurable(bg))
	cancel() // gone before the write even starts
	id := newID()
	if err := c.nodes[0].st().Put(ctx, newRec(id, "")); err != nil {
		t.Fatalf("a cancelled durable write reported failure after it was applied: %v", err)
	}
	held := 0
	for _, tn := range c.nodes[1:] {
		if has(tn.st(), id) {
			held++
		}
	}
	if held < 1 {
		t.Fatal("the write returned before a majority held it")
	}
}

// LOW–MEDIUM (round 7): a node restarting cannot issue tokens from its old data before it has caught up, grace or
// not: changes made while it was down (a user disabled) may not be here yet.
func TestRestartedNodeServesNoTokensUntilCaughtUp(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	time.Sleep(time.Second)
	for _, tn := range c.nodes {
		stop(tn)
	}
	// only node 0 comes back: it cannot catch up with a majority
	c.nodes[0] = c.build(0, c.nodes[0].dir, nil)
	c.start(c.nodes[0])
	time.Sleep(time.Second)
	if c.nodes[0].n.ServesTokens() {
		t.Fatal("a restarted node issues tokens before catching up")
	}
}
