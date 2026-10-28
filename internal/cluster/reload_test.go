package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Configuration reloads and resizes on one healthy cluster (BadgerDB). The last scenario grows the cluster to four.
func TestReloadOnOneCluster(t *testing.T) {
	runOn(t, started(t, badgerBackend()),
		scenario{"reload cluster phases", testReloadClusterPhases},
		scenario{"check resize", testCheckResizeInCluster},
		scenario{"cluster key rotation", testClusterKeyRotation},
		scenario{"resize through a reload", testResizeThroughReloadCluster})
}

// A configuration reload reaches every node in two phases and applies nothing unless every node can.
func testReloadClusterPhases(t *testing.T, c *tcluster) {
	type behaviour struct {
		mu        sync.Mutex
		size      int
		checkErr  string
		applyErr  string
		block     chan struct{}
		applied   int
		lastWant  int
		checkRuns int
	}
	bs := make([]*behaviour, 3)
	for i := range bs {
		b := &behaviour{size: 3}
		bs[i] = b
		c.nodes[i].n.SetReloader(func(ctx context.Context, apply bool, want int) ReloadReport {
			b.mu.Lock()
			size, checkErr, applyErr, block := b.size, b.checkErr, b.applyErr, b.block
			b.mu.Unlock()
			if block != nil {
				select {
				case <-block:
				case <-ctx.Done():
				}
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if !apply {
				b.checkRuns++
				return ReloadReport{Size: size, Error: checkErr}
			}
			b.applied++
			b.lastWant = want
			return ReloadReport{Size: size, Error: applyErr, Changes: []string{"keys"}}
		})
	}
	set := func(i int, f func(*behaviour)) { bs[i].mu.Lock(); f(bs[i]); bs[i].mu.Unlock() }
	a := c.nodes[0].n

	reps, err := a.ReloadCluster(bg)
	if err != nil || len(reps) != 3 {
		t.Fatalf("all agree: %v %v", reps, err)
	}
	for i, b := range bs {
		if b.applied != 1 || b.lastWant != 3 {
			t.Errorf("node %d applied %d times, want size %d", i, b.applied, b.lastWant)
		}
	}
	// Different sizes: nothing is applied.
	set(1, func(b *behaviour) { b.size = 4 })
	if _, err := a.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "different sizes") {
		t.Fatalf("%v", err)
	}
	set(1, func(b *behaviour) { b.size = 3; b.checkErr = "unreadable file" })
	if reps, err := a.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "nothing was reloaded") ||
		!strings.Contains(err.Error(), "unreadable file") || len(reps) != 3 {
		t.Fatalf("a node that cannot read its configuration: %v", err)
	}
	if bs[2].applied != 1 {
		t.Fatalf("applied despite a failing check: %d", bs[2].applied)
	}
	// A node that fails to apply is reported, and the others have applied.
	set(1, func(b *behaviour) { b.checkErr = ""; b.applyErr = "no space left" })
	if reps, err := a.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "not every node reloaded") || len(reps) != 3 {
		t.Fatalf("a node that fails to apply: %v %v", reps, err)
	}
	set(1, func(b *behaviour) { b.applyErr = "" })
	// A node that cannot be reached does not answer.
	c.drop(0, 2, true, msgReload)
	reps, err = a.ReloadCluster(bg)
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("an unreachable node: %v %v", reps, err)
	}
	c.drop(0, 2, false, msgReload)
	// A node that is too slow for the caller's patience.
	release := make(chan struct{})
	set(2, func(b *behaviour) { b.block = release })
	ctx, cancel := context.WithTimeout(bg, 400*time.Millisecond)
	defer cancel()
	reps, err = a.ReloadCluster(ctx)
	close(release)
	if err == nil || !strings.Contains(err.Error(), "nothing was reloaded") {
		t.Fatalf("a slow node: %v %v", reps, err)
	}
	var slow bool
	for _, r := range reps {
		slow = slow || strings.Contains(r.Error, "did not answer")
	}
	if !slow {
		t.Fatalf("the slow node is not reported: %+v", reps)
	}
}

func testCheckResizeInCluster(t *testing.T, c *tcluster) {
	a := c.nodes[0].n
	all := c.addrs
	if err := a.CheckResize(3, all); err != nil {
		t.Errorf("the same size: %v", err)
	}
	if err := a.CheckResize(4, all); err == nil || !strings.Contains(err.Error(), "names 2 other nodes") {
		t.Errorf("a size that does not match the peers: %v", err)
	}
	if err := a.CheckResize(1, all[:1]); err == nil || !strings.Contains(err.Error(), "at least 2") {
		t.Errorf("one node: %v", err)
	}
	five := append(append([]string{}, all...), "127.0.0.1:1", "127.0.0.1:2")
	if err := a.CheckResize(5, five); err == nil || !strings.Contains(err.Error(), "one node at a time") {
		t.Errorf("two at once: %v", err)
	}
	if err := a.CheckResize(2, all[:2]); err == nil || !strings.Contains(err.Error(), "shrinking") {
		t.Errorf("shrinking with every node in view: %v", err)
	}
	if err := a.CheckResize(4, append(append([]string{}, all...), "127.0.0.1:1")); err != nil {
		t.Errorf("growing by one with a majority in view: %v", err)
	}
	if changed, err := a.Resize(3, all); err != nil || changed {
		t.Errorf("resize to the same size: %v %v", changed, err)
	}
	if changed, err := a.Resize(5, five); err == nil || changed {
		t.Errorf("an invalid resize: %v %v", changed, err)
	}
}

// ReloadCluster checks every node's configuration first and applies it only if every node can and all name the same
// size; then every node applies it: here a resize from three nodes to four.
func testResizeThroughReloadCluster(t *testing.T, c *tcluster) {
	var mu sync.Mutex
	conf := map[string]int{} // each node's configured cluster.size, by node id
	peers := append([]string(nil), c.addrs...)
	for _, tn := range c.nodes {
		n := tn.n
		conf[n.ID()] = 3
		n.SetReloader(func(_ context.Context, apply bool, want int) ReloadReport {
			mu.Lock()
			size := conf[n.ID()]
			p := peers[:size]
			mu.Unlock()
			r := ReloadReport{Size: size}
			if err := n.CheckResize(size, p); err != nil {
				r.Error = err.Error()
				return r
			}
			if apply {
				if want != size {
					r.Error = "size differs"
					return r
				}
				if changed, err := n.Resize(size, p); err != nil {
					r.Error = err.Error()
				} else if changed {
					r.Changes = []string{"size"}
				}
			}
			return r
		})
	}
	peers = append(peers, clustertest.FreeAddr(t))

	// one node's configuration was not changed: nothing is applied anywhere
	mu.Lock()
	conf[c.nodes[0].n.ID()], conf[c.nodes[1].n.ID()] = 4, 4
	mu.Unlock()
	reps, err := c.nodes[0].n.ReloadCluster(bg)
	if err == nil || len(reps) != 3 {
		t.Fatalf("mismatched configurations: %v %+v", err, reps)
	}
	for _, tn := range c.nodes {
		if tn.n.Size() != 3 {
			t.Fatalf("a node changed to %d although the configurations disagree", tn.n.Size())
		}
	}

	// every configuration names four nodes: all change, the call made on any node
	mu.Lock()
	conf[c.nodes[2].n.ID()] = 4
	mu.Unlock()
	reps, err = c.nodes[2].n.ReloadCluster(bg)
	if err != nil || len(reps) != 3 {
		t.Fatalf("reload: %v %+v", err, reps)
	}
	for _, r := range reps {
		if r.Error != "" || r.Size != 4 || len(r.Changes) != 1 {
			t.Fatalf("report %+v", r)
		}
	}
	c.waitReady()
	for _, tn := range c.nodes {
		if tn.n.Size() != 4 {
			t.Fatalf("size %d after the reload", tn.n.Size())
		}
	}
	// reloading again changes nothing
	if reps, err = c.nodes[1].n.ReloadCluster(bg); err != nil || len(reps[0].Changes) != 0 {
		t.Fatalf("second reload: %v %+v", err, reps)
	}
}

// A node without a quorum to grow into cannot grow the cluster.
func TestCheckResizeGrowNeedsMajorityInView(t *testing.T) {
	n, _ := gnode(t)
	peers := append(append([]string{}, n.cfg.Cluster.Peers...), "127.0.0.1:1")
	if err := n.CheckResize(4, peers); err == nil || !strings.Contains(err.Error(), "needs 3 of them in view") {
		t.Fatalf("%v", err)
	}
}

func TestHandleReloadAndReloadStandalone(t *testing.T) {
	n, _ := hnode(t)
	if r := n.Reload(bg); r.Error == "" || r.Node != n.ID() {
		t.Fatalf("without a reloader: %+v", r)
	}
	if _, err := n.handleReload(nil, badPacket(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	var calls atomic.Int32
	var lastApply atomic.Bool
	fail := ""
	n.SetReloader(func(_ context.Context, apply bool, want int) ReloadReport {
		calls.Add(1)
		lastApply.Store(apply)
		return ReloadReport{Size: want, Error: fail, Changes: []string{"x"}}
	})
	r, err := n.handleReload(nil, packetOf(t, &reloadReq{Apply: true, Want: 3}))
	if err != nil {
		t.Fatal(err)
	}
	if rep := r.(*ReloadReport); rep.Size != 3 || rep.Node != n.ID() || !lastApply.Load() {
		t.Fatalf("%+v", rep)
	}
	if reps, err := n.ReloadCluster(bg); err != nil || len(reps) != 1 || reps[0].Node != n.ID() {
		t.Fatalf("standalone reload: %v %v", reps, err)
	}
	fail = "bad config"
	if reps, err := n.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "bad config") || len(reps) != 1 {
		t.Fatalf("a failing reload: %v %v", reps, err)
	}
}

// A running cluster grows from 3 nodes to 4 and shrinks back to 3 without a restart, one node at a time: grown, the
// three nodes keep a majority of four and the new node copies from them; shrunk, the node that left was stopped
// first. While only some nodes have changed, the nodes of a size fewer than a majority share do not serve; a shrink
// before the leaving node stopped is refused.
func TestResizeGrowAndShrink(t *testing.T) {
	c := started(t, badgerBackend())
	three := append([]string(nil), c.addrs...)
	write := func(tn *tnode) string {
		t.Helper()
		id := model.NewID()
		if err := tn.st().Put(bg, newRec(id, "")); err != nil {
			t.Fatalf("write on a %d-node cluster: %v", tn.n.Size(), err)
		}
		return id
	}
	before := write(c.nodes[0])

	// grow: every node's configuration names the fourth node, and each reloads (the steps that are refused:
	// testCheckResizeInCluster)
	c.addrs = append(c.addrs, clustertest.FreeAddr(t))
	if changed, err := c.nodes[0].n.Resize(4, c.addrs); err != nil || !changed {
		t.Fatalf("resize node 0: %v %v", changed, err)
	}
	// node 0 alone has the new size: it is the one that refuses; nodes 1 and 2 are a majority of theirs
	waitFor(t, 10*time.Second, "node 0 to refuse while the others have the old size", func() bool {
		ok, _ := c.nodes[0].n.Ready()
		return !ok && !c.nodes[0].n.Writable()
	})
	for _, tn := range c.nodes[1:] {
		if _, err := tn.n.Resize(4, c.addrs); err != nil {
			t.Fatal(err)
		}
	}
	c.waitReady()
	for _, tn := range c.nodes {
		if tn.n.Size() != 4 || tn.n.Quorum() != 3 {
			t.Fatalf("grown: size %d, quorum %d", tn.n.Size(), tn.n.Quorum())
		}
	}
	grown := write(c.nodes[1])
	fourth := c.build(3, "", nil)
	c.nodes = append(c.nodes, fourth)
	c.start(fourth)
	c.waitReady()
	waitFor(t, 20*time.Second, "the new node to copy", func() bool { return has(fourth.st(), before) && has(fourth.st(), grown) })

	// shrink: refused while the node that leaves is still running
	if err := c.nodes[0].n.CheckResize(3, three); err == nil || !strings.Contains(err.Error(), "stop the node") {
		t.Fatalf("shrink with four running: %v", err)
	}
	stop(fourth)
	c.nodes = c.nodes[:3]
	waitFor(t, 20*time.Second, "the fourth node to be gone", func() bool {
		for _, tn := range c.nodes {
			if tn.n.mem.Load().alive != 3 {
				return false
			}
			for _, mb := range tn.n.mem.Load().all {
				if mb.id == fourth.n.ID() && mb.state == gossip.NodeSuspect {
					return false // (wait until it is known dead)
				}
			}
		}
		return true
	})
	for _, tn := range c.nodes {
		if _, err := tn.n.Resize(3, three); err != nil {
			t.Fatal(err)
		}
	}
	c.waitReady()
	for _, tn := range c.nodes {
		if tn.n.Size() != 3 || tn.n.Quorum() != 2 {
			t.Fatalf("shrunk: size %d, quorum %d", tn.n.Size(), tn.n.Quorum())
		}
	}
	shrunk := write(c.nodes[2])
	waitFor(t, 20*time.Second, "a leader", func() bool {
		for _, tn := range c.nodes {
			if tn.n.IsLeader() {
				return true
			}
		}
		return false
	})
	// a node can now be lost, as in any three-node cluster
	stop(c.nodes[2])
	c.nodes = c.nodes[:2]
	waitFor(t, 20*time.Second, "two nodes writable", func() bool { return c.nodes[0].n.Writable() && c.nodes[1].n.Writable() })
	write(c.nodes[0])
	if !has(c.nodes[0].st(), shrunk) && !has(c.nodes[1].st(), shrunk) {
		t.Fatal("a write of the shrunk cluster is on neither remaining node")
	}
}

// The cluster grows from three nodes to four while writers keep writing, then, with one node down, to five (the four
// running nodes' majority of five is in view: three), and the new node copies from the others; the node that was down
// returns with the new size. Every write that was confirmed is on every node, and every node holds the same data.
func TestResizeWithWritesInFlightAndANodeDown(t *testing.T) {
	c := started(t, sqliteBackend())
	c.waitOwners()

	var confirmed sync.Map
	var stopWriters atomic.Bool
	var wg sync.WaitGroup
	var wrote atomic.Int64
	for _, tn := range []*tnode{c.nodes[0], c.nodes[2]} { // (nodes 0 and 2 stay up throughout)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; !stopWriters.Load(); k++ {
				rec := newOrgRec(fmt.Sprintf("org-%d-%d", tn.idx, k%8))
				switch err := tn.st().Put(bg, rec); {
				case err == nil:
					confirmed.Store(rec.ID, true)
					wrote.Add(1)
				case errors.Is(err, store.ErrUnavailable), errors.Is(err, store.ErrUnconfirmed):
					time.Sleep(20 * time.Millisecond) // the sizes disagree for a moment, a partition changes hands
				default:
					t.Errorf("writer on node %d: %v", tn.idx, err)
					return
				}
			}
		}()
	}
	waitWrites := func(more int64) {
		t.Helper()
		from := wrote.Load()
		waitFor(t, 30*time.Second, "writes to go on", func() bool { return wrote.Load() >= from+more })
	}
	resize := func(size int, nodes ...*tnode) {
		t.Helper()
		for _, tn := range nodes {
			if _, err := tn.n.Resize(size, c.addrs); err != nil {
				t.Fatalf("resize node %d to %d: %v", tn.idx, size, err)
			}
		}
	}
	waitWrites(10)

	// grow to four, writers running
	c.addrs = append(c.addrs, clustertest.FreeAddr(t))
	resize(4, c.nodes...)
	c.nodes = append(c.nodes, c.build(3, "", nil))
	c.start(c.nodes[3])
	c.waitReady()
	waitWrites(10)

	// node 1 goes down; grow to five without it
	stop(c.nodes[1])
	running := []*tnode{c.nodes[0], c.nodes[2], c.nodes[3]}
	c.addrs = append(c.addrs, clustertest.FreeAddr(t))
	waitFor(t, 20*time.Second, "node 1 gone from view", func() bool {
		for _, tn := range running {
			if tn.n.mem.Load().alive != 3 {
				return false
			}
		}
		return true
	})
	resize(5, running...)
	c.nodes = append(c.nodes, c.build(4, "", nil))
	c.start(c.nodes[4])
	c.waitReady(append(running, c.nodes[4])...)
	waitWrites(10)

	// node 1 returns, configured for five
	c.nodes[1] = c.build(1, c.nodes[1].dir, nil)
	c.start(c.nodes[1])
	c.waitReady()
	waitWrites(10)
	stopWriters.Store(true)
	wg.Wait()

	var ids []string
	confirmed.Range(func(k, _ any) bool { ids = append(ids, k.(string)); return true })
	waitFor(t, 30*time.Second, "every confirmed write on every node", func() bool { return allHold(c.nodes, ids) })
	waitFor(t, 30*time.Second, "every node at the same position", func() bool { return committedEqual(c.nodes) })
	// (a node that has not heard a partition's owner since the resize refuses to list it for a moment: that is waited
	// out, a difference is not)
	var same bool
	waitFor(t, 30*time.Second, "every node to list its data", func() bool {
		var err error
		same, err = compareData(c.nodes)
		if err != nil && !errors.Is(err, store.ErrUnavailable) {
			t.Fatal(err)
		}
		return err == nil
	})
	if !same {
		t.Fatal("the nodes hold different data")
	}
}

// A cluster key rotation on a running cluster, in the three documented rounds (every node: add the new key as a
// previous one; every node: make it current with the old one previous; every node: drop the old one). Gossip keeps
// replicating after every round. (A key set without the key in use is refused: TestSetClusterKeysOnGossipNode.)
func testClusterKeyRotation(t *testing.T, c *tcluster) {
	old, next := c.key, testKey()

	replicates := func(step string) {
		t.Helper()
		id := model.NewID()
		if err := c.nodes[0].st().Put(bg, newRec(id, "")); err != nil {
			t.Fatalf("%s: write: %v", step, err)
		}
		waitFor(t, 15*time.Second, step+": replication", func() bool {
			for _, tn := range c.nodes {
				if r, err := tn.st().Get(bg, dataKind, id); err != nil || r == nil {
					return false
				}
			}
			return true
		})
	}
	replicates("before")
	rounds := []struct {
		key  string
		prev []string
	}{{old, []string{next}}, {next, []string{old}}, {next, nil}}
	for i, r := range rounds {
		for _, tn := range c.nodes {
			if changed, err := tn.n.SetClusterKeys(r.key, r.prev); err != nil || !changed {
				t.Fatalf("round %d: %v %v", i+1, changed, err)
			}
		}
		replicates("round " + string(rune('1'+i)))
	}
	if ids := c.nodes[1].n.Status().ClusterKeys; len(ids) != 1 {
		t.Fatalf("keys after the rotation: %v", ids)
	}
	if changed, err := c.nodes[1].n.SetClusterKeys(next, nil); err != nil || changed {
		t.Fatalf("the same keys again: %v %v", changed, err)
	}
	c.key = next
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
