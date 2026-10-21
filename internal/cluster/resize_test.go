package cluster

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/store"
)

// A running cluster grows from 3 nodes to 4 and shrinks back to 3 without a restart, one node at a time: grown, the
// three nodes keep a majority of four and the new node copies from them; shrunk, the node that left was stopped
// first. While only some nodes have changed none serves (the sizes disagree), and steps of more than one node, a
// shrink before the leaving node stopped and a peers list that does not match are refused.
func TestResizeGrowAndShrink(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	three := append([]string(nil), c.addrs...)
	write := func(tn *tnode) string {
		t.Helper()
		id := newID()
		if err := tn.st().Put(store.WithDurable(bg), newRec(id, "")); err != nil {
			t.Fatalf("write on a %d-node cluster: %v", tn.n.Size(), err)
		}
		return id
	}
	before := write(c.nodes[0])

	five := append(append([]string(nil), three...), freeAddr(t), freeAddr(t))
	if err := c.nodes[0].n.CheckResize(5, five); err == nil || !strings.Contains(err.Error(), "one node at a time") {
		t.Fatalf("3 to 5 at once: %v", err)
	}
	if err := c.nodes[0].n.CheckResize(4, three); err == nil {
		t.Fatal("size 4 with three peers accepted")
	}

	// grow: every node's configuration names the fourth node, and each reloads
	c.addrs = append(c.addrs, five[3])
	if changed, err := c.nodes[0].n.Resize(4, c.addrs); err != nil || !changed {
		t.Fatalf("resize node 0: %v %v", changed, err)
	}
	waitFor(t, 10*time.Second, "node 1 to see the sizes disagree", func() bool { ok, _ := c.nodes[1].n.Ready(); return !ok })
	if c.nodes[0].n.Writable() {
		t.Fatal("node 0 writable while the sizes disagree")
	}
	for _, tn := range c.nodes[1:] {
		if _, err := tn.n.Resize(4, c.addrs); err != nil {
			t.Fatal(err)
		}
	}
	c.waitReady()
	for _, tn := range c.nodes {
		if tn.n.Size() != 4 || tn.n.Quorum() != 3 || tn.n.le.BaselineSize() != 4 {
			t.Fatalf("grown: size %d, quorum %d, election baseline %d", tn.n.Size(), tn.n.Quorum(), tn.n.le.BaselineSize())
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
		if tn.n.Size() != 3 || tn.n.Quorum() != 2 || tn.n.le.BaselineSize() != 3 {
			t.Fatalf("shrunk: size %d, quorum %d, election baseline %d", tn.n.Size(), tn.n.Quorum(), tn.n.le.BaselineSize())
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

// ReloadCluster checks every node's configuration first and applies it only if every node can and all name the same
// size; then every node applies it.
func TestReloadCluster(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
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
	peers = append(peers, freeAddr(t))

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
