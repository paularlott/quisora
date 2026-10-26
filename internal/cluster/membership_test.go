package cluster

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/store"
)

// Every node lists every member with its address, state and readiness; all agree on one leader, and each marks
// itself.
func testStatusNodes(t *testing.T, c *tcluster) {
	waitFor(t, 15*time.Second, "every node ready, one leader everyone agrees on", func() bool {
		leader := ""
		for _, tn := range c.nodes {
			nodes := tn.n.Status().Nodes
			if len(nodes) != 3 {
				return false
			}
			var leaders []string
			for _, ms := range nodes {
				if !ms.Ready { // peers' readiness arrives by gossip
					return false
				}
				if ms.Leader {
					leaders = append(leaders, ms.ID)
				}
			}
			if len(leaders) != 1 || (leader != "" && leaders[0] != leader) {
				return false
			}
			leader = leaders[0]
		}
		return true
	})
	for _, tn := range c.nodes {
		nodes := tn.n.Status().Nodes
		self := 0
		for i, ms := range nodes {
			if i > 0 && nodes[i-1].ID >= ms.ID {
				t.Fatalf("not in id order: %+v", nodes)
			}
			if ms.State != "alive" || !ms.Ready || ms.Address == "" {
				t.Fatalf("node %s sees %+v", tn.n.ID(), ms)
			}
			if ms.Self {
				self++
				if ms.ID != tn.n.ID() {
					t.Fatalf("node %s marks %s as itself", tn.n.ID(), ms.ID)
				}
			}
		}
		if self != 1 {
			t.Fatalf("node %s marks %d nodes as itself", tn.n.ID(), self)
		}
	}
}

// Membership on one healthy cluster (BadgerDB): what the nodes know of each other, and what they refuse to serve with.
func TestMembershipOnOneCluster(t *testing.T) {
	runOn(t, started(t, badgerBackend()),
		scenario{"status nodes", testStatusNodes},
		scenario{"partitions spread and status", testPartitionsSpreadAndStatus},
		scenario{"incompatible peer refused", testIncompatiblePeerRefused},
		scenario{"unpublished compatibility not judged", testUnpublishedCompatNotJudged},
		scenario{"size mismatch stops only the minority", testSizeMismatchStopsOnlyTheMinority},
		scenario{"restart manager failure leaves no manager", testRestartManagerFailureLeavesNoManager})
}

// Records spread over the partitions by their key, every partition has one owner, and every node counts the same
// committed writes.
func testPartitionsSpreadAndStatus(t *testing.T, c *tcluster) {
	c.waitOwners()
	c.waitSettled()
	var orgs []string
	for i := range 20 {
		org := fmt.Sprintf("spread-%d", i)
		orgs = append(orgs, org)
		writeN(t, c.nodes[i%3], org, 2)
	}
	waitFor(t, 15*time.Second, "every node to hold the same committed writes", func() bool { return committedEqual(c.nodes) })
	seen := map[int]bool{}
	for _, org := range orgs {
		seen[partitionNum(org)] = true
	}
	if len(seen) < 8 {
		t.Fatalf("20 organizations landed on %d partitions", len(seen))
	}
	for _, tn := range c.nodes {
		st := tn.n.Status()
		if len(st.Partitions) != partitions {
			t.Fatalf("status lists %d partitions", len(st.Partitions))
		}
		for _, ps := range st.Partitions {
			if ps.Owner == "" || ps.Epoch == 0 {
				t.Fatalf("partition %d has no owner or epoch in the status of %s: %+v", ps.Partition, tn.n.ID(), ps)
			}
		}
		if st.Writes == 0 {
			t.Fatalf("node %s wrote, and counts no writes: %+v", tn.n.ID(), st)
		}
	}
	// (the statuses are read one after another: a partition changing hands between two reads is counted twice or not at
	// all, so the sum is looked at until it settles)
	waitFor(t, 10*time.Second, "every partition owned by one node, as the statuses say", func() bool {
		owned := 0
		for _, tn := range c.nodes {
			owned += tn.n.Status().PartitionsOwned
		}
		return owned == partitions
	})
}

func TestSizeAndQuorumOfGossipNode(t *testing.T) {
	n, _ := gnode(t)
	if n.Size() != 3 || n.Quorum() != 2 || n.Standalone() {
		t.Fatalf("%d %d", n.Size(), n.Quorum())
	}
	if n.SharedDatabase() {
		t.Fatal("a gossip node does not share a database")
	}
	if n.EphemeralStore() != any(n.Ephemeral()) {
		t.Fatal("ephemeral store")
	}
}

// Every node must be configured with the same cluster.size (one whose size does not match its peers list is refused at
// once: TestNewRefusesBadConfigurations). A node whose cluster.size fewer than a majority of that size share is the
// one configured apart: it refuses to serve, while the nodes of the majority carry on (they log the stranger). Once it
// agrees again it serves.
func testSizeMismatchStopsOnlyTheMinority(t *testing.T, c *tcluster) {
	if st := c.nodes[0].n.Status(); st.Size != 3 || st.Quorum != 2 {
		t.Fatalf("status: size %d quorum %d", st.Size, st.Quorum)
	}
	odd := c.nodes[2].n
	odd.nodes.Store(4) // node 2 alone was reloaded with another size
	odd.gc.LocalMetadata().SetInt(metaSize, 4)
	odd.rebuild()
	waitFor(t, 10*time.Second, "node 2 to refuse", func() bool {
		ok, why := odd.Ready()
		return !ok && strings.Contains(why, "cluster.size") && !odd.Writable()
	})
	consistently(t, time.Second, "the majority serves", func() bool {
		for _, tn := range c.nodes[:2] {
			if ok, _ := tn.n.Ready(); !ok || !tn.n.Writable() {
				return false
			}
		}
		return true
	})
	putRetrying(t, c.nodes[0], newRec(newID(), ""))
	odd.nodes.Store(3)
	odd.gc.LocalMetadata().SetInt(metaSize, 3)
	c.waitReady()
}

// Builds work together when each speaks what the other needs: this build, and the next one keeping this as its
// minimum, do; one from before compatibility was published, or too new, does not. A peer that has not published its
// compatibility yet (it has just joined) is not judged.
func TestCompatibility(t *testing.T) {
	for _, tc := range []struct{ c, min int }{{0, 0}, {compat + 2, compat + 1}} {
		if compatible(tc.c, tc.min) {
			t.Fatalf("compat %d/%d accepted", tc.c, tc.min)
		}
	}
	if !compatible(compat, minCompat) || !compatible(compat+1, compat) {
		t.Fatal("this build, or the next one keeping this as its minimum, refused")
	}
	md := gossip.NewMetadata()
	joining := &gossip.Node{Metadata: md}
	if _, _, ok := publishedCompat(joining); ok || !peerCompatible(joining) {
		t.Fatal("a peer with empty metadata was judged")
	}
	md.SetInt(metaCompat, 0)
	md.SetInt(metaMinCompat, 0)
	if peerCompatible(joining) {
		t.Fatal("a published compatibility 0 was accepted")
	}
}

// A node of an incompatible build (here: one from before compatibility was published) makes the others refuse to serve
// and drop its messages until it is gone or upgraded.
func testIncompatiblePeerRefused(t *testing.T, c *tcluster) {
	md := c.nodes[2].n.gc.LocalMetadata()
	md.SetInt(metaCompat, 0) // an older build
	md.SetInt(metaMinCompat, 0)
	waitFor(t, 10*time.Second, "incompatible peer refused", func() bool {
		ok, why := c.nodes[0].n.Ready()
		return !ok && !c.nodes[0].n.Writable() && strings.Contains(why, "cannot work with")
	})
	md.SetInt(metaCompat, compat)
	md.SetInt(metaMinCompat, minCompat)
	c.waitReady()
}

// A peer that has just joined is known before its metadata arrives: until it has published its compatibility it is
// not judged (its messages are handled, nobody refuses to serve over it), which once logged a false "refusing to
// serve ... it speaks 0" on every start.
func testUnpublishedCompatNotJudged(t *testing.T, c *tcluster) {
	md := c.nodes[2].n.gc.LocalMetadata()
	md.Delete(metaCompat) // as when a peer's metadata has not arrived yet
	md.Delete(metaMinCompat)
	t.Cleanup(func() { md.SetInt(metaCompat, compat); md.SetInt(metaMinCompat, minCompat) })
	// node 0 sees the peer without a published compatibility, and does not judge it
	waitFor(t, 15*time.Second, "node 0 to see node 2 without a compatibility", func() bool {
		for _, mb := range c.nodes[0].n.otherPeers() {
			if mb.id == c.nodes[2].n.id {
				_, _, ok := publishedCompat(mb.node)
				return !ok
			}
		}
		return false
	})
	consistently(t, time.Second, "no refusal over a peer that published nothing", func() bool {
		ok, why := c.nodes[0].n.Ready()
		return ok || !strings.Contains(why, "cannot work with")
	})
}

// Partition numbers are part of the protocol: every node of a cluster, whatever its build, must put a key in the same
// partition, or a mixed-version cluster splits its data silently. An organization's records share a partition; global
// data (an organization itself) is in partition 0.
func TestPartitionNumbersAreStable(t *testing.T) {
	for key, want := range map[string]int{"": 0, "org1": 60, "a": 62, "acme": 39,
		"0198f0e0-0000-7000-8000-000000000001": 56, "tenant/res/https://a.example.com": 57} {
		if got := partitionNum(key); got != want {
			t.Errorf("partition of %q: %d, want %d", key, got, want)
		}
	}
}

// A message from a peer of an incompatible build is not handled.
func TestIncompatiblePeerMessagesAreDropped(t *testing.T) {
	n, _ := gnode(t)
	peer := n.gc.LocalNode()
	called := 0
	hr := compatOnlyReply(func(*gossip.Node, *gossip.Packet) (any, error) { called++; return nil, nil })
	if _, err := hr(peer, badPacket(t)); err != nil || called != 1 {
		t.Fatalf("compatible reply: %v %d", err, called)
	}
	md := n.gc.LocalMetadata()
	md.SetInt(metaCompat, -1)
	md.SetInt(metaMinCompat, 1<<20)
	if _, err := hr(peer, badPacket(t)); !errors.Is(err, errIncompatible) || called != 1 {
		t.Fatalf("incompatible reply: %v %d", err, called)
	}
}

// The peers list names this node by host name while it advertises an IP address (or the reverse): it is not counted
// twice, so three nodes keep a majority of two.
func TestSelfInPeersByAnotherName(t *testing.T) {
	ip := "203.0.113.7"
	for _, tc := range []struct {
		peer, adv string
		self      bool
	}{
		{"10.0.0.1:7946", "10.0.0.1:7946", true},
		{"LOCALHOST:7946", "localhost:7946", true},
		{"10.0.0.2:7946", "10.0.0.1:7946", false},
		{"10.0.0.1:7947", "10.0.0.1:7946", false},
		{"localhost:7946", "[::1]:7946", false}, // loopback says nothing about another machine
		{ip + ":7946", ip + ":7946", true},
	} {
		if got := isSelfAddr(tc.peer, tc.adv); got != tc.self {
			t.Errorf("isSelfAddr(%s, %s) = %v, want %v", tc.peer, tc.adv, got, tc.self)
		}
	}
	// this machine's own host name, with a wildcard bind
	if h, err := os.Hostname(); err == nil {
		if !isSelfAddr(h+":7946", "0.0.0.0:7946") {
			t.Errorf("own host name %s not recognised", h)
		}
	}
}

// A partition Manager that cannot be started (Resize restarts it) leaves the node without one, not with one that was never
// started; the node tries again (joinDataSet) and serves once one runs.
func testRestartManagerFailureLeavesNoManager(t *testing.T, c *tcluster) {
	fail := func(*partition.Manager) error { return errors.New("test: the manager does not start") }
	managerStart.Store(&fail)
	t.Cleanup(func() { managerStart.Store(nil) })
	n0 := c.nodes[0].n
	if err := n0.restartManager(); err == nil {
		t.Fatal("a failed start was not reported")
	}
	n0.pmMu.Lock()
	started := n0.pmStarted
	n0.pmMu.Unlock()
	if started || n0.manager() != nil {
		t.Fatalf("after a failed start: started %v, manager %v", started, n0.manager())
	}
	if ok, _ := n0.Ready(); ok || n0.Writable() {
		t.Fatal("a node without a partition protocol serves")
	}
	if _, err := n0.st.Get(bg, dataKind, "anything"); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("a read on a node without a partition protocol: %v", err)
	}
	managerStart.Store(nil)
	c.waitReady()
	putRetrying(t, c.nodes[0], newRec(newID(), ""))
}
