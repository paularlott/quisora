package cluster

import (
	"testing"
	"time"
)

// Every node lists every member with its address, state and readiness; all agree on one leader, and each marks
// itself.
func TestStatusNodes(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
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
