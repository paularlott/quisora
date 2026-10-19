package cluster

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// A cluster key rotation on a running cluster, in the three documented rounds (every node: add the new key as a
// previous one; every node: make it current with the old one previous; every node: drop the old one). Gossip keeps
// replicating after every round, and a key set without the key in use is refused.
func TestClusterKeyRotation(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	old, next := c.key, testKey()

	replicates := func(step string) {
		t.Helper()
		id := newID()
		if err := c.nodes[0].st().Put(bg, newRec(id, "")); err != nil {
			t.Fatalf("%s: write: %v", step, err)
		}
		waitFor(t, 15*time.Second, step+": replication", func() bool {
			for _, tn := range c.nodes {
				if r, err := tn.st().Get(bg, model.KindGroup, id); err != nil || r == nil {
					return false
				}
			}
			return true
		})
	}
	replicates("before")

	if _, err := c.nodes[0].n.SetClusterKeys(testKey(), nil); err == nil {
		t.Fatal("a key set without the key in use was accepted")
	}
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
}
