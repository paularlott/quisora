package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/store"
)

// Quisora survives the loss of an owner, end to end through its store: the owner of a partition is cut off without a
// word (a crash, as the others see it), the others go on writing the partition, nothing acknowledged is lost, the
// isolated old owner refuses writes (store.ErrNotWritable), and once it is back it holds the same data and writes
// again. (The partition protocol's failover, hand-over, splits, catch-up and resync are gossip/partition's own tests.)
func TestOwnerCrash(t *testing.T) {
	c := started(t, badgerBackend())
	c.waitOwners()
	c.waitSettled()
	org := "crash-org"
	p := partitionNum(org)
	owner := c.ownerOf(p)
	survivors := []int{(owner + 1) % 3, (owner + 2) % 3}
	before := writeN(t, c.nodes[survivors[0]], org, 5)
	c.waitHas(before[len(before)-1])

	c.partition(survivors, []int{owner})
	var during []string
	for _, i := range survivors {
		during = append(during, putRetrying(t, c.nodes[i], newOrgRec(org)))
	}
	pm := c.nodes[survivors[0]].n.manager()
	if o, ok := pm.Owner(p); !ok || o.String() == c.nodes[owner].n.ID() {
		t.Fatalf("the partition was not taken over (owner %v)", o)
	}
	// the old owner, cut off, cannot write the partition
	waitFor(t, 20*time.Second, "the isolated node stops accepting writes", func() bool { return !c.nodes[owner].n.Writable() })
	r := newOrgRec(org)
	if err := c.nodes[owner].st().Put(bg, r); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("a write on the isolated node: %v", err)
	}
	// what the survivors acknowledged is there on both
	waitFor(t, 15*time.Second, "what was acknowledged on both survivors", func() bool {
		return allHold([]*tnode{c.nodes[survivors[0]], c.nodes[survivors[1]]}, append(append([]string{}, before...), during...))
	})

	c.heal()
	c.waitReady()
	waitFor(t, 30*time.Second, "the old owner to catch up", func() bool { return committedEqual(c.nodes) && sameData(c.nodes) })
	if has(c.nodes[owner].st(), r.ID) {
		t.Fatal("a refused write appeared")
	}
	putRetrying(t, c.nodes[owner], newOrgRec(org))
}

// Nothing is ready, and nobody can write, until a majority is up: one node restarting alone after everything stopped
// serves nothing, and issues no tokens from its old data, grace or not (changes made while it was down, a user
// disabled, may not be here yet).
func TestAloneAfterAllStopped(t *testing.T) {
	c := started(t, badgerBackend())
	for _, tn := range c.nodes {
		stop(tn)
	}
	tn := c.build(0, c.nodes[0].dir, nil)
	c.nodes[0] = tn
	c.start(tn)
	// it is up and waiting for a majority to answer (not merely not started yet), and stays so
	waitFor(t, 15*time.Second, "the node to wait for the others", func() bool {
		_, why := tn.n.Ready()
		return strings.Contains(why, "catching up")
	})
	consistently(t, time.Second, "a node alone is neither ready nor writable, and issues no tokens", func() bool {
		ok, _ := tn.n.Ready()
		return !ok && !tn.n.Writable()
	})
	if err := tn.st().Put(bg, newRec(newID(), "")); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("%v", err)
	}
}
