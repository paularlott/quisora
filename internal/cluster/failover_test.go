package cluster

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Quisora survives the loss of an owner, end to end through its store: the owner of a partition is cut off without a
// word (a crash, as the others see it), the others go on writing the partition, nothing acknowledged is lost, the
// isolated old owner refuses writes (store.ErrUnavailable), and once it is back it holds the same data and writes
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
	if err := c.nodes[owner].st().Put(bg, r); !errors.Is(err, store.ErrUnavailable) {
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
	if err := tn.st().Put(bg, newRec(model.NewID(), "")); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

// A lost owner's partitions cannot take a node down: while a partition's owner is gone and not yet replaced, a node
// holds at most maxPartitionWrites writes of it waiting, refuses any more at once (store.ErrUnavailable, not unknown:
// nothing was sent), and goes on writing the other partitions meanwhile.
func TestWritesWaitingForALostOwnerAreCapped(t *testing.T) {
	c := started(t, badgerBackend())
	org, owner := c.orgNotOwnedBy(0)
	p := partitionNum(org)
	elsewhere := ""
	for k := 0; elsewhere == ""; k++ {
		if o := fmt.Sprintf("org-%d", k); partitionNum(o) != p && c.ownerOf(partitionNum(o)) != owner {
			elsewhere = o
		}
	}
	// the owner does not answer node 0's writes (a lost owner cannot be told from a slow one until the owner timeout).
	// Stopped instead, it would leave the cluster and its partitions be taken over at once, and a loaded machine could
	// have that done before every write below had arrived.
	c.hold(0, owner, true, gossip.PartChangeMsg)
	defer c.heal()

	const extra = 16
	type result struct {
		err  error
		took time.Duration
	}
	results := make(chan result, maxPartitionWrites+extra)
	write := func() {
		began := time.Now()
		err := c.nodes[0].st().Put(bg, newOrgRec(org))
		results <- result{err, time.Since(began)}
	}
	// the cap's worth first, every one of them under way, then the extra (all at once, the extra could arrive before
	// the last of the cap's worth on a loaded machine)
	for range maxPartitionWrites {
		go write()
	}
	waitFor(t, 5*time.Second, "the cap's worth of writes to be under way", func() bool {
		return c.nodes[0].n.writing[p].Load() == maxPartitionWrites
	})
	for range extra {
		go write()
	}
	// the other partitions are written promptly while the lost owner's writes wait
	for range 5 {
		began := time.Now()
		if err := c.nodes[0].st().Put(bg, newOrgRec(elsewhere)); err != nil || time.Since(began) > time.Second {
			t.Fatalf("a write of another partition while the owner of partition %d is lost: %v after %s", p, err,
				time.Since(began))
		}
	}
	refused := 0
	for range maxPartitionWrites + extra {
		r := <-results
		if r.err == nil || !strings.Contains(r.err.Error(), "too many writes") {
			continue
		}
		refused++
		if !errors.Is(r.err, store.ErrUnavailable) || errors.Is(r.err, store.ErrUnconfirmed) || r.took > 250*time.Millisecond {
			t.Errorf("a write past the cap: %v after %s, want unavailable at once", r.err, r.took)
		}
	}
	if refused != extra {
		t.Fatalf("%d of %d writes to a partition whose owner is lost were refused at once, want %d (the cap is %d)",
			refused, maxPartitionWrites+extra, extra, maxPartitionWrites)
	}
}
