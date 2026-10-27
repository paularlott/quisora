package cluster

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/store"
)

// In a gossip cluster the owner of partition 0 runs housekeeping (and nobody else): when that node crashes, partition 0
// is taken over and housekeeping continues, at once, on the new owner. (Ownership itself is gossip/partition's.)
func TestHousekeepingFollowsPartitionZero(t *testing.T) {
	c := started(t, badgerBackend())
	c.waitSettled()
	runs := make([]atomic.Int64, len(c.nodes))
	ctx, cancel := context.WithCancel(bg)
	t.Cleanup(cancel)
	for i, tn := range c.nodes {
		go tn.n.RunHousekeeping(ctx, time.Hour, func(context.Context) { runs[i].Add(1) }) // (an hour: only the first pass)
	}
	first := c.ownerOf(globalPartition)
	waitFor(t, 15*time.Second, "the owner of partition 0 to run housekeeping", func() bool { return runs[first].Load() == 1 })
	consistently(t, time.Second, "nobody else runs it", func() bool {
		for i := range runs {
			if i != first && runs[i].Load() != 0 {
				return false
			}
		}
		return true
	})
	for _, ms := range c.nodes[(first+1)%3].n.members(true) {
		if ms.Leader != (ms.ID == c.nodes[first].n.ID()) {
			t.Fatalf("member %s: leader %v", ms.ID, ms.Leader)
		}
	}

	c.partition([]int{(first + 1) % 3, (first + 2) % 3}, []int{first})
	waitFor(t, 30*time.Second, "housekeeping to start on the new owner of partition 0", func() bool {
		return runs[(first+1)%3].Load() == 1 || runs[(first+2)%3].Load() == 1
	})
}

// A housekeeping write is refused once this node no longer owns partition 0 as it did when the pass started, even if
// the node is writable again and owns it again (another tenure, another epoch); other writes are not affected.
func TestHousekeepingFencedAfterDeposed(t *testing.T) {
	c := started(t, badgerBackend())
	c.waitSettled()
	first := c.ownerOf(globalPartition)
	old := c.nodes[first]
	var fctx context.Context
	waitFor(t, 15*time.Second, "the owner to lead", func() bool {
		if !old.n.IsLeader() {
			return false
		}
		fctx = old.n.fence(bg)
		return true
	})
	if err := old.st().Put(fctx, newOrgRec("")); err != nil {
		t.Fatalf("a housekeeping write while leading: %v", err)
	}

	// the others take partition 0 over, whatever the old owner believes meanwhile
	c.partition([]int{(first + 1) % 3, (first + 2) % 3}, []int{first})
	waitFor(t, 30*time.Second, "the others to own partition 0", func() bool {
		return c.nodes[(first+1)%3].n.manager().IsOwner(globalPartition) || c.nodes[(first+2)%3].n.manager().IsOwner(globalPartition)
	})
	c.heal()
	c.waitReady()
	waitFor(t, 30*time.Second, "the old owner to be fenced", func() bool { return old.n.fenced(fctx) != nil })
	if err := old.st().Put(fctx, newOrgRec("")); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a housekeeping write of a deposed leader: %v", err)
	}
	putRetrying(t, old, newOrgRec("")) // the node itself is fine
}
