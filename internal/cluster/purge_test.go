package cluster

import (
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/store"
)

// testRetention is the tombstone retention of these tests. The purge runs as at a time past it (purgeAll), so nothing
// waits it out.
const testRetention = 3 * time.Second

func shortRetention(o *Options) { o.TombstoneRetention = testRetention }

func tombstoned(tn *tnode, id string) bool {
	r, err := tn.st().Inner().Lookup(bg, dataKind, id)
	return err == nil && r.Deleted
}

func gone(tn *tnode, id string) bool {
	_, err := tn.st().Inner().Lookup(bg, dataKind, id)
	return errors.Is(err, store.ErrNotFound)
}

// purgeAll runs the purge of every node as at time now; only the owner of a partition writes its purge. A time ahead of
// the clock is legitimate (a node whose clock is ahead): every node purges the same tombstones whatever its clock. (The
// records that expire before now go too: the tests' records do not expire.)
func purgeAll(c *tcluster, now time.Time) {
	for _, tn := range c.nodes {
		tn.n.purgeOnce(bg, now)
	}
}

// The owner of a partition purges the tombstones older than the retention with a write of the partition: every node
// removes the same ones, and keeps the younger ones and the live records. The scan for them runs within the export slots
// (each long read holds a snapshot, on SQLite a reader connection): with every slot taken it reads nothing and the
// partition still counts as not scanned, and as soon as one is free the next round purges. A pass that finds nothing
// to purge writes nothing.
func TestPurgeTombstones(t *testing.T) {
	eachLocalBackend(t, func(t *testing.T, b backend) {
		c := newTCluster(t, 3, b)
		c.opts = shortRetention
		c.startAll()
		c.waitReady()
		org := "purge-org"
		p := partitionNum(org)
		ids := writeN(t, c.nodes[0], org, 6)
		waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
		tombstones := func(what string, ids []string) {
			t.Helper()
			for _, id := range ids {
				if err := c.nodes[1].st().Put(bg, store.Tombstone(dataKind, id)); err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, 15*time.Second, what+" everywhere", func() bool {
				for _, tn := range c.nodes {
					for _, id := range ids {
						if !tombstoned(tn, id) {
							return false
						}
					}
				}
				return true
			})
		}
		tombstones("the old tombstones", ids[:3])
		past := time.Now().Add(testRetention) // (a time at which these are past the retention)
		tombstones("the young tombstone", ids[3:4])

		// every export slot taken: the scan reads nothing, and the partition is not counted as scanned
		for _, tn := range c.nodes {
			for len(tn.n.pst.exports) < cap(tn.n.pst.exports) {
				tn.n.pst.exports <- struct{}{}
			}
		}
		purgeAll(c, past)
		for i, tn := range c.nodes {
			if tn.n.lastScan[p].Load() != 0 {
				t.Fatalf("node %d: a partition counted as scanned with no export slot free", i)
			}
			for _, id := range ids[:3] {
				if !tombstoned(tn, id) {
					t.Fatalf("node %d purged with no export slot free", i)
				}
			}
		}
		for _, tn := range c.nodes {
			for len(tn.n.pst.exports) > 0 {
				<-tn.n.pst.exports
			}
		}

		purgeAll(c, past)
		waitFor(t, 15*time.Second, "the old tombstones purged everywhere", func() bool {
			for _, tn := range c.nodes {
				for _, id := range ids[:3] {
					if !gone(tn, id) {
						return false
					}
				}
			}
			return true
		})
		for i, tn := range c.nodes {
			if !tombstoned(tn, ids[3]) {
				t.Fatalf("node %d: a tombstone within the retention was purged", i)
			}
			for _, id := range ids[4:] {
				if !has(tn.st(), id) {
					t.Fatalf("node %d lost a live record", i)
				}
			}
			if st, _ := tn.n.pst.pst.PartitionState(bg, p); st.Purged == 0 {
				t.Fatalf("node %d: no purge point", i)
			}
		}
		waitFor(t, 15*time.Second, "every node at the same position", func() bool { return committedEqual(c.nodes) })

		// a second pass (scanning again at once) has nothing to purge, and writes nothing
		committed, _ := c.nodes[0].n.pst.State(p)
		for _, tn := range c.nodes {
			tn.n.lastScan[p].Store(0)
		}
		purgeAll(c, past)
		for i, tn := range c.nodes {
			if st, _ := tn.n.pst.State(p); st.Committed.Seq != committed.Committed.Seq {
				t.Fatalf("node %d: a pass with nothing to purge wrote (sequence %d, was %d)", i, st.Committed.Seq,
					committed.Committed.Seq)
			}
		}
	})
}
