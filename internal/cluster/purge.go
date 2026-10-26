package cluster

import (
	"context"
	"errors"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossip/partition"
)

// Tombstones are kept for the retention (Options.TombstoneRetention) so that a node that was away a while catches up by
// sequence number, which is cheap; a node that was away longer finds its position below the partition's purge point and
// copies the partition whole (partition.ErrPurged), which is always correct. So the retention is a matter of cost, not
// of safety, and a purge is a write of its partition: the owner chooses the sequence number below which every tombstone
// is older than the retention, and every node purges the same ones at the same position, whatever its clock.

// purgeScanEvery is how often the owner of a partition looks for tombstones to purge (a variable for tests).
var purgeScanEvery = time.Hour

// purgeTombstones writes the purge of every partition this node owns that has tombstones past the retention.
func (n *Node) purgeTombstones(ctx context.Context, now time.Time) {
	pm := n.manager()
	if pm == nil || !pm.Ready() || pm.Resyncing() {
		return
	}
	for p := range partitions {
		if ctx.Err() != nil {
			return
		}
		if !pm.IsOwner(p) {
			continue
		}
		if last := n.lastScan[p].Load(); last != 0 && now.Sub(time.Unix(0, last)) < purgeScanEvery {
			continue
		}
		busy, err := n.purgePartition(ctx, p, now)
		if busy {
			return // every export slot is taken: the scan waits for the next round, and so does the pace
		}
		n.lastScan[p].Store(now.UnixNano())
		if err != nil {
			n.log.WithError(err).Warn("purge of a partition's tombstones failed", "partition", p)
		}
	}
}

// purgePartition purges the tombstones of partition p that are older than the retention, if there are any. busy is
// true when no export slot was free to scan with (purgePoint).
func (n *Node) purgePartition(ctx context.Context, p int, now time.Time) (busy bool, err error) {
	before, ok, busy, err := n.purgePoint(ctx, p, now)
	if err != nil || !ok || busy {
		return busy, err
	}
	b, err := encodeMsg(&change{Op: opPurge, Before: before})
	if err != nil {
		return false, err
	}
	_, err = n.manager().Write(ctx, p, b)
	var re *partition.RefusedError
	if errors.As(err, &re) && re.Code == whyNothing {
		return false, nil
	}
	if err == nil {
		n.log.Debug("purged tombstones", "partition", p, "below", before)
	}
	return false, err
}

// purgePoint chooses the sequence number below which tombstones of p are purged: that of the oldest tombstone younger
// than the retention (none: everything committed so far). ok is false when no tombstone lies below it. It reads the
// partition's tombstones only (store.PartitionStore.PartitionTombstones, from an index of them), never its records,
// and holds one of the export slots while it does (a node's long reads are bounded together: each holds a snapshot, on
// SQLite a reader connection): busy is true, and nothing was read, when none is free; the caller tries again later.
func (n *Node) purgePoint(ctx context.Context, p int, now time.Time) (before uint64, ok, busy bool, err error) {
	select {
	case n.pst.exports <- struct{}{}:
		defer func() { <-n.pst.exports }()
	default:
		return 0, false, true, nil
	}
	ps, err := n.pst.pst.PartitionState(ctx, p)
	if err != nil {
		return 0, false, false, err
	}
	var youngest, oldest uint64 // the lowest sequence number of a tombstone younger than the retention, and of an older one
	err = n.pst.pst.PartitionTombstones(ctx, p, ps.Purged, ps.Committed.Seq, func(seq uint64, version hlc.Timestamp) error {
		if now.Sub(version.Time()) < n.opt.TombstoneRetention {
			if youngest == 0 || seq < youngest {
				youngest = seq
			}
		} else if oldest == 0 || seq < oldest {
			oldest = seq
		}
		return nil
	})
	if err != nil {
		return 0, false, false, err
	}
	before = ps.Committed.Seq + 1
	if youngest != 0 {
		before = youngest
	}
	return before, oldest != 0 && oldest < before, false, nil
}
