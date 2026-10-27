package cluster

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/store"
)

// The staleness gate. A node serves a record from its own copy only while it can vouch for the copy of the record's
// partition (partition.Manager.CanRead): it has heard the partition's owner lately (or, owning it, a majority), it has
// not trailed what the owner reported committed for long (a follower whose catch-up keeps failing), and the partition has
// not diverged here. Otherwise a revoked session, a disabled user or a rotated secret could be served from a copy that
// no longer follows the cluster, for as long as it stays behind. The single-record reads of the cluster store refuse,
// as an unavailable store does (store.ErrNotWritable), in gossip mode only; a node's own audit events and short-lived
// state are exempt (they are not in a partition), and a reservation is the partition of its own id.
//
// The node's readiness follows: it is not ready while a partition has diverged here (only an operator can resync it)
// (the reason says so). A partition that is merely unreadable (an owner that cannot be replaced, a catch-up that keeps
// failing) does not: its records are refused one by one while the other partitions keep working, and
// Status.PartitionsUnreadable (quisora_partitions_unreadable) is what an operator alerts on.

// readable reports whether this node may serve its copy of partition p (p < 0: of a record whose partition it cannot
// tell, which is checked for the node as a whole), as nil or as the error a read refused for it returns. A follower
// keeps serving through its owner's hand-over (the library's CanRead follows the last owner heard, within StaleAfter).
//
// A node that is cut off from the majority (fewer than a majority in view) can read none of its partitions: it hears no
// owner, and it is not ready.
//
// It also refuses a copy that is behind what the owner has reported committed (the library counts the lag from when
// the owner's position was heard, not from when it was committed, so a node regaining contact after an outage would
// otherwise serve its old copy for a whole StaleAfter): after waiting for it to apply, up to StaleAfter (the gap between
// hearing a commit and applying it is normally a few milliseconds, longer on a node busy hashing passwords; a copy
// still behind after StaleAfter would be stale beyond the bound, and is refused).
func (n *Node) readable(ctx context.Context, p int) error {
	return n.readableWithin(ctx, p, time.Duration(n.staleAfter.Load()))
}

// readableWithin is readable, waiting at most wait (0: not at all) for a copy that is behind to catch up.
//
// A read that cannot tell its partition (p < 0: an id that is not here and does not name its partition, a listing scoped
// by something other than an organization) is answered only while every partition could be: what it would find, or
// what it lacks, may be in any of them. That is one look at every partition's status, and a wait only for those
// behind, all within the one wait.
func (n *Node) readableWithin(ctx context.Context, p int, wait time.Duration) error {
	pm := n.manager()
	if pm == nil || pm.Resyncing() {
		_, why := n.Ready()
		if why == "" {
			why = "starting"
		}
		return fmt.Errorf("%w: %s", store.ErrNotWritable, why)
	}
	if n.pst != nil {
		// A full import of a partition has begun here and not finished: its reset removed records, so no read of it is
		// true, lag detection or not.
		if p >= 0 {
			if n.pst.isImporting(p) {
				return fmt.Errorf("%w: partition %d cannot be read on this node: importing", store.ErrNotWritable, p)
			}
		} else if q, ok := n.pst.anyImporting(); ok {
			return fmt.Errorf("%w: partition %d cannot be read on this node: importing", store.ErrNotWritable, q)
		}
	}
	if p >= 0 {
		st, err := pm.PartitionStatus(p)
		if err != nil {
			return fmt.Errorf("%w: %v", store.ErrNotWritable, err)
		}
		return n.partitionReadable(ctx, pm, st, wait)
	}
	deadline := time.Now().Add(wait)
	for _, st := range pm.Status().Partitions {
		if err := n.partitionReadable(ctx, pm, st, time.Until(deadline)); err != nil {
			return err
		}
	}
	return nil
}

// partitionReadable is readableWithin for one partition whose status is st.
func (n *Node) partitionReadable(ctx context.Context, pm *partition.Manager, st partition.PartitionStatus, wait time.Duration) error {
	p := st.Partition
	if !st.CanRead {
		return fmt.Errorf("%w: partition %d cannot be read on this node: %s", store.ErrNotWritable, p, unreadableWhy(st))
	}
	if st.Committed.Seq >= st.OwnerCommitted.Seq {
		return nil
	}
	if wait > 0 && n.waitSlot() {
		defer n.waitDone()
		wctx, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		if pm.WaitApplied(wctx, p, st.OwnerCommitted) == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: this node is behind on partition %d", store.ErrNotWritable, p)
}

// unreadableWhy says why a partition is not readable here.
func unreadableWhy(st partition.PartitionStatus) string {
	switch {
	case st.Diverged:
		return "it diverged here (this node holds writes its owner does not have)"
	case st.Lag > 0:
		return fmt.Sprintf("this node has trailed its owner for %s (catching up keeps failing)", st.Lag.Round(time.Millisecond))
	case st.Leading:
		return "this node owns it but has not heard from a majority lately"
	}
	return "no owner of it has been heard lately"
}

// checkPartitions follows the partitions this node cannot vouch for (rebuild runs it every second at most): it logs a
// partition found diverged here, and makes the node not ready while one has diverged. It looks only while the partition
// protocol is ready: catching up after a start has its own reason.
func (n *Node) checkPartitions() {
	pm := n.manager()
	if pm == nil || !pm.Ready() || pm.Resyncing() {
		n.setPartOff("")
		return
	}
	var diverged []string
	for _, st := range pm.Status().Partitions {
		if !st.Diverged {
			continue
		}
		p := st.Partition
		diverged = append(diverged, fmt.Sprint(p))
		if !n.divergedSeen[p].Swap(true) {
			n.log.Warn("a partition diverged on this node: it holds writes the partition's owner does not have, which "+
				"only lost data explains (a disk lost or wrongly restored, here or on a majority elsewhere); the node "+
				"serves nothing of it and is not ready until it is resynced: empty its database and start it again, it "+
				"copies everything from the others", "partition", p, "committed", st.Committed.String(),
				"owner_committed", st.OwnerCommitted.String())
		}
	}
	if len(diverged) > 0 {
		n.setPartOff("partition " + strings.Join(diverged, ", ") + " diverged on this node (it holds writes their owners " +
			"do not have): resync it (empty its database and start it again; it copies everything from the others)")
		return
	}
	n.setPartOff("")
}

// setPartOff records why the node's partitions keep it from being ready ("": they do not), logging each change.
func (n *Node) setPartOff(why string) {
	if why == "" {
		if n.partOff.Swap(nil) != nil {
			n.log.Info("no partition is diverged on this node any more")
		}
		return
	}
	if old := n.partOff.Swap(&why); old == nil || *old != why {
		n.log.Warn("not ready", "reason", why)
	}
}
