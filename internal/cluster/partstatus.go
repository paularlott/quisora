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
// or while one has been unreadable here for unreadableGrace (an owner that cannot be replaced, a catch-up that keeps
// failing), and the reason says which.

// unreadableGrace is how long a partition may be unreadable here before the node stops being ready: a takeover after an
// owner is lost takes a few seconds, during which the partition's records are refused but the node stays in the load
// balancer. A variable for tests.
var unreadableGrace = 30 * time.Second

// handoverWait bounds how long a read waits for a partition that has no live owner while this node sees a majority and
// is not behind on it: its owner is handing it over (a returning node claims it back, an owner stops) or a takeover is
// running, which takes a heartbeat or two. The read is served once the new owner is heard, or refused after this (an
// owner that crashed takes a few seconds to replace: the writes to the partition fail meanwhile too).
const handoverWait = 2 * time.Second

// readable reports whether this node may serve its copy of partition p (p < 0: of a record whose partition it cannot
// tell, which is checked for the node as a whole), as nil or as the error a read refused for it returns. A partition
// being handed over is waited for (handoverWait, or until ctx ends).
func (n *Node) readable(ctx context.Context, p int) error {
	deadline := time.Now().Add(handoverWait)
	for {
		handover, err := n.readableNow(p)
		if err == nil || !handover || !time.Now().Before(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-n.ctx.Done():
			return err
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// readableNow is readable at this moment; handover reports a refusal that the partition's next owner ends (no live
// owner, while this node sees a majority, is not behind and the partition has not diverged here).
//
// A node that is cut off from the majority (fewer than a majority in view) can read none of its partitions: it hears no
// owner. Within cluster.minority_grace it still serves the copies it is not known to trail (it was ready when it was cut
// off, and nothing reported a later write of the partition to it) and that have not diverged: that is the grace the
// token endpoints are given to ride out a short split (Node.ServesTokens), and it ends with it.
func (n *Node) readableNow(p int) (handover bool, err error) {
	pm := n.manager()
	if pm == nil || pm.Resyncing() {
		_, why := n.Ready()
		if why == "" {
			why = "starting"
		}
		return false, fmt.Errorf("%w: %s", store.ErrNotWritable, why)
	}
	if p < 0 || pm.CanRead(p) {
		return false, nil
	}
	st, err := pm.PartitionStatus(p)
	if err != nil {
		return false, fmt.Errorf("%w: %v", store.ErrNotWritable, err)
	}
	current := !st.Diverged && st.Lag == 0
	if st.CanRead || (current && !n.quorumOK() && n.ServesTokens()) {
		return false, nil
	}
	return current && n.quorumOK(), fmt.Errorf("%w: partition %d cannot be read on this node: %s", store.ErrNotWritable, p,
		unreadableWhy(st))
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
// partition found diverged here, and makes the node not ready while one has diverged or one has been unreadable for
// unreadableGrace. It measures only while the partition protocol is ready: catching up after a start has its own reason.
func (n *Node) checkPartitions() {
	pm := n.manager()
	if pm == nil || !pm.Ready() || pm.Resyncing() {
		for p := range partitions {
			n.unreadable[p].Store(0)
		}
		n.setPartOff("")
		return
	}
	now := time.Now()
	var diverged, stale []string
	for _, st := range pm.Status().Partitions {
		p := st.Partition
		if st.Diverged {
			diverged = append(diverged, fmt.Sprint(p))
			if !n.divergedSeen[p].Swap(true) {
				n.log.Warn("a partition diverged on this node: it holds writes the partition's owner does not have, which "+
					"only lost data explains (a disk lost or wrongly restored, here or on a majority elsewhere); the node "+
					"serves nothing of it and is not ready until it is resynced: empty its database and start it again, it "+
					"copies everything from the others", "partition", p, "committed", st.Committed.String(),
					"owner_committed", st.OwnerCommitted.String())
			}
		}
		if st.CanRead {
			n.unreadable[p].Store(0)
			continue
		}
		n.unreadable[p].CompareAndSwap(0, now.UnixNano())
		if since := n.unreadable[p].Load(); since != 0 && now.Sub(time.Unix(0, since)) >= unreadableGrace {
			stale = append(stale, fmt.Sprint(p))
		}
	}
	switch {
	case len(diverged) > 0:
		n.setPartOff("partition " + strings.Join(diverged, ", ") + " diverged on this node (it holds writes their owners " +
			"do not have): resync it (empty its database and start it again; it copies everything from the others)")
	case len(stale) > 0:
		n.setPartOff(fmt.Sprintf("partition %s unreadable on this node for %s or longer (no owner heard, or its catch-up "+
			"keeps failing)", strings.Join(stale, ", "), unreadableGrace))
	default:
		n.setPartOff("")
	}
}

// setPartOff records why the node's partitions keep it from being ready ("": they do not), logging each change.
func (n *Node) setPartOff(why string) {
	if why == "" {
		if n.partOff.Swap(nil) != nil {
			n.log.Info("every partition is readable on this node again")
		}
		return
	}
	if old := n.partOff.Swap(&why); old == nil || *old != why {
		n.log.Warn("not ready", "reason", why)
	}
}
