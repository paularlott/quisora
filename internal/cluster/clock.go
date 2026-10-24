package cluster

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/store"
)

// The peer clock check. Versions come from the nodes' clocks, so a node whose clock is off from the cluster's must
// not vote or write: a voter restarted with its clock stepped back (a VM restored from a snapshot, a manual
// correction) could otherwise grant a version below one it granted before the restart. Every change feed reply
// carries the responder's time (feedResp.Now); the asker reads its offset from each peer as NTP does (the peer's time
// against the midpoint of the request), keeps each peer's latest reading in memory, and takes the median of its own
// clock (offset 0) and the fresh readings: the cluster's clock as its majority keeps it, so a minority of bad clocks,
// this node's or a peer's, is outvoted. It decides only once it has heard from enough peers to make a quorum with
// itself; until then nothing changes. Off by more than clockLimit, the node refuses
// to serve (clockOff) until it is back within clockOK. Feeds are pulled from every peer every few seconds, and at
// start-up during catch-up, before the node votes. Nothing is kept on disk.
const (
	clockLimit = store.MaxSkew // further off from the cluster's median: refuse to serve
	clockOK    = clockLimit / 2
	clockFresh = 30 * time.Second // older readings (a peer gone quiet) do not count
)

type clockReading struct {
	offset time.Duration // the peer's clock minus this node's
	at     time.Time
}

type peerClocks struct {
	mu   sync.Mutex
	last map[string]clockReading // node id -> latest reading
}

// clockReading records the time a peer gave in a reply (unix nanos) to a request sent at sent and answered at got.
func (n *Node) clockReading(peer string, sent, got time.Time, peerNow int64) {
	if peerNow == 0 {
		return // a reply that carries no time
	}
	offset := time.Unix(0, peerNow).Sub(sent.Add(got.Sub(sent) / 2))
	n.clocks.mu.Lock()
	if n.clocks.last == nil {
		n.clocks.last = map[string]clockReading{}
	}
	n.clocks.last[peer] = clockReading{offset, got}
	n.clocks.mu.Unlock()
	n.checkClock()
}

// clockOffset returns how far the cluster's clock is ahead of this node's: the median of this node's own (0) and the
// fresh readings of its peers; false until fresh readings from at least quorum-1 peers make a quorum with it.
func (n *Node) clockOffset() (time.Duration, bool) {
	n.clocks.mu.Lock()
	defer n.clocks.mu.Unlock()
	offs := []time.Duration{0} // this node's own clock
	for _, r := range n.clocks.last {
		if time.Since(r.at) < clockFresh {
			offs = append(offs, r.offset)
		}
	}
	if len(offs) < max(n.Quorum(), 2) {
		return 0, false
	}
	slices.Sort(offs)
	if len(offs)%2 == 1 {
		return offs[len(offs)/2], true
	}
	return (offs[len(offs)/2-1] + offs[len(offs)/2]) / 2, true
}

// checkClock refuses to serve while this node's clock is off from the cluster's, and serves again once it is close.
// A voter that has not voted yet (restarting) also takes its start floor from the cluster's time (voter.startFrom):
// every version granted before the restart is below it, whatever this node's clock says.
func (n *Node) checkClock() {
	off, ok := n.clockOffset()
	if !ok {
		return
	}
	if v := n.voter; v != nil && off > 0 && (!n.votes() || time.Now().Before(v.resumeAt)) {
		v.startFrom(off)
	}
	abs := max(off, -off)
	switch {
	case abs > clockLimit:
		dir := "behind"
		if off < 0 {
			dir = "ahead of"
		}
		why := fmt.Sprintf("this node's clock is %s %s the other nodes': fix its time synchronisation (NTP)",
			abs.Round(time.Second), dir)
		if n.clockOff.Swap(&why) == nil {
			n.log.Error("refusing to serve", "reason", why)
			n.rebuild()
		}
	case abs < clockOK:
		if n.clockOff.Swap(nil) != nil {
			n.log.Info("this node's clock agrees with the other nodes' again", "offset", off.Round(time.Millisecond))
			n.rebuild()
		}
	}
}
