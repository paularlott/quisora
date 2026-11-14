package cluster

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/store"
)

// The peer clock check. Versions come from the owners' clocks (they only ever rise per record), but sessions, grants
// and every end date expire by each node's own clock, so a node whose clock is off from the cluster's must not serve.
// Every ClockInterval a node asks each peer for its time (msgClock); it reads the offset as NTP does (the peer's time
// against the midpoint of the request), keeps each peer's latest reading in memory, and takes the median of its own
// clock (offset 0) and the fresh readings: the cluster's clock as its majority keeps it, so a minority of bad clocks,
// this node's or a peer's, is outvoted. It decides only once it has heard from enough peers to make a quorum with
// itself; until then nothing changes. Off by more than clockLimit, the node refuses to serve (clockOff) until it is
// back within clockOK. Nothing is kept on disk.
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
// fresh readings of its peers; false until fresh readings from at least quorum-1 peers make a quorum with it. Without
// gossip, nodes sharing a database have no peers to ask: it is how far the database server's clock is ahead (false
// until the first reading).
func (n *Node) clockOffset() (time.Duration, bool) {
	if n.lease != nil { // a shared database: its server's clock is the one measured against
		if off := n.lease.skew.Load(); off != nil {
			return *off, true
		}
		return 0, false
	}
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

// checkClock judges this node's clock against the other nodes' (gossip).
func (n *Node) checkClock() {
	if off, ok := n.clockOffset(); ok {
		n.judgeClock(off, "the other nodes'")
	}
}

// judgeClock refuses to serve while this node's clock is off by more than clockLimit from the one it is measured
// against (the other nodes' median, or a shared database's server: lease.go), and serves again once it is within
// clockOK. off is how far that clock is ahead of this node's.
func (n *Node) judgeClock(off time.Duration, against string) {
	abs := max(off, -off)
	switch {
	case abs > clockLimit:
		dir := "behind"
		if off < 0 {
			dir = "ahead of"
		}
		why := fmt.Sprintf("this node's clock is %s %s %s: fix its time synchronisation (NTP)",
			abs.Round(time.Second), dir, against)
		if n.clockOff.Swap(&why) == nil {
			n.log.Error("refusing to serve", "reason", why)
			n.rebuild()
		}
	case abs < clockOK:
		if n.clockOff.Swap(nil) != nil {
			n.log.Info("this node's clock agrees with "+against+" again", "offset", off.Round(time.Millisecond))
			n.rebuild()
		}
	}
}

type clockReq struct {
	V int // nothing: a request carries a body
}

type clockResp struct {
	Now int64 // the responder's clock, unix nanos
}

// handleClock answers a peer's clock reading.
func (n *Node) handleClock(*gossip.Node, *gossip.Packet) (any, error) {
	return &clockResp{Now: time.Now().UnixNano()}, nil
}

// watchLoop reads every alive peer's clock every ClockInterval, and refreshes the membership view and this node's
// published readiness every second at most (the partition protocol becomes ready, or stops being, without a gossip
// event to say so); a node that holds no data set yet looks for one to join as often (joinDataSet), and one that has
// not formed the cluster names the peers it cannot see, a minute after starting and every minute after
// (warnMissingPeers).
func (n *Node) watchLoop() {
	defer n.wg.Done()
	t := time.NewTicker(min(n.opt.ClockInterval, time.Second))
	defer t.Stop()
	var last time.Time
	n.peersChecked = time.Now() // (forming takes seconds: nothing is said before a minute)
	for {
		if time.Since(last) >= n.opt.ClockInterval {
			last = time.Now()
			n.readClocks()
		}
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
			n.rebuild()
			if err := n.joinDataSet(); err != nil {
				n.log.WithError(err).Error("could not start the partition protocol")
			}
			n.warnMissingPeers(time.Now())
		}
	}
}

// readClocks asks each alive peer for its time (a peer that does not answer in a few seconds is left out).
func (n *Node) readClocks() {
	for _, mb := range n.otherPeers() {
		n.wg.Add(1)
		go func(mb *member) {
			defer n.wg.Done()
			ctx, cancel := context.WithTimeout(n.ctx, 3*time.Second)
			defer cancel()
			sent := time.Now()
			var resp clockResp
			if err := n.gc.SendToWithResponseContext(ctx, mb.node, msgClock, &clockReq{}, &resp); err == nil {
				n.clockReading(mb.id, sent, time.Now(), resp.Now)
			}
		}(mb)
	}
}
