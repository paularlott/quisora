package cluster

import (
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
)

// Every node reads the others' clocks from the change feed: in a healthy cluster each knows its offset, and it is
// small.
func TestClockReadFromPeers(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	for i, tn := range c.nodes {
		waitFor(t, 10*time.Second, "clock read from the peers", func() bool { _, ok := tn.n.clockOffset(); return ok })
		if off, _ := tn.n.clockOffset(); off > time.Second || off < -time.Second {
			t.Fatalf("node %d: offset %s on one machine", i, off)
		}
		if st := tn.n.Status(); st.ClockOffsetMs == nil {
			t.Fatalf("node %d: no clock offset in its status", i)
		}
	}
}

// A node whose clock is off from the other nodes' refuses to serve until it agrees again; one peer with a bad clock
// is outvoted by the median and stops nobody.
func TestClockOffRefusesToServe(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	n := c.nodes[0].n
	// Readings as if from more peers than the real two (which read ~0 every few seconds): the median decides.
	read := func(peer string, off time.Duration) {
		now := time.Now()
		n.clockReading(peer, now, now, now.Add(off).UnixNano())
	}

	read("bad-peer", time.Minute) // one peer a minute ahead, two at ~0: outvoted
	if ok, why := n.Ready(); !ok {
		t.Fatalf("one peer with a bad clock stopped a healthy node: %s", why)
	}

	for _, p := range []string{"x1", "x2", "x3"} { // now most peers say this node is a minute behind
		read(p, time.Minute)
	}
	if ok, why := n.Ready(); ok || !strings.Contains(why, "behind") || n.Writable() || n.votes() || n.ServesTokens() {
		t.Fatalf("a node a minute behind the cluster: ready %v (%s), writable %v, votes %v", ok, why, n.Writable(), n.votes())
	}

	for _, p := range []string{"bad-peer", "x1", "x2", "x3"} { // the clock fixed
		read(p, 0)
	}
	waitFor(t, 10*time.Second, "serving again once the clocks agree", func() bool { ok, _ := n.Ready(); return ok })
}

// A voter that has not voted yet since it started (here: inside its restart pause) takes its start floor from the
// cluster's time, so a clock stepped back across the restart cannot let it grant a version below one it granted
// before.
func TestClockRaisesRestartFloor(t *testing.T) {
	saved := restartPause
	t.Cleanup(func() { restartPause = saved }) // after the cluster below has stopped (cleanups run in reverse)
	restartPause = time.Minute                 // every voter is still in its restart pause throughout
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	n := c.nodes[0].n
	v := n.voter
	floor := func() hlc.Timestamp { v.mu.Lock(); defer v.mu.Unlock(); return v.floor }
	now := time.Now()
	for _, p := range []string{"x1", "x2", "x3"} { // the other nodes' clocks 3 s ahead of this one's
		n.clockReading(p, now, now, now.Add(3*time.Second).UnixNano())
	}
	if want := hlc.FromTime(v.started.Add(3*time.Second + startLead())); floor() < want {
		t.Fatalf("restart floor %v, want the start floor by the cluster's clock (%v)", floor(), want)
	}
}

// Once a voter votes, readings no longer move its floor (it would answer every write low).
func TestClockLeavesVotingFloor(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	n := c.nodes[0].n
	v := n.voter
	v.mu.Lock()
	before := v.floor
	v.mu.Unlock()
	now := time.Now()
	for _, p := range []string{"x1", "x2", "x3"} {
		n.clockReading(p, now, now, now.Add(3*time.Second).UnixNano())
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.floor != before {
		t.Fatal("a reading moved the floor of a voter that votes")
	}
}
