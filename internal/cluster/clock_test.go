package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// The peer clock check on one healthy cluster (BadgerDB).
func TestClockOnOneCluster(t *testing.T) {
	runOn(t, started(t, badgerBackend()),
		scenario{"read from peers", testClockReadFromPeers},
		scenario{"clock off refuses to serve", testClockOffRefusesToServe})
}

// Every node asks the others for their time: in a healthy cluster each knows its offset, and it is small.
func testClockReadFromPeers(t *testing.T, c *tcluster) {
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
func testClockOffRefusesToServe(t *testing.T, c *tcluster) {
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
	if ok, why := n.Ready(); ok || !strings.Contains(why, "behind") || n.Writable() {
		t.Fatalf("a node a minute behind the cluster: ready %v (%s), writable %v", ok, why, n.Writable())
	}

	for _, p := range []string{"bad-peer", "x1", "x2", "x3"} { // the clock fixed
		read(p, 0)
	}
	waitFor(t, 10*time.Second, "serving again once the clocks agree", func() bool { ok, _ := n.Ready(); return ok })
}

func TestClockReadings(t *testing.T) {
	n, _ := gnode(t)
	now := time.Now()
	n.clockReading("p1", now, now, 0) // a reply with no time says nothing
	if len(n.clocks.last) != 0 {
		t.Fatal("a reading without a time was kept")
	}
	// A peer whose clock is hours behind this one's: this node's is ahead of the cluster's, and it stops serving.
	n.clockReading("p1", now, now, now.Add(-2*time.Hour).UnixNano())
	if why := n.clockOff.Load(); why == nil || !strings.Contains(*why, "ahead of") {
		t.Fatalf("%v", why)
	}
	n.clockReading("p1", now, now, now.UnixNano())
	if n.clockOff.Load() != nil {
		t.Fatal("not serving again once the clocks agree")
	}
	n.clockReading("p1", now, now, now.Add(2*time.Hour).UnixNano())
	if why := n.clockOff.Load(); why == nil || !strings.Contains(*why, "behind") {
		t.Fatalf("%v", why)
	}
	// Three clocks: this node's and a healthy peer's outvote a skewed peer's (the median), which stops nobody.
	n, _ = gnode(t)
	n.clockReading("healthy-peer", now, now, now.UnixNano())
	n.clockReading("skewed-peer", now, now, now.Add(time.Minute).UnixNano())
	if why := n.clockOff.Load(); why != nil {
		t.Fatalf("a healthy majority refused to serve: %s", *why)
	}
}

func TestCheckSkewWarnsOncePerOrigin(t *testing.T) {
	n, _ := hnode(t)
	rec := newRec(newID(), "")
	rec.Origin = "far-ahead-node"
	rec.Version = hlc.FromTime(time.Now().Add(2 * time.Hour))
	n.checkSkew(rec)
	n.checkSkew(rec)
	if n.skewed.Load() != 2 {
		t.Fatalf("counted %d", n.skewed.Load())
	}
	if _, ok := n.skewWarned.Load("far-ahead-node"); !ok {
		t.Fatal("not noted")
	}
}

// A node refuses to start on a clock set before the version clock's epoch; a version far ahead of this node's
// clock is applied but not followed (counted), so this node's own versions do not inherit the skew.
func TestClockGuards(t *testing.T) {
	saved := wallNow
	wallNow = func() time.Time { return time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := New(tempConfig(t), memstore.New(), Options{}); !errors.Is(err, ErrClockBeforeEpoch) {
		t.Fatalf("a clock before the epoch: %v", err)
	}
	wallNow = saved
	n, err := New(tempConfig(t), memstore.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	before := store.SkewRefused()
	far := newRec(newID(), "")
	far.Version = hlc.FromTime(time.Now().Add(time.Hour))
	if _, err := n.st.inner.PutReplicated(bg, far); err != nil { // (the backend follows versions: store.Witness)
		t.Fatal(err)
	}
	n.checkSkew(far)
	if store.SkewRefused() <= before || n.Status().ClockSkewed == 0 || n.Status().SkewRefused == 0 {
		t.Fatal("the skew was not counted")
	}
	if v := store.Clock.Now(); v >= far.Version {
		t.Fatal("the clock followed a version an hour ahead")
	}
}

// A node whose clock is off from the others' leads no partition (partition.Manager.SetEligible): it steps down from
// what it owns at once, and takes partitions again once its clock agrees again. (What an ineligible node does is
// gossip/partition's TestIneligibleNodeOnlyFollows.)
func TestClockOffMakesTheNodeIneligible(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend())
	c.opts = func(o *Options) { o.ClockInterval = time.Hour } // (the clock readings below are the only ones)
	c.startAll()
	c.waitReady()
	c.waitSettled()
	n0 := c.nodes[0].n
	read := func(off time.Duration) {
		now := time.Now()
		for _, tn := range c.nodes[1:] {
			n0.clockReading(tn.n.ID(), now, now, now.Add(off).UnixNano())
		}
	}
	read(10 * time.Second)
	waitFor(t, 10*time.Second, "node 0 ineligible, owning nothing", func() bool {
		pm := n0.manager()
		if pm.Eligible() {
			return false
		}
		for p := range partitions {
			if pm.IsOwner(p) {
				return false
			}
		}
		return true
	})
	read(0)
	waitFor(t, 20*time.Second, "node 0 to lead again", func() bool {
		pm := n0.manager()
		if !pm.Eligible() {
			return false
		}
		for p := range partitions {
			if pm.IsOwner(p) {
				return true
			}
		}
		return false
	})
}
