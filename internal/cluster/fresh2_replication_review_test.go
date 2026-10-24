package cluster

import (
	"testing"
	"time"
)

// In a three-node cluster, the local healthy clock and the other healthy node
// outvote a single skewed node. The skewed node must not disable both healthy voters.
func TestFreshTwoHealthyClocksOutvoteOneSkewedPeer(t *testing.T) {
	n := voterNode(t)
	now := time.Now()
	n.clockReading("healthy-peer", now, now, now.UnixNano())
	n.clockReading("skewed-peer", now, now, now.Add(time.Minute).UnixNano())
	if why := n.clockOff.Load(); why != nil {
		t.Fatalf("healthy majority refused to serve: %s", *why)
	}
}
