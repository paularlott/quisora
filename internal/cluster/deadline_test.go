package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// A quorum write ends with its caller's deadline when its peers are slow to answer: the deadline reaches the
// transport (gossip.ContextTransport) instead of each exchange running out the transport's own timeouts.
func TestQuorumWriteHonoursCallerDeadline(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	ns := c.net(0)
	ns.mu.Lock()
	ns.slowMsg, ns.slowBy = msgPrepare, 2*time.Second
	ns.mu.Unlock()
	defer func() {
		ns.mu.Lock()
		ns.slowBy = 0
		ns.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(bg, 25*time.Millisecond)
	defer cancel()
	u := newUser("org1", "deadline-write")
	u.ID = model.NewID()
	start := time.Now()
	err := users(c.nodes[0]).Create(ctx, u)
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("quorum write ignored its 25ms deadline for %s: %v", elapsed, err)
	}
	if err == nil {
		t.Fatal("a quorum write no peer answered in time succeeded")
	}
}
