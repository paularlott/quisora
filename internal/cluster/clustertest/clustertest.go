// Package clustertest holds what the tests of gossip clusters share: timings short enough for a test, and free
// addresses to bind.
package clustertest

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/partition"
)

// FreeAddr returns a 127.0.0.1 address whose TCP and UDP ports are both free (gossip binds both).
func FreeAddr(t testing.TB) string {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		l.Close()
		if err != nil {
			continue
		}
		u.Close()
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	t.Fatal("no free port")
	return ""
}

// Gossip shortens gossip's timings (cluster.Options.Gossip): a stopped node is seen dead within about three seconds.
func Gossip(c *gossip.Config) {
	c.GossipInterval = 300 * time.Millisecond
	c.GossipMaxInterval = time.Second
	c.MetadataGossipInterval = 200 * time.Millisecond
	c.StateGossipInterval = time.Second
	c.HealthCheckInterval = 300 * time.Millisecond
	c.PingTimeout = 200 * time.Millisecond
	c.SuspectTimeout = 600 * time.Millisecond
	c.SuspectRetryInterval = 300 * time.Millisecond
	c.DeadNodeTimeout = 2 * time.Second
	c.PeerRecoveryInterval = time.Second
}

// Partition shortens the partition protocol's timings (cluster.Options.Partition): a takeover after a crash takes about
// a second.
func Partition(c *partition.Config) {
	c.HeartbeatInterval = 100 * time.Millisecond
	c.OwnerTimeout = 300 * time.Millisecond
	c.Tuning.BackoffMax = 200 * time.Millisecond
	c.Tuning.RankDelay = 200 * time.Millisecond
	c.Tuning.ReadyHoldDown = 500 * time.Millisecond
	c.Tuning.TakeoverBackoffMax = 3 * time.Second
}
