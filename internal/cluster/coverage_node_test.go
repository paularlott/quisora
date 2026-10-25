package cluster

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func TestNewRefusesBadConfigurations(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		tweak func(*config.Config)
		want  string
	}{
		{"no size", func(cfg *config.Config) { cfg.Cluster.Size = 1 }, "cluster.size is required"},
		{"size and peers disagree", func(cfg *config.Config) { cfg.Cluster.Size = 5 }, "names 2 other nodes"},
		{"bad key", func(cfg *config.Config) { cfg.Cluster.Key = "not a key" }, "cluster.key"},
		{"bad previous key", func(cfg *config.Config) { cfg.Cluster.PreviousKeys = []string{"short"} }, "previous_keys[0]"},
		{"wildcard bind", func(cfg *config.Config) { cfg.Cluster.Bind = "0.0.0.0:7946" }, "cluster.advertise is required"},
		{"bind without a port", func(cfg *config.Config) { cfg.Cluster.Bind = "localhost" }, "cluster.advertise is required"},
		{"node id", func(cfg *config.Config) { cfg.Cluster.NodeID = "nope" }, "node_id must be a UUID"},
		{"data directory", func(cfg *config.Config) { cfg.Server.DataDir = filepath.Join(file, "data") }, "data dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := c.config(0, t.TempDir())
			tc.tweak(cfg)
			n, err := New(cfg, memstore.New(), fastOptions())
			if err == nil {
				n.Close()
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want %q", err, tc.want)
			}
		})
	}
}

func TestNewNotifySettings(t *testing.T) {
	cfg := tempConfig(t)
	cfg.Storage.Backend = "postgres"
	cfg.Cluster.Notify = config.Notify{Bind: freeAddr(t), Key: "not a key"}
	if n, err := New(cfg, memstore.New(), Options{}); err == nil {
		n.Close()
		t.Fatal("a mistyped notice key was accepted")
	}
	// With gossip the notice settings are ignored (replication delivers every change already).
	c := newTCluster(t, 3, memBackend)
	cfg = c.config(0, t.TempDir())
	cfg.Cluster.Notify = config.Notify{Bind: freeAddr(t), Key: testKey()}
	n, err := New(cfg, memstore.New(), fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if n.ngc != nil {
		t.Fatal("notice gossip built next to cluster gossip")
	}
}

// A node that cannot find others to join stops waiting when its caller does.
func TestStartStopsWaitingForPeers(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.opts = func(o *Options) { o.JoinWait = time.Minute }
	tn := c.build(0, "", nil)
	defer func() { tn.n.Close(); tn.n.Store().Close() }()
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	err := tn.n.Start(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if err := tn.n.Start(bg); err != nil { // started once: the second call does nothing
		t.Fatalf("second start: %v", err)
	}
}

// A message from a peer of an incompatible build is not handled.
func TestIncompatiblePeerMessagesAreDropped(t *testing.T) {
	n, _ := gnode(t)
	peer := n.gc.LocalNode()
	called := 0
	h := compatOnly(func(*gossip.Node, *gossip.Packet) error { called++; return nil })
	hr := compatOnlyReply(func(*gossip.Node, *gossip.Packet) (any, error) { called++; return nil, nil })
	if err := h(peer, covBad(t)); err != nil || called != 1 {
		t.Fatalf("compatible: %v %d", err, called)
	}
	if _, err := hr(peer, covBad(t)); err != nil || called != 2 {
		t.Fatalf("compatible reply: %v %d", err, called)
	}
	md := n.gc.LocalMetadata()
	md.SetInt(metaCompat, -1)
	md.SetInt(metaMinCompat, 1<<20)
	if err := h(peer, covBad(t)); err != nil || called != 2 {
		t.Fatalf("incompatible: %v %d", err, called)
	}
	if _, err := hr(peer, covBad(t)); !errors.Is(err, errIncompatible) || called != 2 {
		t.Fatalf("incompatible reply: %v %d", err, called)
	}
}

func TestSizeAndQuorumOfGossipNode(t *testing.T) {
	n, _ := gnode(t)
	if n.Size() != 3 || n.Quorum() != 2 || n.Standalone() || !n.Replicating() {
		t.Fatalf("%d %d", n.Size(), n.Quorum())
	}
	if n.SharedDatabase() {
		t.Fatal("a gossip node does not share a database")
	}
	if n.EphemeralStore() != any(n.Ephemeral()) {
		t.Fatal("ephemeral store")
	}
}
