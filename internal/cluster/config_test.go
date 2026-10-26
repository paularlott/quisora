package cluster

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func TestNewRefusesBadConfigurations(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend())
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
	cfg.Cluster.Notify = config.Notify{Bind: clustertest.FreeAddr(t), Key: "not a key"}
	if n, err := New(cfg, memstore.New(), Options{}); err == nil {
		n.Close()
		t.Fatal("a mistyped notice key was accepted")
	}
	// With gossip the notice settings are ignored (replication delivers every change already).
	c := newTCluster(t, 3, badgerBackend())
	cfg = c.config(0, t.TempDir())
	cfg.Cluster.Notify = config.Notify{Bind: clustertest.FreeAddr(t), Key: testKey()}
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
	c := newTCluster(t, 3, badgerBackend())
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

func TestStartWithoutOtherPeers(t *testing.T) {
	n, _ := gnode(t)
	n.seedMu.Lock()
	n.seeds, n.seedsSet = nil, true
	n.seedMu.Unlock()
	if err := n.Start(bg); err == nil || !strings.Contains(err.Error(), "names no other node") {
		t.Fatalf("%v", err)
	}
}

func TestDecodeClusterKeysAndLoadNodeID(t *testing.T) {
	good := testKey()
	if k, prev, err := decodeClusterKeys(good, []string{testKey()}); err != nil || len(k) != 32 || len(prev) != 1 {
		t.Fatalf("%v", err)
	}
	for _, key := range []string{"", "!!!", "AAAA"} {
		if _, _, err := decodeClusterKeys(key, nil); err == nil || !strings.Contains(err.Error(), "cluster.key") {
			t.Errorf("key %q: %v", key, err)
		}
	}
	if _, _, err := decodeClusterKeys(good, []string{testKey(), "short"}); err == nil || !strings.Contains(err.Error(), "previous_keys[1]") {
		t.Errorf("previous key: %v", err)
	}

	dir := t.TempDir()
	if id, err := loadNodeID(dir, "0198f0e0-0000-7000-8000-000000000001"); err != nil || id != "0198f0e0-0000-7000-8000-000000000001" {
		t.Errorf("configured: %v %v", id, err)
	}
	if _, err := loadNodeID(dir, "not-a-uuid"); err == nil || !strings.Contains(err.Error(), "node_id must be a UUID") {
		t.Errorf("bad configured id: %v", err)
	}
	if id, err := loadNodeID("", ""); err != nil || id == "" {
		t.Errorf("no directory: %v %v", id, err)
	}
	first, err := loadNodeID(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := loadNodeID(dir, ""); again != first {
		t.Errorf("the persisted id changed: %s %s", first, again)
	}
	// A damaged file is replaced by a new id.
	if err := os.WriteFile(filepath.Join(dir, "node_id"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fresh, err := loadNodeID(dir, ""); err != nil || fresh == first {
		t.Errorf("after damage: %v %v", fresh, err)
	}
	if _, err := loadNodeID(filepath.Join(dir, "missing"), ""); err == nil || !strings.Contains(err.Error(), "persist node id") {
		t.Errorf("unwritable directory: %v", err)
	}
}
