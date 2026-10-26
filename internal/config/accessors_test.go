package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDerivedAccessors(t *testing.T) {
	c := Default()
	c.Server.DataDir = "/d"
	if c.DataPath() != "/d" || c.DataPath("a", "b") != filepath.Join("/d", "a", "b") {
		t.Fatal("DataPath")
	}
	if !c.LocalStorage() || c.SharedStorage() || c.Replicate() {
		t.Fatal("badgerdb is local, no gossip")
	}
	c.Storage.Backend, c.Cluster.Bind = "postgres", ":1"
	if c.LocalStorage() || !c.SharedStorage() || !c.Replicate() {
		t.Fatal("postgres is shared, gossip replicates")
	}
	if tk := (Tokens{AccessTTL: 1, IDTokenTTL: 2, RefreshTTL: 3, CodeTTL: 4}); tk.Access() != time.Second || tk.IDToken() != 2*time.Second ||
		tk.Refresh() != 3*time.Second || tk.Code() != 4*time.Second {
		t.Fatal("token durations")
	}
}

func TestKeyReaders(t *testing.T) {
	c := Default()
	if m, p, err := c.MasterKeys(); err != nil || m != "" || len(p) != 0 {
		t.Fatalf("no key: %q %v %v", m, p, err)
	}
	c.Server.MasterKey, c.Server.PreviousMasterKeys = key(1), []string{key(2)}
	if m, p, err := c.MasterKeys(); err != nil || m != key(1) || len(p) != 1 {
		t.Fatalf("%v", err)
	}
	c.Server.PreviousMasterKeys = []string{"bad", key(1)}
	if _, _, err := c.MasterKeys(); err == nil || !strings.Contains(err.Error(), "[0]") || !strings.Contains(err.Error(), "[1]") {
		t.Fatalf("both previous keys named: %v", err)
	}

	if _, _, err := c.ClusterKeys(); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("no cluster key: %v", err)
	}
	c.Cluster.Key, c.Cluster.PreviousKeys = key(3), []string{key(4)}
	if k, p, err := c.ClusterKeys(); err != nil || k != key(3) || len(p) != 1 {
		t.Fatal(err)
	}
	c.Cluster.PreviousKeys = []string{key(3)}
	if _, _, err := c.ClusterKeys(); err == nil {
		t.Fatal("previous equal to current accepted")
	}

	c.Cluster.Size, c.Cluster.Peers = 3, []string{"a:1", "b:2"}
	if n, p, err := c.ClusterSize(); err != nil || n != 3 || len(p) != 2 {
		t.Fatal(err)
	}
	c.Cluster.Peers = []string{"a:1", "b"}
	if _, _, err := c.ClusterSize(); err == nil || !strings.Contains(err.Error(), `"b"`) {
		t.Fatalf("%v", err)
	}
}
