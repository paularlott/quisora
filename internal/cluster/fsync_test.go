package cluster

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// MarkSynced writes the cluster state durably (a crash during bootstrap leaves it whole or absent), and a stale
// temporary file is cleared when a node opens its data directory.
func TestMarkSyncedIsAtomicAndStaleTempIsCleared(t *testing.T) {
	dir := t.TempDir()
	if err := MarkSynced(dir, "feed-1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "cluster-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ps persisted
	if err := json.Unmarshal(b, &ps); err != nil || ps.Self != "feed-1" || ps.LastSync == 0 {
		t.Fatalf("state %s: %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-state.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json.tmp"), []byte(`{"torn`), 0o600); err != nil {
		t.Fatal(err)
	}
	tn := newTCluster(t, 2, memBackend).build(0, dir, nil) // New reads the state and clears the temporary file
	defer stop(tn)
	if _, err := os.Stat(filepath.Join(dir, "cluster-state.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("a crash's temporary state file was not cleared when the node opened its data directory")
	}
	if !tn.n.hadStateFile {
		t.Fatal("the state file was not read")
	}
}
