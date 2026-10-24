package cluster

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeSynced leaves the file whole or untouched, never torn: a temporary file a crash left behind is replaced, not
// read, and a write that fails leaves the old contents and no temporary file.
func TestWriteSyncedReplacesTornTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster-state.json")
	if err := writeSynced(path, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", []byte(`{"v":2,"torn`), 0o600); err != nil { // a crash mid-save
		t.Fatal(err)
	}
	if err := writeSynced(path, []byte(`{"v":3}`)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != `{"v":3}` {
		t.Fatalf("state %s", b)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	// The temporary file's place is taken by a directory: the write fails and the old state stays as it was.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(path, []byte(`{"v":4}`)); err == nil {
		t.Fatal("a write that could not use its temporary file succeeded")
	}
	if b, _ := os.ReadFile(path); string(b) != `{"v":3}` {
		t.Fatalf("state after a failed write %s", b)
	}
}

// MarkSynced writes the cluster state the same way (a crash during bootstrap leaves it whole or absent), and a stale
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
