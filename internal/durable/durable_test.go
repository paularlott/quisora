package durable

import (
	"os"
	"path/filepath"
	"testing"
)

// WriteFile leaves the file whole or untouched, never torn: a temporary file a crash left behind is replaced, not
// read, and a write that fails leaves the old contents and no temporary file.
func TestWriteFileReplacesTornTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	tmp := path + ".tmp"
	if err := WriteFile(tmp, path, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte(`{"v":2,"torn`), 0o600); err != nil { // a crash mid-save
		t.Fatal(err)
	}
	if err := WriteFile(tmp, path, []byte(`{"v":3}`)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != `{"v":3}` {
		t.Fatalf("state %s", b)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	// The temporary file's place is taken by a directory: the write fails and the old state stays as it was.
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(tmp, path, []byte(`{"v":4}`)); err == nil {
		t.Fatal("a write that could not use its temporary file succeeded")
	}
	if b, _ := os.ReadFile(path); string(b) != `{"v":3}` {
		t.Fatalf("state after a failed write %s", b)
	}
}

func TestWriteFileAndSyncDirErrors(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(filepath.Join(dir, "missing", "x.tmp"), filepath.Join(dir, "missing", "x"), []byte("x")); err == nil {
		t.Error("write into a missing directory succeeded")
	}
	// The final name is a non-empty directory: the rename fails and the temporary file is not left behind.
	blocker := filepath.Join(dir, "blocker")
	if err := os.MkdirAll(filepath.Join(blocker, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(blocker+".tmp", blocker, []byte("x")); err == nil {
		t.Error("rename over a directory succeeded")
	}
	if _, err := os.Stat(blocker + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temporary file left behind: %v", err)
	}
	if err := SyncDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("sync of a missing directory succeeded")
	}
}
