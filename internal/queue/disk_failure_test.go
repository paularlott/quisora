package queue

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/secure"
)

func TestOpenFailures(t *testing.T) {
	s := sealer(t, secure.RandomBytes(32))
	opts := Options[string]{Name: "q", Log: logger.NewNullLogger(), Sealer: s, Binding: "b", Max: 1, Deliver: (&sink{}).deliver}

	base := t.TempDir()
	put(t, base, "file", "x")
	if _, err := Open(filepath.Join(base, "file", "sub"), opts); err == nil {
		t.Fatal("a directory under a regular file was opened")
	}

	// A directory that cannot be listed: the queue is unreadable and Open says so instead of starting a worker.
	dir := filepath.Join(base, "unreadable")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, dir, 0)
	if q, err := Open(dir, opts); err == nil {
		q.Close()
		t.Fatal("an unreadable queue directory was opened")
	}
}

func TestAddFailures(t *testing.T) {
	s := sealer(t, secure.RandomBytes(32))
	t.Run("unmarshalable", func(t *testing.T) {
		q := idle(t.TempDir(), Options[func()]{Sealer: s})
		if err := q.Add(func() {}, 0, 0); err == nil {
			t.Fatal("an item JSON cannot hold was queued")
		}
		if q.Queued() != 0 {
			t.Fatalf("queued %d", q.Queued())
		}
	})
	t.Run("directory gone", func(t *testing.T) {
		dir := t.TempDir()
		q := idle(dir, Options[string]{Sealer: s})
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := q.Add("a", 0, 0); err == nil || q.Queued() != 0 {
			t.Fatalf("add into a missing directory: %v, queued %d", err, q.Queued())
		}
	})
	t.Run("read-only directory", func(t *testing.T) {
		dir := t.TempDir()
		q := idle(dir, Options[string]{Sealer: s})
		chmod(t, dir, 0o500)
		if err := q.Add("a", 0, 0); err == nil || q.Queued() != 0 {
			t.Fatalf("add into a read-only directory: %v, queued %d", err, q.Queued())
		}
	})
	t.Run("rename fails", func(t *testing.T) {
		dir := t.TempDir()
		q := idle(dir, Options[string]{Sealer: s})
		blocker := filepath.Join(dir, "x"+ext)
		if err := os.MkdirAll(filepath.Join(blocker, "inner"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := q.writeSealed("x"+ext, "sealed"); err == nil {
			t.Fatal("rename over a non-empty directory succeeded")
		}
		if _, err := os.Stat(filepath.Join(dir, ".x"+ext+".tmp")); !os.IsNotExist(err) {
			t.Fatalf("temporary file left behind: %v", err)
		}
	})
	t.Run("directory not syncable", func(t *testing.T) {
		dir := t.TempDir()
		q := idle(dir, Options[string]{Sealer: s})
		chmod(t, dir, 0o300) // may create and rename, may not open the directory to sync it
		if err := q.writeSealed("y"+ext, "sealed"); err == nil {
			t.Fatal("a write whose directory sync failed was reported durable")
		}
	})
}
