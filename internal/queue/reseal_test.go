package queue

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/secure"
)

// A failed reseal leaves the item sealed with the old key, so the old key must stay configured until Reseal
// reports no failures; once it goes, the item is unreadable.
func TestFailedResealKeepsItemOpenableByPreviousKey(t *testing.T) {
	oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
	ring := sealer(t, oldKey)
	q := open(t, t.TempDir(), ring, &sink{})
	if err := q.Add("queued invitation", time.Hour, 0); err != nil {
		q.Close()
		t.Fatal(err)
	}
	q.Close()
	names, err := q.files()
	if err != nil || len(names) != 1 {
		t.Fatalf("files=%v err=%v", names, err)
	}
	// Deterministically fail the atomic replacement's temporary-file open.
	tmp := filepath.Join(q.dir, "."+names[0]+".tmp")
	if err := os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	ring.Replace(sealer(t, newKey, oldKey))
	failures, _ := q.Reseal()
	if failures != 1 {
		t.Fatalf("failures=%d", failures)
	}
	if _, err := q.read(names[0]); err != nil {
		t.Fatal("old key should still open preserved item", err)
	}
	ring.Replace(sealer(t, newKey))
	_, err = q.read(names[0])
	if !errors.Is(err, secure.ErrUnknownKey) {
		t.Fatalf("expected missing previous key, got %v", err)
	}
}

func TestResealUnreadableAndInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	s := sealer(t, secure.RandomBytes(32))
	q := idle(dir, Options[string]{Sealer: s})
	put(t, dir, "00000000000000000001-aa"+ext, "this is not a sealed value")
	if n, _ := q.Reseal(); n != 1 {
		t.Fatalf("an unsealable file counts as not re-sealed: %d", n)
	}
	// The file vanishing between listing and reading is a delivery, not a failure.
	if err := q.reseal("gone" + ext); err != nil {
		t.Fatal(err)
	}
	// An unreadable file counts as still needing its key.
	name := "00000000000000000002-bb" + ext
	put(t, dir, name, "x")
	chmod(t, filepath.Join(dir, name), 0)
	if err := q.reseal(name); err == nil {
		t.Fatal("unreadable file re-sealed")
	}
	if n, _ := q.Reseal(); n != 2 {
		t.Fatalf("stale %d", n)
	}
}

func TestResealUnreadableQueue(t *testing.T) {
	dir := t.TempDir()
	q := idle(dir, Options[string]{Sealer: sealer(t, secure.RandomBytes(32))})
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if n, _ := q.Reseal(); n != 1 {
		t.Fatalf("an unreadable queue counts as one: %d", n)
	}
	if _, err := q.read("none" + ext); err == nil {
		t.Fatal("read of a missing file")
	}
	if next := pass(q, context.Background()); !next.IsZero() {
		t.Fatalf("next %v", next)
	}
}
