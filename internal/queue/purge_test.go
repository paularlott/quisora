package queue

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/secure"
)

// PurgeLost removes only the items no configured key opens; the next start counts what is left, and a queue whose
// lost items are purged no longer keeps a previous key from being retired.
func TestPurgeLost(t *testing.T) {
	dir := t.TempDir()
	lostKey, key := secure.RandomBytes(32), secure.RandomBytes(32)
	down := &sink{}
	down.fail.Store(100)
	q := open(t, dir, sealer(t, lostKey), down, time.Hour)
	_ = q.Add("lost", 0, 0)
	waitFor(t, func() bool { return down.n.Load() == 1 })
	q.Close()
	q = open(t, dir, sealer(t, key), down, time.Hour)
	_ = q.Add("kept", time.Hour, 0)
	if _, lost := q.Reseal(); lost != 1 {
		t.Fatalf("lost items before the purge: %d", lost)
	}
	q.Close()

	if n, err := PurgeLost(dir, sealer(t, key), time.Now()); err != nil || n != 1 {
		t.Fatalf("purged %d: %v", n, err)
	}
	q = open(t, dir, sealer(t, key), down, time.Hour)
	defer q.Close()
	if stale, lost := q.Reseal(); q.Queued() != 1 || stale+lost != 0 {
		t.Fatalf("after the purge: queued %d", q.Queued())
	}
	if n, err := PurgeLost(filepath.Join(dir, "missing"), sealer(t, key), time.Now()); err != nil || n != 0 {
		t.Fatalf("a queue never made: %d %v", n, err)
	}
}

// With a time, only the lost items queued before it go (their names say when), while the queue runs; a younger lost
// item stays, to go out if its key is configured again, and a name that is not a queued item's is never judged old.
func TestPurgeLostOlderThan(t *testing.T) {
	dir := t.TempDir()
	lost, key := sealer(t, secure.RandomBytes(32)), sealer(t, secure.RandomBytes(32))
	put := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(lost.SealFor("", []byte("x"))), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stamp := func(at time.Time) string { return fmt.Sprintf("%020d-%s%s", at.UnixNano(), "ab", ext) }
	old := put(stamp(time.Now().Add(-10 * 24 * time.Hour)))
	young := put(stamp(time.Now().Add(-time.Hour)))
	odd := put("not-a-time" + ext)
	// The items are on disk before the queue starts: its worker never reads one half written (and drops it).
	q := open(t, dir, key, &sink{}, time.Hour)
	defer q.Close()
	if n, err := q.PurgeLost(time.Now().Add(-8 * 24 * time.Hour)); err != nil || n != 1 {
		t.Fatalf("purged %d: %v", n, err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the old lost item stayed")
	}
	for _, p := range []string{young, odd} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was purged", filepath.Base(p))
		}
	}
	if q.Queued() != 2 {
		t.Fatalf("queued %d", q.Queued())
	}
}

func TestPurgeLostFailures(t *testing.T) {
	lostKey, key := sealer(t, secure.RandomBytes(32)), sealer(t, secure.RandomBytes(32))
	lostItem := lostKey.SealFor("", []byte("x"))

	base := t.TempDir()
	put(t, base, "file", "x")
	if _, err := PurgeLost(filepath.Join(base, "file"), key, time.Now()); err == nil {
		t.Fatal("a regular file is not a queue directory")
	}

	// An unreadable item stops the purge with an error, counting what it removed before.
	dir := t.TempDir()
	put(t, dir, "00000000000000000001-aa"+ext, lostItem)
	put(t, dir, "00000000000000000002-bb"+ext, "x")
	chmod(t, filepath.Join(dir, "00000000000000000002-bb"+ext), 0)
	if n, err := PurgeLost(dir, key, time.Now()); err == nil || n != 1 {
		t.Fatalf("purged %d, err %v", n, err)
	}

	// A lost item that cannot be removed is an error too.
	dir = t.TempDir()
	put(t, dir, "00000000000000000001-aa"+ext, lostItem)
	chmod(t, dir, 0o500)
	if n, err := PurgeLost(dir, key, time.Now()); err == nil || n != 0 {
		t.Fatalf("purged %d, err %v", n, err)
	}
}

func TestPurgeLostKeepsOpenableAndForeignItems(t *testing.T) {
	dir := t.TempDir()
	key := sealer(t, secure.RandomBytes(32))
	put(t, dir, "00000000000000000001-aa"+ext, key.SealFor("", []byte("mine")))
	put(t, dir, "00000000000000000002-bb"+ext, key.SealFor("other/queue", []byte("another binding")))
	put(t, dir, "00000000000000000003-cc"+ext, "not sealed at all")
	put(t, dir, "notes.txt", "ignored")
	if n, err := PurgeLost(dir, key, time.Now()); err != nil || n != 0 {
		t.Fatalf("purged %d: %v", n, err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 4 {
		t.Fatalf("%d files left", len(ents))
	}
}

// The daily sweep subtracts what it removed: a place an add has taken but not yet written to disk stays taken.
func TestPurgeLostKeepsPlacesOfAddsInFlight(t *testing.T) {
	q := idle(t.TempDir(), Options[string]{Sealer: sealer(t, secure.RandomBytes(32)), Max: 1})
	q.queued.Add(1) // an add between taking its place and writing its file
	q.inflight.Add(1)
	if _, err := q.PurgeLost(time.Now()); err != nil {
		t.Fatal(err)
	}
	if q.Queued() != 1 {
		t.Fatalf("queued %d after the sweep, want the add in flight's 1", q.Queued())
	}
	if err := q.Add("x", 0, 0); err != ErrFull {
		t.Fatalf("a second add while the first holds the only place: %v", err)
	}
}
