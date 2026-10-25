package queue

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/secure"
)

// idle returns a queue whose worker is not started: the tests drive deliverOne, deliverDue and the file helpers
// themselves, so nothing races them.
func idle[T any](dir string, o Options[T]) *Queue[T] {
	o.Log = logger.NewNullLogger()
	if o.Binding == "" {
		o.Binding = "test/queue"
	}
	if o.Max == 0 {
		o.Max = 100
	}
	return &Queue[T]{o: o, dir: dir, kick: make(chan struct{}, 1), stop: make(chan struct{})}
}

// chmod changes a mode for the test and restores 0o700 before the temporary directory is removed. Permission bits do
// not bind root, so the test is skipped there.
func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
}

func put(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

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

func TestResealUnreadableAndInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	s := sealer(t, secure.RandomBytes(32))
	q := idle(dir, Options[string]{Sealer: s})
	put(t, dir, "00000000000000000001-aa"+ext, "this is not a sealed value")
	if n := q.Reseal(); n != 1 {
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
	if n := q.Reseal(); n != 2 {
		t.Fatalf("stale %d", n)
	}
}

func TestResealUnreadableQueue(t *testing.T) {
	dir := t.TempDir()
	q := idle(dir, Options[string]{Sealer: sealer(t, secure.RandomBytes(32))})
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if n := q.Reseal(); n != 1 {
		t.Fatalf("an unreadable queue counts as one: %d", n)
	}
	if _, err := q.read("none" + ext); err == nil {
		t.Fatal("read of a missing file")
	}
	if next := q.deliverDue(context.Background()); !next.IsZero() {
		t.Fatalf("next %v", next)
	}
}

func TestDeliverOneCorruptItemIsDropped(t *testing.T) {
	dir := t.TempDir()
	s := sealer(t, secure.RandomBytes(32))
	sk := &sink{}
	q := idle(dir, Options[string]{Sealer: s, Deliver: sk.deliver})
	name := "00000000000000000001-aa" + ext
	put(t, dir, name, "garbage")
	q.queued.Store(1)
	if next := q.deliverOne(context.Background(), name); !next.IsZero() {
		t.Fatalf("next %v", next)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) || q.Queued() != 0 || sk.n.Load() != 0 {
		t.Fatalf("corrupt item kept (%v), queued %d, delivered %d", err, q.Queued(), sk.n.Load())
	}
	// A sealed value that opens but is not JSON of an item is dropped the same way.
	put(t, dir, name, s.SealFor("test/queue", []byte("not json")))
	q.queued.Store(1)
	q.deliverOne(context.Background(), name)
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatalf("non-JSON item kept: %v", err)
	}
}

func TestDeliverOneStoppingDoesNotCountAttempt(t *testing.T) {
	dir := t.TempDir()
	s := sealer(t, secure.RandomBytes(32))
	var failed int
	ctx, cancel := context.WithCancel(context.Background())
	q := idle(dir, Options[string]{Sealer: s, Backoff: []time.Duration{time.Hour},
		Deliver: func(context.Context, string) error { cancel(); return errors.New("interrupted") },
		Failed:  func(string, int, time.Duration, error) { failed++ }})
	if err := q.Add("a", 0, 0); err != nil {
		t.Fatal(err)
	}
	names, _ := q.files()
	if next := q.deliverOne(ctx, names[0]); !next.IsZero() {
		t.Fatalf("next %v", next)
	}
	it, err := q.read(names[0])
	if err != nil || it.Attempt != 0 || failed != 0 {
		t.Fatalf("attempt %v, failed callbacks %d, err %v", it, failed, err)
	}
	// With the context already cancelled deliverDue does not even try.
	if next := q.deliverDue(ctx); !next.IsZero() {
		t.Fatalf("next %v", next)
	}
}

func TestDeliverOneFailureCallbackAndLostRetryWrite(t *testing.T) {
	dir := t.TempDir()
	s := sealer(t, secure.RandomBytes(32))
	var attempts []int
	var retries []time.Duration
	lock := false
	q := idle(dir, Options[string]{Sealer: s, Backoff: []time.Duration{time.Hour, 2 * time.Hour},
		Deliver: func(context.Context, string) error {
			if lock { // the disk fails while the delivery is in flight
				chmod(t, dir, 0o500)
			}
			return errors.New("down")
		},
		Failed: func(_ string, attempt int, retry time.Duration, _ error) {
			attempts = append(attempts, attempt)
			retries = append(retries, retry)
		}})
	if err := q.Add("a", 0, 0); err != nil {
		t.Fatal(err)
	}
	name := mustOne(t, q)
	before := time.Now()
	next := q.deliverOne(context.Background(), name)
	if next.Before(before.Add(time.Hour)) || next.After(time.Now().Add(time.Hour)) {
		t.Fatalf("next retry %v is not an hour away", next)
	}
	if it, err := q.read(name); err != nil || it.Attempt != 1 {
		t.Fatalf("retry not recorded: %+v %v", it, err)
	}

	// The retry cannot be written: logged, still returned as the next due time, and the file keeps its old state.
	if os.Geteuid() != 0 {
		put := func() {
			it, _ := q.read(name)
			it.Next = time.Time{}
			if err := q.write(name, it); err != nil {
				t.Fatal(err)
			}
		}
		put()
		lock = true
		if next := q.deliverOne(context.Background(), name); next.IsZero() {
			t.Fatal("a failed retry write dropped the schedule")
		}
		_ = os.Chmod(dir, 0o700)
		if it, err := q.read(name); err != nil || it.Attempt != 1 {
			t.Fatalf("file changed despite the failed write: %+v %v", it, err)
		}
		lock = false
	}

	// The last failure gives up: the item is gone and the callback saw retry 0.
	it, _ := q.read(name)
	it.Attempt, it.Next = 2, time.Time{}
	if err := q.write(name, it); err != nil {
		t.Fatal(err)
	}
	if next := q.deliverOne(context.Background(), name); !next.IsZero() {
		t.Fatalf("next %v after giving up", next)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) || q.Queued() != 0 {
		t.Fatalf("given-up item kept: %v, queued %d", err, q.Queued())
	}
	if last := len(retries) - 1; retries[last] != 0 || attempts[last] != 3 || retries[0] != time.Hour || attempts[0] != 1 {
		t.Fatalf("callbacks: attempts %v retries %v", attempts, retries)
	}
}

func mustOne[T any](t *testing.T, q *Queue[T]) string {
	t.Helper()
	names, err := q.files()
	if err != nil || len(names) != 1 {
		t.Fatalf("files %v %v", names, err)
	}
	return names[0]
}

func TestDeliverOneNotDueAndUnknownKey(t *testing.T) {
	dir := t.TempDir()
	lost, key := sealer(t, secure.RandomBytes(32)), sealer(t, secure.RandomBytes(32))
	sk := &sink{}
	q := idle(dir, Options[string]{Sealer: lost, Deliver: sk.deliver})
	if err := q.Add("later", time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	name := mustOne(t, q)
	if next := q.deliverOne(context.Background(), name); next.IsZero() || sk.n.Load() != 0 {
		t.Fatalf("a future item: next %v, delivered %d", next, sk.n.Load())
	}
	// The same file under a keyring without its key (a restart with another master key): kept, not delivered, not
	// dropped.
	q.o.Sealer, q.waiting = key, nil
	if next := q.deliverOne(context.Background(), name); !next.IsZero() || sk.n.Load() != 0 {
		t.Fatalf("lost-key item: next %v, delivered %d", next, sk.n.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("lost-key item removed: %v", err)
	}
	// deliverDue reports the earliest due time over several waiting items.
	q.o.Sealer = lost
	if err := q.Add("sooner", 30*time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	next := q.deliverDue(context.Background())
	if next.IsZero() || time.Until(next) > 31*time.Minute {
		t.Fatalf("earliest due %v", time.Until(next))
	}
}

func TestPurgeLostFailures(t *testing.T) {
	lostKey, key := sealer(t, secure.RandomBytes(32)), sealer(t, secure.RandomBytes(32))
	lostItem := lostKey.SealFor("", []byte("x"))

	base := t.TempDir()
	put(t, base, "file", "x")
	if _, err := PurgeLost(filepath.Join(base, "file"), key); err == nil {
		t.Fatal("a regular file is not a queue directory")
	}

	// An unreadable item stops the purge with an error, counting what it removed before.
	dir := t.TempDir()
	put(t, dir, "00000000000000000001-aa"+ext, lostItem)
	put(t, dir, "00000000000000000002-bb"+ext, "x")
	chmod(t, filepath.Join(dir, "00000000000000000002-bb"+ext), 0)
	if n, err := PurgeLost(dir, key); err == nil || n != 1 {
		t.Fatalf("purged %d, err %v", n, err)
	}

	// A lost item that cannot be removed is an error too.
	dir = t.TempDir()
	put(t, dir, "00000000000000000001-aa"+ext, lostItem)
	chmod(t, dir, 0o500)
	if n, err := PurgeLost(dir, key); err == nil || n != 0 {
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
	if n, err := PurgeLost(dir, key); err != nil || n != 0 {
		t.Fatalf("purged %d: %v", n, err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 4 {
		t.Fatalf("%d files left", len(ents))
	}
}
