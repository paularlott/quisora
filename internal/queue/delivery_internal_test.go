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

func TestPassCorruptItemIsDropped(t *testing.T) {
	dir := t.TempDir()
	s := sealer(t, secure.RandomBytes(32))
	sk := &sink{}
	q := idle(dir, Options[string]{Sealer: s, Deliver: sk.deliver})
	name := "00000000000000000001-aa" + ext
	put(t, dir, name, "garbage")
	q.queued.Store(1)
	if next := pass(q, context.Background()); !next.IsZero() {
		t.Fatalf("next %v", next)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) || q.Queued() != 0 || sk.n.Load() != 0 {
		t.Fatalf("corrupt item kept (%v), queued %d, delivered %d", err, q.Queued(), sk.n.Load())
	}
	// A sealed value that opens but is not JSON of an item is dropped the same way.
	put(t, dir, name, s.SealFor("test/queue", []byte("not json")))
	q.queued.Store(1)
	pass(q, context.Background())
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatalf("non-JSON item kept: %v", err)
	}
}

func TestPassStoppingDoesNotCountAttempt(t *testing.T) {
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
	if next := pass(q, ctx); !next.IsZero() {
		t.Fatalf("next %v", next)
	}
	it, err := q.read(names[0])
	if err != nil || it.Attempt != 0 || failed != 0 {
		t.Fatalf("attempt %v, failed callbacks %d, err %v", it, failed, err)
	}
	// With the context already cancelled the scheduler does not even try.
	if next := pass(q, ctx); !next.IsZero() {
		t.Fatalf("next %v", next)
	}
}

func TestPassFailureCallbackAndLostRetryWrite(t *testing.T) {
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
	next := pass(q, context.Background())
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
		if next := pass(q, context.Background()); next.IsZero() {
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
	if next := pass(q, context.Background()); !next.IsZero() {
		t.Fatalf("next %v after giving up", next)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) || q.Queued() != 0 {
		t.Fatalf("given-up item kept: %v, queued %d", err, q.Queued())
	}
	if last := len(retries) - 1; retries[last] != 0 || attempts[last] != 3 || retries[0] != time.Hour || attempts[0] != 1 {
		t.Fatalf("callbacks: attempts %v retries %v", attempts, retries)
	}
}

func TestPassNotDueAndUnknownKey(t *testing.T) {
	dir := t.TempDir()
	lost, key := sealer(t, secure.RandomBytes(32)), sealer(t, secure.RandomBytes(32))
	sk := &sink{}
	q := idle(dir, Options[string]{Sealer: lost, Deliver: sk.deliver})
	if err := q.Add("later", time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	name := mustOne(t, q)
	if next := pass(q, context.Background()); next.IsZero() || sk.n.Load() != 0 {
		t.Fatalf("a future item: next %v, delivered %d", next, sk.n.Load())
	}
	// The same file under a keyring without its key (a restart with another master key): kept, not delivered, not
	// dropped.
	q.o.Sealer, q.waiting = key, nil
	if next := pass(q, context.Background()); !next.IsZero() || sk.n.Load() != 0 {
		t.Fatalf("lost-key item: next %v, delivered %d", next, sk.n.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("lost-key item removed: %v", err)
	}
	// A pass reports the earliest due time over several waiting items.
	q.o.Sealer = lost
	if err := q.Add("sooner", 30*time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	next := pass(q, context.Background())
	if next.IsZero() || time.Until(next) > 31*time.Minute {
		t.Fatalf("earliest due %v", time.Until(next))
	}
}
