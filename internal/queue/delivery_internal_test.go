package queue

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// An item that cannot be read (not sealed, or not an item) is dropped, not delivered.
func TestCorruptItemIsDropped(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		sk := &sink{}
		o := options(t, st, sk.deliver)
		ctx := context.Background()
		for _, sealed := range []string{"garbage", o.Sealer.SealFor(o.Binding, []byte("not json"))} {
			it := &model.QueueItem{Meta: model.Meta{ID: model.NewID()}, Queue: o.Name, Node: o.Node,
				Next: time.Now(), Sealed: sealed, Expires: time.Now().Add(time.Hour)}
			if err := store.NewTable[model.QueueItem](st).Create(ctx, it); err != nil {
				t.Fatal(err)
			}
			q := newQueue(o) // (listed by its first pass, the item in it)
			if next := pass(q, ctx); !next.IsZero() {
				t.Fatalf("next %v", next)
			}
			if q.Queued() != 0 || sk.n.Load() != 0 {
				t.Fatalf("%q: queued %d, delivered %d", sealed, q.Queued(), sk.n.Load())
			}
		}
	})
}

// A delivery cut short by the queue closing does not count as an attempt; with its context ended the scheduler does
// not even try.
func TestStoppingDoesNotCountAttempt(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		var failed int
		ctx, cancel := context.WithCancel(context.Background())
		o := options(t, st, func(context.Context, string) error { cancel(); return errors.New("interrupted") })
		o.Backoff, o.Failed = []time.Duration{time.Hour}, func(string, int, time.Duration, error) { failed++ }
		q := newQueue(o)
		addAll(t, q, "a")
		if next := pass(q, ctx); !next.IsZero() {
			t.Fatalf("next %v", next)
		}
		if it := only(t, q); it.Attempt != 0 || failed != 0 {
			t.Fatalf("attempt %d, failed callbacks %d", it.Attempt, failed)
		}
		if next := pass(q, ctx); !next.IsZero() {
			t.Fatalf("next %v", next)
		}
	})
}

// A failed delivery is told to Failed and waits for its next delay; one whose retry the store does not take keeps
// that retry here (its delay, its attempt), and is not tried again before it; the last failure gives the item up.
func TestFailureCallbackAndLostRetryWrite(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		inner, _ := b.open(t)
		st := &faulty{Store: inner}
		var attempts []int
		var retries []time.Duration
		var calls atomic.Int32
		o := options(t, st, func(context.Context, string) error { calls.Add(1); return errors.New("down") })
		o.Backoff = []time.Duration{time.Hour, 2 * time.Hour}
		o.Failed = func(_ string, attempt int, retry time.Duration, _ error) {
			attempts = append(attempts, attempt)
			retries = append(retries, retry)
		}
		q := newQueue(o)
		ctx := context.Background()
		addAll(t, q, "a")
		before := time.Now()
		next := pass(q, ctx)
		if next.Before(before.Add(time.Hour-time.Second)) || next.After(time.Now().Add(time.Hour)) {
			t.Fatalf("next retry %v is not an hour away", next)
		}
		if it := only(t, q); it.Attempt != 1 {
			t.Fatalf("retry not recorded: %+v", it)
		}

		// The retry cannot be written: the store keeps the item as it was, and the queue the retry it could not write
		// (the item is not tried again before its delay of two hours).
		elapse(q)
		st.refuse.Store(true)
		was := calls.Load()
		next = pass(q, ctx)
		st.refuse.Store(false)
		if it := only(t, q); it.Attempt != 1 {
			t.Fatalf("item changed despite the failed write: %+v", it)
		}
		if time.Until(next) < 2*time.Hour-time.Minute {
			t.Fatalf("next try %v: the retry's delay was not kept", next)
		}
		pass(q, ctx)
		if n := calls.Load() - was; n != 1 {
			t.Fatalf("tried %d times, want once before the retry's delay", n)
		}

		// The last failure gives up: the item is gone and the callback saw retry 0.
		elapse(q)
		if next := pass(q, ctx); !next.IsZero() {
			t.Fatalf("next %v after giving up", next)
		}
		if q.Queued() != 0 || len(stored(t, q)) != 0 {
			t.Fatalf("given-up item kept: queued %d", q.Queued())
		}
		if !slices.Equal(attempts, []int{1, 2, 3}) || !slices.Equal(retries, []time.Duration{time.Hour, 2 * time.Hour, 0}) {
			t.Fatalf("callbacks: attempts %v retries %v", attempts, retries)
		}
	})
}

// A delivered item whose end the store does not take (a store refusing writes: a full disk, a database read-only
// after a failover) is not delivered again: its end is written again until the store takes it.
func TestDeliveredItemWithUnrecordedEndIsNotDeliveredAgain(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		inner, _ := b.open(t)
		st := &faulty{Store: inner}
		s := &sink{}
		q := newQueue(options(t, st, s.deliver))
		ctx := context.Background()
		addAll(t, q, "reset link")
		st.refuse.Store(true)
		pass(q, ctx)
		for range 3 { // the store still refuses, each time the end is written again
			elapse(q)
			pass(q, ctx)
		}
		if s.n.Load() != 1 || q.Queued() != 1 {
			t.Fatalf("delivered %d times, %d queued: want once, its end still to write", s.n.Load(), q.Queued())
		}
		st.refuse.Store(false)
		elapse(q)
		pass(q, ctx)
		if s.n.Load() != 1 || q.Queued() != 0 || len(stored(t, q)) != 0 {
			t.Fatalf("delivered %d times, %d queued, %d stored: want once, ended", s.n.Load(), q.Queued(), len(stored(t, q)))
		}
	})
}

// An item not yet due is not delivered, and the pass tells when the earliest is; an item no configured key opens is
// kept, neither delivered nor dropped, and goes out once its key is configured again.
func TestNotDueAndUnknownKey(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		sk := &sink{}
		o := options(t, st, sk.deliver)
		lost := o.Sealer
		q := newQueue(o)
		ctx := context.Background()
		if err := q.Add("later", time.Hour, 0); err != nil {
			t.Fatal(err)
		}
		if err := q.Add("sooner", 30*time.Minute, 0); err != nil {
			t.Fatal(err)
		}
		if next := pass(q, ctx); next.IsZero() || time.Until(next) > 31*time.Minute || sk.n.Load() != 0 {
			t.Fatalf("future items: next %v, delivered %d", next, sk.n.Load())
		}
		addAll(t, q, "now")
		q.o.Sealer = sealer(t, secure.RandomBytes(32)) // a restart with another master key
		pass(q, ctx)
		if sk.n.Load() != 0 || q.Queued() != 3 {
			t.Fatalf("lost-key item: delivered %d, queued %d", sk.n.Load(), q.Queued())
		}
		if stale, lost := q.Reseal(); stale != 0 || lost != 3 {
			t.Fatalf("stale %d lost %d", stale, lost)
		}
		q.o.Sealer = lost // its key is back
		q.Reseal()
		pass(q, ctx)
		if sk.count() != 1 || sk.got[0] != "now" {
			t.Fatalf("delivered %v once its key was back", sk.got)
		}
	})
}

// A failed re-seal leaves the item sealed with the old key, so the old key must stay configured until Reseal reports
// no failures; once it goes, the item does not open. An item that cannot be read counts as stale.
func TestFailedResealKeepsItemOpenableByPreviousKey(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		inner, _ := b.open(t)
		st := &faulty{Store: inner}
		oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
		ring := sealer(t, oldKey)
		o := options(t, st, (&sink{}).deliver)
		o.Sealer = ring
		q := newQueue(o)
		if err := q.Add("queued invitation", time.Hour, 0); err != nil {
			t.Fatal(err)
		}
		pass(q, context.Background()) // (the queue listed: it holds what it was told of only)
		ring.Replace(sealer(t, newKey, oldKey))
		st.refuse.Store(true)
		if stale, _ := q.Reseal(); stale != 1 {
			t.Fatalf("stale %d", stale)
		}
		st.refuse.Store(false)
		it := only(t, q)
		if _, err := open(q, it); err != nil {
			t.Fatal("the old key should still open the item", err)
		}
		ring.Replace(sealer(t, newKey))
		if _, err := open(q, it); !errors.Is(err, secure.ErrUnknownKey) {
			t.Fatalf("expected the previous key missing, got %v", err)
		}

		st.blind.Store(true)
		if stale, _ := q.Reseal(); stale != 1 {
			t.Fatalf("an item that cannot be read: stale %d", stale)
		}
	})
}
