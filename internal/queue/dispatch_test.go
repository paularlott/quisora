package queue

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/secure"
)

// Deliveries are by at most Workers at once and by at most PerKey of one key; what a key's limit holds back is
// delivered as its deliveries end, and everything is delivered in the end.
func TestWorkersAndPerKeyBound(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		g := newGate()
		o := options(t, st, g.deliver)
		o.Workers, o.Key, o.PerKey = 3, keyOf, 2
		q := start(t, o)
		addAll(t, q, "A1", "A2", "A3", "A4", "B1", "B2", "B3")
		waitFor(t, func() bool { return g.inFlight() == 3 })
		time.Sleep(50 * time.Millisecond) // for any delivery that should not start
		g.mu.Lock()
		if g.total != 3 || g.perKey["A"] != 2 || g.perKey["B"] != 1 {
			t.Errorf("in flight %d (A %d, B %d), want 3 workers: A twice, B once", g.total, g.perKey["A"], g.perKey["B"])
		}
		g.mu.Unlock()
		close(g.release)
		waitFor(t, func() bool { return q.Queued() == 0 && g.done.Load() == 7 })
		if g.maxAll > 3 || g.maxKey["A"] > 2 || g.maxKey["B"] > 2 {
			t.Errorf("at most %d at once (A %d, B %d), want 3, 2 and 2", g.maxAll, g.maxKey["A"], g.maxKey["B"])
		}
	})
}

// One key's slow deliveries do not delay another key's due item: with its limit reached the slow key's other items
// wait, and the other key's item is delivered while the slow ones are still running.
func TestSlowKeyDoesNotDelayAnother(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		g := newGate()
		o := options(t, st, g.deliver)
		o.Workers, o.Key, o.PerKey = 2, keyOf, 1
		q := start(t, o)
		addAll(t, q, "A1", "A2", "B1")
		got := map[string]bool{g.next(t): true, g.next(t): true}
		if !got["A1"] || !got["B1"] {
			t.Fatalf("started %v, want A1 and B1 (A2 waits for its key)", got)
		}
	})
}

// An item added while another key's delivery is slow is delivered at once, not once that delivery has ended: the
// workers are free for it (the back-channel retries of one organization that never answers must not hold the first
// retry of another for the 8 s timeout).
func TestAddedItemDoesNotWaitForSlowDelivery(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		g := newGate()
		o := options(t, st, g.deliver)
		o.Workers, o.Key, o.PerKey = 8, keyOf, 2
		q := start(t, o)
		addAll(t, q, "A1")
		if it := g.next(t); it != "A1" {
			t.Fatalf("started %s", it)
		}
		addAll(t, q, "B1") // A1 is still running: nothing has released it
		if it := g.next(t); it != "B1" {
			t.Fatalf("started %s, want B1 while A1 is running", it)
		}
		close(g.release)
		waitFor(t, func() bool { return q.Queued() == 0 })
	})
}

// An item that comes due while another key's delivery is slow is delivered when it does, not once that delivery has
// ended.
func TestDueItemDoesNotWaitForSlowDelivery(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		g := newGate()
		o := options(t, st, g.deliver)
		o.Workers, o.Key, o.PerKey = 8, keyOf, 2
		q := start(t, o)
		if err := q.Add("B1", 200*time.Millisecond, 0); err != nil {
			t.Fatal(err)
		}
		addAll(t, q, "A1")
		if it := g.next(t); it != "A1" {
			t.Fatalf("started %s, want A1 (B1 is not due)", it)
		}
		if it := g.next(t); it != "B1" {
			t.Fatalf("started %s, want B1 once due while A1 is running", it)
		}
		close(g.release)
		waitFor(t, func() bool { return q.Queued() == 0 })
	})
}

// With every worker held by a few keys at PerKey, the next free worker serves a key with no delivery under way, not
// the older backlog of the key it came from: another organization's item waits for a worker, not behind the busy
// organizations' backlogs.
func TestFreeWorkerServesAnIdleKeyFirst(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		started := make(chan string, 100)
		var mu sync.Mutex
		release := map[string]chan struct{}{}
		gate := func(it string) chan struct{} {
			mu.Lock()
			defer mu.Unlock()
			if release[it] == nil {
				release[it] = make(chan struct{})
			}
			return release[it]
		}
		o := options(t, st, func(ctx context.Context, it string) error {
			started <- it
			select {
			case <-gate(it):
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
		o.Workers, o.Key, o.PerKey = 4, keyOf, 2
		q := start(t, o)
		defer func() {
			for _, it := range []string{"A1", "A2", "A3", "A4", "B1", "B2", "B3", "B4", "C1"} {
				select {
				case <-gate(it):
				default:
					close(gate(it))
				}
			}
		}()
		addAll(t, q, "A1", "A2", "A3", "A4", "B1", "B2", "B3", "B4")
		next := func() string {
			t.Helper()
			select {
			case it := <-started:
				return it
			case <-time.After(5 * time.Second):
				t.Fatal("nothing was delivered")
				return ""
			}
		}
		got := []string{next(), next(), next(), next()}
		slices.Sort(got)
		if !slices.Equal(got, []string{"A1", "A2", "B1", "B2"}) {
			t.Fatalf("started %v", got)
		}
		addAll(t, q, "C1")
		close(gate("A1"))
		if it := next(); it != "C1" {
			t.Fatalf("a free worker started %s, want C1 (its key has none under way) before A's backlog", it)
		}
	})
}

// A queue of one worker (the mail queue) delivers one item at a time, oldest first, even with more due at once.
func TestSerialQueueOldestFirst(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		var mu sync.Mutex
		var order []string
		var active, overlap atomic.Int32
		q := start(t, options(t, st, func(_ context.Context, it string) error {
			if active.Add(1) > 1 {
				overlap.Add(1)
			}
			time.Sleep(2 * time.Millisecond)
			active.Add(-1)
			mu.Lock()
			order = append(order, it)
			mu.Unlock()
			return nil
		}))
		want := []string{"1", "2", "3", "4", "5", "6"}
		addAll(t, q, want...)
		waitFor(t, func() bool { return q.Queued() == 0 })
		mu.Lock()
		defer mu.Unlock()
		if overlap.Load() != 0 || !slices.Equal(order, want) {
			t.Errorf("delivered %v with %d overlaps, want %v one at a time", order, overlap.Load(), want)
		}
	})
}

// Close cancels the deliveries in flight and waits for them: their attempts do not count, and the items stay queued.
func TestCloseCancelsDeliveries(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		g := newGate()
		var failed atomic.Int32
		o := options(t, st, g.deliver)
		o.Workers, o.Backoff = 2, []time.Duration{time.Hour}
		o.Failed = func(string, int, time.Duration, error) { failed.Add(1) }
		q := Open(o)
		addAll(t, q, "A1", "B1")
		g.next(t)
		g.next(t)
		closed := make(chan struct{})
		go func() { q.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Close waits for the deliveries")
		}
		if failed.Load() != 0 || q.Queued() != 2 || g.inFlight() != 0 {
			t.Errorf("failed %d, queued %d, in flight %d, want 0, 2 and 0", failed.Load(), q.Queued(), g.inFlight())
		}
		for _, it := range stored(t, q) {
			if it.Attempt != 0 {
				t.Errorf("an attempt cut short counted: %+v", it)
			}
		}
	})
}

// Items are never delivered twice at the same time, whatever the number of workers and passes: every attempt of an
// item ends before its next starts, and each is tried once per delay of the backoff and once at first.
func TestNeverDeliveredTwiceAtOnce(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		var mu sync.Mutex
		active := map[string]bool{}
		attempts := map[string]int{}
		var overlap atomic.Bool
		deliver := func(_ context.Context, it string) error {
			mu.Lock()
			if active[it] {
				overlap.Store(true)
			}
			active[it] = true
			attempts[it]++
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			active[it] = false
			mu.Unlock()
			return errors.New("down")
		}
		o := options(t, st, deliver)
		o.Backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
		o.Workers, o.Key, o.PerKey = 8, keyOf, 3
		q := start(t, o)
		for i := range 30 {
			addAll(t, q, string(rune('A'+i%3))+string(rune('a'+i)))
		}
		waitFor(t, func() bool { return q.Queued() == 0 })
		mu.Lock()
		defer mu.Unlock()
		if overlap.Load() {
			t.Error("an item was delivered twice at once")
		}
		for it, n := range attempts {
			if n != len(o.Backoff)+1 {
				t.Errorf("%s tried %d times, want %d", it, n, len(o.Backoff)+1)
			}
		}
		if len(attempts) != 30 {
			t.Errorf("%d items tried, want 30", len(attempts))
		}
	})
}

// A master key change re-seals the queue while a delivery is in flight, and does not wait for it. The item is then
// recorded as the delivery ended: a delivered one is gone, a failed one is back in the queue sealed with the new key
// (the previous key can go), neither lost nor left as it was.
func TestResealDuringDelivery(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		for _, fail := range []bool{false, true} {
			st, _ := b.open(t)
			oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
			ring := sealer(t, oldKey)
			release := make(chan struct{})
			started := make(chan struct{})
			var delivered atomic.Int32
			o := options(t, st, func(context.Context, string) error {
				delivered.Add(1)
				close(started)
				<-release
				if fail {
					return errors.New("down")
				}
				return nil
			})
			o.Sealer, o.Backoff, o.Workers = ring, []time.Duration{time.Hour}, 2
			q := newQueue(o)
			addAll(t, q, "A1")
			q.dispatch(context.Background())
			<-started
			ring.Replace(sealer(t, newKey, oldKey))
			resealed := make(chan struct{})
			go func() {
				if stale, lost := q.Reseal(); stale != 0 || lost != 0 {
					t.Errorf("stale %d lost %d", stale, lost)
				}
				close(resealed)
			}()
			select {
			case <-resealed:
			case <-time.After(5 * time.Second):
				t.Fatal("Reseal waits for the delivery")
			}
			close(release)
			q.deliveries.Wait()
			ring.Replace(sealer(t, newKey)) // the previous key is retired
			items := stored(t, q)
			switch {
			case !fail && (len(items) != 0 || q.Queued() != 0):
				t.Errorf("delivered item kept: %d, queued %d", len(items), q.Queued())
			case fail && (len(items) != 1 || q.Queued() != 1):
				t.Fatalf("failed item lost: %d, queued %d", len(items), q.Queued())
			case fail:
				if v, err := open(q, items[0]); err != nil || v != `"A1"` || items[0].Attempt != 1 {
					t.Errorf("item after the retry: %q, %+v, %v (not readable with the new key only?)", v, items[0], err)
				}
			}
			if delivered.Load() != 1 {
				t.Errorf("delivered %d times, want once", delivered.Load())
			}
		}
	})
}

// A key whose deliveries never end (an application that never answers) and whose items are many does not cost the
// scheduler a read of each of them every time it looks at the queue: another key's items, added while it is blocked,
// are delivered at once, and the blocked backlog is not read again.
func TestBlockedBacklogIsNotReadAgain(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		const backlog, others = 1000, 20
		inner, _ := b.open(t)
		st := &reads{Store: inner}
		var blocked atomic.Int64
		var delivered sync.Map
		o := options(t, st, func(ctx context.Context, it string) error {
			if keyOf(it) == "A" {
				blocked.Add(1)
				<-ctx.Done()
				return ctx.Err()
			}
			delivered.Store(it, true)
			return nil
		})
		o.Max, o.Workers, o.Key, o.PerKey = 2*backlog, 8, keyOf, 2
		q := start(t, o)
		for i := range backlog {
			addAll(t, q, fmt.Sprintf("A%d", i))
		}
		waitFor(t, func() bool { return blocked.Load() == 2 }) // key A is at its limit

		before, worst := st.n.Load(), time.Duration(0)
		for i := range others {
			it := fmt.Sprintf("B%d", i)
			start := time.Now()
			addAll(t, q, it)
			for {
				if _, ok := delivered.Load(it); ok {
					break
				}
				if time.Since(start) > 10*time.Second {
					t.Fatalf("%s not delivered while key A is blocked", it)
				}
				time.Sleep(time.Millisecond)
			}
			worst = max(worst, time.Since(start))
		}
		n := st.n.Load() - before
		t.Logf("%d items of key B delivered beside %d blocked of key A: slowest %v, %d queued items read", others,
			backlog, worst, n)
		// The few each item of B costs (its own reads), not a read of the backlog per wake.
		if n > others*5 {
			t.Fatalf("%d queued items read to deliver %d items while %d were blocked", n, others, backlog)
		}
		waitFor(t, func() bool { return q.Queued() == backlog }) // the last one ends when its delivery returns
	})
}

// What an item costs the store does not grow with the items it has ended, which the store keeps (expired) until its
// purge: an Add is one write, a delivery a read and a write, and neither lists or counts the queue (whose cost grows
// with every item the store holds of it, expired ones too).
func TestStoreCallsDoNotGrowWithEndedItems(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		const ended = 1000
		inner, _ := b.open(t)
		st := &ops{Store: inner}
		s := &sink{}
		o := options(t, st, s.deliver)
		o.Max, o.MaxPerKey, o.Key, o.Workers, o.PerKey = 2*ended, ended, keyOf, 8, 2
		q := start(t, o)
		one := func(it string) (all, scans int64, took time.Duration) {
			t.Helper()
			all0, scans0, n, start := st.all.Load(), st.scans.Load(), s.count(), time.Now()
			addAll(t, q, it)
			waitFor(t, func() bool { return s.count() == n+1 && q.Queued() == 0 })
			return st.all.Load() - all0, st.scans.Load() - scans0, time.Since(start)
		}
		firstAll, firstScans, firstTook := one("A first")
		for i := range ended {
			addAll(t, q, fmt.Sprintf("%c%d", 'A'+i%4, i))
		}
		waitFor(t, func() bool { return s.count() == ended+1 && q.Queued() == 0 })
		all, scans, took := one("B last")
		t.Logf("one item: %d store calls, %d listings or counts, %v; after %d ended: %d, %d, %v", firstAll, firstScans,
			firstTook, ended, all, scans, took)
		if firstScans != 0 || scans != 0 || all != 3 || firstAll != 3 {
			t.Fatalf("an item cost %d store calls (%d listings or counts), %d after %d ended (%d): want 3 (an add, a "+
				"read, an end) and none", firstAll, firstScans, all, ended, scans)
		}
	})
}

// A request's Add does not wait for the scheduler, whatever the store takes to answer the scheduler's reads.
func TestAddDoesNotWaitForAPass(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		inner, _ := b.open(t)
		st := &slow{Store: inner}
		s := &sink{}
		q := start(t, options(t, st, s.deliver))
		st.slow.Store(true)
		addAll(t, q, "A1")                // the scheduler reads the queue, slowly
		time.Sleep(50 * time.Millisecond) // (and is reading it now)
		begin := time.Now()
		addAll(t, q, "B1")
		if took := time.Since(begin); took > 150*time.Millisecond {
			t.Fatalf("an Add took %v: it waited for the scheduler's reads", took)
		}
		st.slow.Store(false)
		waitFor(t, func() bool { return s.count() == 2 })
	})
}
