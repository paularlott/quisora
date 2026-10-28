package queue

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/secure"
)

// keyOf is the fairness key of the test items: the first letter ("A1" is of key "A").
func keyOf(s string) string { return s[:1] }

// gate is a Deliver that holds every item until it is released, and records which are being delivered at once.
type gate struct {
	release chan struct{}
	mu      sync.Mutex
	active  map[string]int // by item
	perKey  map[string]int
	total   int
	maxKey  map[string]int
	maxAll  int
	started chan string
	done    atomic.Int32
}

func newGate() *gate {
	return &gate{release: make(chan struct{}), active: map[string]int{}, perKey: map[string]int{},
		maxKey: map[string]int{}, started: make(chan string, 100)}
}

func (g *gate) deliver(_ context.Context, it string) error {
	g.mu.Lock()
	g.active[it]++
	g.perKey[keyOf(it)]++
	g.total++
	g.maxKey[keyOf(it)] = max(g.maxKey[keyOf(it)], g.perKey[keyOf(it)])
	g.maxAll = max(g.maxAll, g.total)
	g.mu.Unlock()
	g.started <- it
	<-g.release
	g.mu.Lock()
	g.active[it]--
	g.perKey[keyOf(it)]--
	g.total--
	g.mu.Unlock()
	g.done.Add(1)
	return nil
}

func (g *gate) inFlight() int { g.mu.Lock(); defer g.mu.Unlock(); return g.total }

func addAll(t *testing.T, q *Queue[string], items ...string) {
	t.Helper()
	for _, it := range items {
		if err := q.Add(it, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
}

// A pass delivers by at most Workers at once and by at most PerKey of one key; what a key's limit holds back is
// delivered by the next pass, and the pass says so (its next time is now).
func TestWorkersAndPerKeyBound(t *testing.T) {
	g := newGate()
	q := idle(t.TempDir(), Options[string]{Sealer: sealer(t, secure.RandomBytes(32)), Deliver: g.deliver,
		Workers: 3, Key: keyOf, PerKey: 2})
	addAll(t, q, "A1", "A2", "A3", "A4", "B1", "B2", "B3")
	var next atomic.Value
	passed := make(chan struct{})
	go func() { next.Store(q.deliverDue(context.Background())); close(passed) }()
	waitFor(t, func() bool { return g.inFlight() == 3 })
	time.Sleep(50 * time.Millisecond) // for any delivery that should not start
	g.mu.Lock()
	if g.total != 3 || g.perKey["A"] != 2 || g.perKey["B"] != 1 {
		t.Errorf("in flight %d (A %d, B %d), want 3 workers: A twice, B once", g.total, g.perKey["A"], g.perKey["B"])
	}
	g.mu.Unlock()
	close(g.release)
	<-passed
	if g.maxAll > 3 || g.maxKey["A"] > 2 || g.maxKey["B"] > 2 {
		t.Errorf("at most %d at once (A %d, B %d), want 3, 2 and 2", g.maxAll, g.maxKey["A"], g.maxKey["B"])
	}
	if n := next.Load().(time.Time); n.IsZero() || time.Until(n) > time.Second {
		t.Errorf("a pass that held items back must be followed at once: next %v", n)
	}
	// A3 and A4 were held back by their key (both A deliveries were running when the pass reached them); B3 too
	// when B1 had not finished by then, which depends on timing.
	if n := q.Queued(); n < 2 || n > 3 {
		t.Fatalf("%d queued after the first pass, want A3 and A4 (and perhaps B3) held back", n)
	}
	for range 3 { // each pass delivers what the last held back
		if q.Queued() == 0 {
			break
		}
		q.deliverDue(context.Background())
	}
	if q.Queued() != 0 || g.done.Load() != 7 {
		t.Fatalf("queued %d, delivered %d, want 0 and 7", q.Queued(), g.done.Load())
	}
}

// One key's slow deliveries do not delay another key's due item: with its limit reached the slow key's other items
// wait, and the other key's item is delivered while the slow ones are still running.
func TestSlowKeyDoesNotDelayAnother(t *testing.T) {
	g := newGate()
	q := idle(t.TempDir(), Options[string]{Sealer: sealer(t, secure.RandomBytes(32)), Deliver: g.deliver,
		Workers: 2, Key: keyOf, PerKey: 1})
	addAll(t, q, "A1", "A2", "B1")
	passed := make(chan struct{})
	go func() { q.deliverDue(context.Background()); close(passed) }()
	got := map[string]bool{}
	for range 2 {
		select {
		case it := <-g.started:
			got[it] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("only %v started: the slow key holds the queue", got)
		}
	}
	if !got["A1"] || !got["B1"] {
		t.Fatalf("started %v, want A1 and B1 (A2 waits for its key)", got)
	}
	close(g.release)
	<-passed
}

// Items are never delivered twice at the same time, whatever the number of workers and passes: every attempt of an
// item ends before its next starts, and each is tried once per delay of the backoff and once at first.
func TestNeverDeliveredTwiceAtOnce(t *testing.T) {
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
	backoff := []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	q, err := Open(t.TempDir(), Options[string]{Name: "test queue", Log: logger.NewNullLogger(),
		Sealer: sealer(t, secure.RandomBytes(32)), Binding: "test/queue", Backoff: backoff, Max: 100, Deliver: deliver,
		Workers: 8, Key: keyOf, PerKey: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
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
		if n != len(backoff)+1 {
			t.Errorf("%s tried %d times, want %d", it, n, len(backoff)+1)
		}
	}
	if len(attempts) != 30 {
		t.Errorf("%d items tried, want 30", len(attempts))
	}
}

// A master key change re-seals the queue while a delivery is in flight, and does not wait for it. The item is then
// recorded as the delivery ended: a delivered one is gone, a failed one is back in the queue sealed with the new key
// (the previous key can go), neither lost nor left as it was.
func TestResealDuringDelivery(t *testing.T) {
	for _, fail := range []bool{false, true} {
		oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
		ring := sealer(t, oldKey)
		release := make(chan struct{})
		started := make(chan struct{})
		var delivered atomic.Int32
		q := idle(t.TempDir(), Options[string]{Sealer: ring, Backoff: []time.Duration{time.Hour}, Workers: 2,
			Deliver: func(context.Context, string) error {
				delivered.Add(1)
				close(started)
				<-release
				if fail {
					return errors.New("down")
				}
				return nil
			}})
		addAll(t, q, "A1")
		passed := make(chan struct{})
		go func() { q.deliverDue(context.Background()); close(passed) }()
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
		<-passed
		ring.Replace(sealer(t, newKey)) // the previous key is retired
		names, err := q.files()
		switch {
		case err != nil:
			t.Fatal(err)
		case !fail && (len(names) != 0 || q.Queued() != 0):
			t.Errorf("delivered item kept: %v, queued %d", names, q.Queued())
		case fail && (len(names) != 1 || q.Queued() != 1):
			t.Fatalf("failed item lost: %v, queued %d", names, q.Queued())
		case fail:
			if it, err := q.read(names[0]); err != nil || it.Item != "A1" || it.Attempt != 1 {
				t.Errorf("item after the retry: %+v, %v (not readable with the new key only?)", it, err)
			}
		}
		if delivered.Load() != 1 {
			t.Errorf("delivered %d times, want once", delivered.Load())
		}
	}
}
