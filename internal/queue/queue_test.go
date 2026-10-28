package queue

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// An item that fails is retried after each delay of the backoff, and given up on after the last.
func TestRetryThenGiveUp(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		s := &sink{}
		s.fail.Store(2)
		o := options(t, st, s.deliver)
		o.Backoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
		q := start(t, o)
		addAll(t, q, "a")
		waitFor(t, func() bool { return s.count() == 1 })
		if s.n.Load() != 3 {
			t.Fatalf("attempts %d", s.n.Load())
		}

		s.n.Store(0)
		s.fail.Store(100)
		addAll(t, q, "b")
		waitFor(t, func() bool { return q.Queued() == 0 })
		if s.n.Load() != 3 {
			t.Fatalf("expected 3 attempts then give up, got %d", s.n.Load())
		}
	})
}

// Add with attempts already made starts further down the backoff (a first attempt made elsewhere).
func TestAddAfterAttempts(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		s := &sink{}
		s.fail.Store(100)
		o := options(t, st, s.deliver)
		o.Backoff = []time.Duration{time.Hour, 10 * time.Millisecond}
		q := start(t, o)
		if err := q.Add("a", 10*time.Millisecond, 1); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return q.Queued() == 0 })
		if s.n.Load() != 2 { // the attempts left after the first: the one 10ms on, then give up after the last delay
			t.Fatalf("attempts %d", s.n.Load())
		}
	})
}

// The queue is in the store and sealed: an item not yet delivered when the queue stops goes out from the next one of
// the same node, and nothing of it is readable in the stored record.
func TestSurvivesRestart(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		down := &sink{}
		down.fail.Store(100)
		o := options(t, st, down.deliver)
		o.Backoff = []time.Duration{time.Hour}
		q := Open(o)
		if err := q.Add("ann@example.com s3cr3t", 0, 0); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return down.n.Load() == 1 })
		q.Close()
		it := only(t, q)
		raw, err := st.Get(context.Background(), model.KindQueue, it.ID)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw.Data), "ann@example.com") || strings.Contains(string(raw.Data), "s3cr3t") {
			t.Fatal("queued item readable in the store")
		}
		it.Next = time.Now() // due now
		if err := q.items.Update(context.Background(), it); err != nil {
			t.Fatal(err)
		}
		up := &sink{}
		o.Deliver = up.deliver
		q2 := start(t, o)
		waitFor(t, func() bool { return up.count() == 1 && q2.Queued() == 0 })
	})
}

// A master key rotation re-seals the queue, so the previous key can go without losing an item; an item sealed with a
// key that is not configured is kept, not dropped, and counted as lost (it needs no configured key), not as stale.
func TestSurvivesKeyRotation(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
		down := &sink{}
		down.fail.Store(100)
		o := options(t, st, down.deliver)
		o.Backoff, o.Sealer = []time.Duration{time.Hour}, sealer(t, oldKey)
		q := Open(o)
		addAll(t, q, "invite")
		waitFor(t, func() bool { return down.n.Load() == 1 })
		q.Close()

		o.Sealer = sealer(t, newKey) // the old key removed too early
		q2 := Open(o)
		if stale, lost := q2.Reseal(); stale != 0 || lost != 1 || q2.Queued() != 1 {
			t.Fatalf("stale %d, lost %d, queued %d", stale, lost, q2.Queued())
		}
		q2.Close()

		o.Sealer = sealer(t, newKey, oldKey) // the rotation's keys: Open re-seals
		q3 := Open(o)
		q3.Close()
		q3.o.Sealer = sealer(t, newKey)
		if v, err := open(q3, only(t, q3)); err != nil || v != `"invite"` {
			t.Fatalf("after the re-seal: %v %q", err, v)
		}
	})
}

// Add refuses an item past Max, and one of a key past MaxPerKey without taking what other keys need: an organization
// whose application never answers fills its own share of the queue, not the queue, and its share survives a restart.
func TestCaps(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		stuck := func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() } // never delivers
		o := options(t, st, stuck)
		o.Max, o.MaxPerKey, o.Key = 7, 3, keyOf
		q := Open(o)
		addAll(t, q, "A1", "A2", "A3")
		if err := q.Add("A4", 0, 0); !errors.Is(err, ErrFull) {
			t.Fatalf("a fourth item of A: %v, want ErrFull", err)
		}
		addAll(t, q, "B1", "B2", "B3") // A at its limit takes nothing from the others
		q.Close()

		// What the previous run left counts: each key is still at its limit, and another has room until Max.
		q = start(t, o)
		for _, it := range []string{"A4", "B4"} {
			if err := q.Add(it, 0, 0); !errors.Is(err, ErrFull) {
				t.Fatalf("%s after a restart: %v, want ErrFull", it, err)
			}
		}
		addAll(t, q, "C1")
		if err := q.Add("C2", 0, 0); !errors.Is(err, ErrFull) {
			t.Fatalf("an item past Max: %v, want ErrFull", err)
		}
		if n := q.Queued(); n != 7 {
			t.Fatalf("%d queued, want 7", n)
		}
	})
}

// A key's share is given back by every way an item leaves the queue: delivered, given up on, and discarded at its
// horizon (the store no longer holds it), so the caps cannot drift to refuse a key for good.
func TestCapsFollowTheStore(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		s := &sink{}
		o := options(t, st, s.deliver)
		o.Max, o.MaxPerKey, o.Key, o.Workers = 10, 2, keyOf, 4
		q := newQueue(o)
		ctx := context.Background()
		refill := func(what string) {
			t.Helper()
			addAll(t, q, "A1", "A2")
			if err := q.Add("A3", 0, 0); !errors.Is(err, ErrFull) {
				t.Fatalf("%s: a third item of A: %v, want ErrFull", what, err)
			}
		}
		refill("fresh")
		pass(q, ctx) // delivered
		refill("after delivering")
		s.fail.Store(2)
		pass(q, ctx) // no Backoff: given up on at the first failure
		refill("after giving up")
		for _, it := range stored(t, q) { // their horizon has passed
			it.Expires = time.Now().Add(-time.Second)
			if err := q.items.Update(ctx, it); err != nil {
				t.Fatal(err)
			}
		}
		pass(q, ctx) // discarded, not delivered
		if s.count() != 2 {
			t.Fatalf("delivered %d, want only the first two", s.count())
		}
		refill("after the horizon")
		if q.Queued() != 2 {
			t.Fatalf("%d queued", q.Queued())
		}
		// An item JSON cannot hold is refused with its own error, and takes no place.
		fq := newQueue(Options[func()]{Name: "test", Store: st, Node: o.Node + "-f", Sealer: o.Sealer, Max: 1})
		for range 3 {
			if err := fq.Add(func() {}, 0, 0); err == nil || errors.Is(err, ErrFull) {
				t.Fatalf("an item JSON cannot hold: %v, want its own error", err)
			}
		}
	})
}

// Adds at once are all stored and delivered, and never pass Max between them.
func TestConcurrentAdds(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		s := &sink{}
		o := options(t, st, s.deliver)
		o.Workers = 4
		q := start(t, o)
		var wg sync.WaitGroup
		for i := range 100 {
			wg.Go(func() {
				if err := q.Add(strconv.Itoa(i), 0, 0); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		waitFor(t, func() bool { return s.count() == 100 && q.Queued() == 0 })

		o.Max, o.Deliver = 10, func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }
		o.Node = model.NewID()
		full := start(t, o)
		var mu sync.Mutex
		accepted := 0
		for i := range 30 {
			wg.Go(func() {
				if err := full.Add(strconv.Itoa(i), 0, 0); err == nil {
					mu.Lock()
					accepted++
					mu.Unlock()
				} else if !errors.Is(err, ErrFull) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if accepted != 10 || full.Queued() != 10 {
			t.Fatalf("%d accepted, %d queued, want Max (10)", accepted, full.Queued())
		}
	})
}

// A delivered item is gone from the queue at once and from the store at its next purge; every item carries the
// queue's discard horizon, past its last retry.
func TestEndedItemsArePurged(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, _ := b.open(t)
		s := &sink{}
		o := options(t, st, s.deliver)
		o.Backoff = []time.Duration{time.Minute, time.Hour}
		q := newQueue(o)
		ctx := context.Background()
		before := time.Now()
		if err := q.Add("a", time.Second, 0); err != nil {
			t.Fatal(err)
		}
		it := only(t, q)
		if lo, hi := before.Add(time.Second+time.Minute+time.Hour+discardMargin), time.Now().Add(time.Second+time.Minute+time.Hour+discardMargin); it.Expires.Before(lo.Add(-time.Millisecond)) || it.Expires.After(hi.Add(time.Millisecond)) {
			t.Fatalf("expires %v, want past the last retry by %v", it.Expires, discardMargin)
		}
		elapse(q)
		pass(q, ctx)
		if s.count() != 1 || q.Queued() != 0 {
			t.Fatalf("delivered %d, queued %d", s.count(), q.Queued())
		}
		if r, err := st.Lookup(ctx, model.KindQueue, it.ID); err != nil || r.Live(time.Now()) {
			t.Fatalf("the delivered item: %v, %v (want it stored expired, until the purge)", r, err)
		}
		if _, err := st.Purge(ctx, time.Now(), time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Lookup(ctx, model.KindQueue, it.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the delivered item after a purge: %v", err)
		}
	})
}

// Nodes that share a database each deliver their own items only, never one of another node, whatever each of them
// holds; each node's caps and count are of its own items.
func TestNodesDeliverTheirOwnItems(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, again := b.open(t)
		if again == nil {
			t.Skip("one process per database")
		}
		var mu sync.Mutex
		got := map[string][]string{} // node -> items it delivered
		deliverAs := func(node string) func(context.Context, string) error {
			return func(_ context.Context, it string) error {
				mu.Lock()
				defer mu.Unlock()
				got[node] = append(got[node], it)
				return nil
			}
		}
		oa, ob := options(t, st, nil), options(t, again(), nil)
		ob.Sealer = oa.Sealer // (nodes sharing a database share the master key)
		oa.Deliver, ob.Deliver, oa.Workers, ob.Workers = deliverAs("a"), deliverAs("b"), 4, 4
		qa, qb := start(t, oa), start(t, ob)
		for i := range 20 {
			addAll(t, qa, "a"+strconv.Itoa(i))
			addAll(t, qb, "b"+strconv.Itoa(i))
		}
		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got["a"])+len(got["b"]) == 40 })
		mu.Lock()
		for node, items := range got {
			seen := map[string]bool{}
			for _, it := range items {
				if !strings.HasPrefix(it, node) || seen[it] {
					t.Errorf("node %s delivered %s (its items: %v)", node, it, items)
				}
				seen[it] = true
			}
			if len(items) != 20 {
				t.Errorf("node %s delivered %d items, want its 20", node, len(items))
			}
		}
		mu.Unlock()

		// A node that cannot deliver holds its items; the other's count and caps are of its own.
		qa.Close()
		oa.Deliver, oa.Backoff, oa.Max = func(context.Context, string) error { return errors.New("down") }, []time.Duration{time.Hour}, 3
		qa = start(t, oa)
		addAll(t, qa, "a1", "a2", "a3")
		if err := qa.Add("a4", 0, 0); !errors.Is(err, ErrFull) {
			t.Fatalf("a's fourth item: %v, want ErrFull", err)
		}
		qb.Close()
		ob.Max = 3
		qb = start(t, ob)
		if n := qb.Queued(); n != 0 {
			t.Fatalf("b counts %d items, want none of a's", n)
		}
		addAll(t, qb, "b1", "b2", "b3")
	})
}

// The items of a node that is gone are never delivered by another: they wait for their node, and once past their
// horizon (the time they would have been given up anyway) they are discarded, not counted or delivered by anyone, and
// purged from the store.
func TestGoneNodesItemsAreDiscarded(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		st, again := b.open(t)
		if again == nil {
			t.Skip("one process per database")
		}
		ctx := context.Background()
		gone := options(t, st, func(context.Context, string) error { return errors.New("down") })
		gone.Backoff = []time.Duration{time.Hour}
		qg := newQueue(gone) // (no scheduler: it queues and is gone)
		addAll(t, qg, "g1", "g2")

		other := &sink{}
		oo := options(t, again(), other.deliver)
		oo.Sealer = gone.Sealer
		qo := newQueue(oo)
		addAll(t, qo, "o1")
		for _, it := range stored(t, qg) { // due long ago
			it.Next = time.Now().Add(-time.Hour)
			if err := qg.items.Update(ctx, it); err != nil {
				t.Fatal(err)
			}
		}
		pass(qo, ctx)
		if other.count() != 1 || other.got[0] != "o1" || qo.Queued() != 0 {
			t.Fatalf("the other node delivered %v, holds %d", other.got, qo.Queued())
		}

		var ids []string
		for _, it := range stored(t, qg) { // their horizon has passed
			it.Expires = time.Now().Add(-time.Second)
			if err := qg.items.Update(ctx, it); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, it.ID)
		}
		back := &sink{}
		gone.Deliver = back.deliver
		qb := newQueue(gone) // the node, back at last
		pass(qb, ctx)
		if back.n.Load() != 0 || qb.Queued() != 0 {
			t.Fatalf("items past their horizon: %d delivered, %d counted", back.n.Load(), qb.Queued())
		}
		if _, err := st.Purge(ctx, time.Now(), time.Now()); err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			if _, err := st.Lookup(ctx, model.KindQueue, id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("an item past its horizon after a purge: %v", err)
			}
		}
	})
}
