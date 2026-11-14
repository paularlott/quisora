package ephemeral

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/store/memstore"
)

// replacer is Store.Replace, asked for by name so that these tests say what they need of a store.
type replacer interface {
	Replace(ctx context.Context, ns, id string, value []byte) error
}

// Replace writes only over what is there, in a node's memory and in a shared database: an entry that was taken,
// deleted or never made is ErrNotFound and is not made by it, so a request that read an entry before another ended
// it cannot bring it back.
func TestReplaceOnlyWhatIsThere(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	for name, st := range map[string]Store{"local": l, "shared": NewShared(memstore.New())} {
		if err := st.Replace(ctx, "flow", "never", []byte("v")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: replacing what was never there: %v", name, err)
		}
		if _, err := st.Get(ctx, "flow", "never"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: Replace made an entry: %v", name, err)
		}
		id, err := st.New(ctx, "flow", []byte("one"), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Replace(ctx, "flow", id, []byte("two, and longer")); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v, err := st.Get(ctx, "flow", id); err != nil || string(v) != "two, and longer" {
			t.Fatalf("%s: after Replace: %q %v", name, v, err)
		}
		if v, err := st.Take(ctx, "flow", id); err != nil || string(v) != "two, and longer" {
			t.Fatalf("%s: take: %q %v", name, v, err)
		}
		if err := st.Replace(ctx, "flow", id, []byte("three")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: replacing what was taken: %v", name, err)
		}
		if _, err := st.Get(ctx, "flow", id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: Replace made a taken entry again: %v", name, err)
		}
		// a counter is not a value to replace
		if _, err := st.Incr(ctx, "rate", "k", 1, time.Minute); err != nil {
			t.Fatal(err)
		}
		if name == "local" {
			if err := st.Replace(ctx, "rate", "k", []byte("v")); !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: replacing a counter: %v", name, err)
			}
		}
	}
	if l.Used() != 0 {
		t.Fatalf("%d bytes of values counted with none left", l.Used())
	}
}

// Replace keeps the expiry the entry has: an entry saved again lives no longer for it, and one that has expired is
// not there to replace. Its room is counted as the value changes size, and a value that would grow past the budget
// is refused with the entry as it was.
func TestReplaceKeepsExpiry(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	sh := NewShared(memstore.New())
	for name, st := range map[string]Store{"local": l, "shared": sh} {
		if err := st.Set(ctx, "flow", "a", []byte("v1"), 300*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond)
		if err := st.Replace(ctx, "flow", "a", []byte("v2")); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		time.Sleep(200 * time.Millisecond) // past its first expiry, well within a new 300 ms
		if v, err := st.Get(ctx, "flow", "a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: an entry replaced halfway through its time outlived it: %q %v", name, v, err)
		}
		if err := st.Replace(ctx, "flow", "a", []byte("v3")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: replacing what has expired: %v", name, err)
		}
	}
	l.Budget = 2000
	if err := l.Set(ctx, "flow", "b", make([]byte, 1000), time.Minute); err != nil {
		t.Fatal(err)
	}
	used := l.Used()
	if err := l.Replace(ctx, "flow", "b", make([]byte, 1500)); err != nil || l.Used() != used+500 {
		t.Fatalf("a value replaced by a longer one: %v, %d bytes from %d", err, l.Used(), used)
	}
	if err := l.Replace(ctx, "flow", "b", make([]byte, 5000)); !errors.Is(err, ErrFull) || l.Used() != used+500 {
		t.Fatalf("a value replaced by one past the budget: %v, %d bytes", err, l.Used())
	}
	if v, _ := l.Get(ctx, "flow", "b"); len(v) != 1500 {
		t.Fatalf("a refused Replace changed the entry: %d bytes", len(v))
	}
	if err := l.Replace(ctx, "flow", "b", nil); err != nil || l.Used() != used-1000 {
		t.Fatalf("a value replaced by a shorter one: %v, %d bytes from %d", err, l.Used(), used)
	}
}

// Of a Take and Replaces of one entry racing, the entry never survives its Take: whatever Replace reports, once the
// Take has had the entry it is gone for good.
func TestReplaceNeverRevivesWhatWasTaken(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	for i := range 2000 {
		id := fmt.Sprintf("k%d", i)
		_ = l.Set(ctx, "flow", id, []byte("v"), time.Minute)
		var wg sync.WaitGroup
		var took error
		wg.Add(3)
		go func() { defer wg.Done(); _, took = l.Take(ctx, "flow", id) }()
		for range 2 {
			go func() { defer wg.Done(); _ = l.Replace(ctx, "flow", id, []byte("again")) }()
		}
		wg.Wait()
		if took != nil {
			t.Fatalf("take: %v", took)
		}
		if _, err := l.Get(ctx, "flow", id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("an entry that was taken is there again after a Replace raced its Take: %v", err)
		}
	}
	if l.Used() != 0 {
		t.Fatalf("%d bytes counted with nothing kept", l.Used())
	}
}

// The values' budget and the guard records' cap hold when entries are kept at once under different shards' locks:
// each is checked and counted in one step, so writers that would each fit alone never pass the cap together.
func TestCapsHoldAcrossShards(t *testing.T) {
	ctx := context.Background()
	for _, ns := range []string{"flow", GuardPrefix + "used"} {
		for round := range 20 {
			l := NewLocal("n")
			l.Budget, l.GuardBudget = 8<<10, 8<<10
			var wg sync.WaitGroup
			for g := range 32 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range 40 {
						_ = l.Set(ctx, ns, fmt.Sprintf("g%d-k%d", g, i), make([]byte, 150), time.Minute)
					}
				}()
			}
			wg.Wait()
			got := l.Used() + l.Guarded()
			l.Close()
			if got > 8<<10 {
				t.Fatalf("%s, round %d: %d bytes kept under a cap of %d", ns, round, got, 8<<10)
			}
		}
	}
}

// The counts of each kind of entry are exact after a storm of every operation on shared keys: each pool holds what
// its entries take, no more and no less, and every cache value has its place in the order of eviction.
func TestPoolsExactUnderStorm(t *testing.T) {
	l := NewLocal("n")
	defer l.Close()
	l.Budget, l.CacheBudget, l.GuardBudget = 1<<20, 8<<10, 8<<10
	ctx := context.Background()
	nss := []string{"v", CachePrefix + "c", GuardPrefix + "g"}
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(g), 7))
			for range 20000 {
				ns := nss[r.IntN(len(nss))]
				k := fmt.Sprintf("k%d", r.IntN(40))
				switch r.IntN(8) {
				case 0, 1:
					ttl := time.Minute
					if r.IntN(4) == 0 {
						ttl = time.Microsecond
					}
					_ = l.Set(ctx, ns, k, make([]byte, r.IntN(900)), ttl)
				case 2:
					_, _ = l.Take(ctx, ns, k)
				case 3:
					_ = l.Delete(ctx, ns, k)
				case 4:
					_, _ = l.Incr(ctx, ns, k, int64(r.IntN(3)-1), time.Duration(r.IntN(2)+1)*time.Microsecond*50)
				case 5:
					_ = l.Replace(ctx, ns, k, make([]byte, r.IntN(900)))
				default:
					_, _ = l.Get(ctx, ns, k)
				}
				if c := l.Cached(); c > l.CacheLimit() {
					t.Errorf("cache %d past cap %d", c, l.CacheLimit())
					return
				}
				if c := l.Guarded(); c > l.GuardLimit() {
					t.Errorf("guard records %d past cap %d", c, l.GuardLimit())
					return
				}
			}
		}()
	}
	wg.Wait()
	var used, cache, guard, counters int64
	n := 0
	for i := range l.shard {
		s := &l.shard[i]
		for k, v := range s.m {
			switch {
			case v.counter:
				counters += v.size(k)
			case v.cache:
				cache += v.size(k)
				n++
				if v.elem == nil {
					t.Errorf("cache item %s without a place in the order", k)
				}
			case v.guard:
				guard += v.size(k)
			default:
				used += v.size(k)
			}
		}
	}
	if used != l.Used() || cache != l.Cached() || guard != l.Guarded() || counters != l.Counters() || n != l.cacheOrder.Len() {
		t.Fatalf("counted against kept: values %d/%d cache %d/%d guard %d/%d counters %d/%d order %d/%d", l.Used(), used,
			l.Cached(), cache, l.Guarded(), guard, l.Counters(), counters, l.cacheOrder.Len(), n)
	}
}

// A charge counts against its requester's own key and its wider one in the same window, also when the window turns
// between the two counts: counted either side of the turn, the charge would be given back into one window only, and
// the wider key would stay charged for what had ended.
func TestChargeCountsEveryKeyInOneWindow(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	b := &Budget{Store: l, Limit: func() int64 { return 64 << 10 }}
	at := time.Unix(1_800_000_000, 0).Truncate(HeldWindow)
	first := true
	restore := SetNow(func() time.Time {
		if first { // the window turns after the first look at the clock
			first = false
			return at.Add(-time.Second)
		}
		return at
	})
	defer restore()
	h := Holder{Key: "ip|2001:db8:1:2::/64", Wide: "net|2001:db8:1::/48"}
	held, err := b.Charge(ctx, h, "flow", 1000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	holding := func(key string, at time.Time) int64 {
		n, _ := l.Incr(ctx, HeldNS, counterKey(key, HeldWindow, at.UnixNano()/int64(HeldWindow)), 0, HeldWindow)
		return n
	}
	before := at.Add(-time.Second)
	if n, w := holding(h.Key, before), holding(h.Wide, before); n != held.N || w != held.N || holding(h.Wide, at) != 0 {
		t.Fatalf("a charge of %d: %d counted for the address and %d for its network in the window it was made in, %d for "+
			"the network in the next", held.N, n, w, holding(h.Wide, at))
	}
	held.Refund(ctx, l)
	for _, key := range []string{h.Key, h.Wide} {
		if n := holding(key, before) + holding(key, at); n != 0 {
			t.Fatalf("%s is still charged %d for an entry that ended", key, n)
		}
	}
}

// An IPv6 address's widest key (its /32) holds sixty-four budgets and no more, whatever /48s the charges come from;
// a refusal there leaves nothing counted for the narrower keys, and what is given back makes room again.
func TestWidestKeyHoldsItsShare(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	const limit = 4 << 10
	b := &Budget{Store: l, Limit: func() int64 { return limit }}
	var last *Held
	charged := 0
	var err error
	for site := 0; site < 100; site++ { // each charge from a /48 of its own: only the /32 is shared
		h := Holder{Key: fmt.Sprintf("ip|2001:db8:%x:1::/64", site), Wide: fmt.Sprintf("net|2001:db8:%x::/48", site), Widest: "net|2001:db8::/32"}
		var hd *Held
		if hd, err = b.Charge(ctx, h, "flow", 3000, time.Minute); err != nil {
			break
		}
		last, charged = hd, charged+1
	}
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("after %d charges: %v", charged, err)
	}
	n := last.N
	if total, _ := Holding(ctx, l, HeldNS, "net|2001:db8::/32", HeldWindow); total != int64(charged)*n || total > WidestFactor*limit ||
		total+n <= WidestFactor*limit {
		t.Fatalf("the /32 holds %d bytes in %d charges of %d, under sixty-four budgets of %d", total, charged, n, limit)
	}
	fresh := Holder{Key: "ip|2001:db8:ffff:1::/64", Wide: "net|2001:db8:ffff::/48", Widest: "net|2001:db8::/32"}
	if _, err := b.Charge(ctx, fresh, "flow", 3000, time.Minute); !errors.Is(err, ErrHeld) {
		t.Fatalf("a new /48 of a /32 at its budget: %v", err)
	}
	for _, key := range []string{fresh.Key, fresh.Wide} {
		if got, _ := Holding(ctx, l, HeldNS, key, HeldWindow); got != 0 {
			t.Fatalf("a charge refused for the /32 left %d counted for %s", got, key)
		}
	}
	last.Refund(ctx, l)
	if _, err := b.Charge(ctx, fresh, "flow", 3000, time.Minute); err != nil {
		t.Fatalf("after one charge of the /32 was given back: %v", err)
	}
	if _, err := b.Charge(ctx, Holder{Key: "ip|2001:db9::/64", Wide: "net|2001:db9::/48", Widest: "net|2001:db9::/32"}, "flow", 3000, time.Minute); err != nil {
		t.Fatalf("another /32: %v", err)
	}
}

// Guard records are charged against a budget of their own, a sixteenth of the requester's (at least MinGuardHeld),
// apart from what it holds otherwise; and what lives a short time of its own (a code) against one counted in
// windows of that time, which comes back when the entries expire, not twenty minutes later.
func TestGuardAndShortLivedBudgetsAreApart(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	limit := int64(1 << 20)
	b := &Budget{Store: l, Limit: func() int64 { return limit }}
	h := Holder{Key: "user|u1"}
	if GuardLimit(limit) != 64<<10 || GuardLimit(64<<10) != MinGuardHeld {
		t.Fatalf("guard budgets %d and %d", GuardLimit(limit), GuardLimit(64<<10))
	}
	n := 0
	var err error
	for ; n < 1000; n++ {
		if _, err = b.ChargeGuard(ctx, h, GuardPrefix+"used", 400, 20*time.Minute); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrHeld) || n < 60 || n > 90 {
		t.Fatalf("%d guard records of about 770 bytes charged within %d: %v", n, GuardLimit(limit), err)
	}
	if got, _ := Holding(ctx, l, HeldNS, "user|u1", HeldWindow); got != 0 {
		t.Fatalf("guard records took %d bytes of the requester's own budget", got)
	}
	if _, err := b.Charge(ctx, h, "flow", 1000, time.Minute); err != nil {
		t.Fatalf("a flow for a requester at its guard budget: %v", err)
	}

	at := time.Unix(1_800_000_000, 0).Truncate(HeldWindow)
	restore := SetNow(func() time.Time { return at })
	defer restore()
	limit = 8 << 10
	for i := range 4 {
		if _, err := b.ChargeFor(ctx, h, "code", 1500, time.Minute); err != nil {
			t.Fatalf("code %d: %v", i, err)
		}
	}
	if _, err := b.ChargeFor(ctx, h, "code", 1500, time.Minute); !errors.Is(err, ErrHeld) {
		t.Fatalf("a fifth code of 1.9 KB within 8 KiB: %v", err)
	}
	if _, err := b.Charge(ctx, h, "flow", 1500, time.Minute); err != nil {
		t.Fatalf("a flow for a requester at its budget of codes: %v", err)
	}
	at = at.Add(time.Minute) // the codes' window turns with their lifetime, the flows' has nineteen minutes left
	if _, err := b.ChargeFor(ctx, h, "code", 1500, time.Minute); err != nil {
		t.Fatalf("a code a minute later, when the earlier ones have expired: %v", err)
	}
}

// A full cache in a shared database makes room as a node's own does: the oldest rows this node wrote go for a new
// one, and nothing is refused but a row larger than the whole cap. Refused, a document read for a sign-in could not
// be kept, and the sign-in after it had nothing to read it from.
func TestSharedCacheEvictsOldestInsteadOfRefusing(t *testing.T) {
	ctx := context.Background()
	e := NewShared(memstore.New())
	e.CacheBudget = 8 << 10
	ns := CachePrefix + "doc"
	for i := range 40 {
		if err := e.Set(ctx, ns, fmt.Sprintf("d%d", i), make([]byte, 1000), time.Minute); err != nil {
			t.Fatalf("cache row %d, past the cap: %v", i, err)
		}
		if e.Cached() > e.CacheLimit() {
			t.Fatalf("%d bytes of cache rows counted past the cap of %d", e.Cached(), e.CacheLimit())
		}
	}
	if _, err := e.Get(ctx, ns, "d39"); err != nil {
		t.Fatalf("the newest row: %v", err)
	}
	if _, err := e.Get(ctx, ns, "d0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the oldest row is still in the database after it made room: %v", err)
	}
	kept := 0
	for i := range 40 {
		if _, err := e.Get(ctx, ns, fmt.Sprintf("d%d", i)); err == nil {
			kept++
			if i < 40-7 {
				t.Fatalf("row %d was kept over newer ones", i)
			}
		}
	}
	if kept < 5 || kept > 7 || len(e.led.cacheElem) != kept || e.led.cacheOrder.Len() != kept {
		t.Fatalf("%d rows of 1.1 KB kept under 8 KiB (%d in the order of eviction)", kept, e.led.cacheOrder.Len())
	}
	// a row written again is the newest; one taken leaves the order
	oldest := fmt.Sprintf("d%d", 40-kept)
	if err := e.Set(ctx, ns, oldest, make([]byte, 1000), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.Set(ctx, ns, "one more", make([]byte, 1000), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Get(ctx, ns, oldest); err != nil {
		t.Fatalf("a row written again was evicted as the oldest: %v", err)
	}
	if _, err := e.Take(ctx, ns, "one more"); err != nil || e.led.cacheOrder.Len() != kept-1 {
		t.Fatalf("after a take: %v, %d in the order", err, e.led.cacheOrder.Len())
	}
	if err := e.Set(ctx, ns, "big", make([]byte, e.CacheLimit()), time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("a row larger than the whole cap: %v", err)
	}
	// values and guard records still refuse at their caps: only a cache makes room
	e.Budget = 2000
	_ = e.Set(ctx, "flow", "a", make([]byte, 1500), time.Minute)
	if err := e.Set(ctx, "flow", "b", make([]byte, 1500), time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("a value past the budget: %v", err)
	}
}
