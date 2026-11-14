package ephemeral_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/metrics"
)

// stores are the stores a held budget must count the same in: a node's own, and a shared database's.
func stores(t *testing.T) map[string]ephemeral.Store {
	l := ephemeral.NewLocal("n1")
	t.Cleanup(l.Close)
	return map[string]ephemeral.Store{"local": l, "shared": newSharedSQLite(t)}
}

// A counter never goes below zero, whatever is given back: a count below zero would admit that many more than its
// limit (the sign-in flows of an address counted in a window that has since started again, then cancelled).
func TestIncrNeverBelowZero(t *testing.T) {
	ctx := context.Background()
	for name, st := range stores(t) {
		if n, err := st.Incr(ctx, "c", "k", 2, time.Minute); err != nil || n != 2 {
			t.Fatalf("%s: %d %v", name, n, err)
		}
		if n, err := st.Incr(ctx, "c", "k", -5, time.Minute); err != nil || n != 0 {
			t.Fatalf("%s: given back more than it held: %d %v, want 0", name, n, err)
		}
		if n, _ := st.Incr(ctx, "c", "k", 1, time.Minute); n != 1 {
			t.Fatalf("%s: the next count after that: %d, want 1", name, n)
		}
	}
}

// What a requester holds is counted in windows, each charge stamped with its window and given back into that one
// only: ending what was counted in the window before buys no room in this one, a charge is given back once in effect
// (never below zero), and the limit holds for charges arriving in any order.
func TestHoldCountsByWindowAndRefundsIntoItsOwn(t *testing.T) {
	ctx := context.Background()
	const window = 20 * time.Minute
	for name, st := range stores(t) {
		at := time.Unix(1_800_000_000, 0).Truncate(window)
		restore := ephemeral.SetNow(func() time.Time { return at })
		var old []ephemeral.Held
		for i := range 3 {
			h, ok, err := ephemeral.Hold(ctx, st, "held", "addr", 1, 3, window)
			if !ok || err != nil {
				t.Fatalf("%s: charge %d: %v %v", name, i, ok, err)
			}
			old = append(old, h)
		}
		if _, ok, _ := ephemeral.Hold(ctx, st, "held", "addr", 1, 3, window); ok {
			t.Fatalf("%s: a fourth within a limit of three", name)
		}
		if n, _ := ephemeral.Holding(ctx, st, "held", "addr", window); n != 3 {
			t.Fatalf("%s: a refused charge stayed counted: %d", name, n)
		}
		// the next window: its own count, and what the old one's charges give back does not touch it
		at = at.Add(window)
		for i := range 3 {
			if _, ok, err := ephemeral.Hold(ctx, st, "held", "addr", 1, 3, window); !ok || err != nil {
				t.Fatalf("%s: charge %d of the next window: %v %v", name, i, ok, err)
			}
		}
		for _, h := range old {
			ephemeral.Release(ctx, st, "held", h)
			ephemeral.Release(ctx, st, "held", h) // twice: nothing more comes back
		}
		if n, _ := ephemeral.Holding(ctx, st, "held", "addr", window); n != 3 {
			t.Fatalf("%s: ending the last window's charges changed this window's count to %d", name, n)
		}
		if _, ok, _ := ephemeral.Hold(ctx, st, "held", "addr", 1, 3, window); ok {
			t.Fatalf("%s: ending the last window's charges bought room in this one", name)
		}
		// a charge of this window given back does make room, once
		h, _, _ := ephemeral.Hold(ctx, st, "held", "other", 2, 2, window)
		ephemeral.Release(ctx, st, "held", h)
		if _, ok, _ := ephemeral.Hold(ctx, st, "held", "other", 2, 2, window); !ok {
			t.Fatalf("%s: a charge given back made no room", name)
		}
		restore()
	}
}

// A budget charges a requester's entries in bytes and refuses past its limit (ErrHeld, counted); another requester is
// not held back, a refund makes room again, and the wider key (an IPv6 /48) holds WideFactor budgets and no more,
// however many narrower keys (/64s) charge it.
func TestBudgetChargesBytesPerHolder(t *testing.T) {
	ctx := context.Background()
	for name, st := range stores(t) {
		limit := int64(8 << 10)
		b := &ephemeral.Budget{Store: st, Limit: func() int64 { return limit }}
		a := ephemeral.Holder{Key: "ip|192.0.2.1"}
		before := metrics.EphemeralRefused.Value("held_bytes")
		var held []*ephemeral.Held
		var err error
		for range 100 {
			var h *ephemeral.Held
			if h, err = b.Charge(ctx, a, "ns", 1000, 10*time.Minute); err != nil {
				break
			}
			held = append(held, h)
		}
		if !errors.Is(err, ephemeral.ErrHeld) || len(held) < 4 || len(held) > 8 {
			t.Fatalf("%s: %d charges of about 1.4 KB within 8 KiB, then %v", name, len(held), err)
		}
		if got := metrics.EphemeralRefused.Value("held_bytes") - before; got != 1 {
			t.Fatalf("%s: %d refusals counted, want 1", name, got)
		}
		if _, err := b.Charge(ctx, ephemeral.Holder{Key: "ip|192.0.2.2"}, "ns", 1000, 10*time.Minute); err != nil {
			t.Fatalf("%s: another requester: %v", name, err)
		}
		held[0].Refund(ctx, st)
		if _, err := b.Charge(ctx, a, "ns", 1000, 10*time.Minute); err != nil {
			t.Fatalf("%s: after a refund: %v", name, err)
		}
		// the wider key: each /64 stays within its own budget, and together they stop at WideFactor of them
		limit = 2 << 10
		n := 0
		for i := range 4 * ephemeral.WideFactor {
			h := ephemeral.Holder{Key: "ip|2001:db8:0:" + strconv.Itoa(i) + "::/64", Wide: "net|2001:db8::/48"}
			if _, err := b.Charge(ctx, h, "ns", 1000, 10*time.Minute); err == nil {
				n++
			} else if !errors.Is(err, ephemeral.ErrHeld) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if most := int(limit * ephemeral.WideFactor / 1000); n == 0 || n > most {
			t.Fatalf("%s: %d /64s of one /48 each kept a kilobyte, past the /48's %d", name, n, most)
		}
		// no budget, or nobody to charge: nothing charged, nothing refused
		limit = 0
		if h, err := b.Charge(ctx, a, "ns", 1<<20, time.Minute); h != nil || err != nil {
			t.Fatalf("%s: with no limit: %v %v", name, h, err)
		}
		if h, err := (*ephemeral.Budget)(nil).Charge(ctx, a, "ns", 1, time.Minute); h != nil || err != nil {
			t.Fatalf("%s: a nil budget: %v %v", name, h, err)
		}
		if h, err := ephemeral.Charge(ctx, "ns", 1, time.Minute); h != nil || err != nil {
			t.Fatalf("%s: a context naming nobody: %v %v", name, h, err)
		}
		limit = 4 << 10
		cctx := b.With(ctx, ephemeral.Holder{Key: "user|u1"})
		if _, err := ephemeral.Charge(cctx, "ns", 8<<10, time.Minute); !errors.Is(err, ephemeral.ErrHeld) {
			t.Fatalf("%s: a charge through the context past the limit: %v", name, err)
		}
	}
}

// The records protections rest on (guard namespaces) have room of their own: sign-in state that fills the node does
// not refuse them, they do not take the sign-in state's room, and past their own cap they are refused (the callers
// fail closed), except a record that only replaces one of the same size.
func TestLocalGuardRecordsKeptApart(t *testing.T) {
	ctx := context.Background()
	l := ephemeral.NewLocal("n1")
	defer l.Close()
	l.Budget, l.GuardBudget = 4<<10, 1<<10
	guard := ephemeral.GuardPrefix + "used"
	for i := 0; ; i++ {
		if _, err := l.New(ctx, "flow", make([]byte, 512), time.Minute); err != nil {
			if !errors.Is(err, ephemeral.ErrFull) {
				t.Fatal(err)
			}
			break
		}
		if i > 100 {
			t.Fatal("the values never filled")
		}
	}
	used := l.Used()
	if err := l.Set(ctx, guard, "k1", []byte("grant"), time.Minute); err != nil {
		t.Fatalf("a guard record on a node whose sign-in state is full: %v", err)
	}
	if l.Used() != used || l.Guarded() == 0 {
		t.Fatalf("a guard record counted against the sign-in state: used %d -> %d, guarded %d", used, l.Used(), l.Guarded())
	}
	before := metrics.EphemeralRefused.Value("guard")
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		err = l.Set(ctx, guard, "fill"+strconv.Itoa(i), make([]byte, 100), time.Minute)
	}
	if !errors.Is(err, ephemeral.ErrFull) || metrics.EphemeralRefused.Value("guard") == before {
		t.Fatalf("guard records past their cap: %v", err)
	}
	if l.Guarded() > l.GuardLimit() {
		t.Fatalf("guard records take %d, past their cap %d", l.Guarded(), l.GuardLimit())
	}
	if err := l.Set(ctx, guard, "k1", []byte("GRANT"), time.Minute); err != nil {
		t.Fatalf("replacing a guard record with one of its size at the cap: %v", err)
	}
	if _, err := l.Take(ctx, guard, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Set(ctx, guard, "k2", []byte("grant"), time.Minute); err != nil {
		t.Fatalf("after one was taken: %v", err)
	}
}

// Stored state is encoded without the HTML escaping: what a requester sent costs its own length to hold.
func TestJSONDoesNotEscapeHTML(t *testing.T) {
	in := struct {
		S string `json:"s"`
	}{strings.Repeat("<&>", 100)}
	if b := ephemeral.JSON(in); len(b) != 300+len(`{"s":""}`) || strings.Contains(string(b), "u003c") {
		t.Fatalf("%d bytes: %.60s", len(b), b)
	}
}

// contended is a store whose counters are too contended to update: nothing is counted, and Incr says so.
type contended struct {
	ephemeral.Store
	deltas []int64
}

func (c *contended) Incr(_ context.Context, _, _ string, delta int64, _ time.Duration) (int64, error) {
	c.deltas = append(c.deltas, delta)
	return ephemeral.Contended, nil
}

// A charge that could not be counted (the counter too contended, or past the counters' cap) is refused
// (ErrContended), and nothing is given back for it: it counted nothing, and taking it off again would leave the
// counter below what is held.
func TestHoldGivesNothingBackForAChargeNotCounted(t *testing.T) {
	st := &contended{}
	if _, ok, err := ephemeral.Hold(context.Background(), st, "held", "addr", 5, 100, time.Minute); ok || !errors.Is(err, ephemeral.ErrContended) {
		t.Fatalf("a charge on a contended counter: %v %v", ok, err)
	}
	if len(st.deltas) != 1 || st.deltas[0] != 5 {
		t.Fatalf("counter updates %v, want the charge alone", st.deltas)
	}
}
