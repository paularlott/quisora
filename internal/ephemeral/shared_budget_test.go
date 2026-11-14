package ephemeral

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// The rows a node writes to the shared database count against the same budgets as a Local's memory: values against
// Budget (limits.ephemeral_mb), refused past it with ErrFull until one is taken, deleted or expires; values of a cache
// namespace against the caches' cap, apart from them; and a new counter past the counters' cap reports Contended (the
// limit refuses for that key), while a counter that exists goes on counting. Each refusal is counted.
func TestSharedBudgets(t *testing.T) {
	ctx := context.Background()
	e := NewShared(memstore.New())
	e.Budget = 10 << 10
	if e.Limit() != 10<<10 || e.CounterLimit() != minCounterBudget || e.CacheLimit() != minCacheBudget {
		t.Fatalf("budgets %d %d %d", e.Limit(), e.CounterLimit(), e.CacheLimit())
	}
	full := metrics.EphemeralRefused.Value("full")
	var ids []string
	var err error
	for range 100 {
		var id string
		if id, err = e.New(ctx, "flow", make([]byte, 1000), time.Minute); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if !errors.Is(err, ErrFull) || len(ids) < 8 || e.Used() > e.Budget || e.Len() != len(ids) {
		t.Fatalf("%d values, %d bytes of %d, then %v", len(ids), e.Used(), e.Budget, err)
	}
	if metrics.EphemeralRefused.Value("full") == full {
		t.Fatal("the refusal is not counted")
	}
	if err := e.Set(ctx, "flow", "more", make([]byte, 1000), time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("set past the budget: %v", err)
	}
	if err := e.Set(ctx, "flow", ids[2], make([]byte, 500), time.Minute); err != nil {
		t.Fatalf("a value replaced by a smaller one: %v", err)
	}
	if _, err := e.Take(ctx, "flow", ids[0]); err != nil {
		t.Fatal(err)
	}
	if err := e.Set(ctx, "flow", "more", make([]byte, 1000), time.Minute); err != nil {
		t.Fatalf("set once a value was taken: %v", err)
	}
	if err := e.Delete(ctx, "flow", ids[1]); err != nil {
		t.Fatal(err)
	}
	if err := e.Set(ctx, "flow", "more2", make([]byte, 1000), time.Minute); err != nil {
		t.Fatalf("set once a value was deleted: %v", err)
	}

	// the caches' cap is apart: a full budget refuses no cache entry, and a full cache no value
	if err := e.Set(ctx, CachePrefix+"doc", "u", make([]byte, 1000), time.Minute); err != nil || e.Cached() == 0 {
		t.Fatalf("a cache entry while the values are full: %v (%d bytes)", err, e.Cached())
	}
	if err := e.Set(ctx, CachePrefix+"doc", "big", make([]byte, e.CacheLimit()), time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("a cache entry past the caches' cap: %v", err)
	}

	// counters: apart from the values, with a cap of their own
	if n, err := e.Incr(ctx, "rate", "a", 1, time.Minute); err != nil || n != 1 || e.Counters() == 0 {
		t.Fatalf("a counter while the values are full: %d %v (%d bytes)", n, err, e.Counters())
	}
	e.led.pool[rowCounter].Store(e.CounterLimit()) // as if a flood of keys had made counters up to the cap
	if n, err := e.Incr(ctx, "rate", "b", 1, time.Minute); err != nil || n != Contended {
		t.Fatalf("a new counter past the cap: %d %v, want Contended", n, err)
	}
	if n, _ := e.Incr(ctx, "rate", "b", 0, time.Minute); n != 0 {
		t.Fatalf("a refused counter was made: %d", n)
	}
	if n, err := e.Incr(ctx, "rate", "a", 1, time.Minute); err != nil || n != 2 {
		t.Fatalf("a counter that exists, past the cap: %d %v", n, err)
	}
}

// What expires leaves the ledger: its budget is free again without anyone taking it.
func TestSharedBudgetExpiry(t *testing.T) {
	ctx := context.Background()
	e := NewShared(memstore.New())
	e.Budget = 4 << 10
	if err := e.Set(ctx, "flow", "a", make([]byte, 3000), 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := e.Set(ctx, "flow", "b", make([]byte, 3000), time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("past the budget: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	e.led.swept.Store(0) // the sweep is due
	if err := e.Set(ctx, "flow", "c", make([]byte, 100), time.Minute); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.Used() > 3000 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := e.Set(ctx, "flow", "b", make([]byte, 3000), time.Minute); err != nil {
		t.Fatalf("once the first expired: %v (%d bytes counted)", err, e.Used())
	}
}

// The records protections rest on (guard namespaces) are kept apart in the shared database as in a Local's memory:
// a node whose values are at their budget still writes them, and past their own cap they are refused (their callers
// fail closed), counted as "guard".
func TestSharedGuardRecordsKeptApart(t *testing.T) {
	ctx := context.Background()
	e := NewShared(memstore.New())
	e.Budget, e.GuardBudget = 4<<10, 2<<10
	for {
		if _, err := e.New(ctx, "flow", make([]byte, 1000), time.Minute); err != nil {
			break
		}
	}
	if err := e.Set(ctx, GuardPrefix+"used", "c1", make([]byte, 500), time.Minute); err != nil {
		t.Fatalf("a guard record on a node whose values are full: %v", err)
	}
	guard := metrics.EphemeralRefused.Value("guard")
	if err := e.Set(ctx, GuardPrefix+"used", "c2", make([]byte, 2000), time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("a guard record past the guards' cap: %v", err)
	}
	if metrics.EphemeralRefused.Value("guard") == guard {
		t.Fatal("the refusal is not counted as guard")
	}
}
