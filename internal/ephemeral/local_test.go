package ephemeral

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/metrics"
)

func TestLocalNamespacesTakeExpiryAndCounters(t *testing.T) {
	l := NewLocal("n1")
	defer l.Close()
	ctx := context.Background()
	id, _ := l.New(ctx, "code", []byte("v"), time.Minute)
	if Owner(id) != "n1" {
		t.Fatal("owner")
	}
	if v, err := l.Get(ctx, "code", id); err != nil || string(v) != "v" {
		t.Fatal("get")
	}
	if _, err := l.Get(ctx, "other", id); err != ErrNotFound {
		t.Fatal("namespace isolation")
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := l.Take(ctx, "code", id); err == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("take must be single-use, got %d", wins.Load())
	}
	l.Set(ctx, "x", "k", []byte("1"), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, err := l.Get(ctx, "x", "k"); err != ErrNotFound {
		t.Fatal("expiry")
	}
	for i := range 3 {
		n, _ := l.Incr(ctx, "rl", "ip", 1, time.Minute)
		if n != int64(i+1) {
			t.Fatal("incr")
		}
	}
}

// Values count against the budget, which refuses past it and frees as they go; reading a counter keeps nothing.
func TestLocalBudgetRefusesValuesButNotCounters(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	l.Budget = 10 << 10 // 10 KiB
	val := make([]byte, 1000)
	var ids []string
	for {
		id, err := l.New(ctx, "flow", val, time.Minute)
		if errors.Is(err, ErrFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		if len(ids) > 20 {
			t.Fatal("the budget never refused")
		}
	}
	if len(ids) < 8 || l.Used() > l.Budget {
		t.Fatalf("%d values, %d bytes used of %d", len(ids), l.Used(), l.Budget)
	}
	// Counters are never refused, even when values have filled the budget.
	if n, err := l.Incr(ctx, "rate", "ip", 1, time.Minute); err != nil || n != 1 {
		t.Fatalf("counter while full: %d %v", n, err)
	}
	for _, id := range ids {
		if _, err := l.Take(ctx, "flow", id); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Delete(ctx, "rate", "ip")
	if l.Used() != 0 {
		t.Fatalf("%d bytes still counted after everything went", l.Used())
	}
	// Reading a counter that does not exist keeps nothing (a flood of requests from new addresses costs nothing).
	for i := range 1000 {
		if n, err := l.Incr(ctx, "rate", string(rune(i)), 0, time.Minute); err != nil || n != 0 {
			t.Fatal(n, err)
		}
	}
	if l.Used() != 0 {
		t.Fatalf("reading counters kept %d bytes", l.Used())
	}
}

func BenchmarkNewTake(b *testing.B) {
	l := NewLocal("n1")
	defer l.Close()
	ctx := context.Background()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id, _ := l.New(ctx, "code", []byte("value"), time.Minute)
			l.Take(ctx, "code", id)
		}
	})
}

// warnings counts a logger's warnings.
type warnings struct {
	logger.Logger
	n atomic.Int32
}

func (w *warnings) Warn(string, ...any) { w.n.Add(1) }

// Every refusal of a full store is counted (quisora_ephemeral_refused_total{reason="full"}), but logged once a
// minute, however many requests are refused; Len and Limit report what the gauges read.
func TestLocalFullCountedLoggedOnceAndMeasured(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	log := &warnings{Logger: logger.NewNullLogger()}
	l.Budget, l.Log = 4<<10, log
	if l.Limit() != 4<<10 || (&Local{}).Limit() != DefaultBudget {
		t.Fatalf("limit %d", l.Limit())
	}
	before := metrics.EphemeralRefused.Value("full")
	held := 0
	for range 100 {
		if _, err := l.New(ctx, "flow", make([]byte, 1000), time.Minute); err == nil {
			held++
		} else if !errors.Is(err, ErrFull) {
			t.Fatal(err)
		}
	}
	if held == 0 || held >= 100 {
		t.Fatalf("%d values held", held)
	}
	if got := metrics.EphemeralRefused.Value("full") - before; got != uint64(100-held) {
		t.Fatalf("%d refusals counted, want %d", got, 100-held)
	}
	if log.n.Load() != 1 {
		t.Fatalf("%d warnings for %d refusals, want 1", log.n.Load(), 100-held)
	}
	_, _ = l.Incr(ctx, "rate", "ip", 1, time.Minute)
	if l.Len() != held+1 {
		t.Fatalf("len %d, want %d", l.Len(), held+1)
	}
	// another minute on, the next refusal is logged again
	l.logged.Add(-int64(time.Minute))
	if _, err := l.New(ctx, "flow", make([]byte, 4000), time.Minute); !errors.Is(err, ErrFull) || log.n.Load() != 2 {
		t.Fatalf("%v, %d warnings", err, log.n.Load())
	}
}

// Counters whose keys a client chooses cannot grow without bound: past the budget (at least minCounterBudget) a new
// counter is not made and Incr reports Contended, so the limit refuses; counters already held go on counting, and
// expiries make room again.
func TestLocalCountersCapped(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	l.Budget = 1 << 20
	before := metrics.EphemeralRefused.Value("counters")
	if n, err := l.Incr(ctx, "lockout", "real-user", 1, time.Minute); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	refused := 0
	for i := range 200_000 {
		n, err := l.Incr(ctx, "lockout", fmt.Sprintf("org:nobody-%d@example.com", i), 1, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if n == Contended {
			refused++
		}
	}
	if refused == 0 || l.counters.Load() > minCounterBudget || l.Used() > minCounterBudget {
		t.Fatalf("refused %d of 200000; %d bytes of counters, %d used", refused, l.counters.Load(), l.Used())
	}
	if got := metrics.EphemeralRefused.Value("counters") - before; got != uint64(refused) {
		t.Fatalf("metric counted %v refusals, %d made", got, refused)
	}
	if n, _ := l.Incr(ctx, "lockout", "real-user", 1, time.Minute); n != 2 {
		t.Fatalf("an existing counter stopped counting: %d", n)
	}
	// Short windows expire and give their room back.
	l2 := NewLocal("n")
	defer l2.Close()
	l2.Budget = 1 << 20
	for i := range 200_000 {
		l2.Incr(ctx, "rl", fmt.Sprint(i), 1, time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond)
	for i := range 100 {
		if n, _ := l2.Incr(ctx, "rl", fmt.Sprint(i), 1, time.Minute); n != 1 {
			t.Fatalf("an expired counter's key: %d", n)
		}
	}
	for i := range 100 {
		l2.Delete(ctx, "rl", fmt.Sprint(i))
	}
	for i := range 200_000 {
		l2.Delete(ctx, "rl", fmt.Sprint(i))
	}
	if l2.Used() != 0 || l2.counters.Load() != 0 {
		t.Fatalf("%d bytes, %d of counters, still counted after everything went", l2.Used(), l2.counters.Load())
	}
}

// Counters, however many, never take the values' room: with the counters at their cap a new sign-in's state is still
// kept, and Used (what Budget limits) counts only the values.
func TestLocalCountersDoNotSqueezeValues(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	l.Budget = 1 << 20 // the counters' cap is minCounterBudget, far above it
	for i := 0; ; i++ {
		n, _ := l.Incr(ctx, "lockout", fmt.Sprint(i), 1, time.Minute)
		if n == Contended {
			break
		}
		if i > 1_000_000 {
			t.Fatal("the counters' cap never refused")
		}
	}
	if l.Counters() <= l.Budget || l.Counters() > l.CounterLimit() || l.Used() != 0 {
		t.Fatalf("counters %d (cap %d), values %d", l.Counters(), l.CounterLimit(), l.Used())
	}
	held := 0
	for range 100 {
		if _, err := l.New(ctx, "flow", make([]byte, 1000), time.Minute); err == nil {
			held++
		}
	}
	if held != 100 {
		t.Fatalf("values refused beside full counters: %d of 100 kept", held)
	}
}

// A counter's key given a value stops being a counter: its room moves from the counters to the values, checked
// against the budget like any value.
func TestLocalCounterKeyGivenAValue(t *testing.T) {
	ctx := context.Background()
	l := NewLocal("n")
	defer l.Close()
	l.Incr(ctx, "x", "k", 1, time.Minute)
	if l.Counters() == 0 || l.Used() != 0 {
		t.Fatalf("counter: %d counters, %d values", l.Counters(), l.Used())
	}
	if err := l.Set(ctx, "x", "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if l.Counters() != 0 || l.Used() != int64(len("x/k")+1+itemOverhead) {
		t.Fatalf("value: %d counters, %d values", l.Counters(), l.Used())
	}
	l.Incr(ctx, "y", "k", 1, time.Minute)
	l.Budget = 1
	if err := l.Set(ctx, "y", "k", nil, time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("a counter's key given a value past the budget: %v", err)
	}
	if l.Counters() == 0 {
		t.Fatal("the refused Set dropped the counter")
	}
}
