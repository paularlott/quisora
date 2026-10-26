package ephemeral

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
