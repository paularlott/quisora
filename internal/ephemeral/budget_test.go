package ephemeral

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Values count against the budget, which refuses past it and frees as they go; reading a counter keeps nothing.
func TestLocalBudget(t *testing.T) {
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
