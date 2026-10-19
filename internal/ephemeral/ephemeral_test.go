package ephemeral

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocal(t *testing.T) {
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
