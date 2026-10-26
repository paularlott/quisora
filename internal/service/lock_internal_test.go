package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/store/memstore"
)

// A caller waiting for a held lock stops waiting when its context ends, not when the wait runs out.
func TestLockWaitEndsWithTheContext(t *testing.T) {
	s := newInternalService(t, memstore.New())
	held, err := s.lock(context.Background(), "test/lock", time.Minute, time.Second, "held")
	if err != nil {
		t.Fatal(err)
	}
	defer held.release(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = s.lock(ctx, "test/lock", time.Minute, 10*time.Second, "held")
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("waited %s", d)
	}
}
