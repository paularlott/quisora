package service_test

import (
	"context"
	"testing"
	"time"
)

// Background work runs on a context that outlives the request that started it, and WaitBackground waits for it.
func TestBackgroundWorkWaits(t *testing.T) {
	e := newEnv(t)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(e.ctx)
	e.svc.Background(ctx, time.Minute, func(ctx context.Context) {
		cancel() // the request ends; the work's context does not
		if ctx.Err() != nil {
			t.Error("background context was cancelled with the request")
		}
		close(done)
	})
	e.svc.WaitBackground()
	select {
	case <-done:
	default:
		t.Error("WaitBackground returned before the work finished")
	}
}

// A background run whose work waits on its context is ended by the deadline, so a stalled store cannot keep
// goroutines for as long as it stalls.
func TestBackgroundDeadline(t *testing.T) {
	e := newEnv(t)
	start := time.Now()
	e.svc.Background(e.ctx, 50*time.Millisecond, func(ctx context.Context) { <-ctx.Done() })
	e.svc.WaitBackground()
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("background work ran %v past its deadline", d)
	}
}
