package service_test

import (
	"context"
	"testing"
)

// Background work runs on a context that outlives the request that started it, and WaitBackground waits for it.
func TestBackgroundWorkWaits(t *testing.T) {
	e := newEnv(t)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(e.ctx)
	e.svc.Background(ctx, func(ctx context.Context) {
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
