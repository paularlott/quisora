package service_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// WaitBackground may run from many goroutines while others go on starting background work (a request finishing while
// a test or shutdown waits): it returns once nothing started before it is running, and never panics.
func TestWaitBackgroundWhileStarting(t *testing.T) {
	e := newEnv(t)
	var ran atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				e.svc.Background(context.Background(), time.Second, func(context.Context) { ran.Add(1) })
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				e.svc.WaitBackground()
			}
		}()
	}
	wg.Wait()
	e.svc.WaitBackground()
	if n := ran.Load(); n != 8*200 {
		t.Fatalf("%d runs, want %d", n, 8*200)
	}
	// what a wait returns after has finished
	done := make(chan struct{})
	e.svc.Background(context.Background(), time.Second, func(context.Context) { time.Sleep(20 * time.Millisecond); close(done) })
	e.svc.WaitBackground()
	select {
	case <-done:
	default:
		t.Fatal("WaitBackground returned before the work it waited for finished")
	}
}
