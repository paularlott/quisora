package oidc

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

// A sign-out of very many sessions queues their back-channel logouts for a bounded number of senders: it does not
// start a goroutine per logout, and what the queue cannot hold is dropped, not kept in memory. A logout that fails
// on the way (a connection the relying party closed, under load) is retried from the queue on disk: none of those
// queued is lost.
func TestBackchannelFanOutBounded(t *testing.T) {
	release := make(chan struct{})
	var got atomic.Int64
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		got.Add(1)
	}))
	defer rp.Close()
	h := setup(t, nil)
	saved := logoutBackoff
	logoutBackoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	defer func() { logoutBackoff = saved }()
	retries, err := h.p.OpenLogoutQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer retries.Close()
	cl, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	ce, err := h.p.client(t.Context(), cl.ID)
	if err != nil {
		t.Fatal(err)
	}
	base := runtime.NumGoroutine()
	targets := make([]bcTarget, 2*bcQueueMax)
	for i := range targets {
		targets[i] = bcTarget{client: ce.c, sub: "user", sid: "s"}
	}
	h.p.dispatch(targets)
	if n := runtime.NumGoroutine() - base; n > 4*bcWorkersMax { // senders plus their connections
		t.Fatalf("%d goroutines for %d logouts", n, len(targets))
	}
	if q := len(h.p.bcQueue); q > bcQueueMax {
		t.Fatalf("queue holds %d", q)
	}
	close(release)
	h.p.Wait()
	deadline := time.Now().Add(30 * time.Second)
	for retries.Queued() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// Each queued logout arrives (a retried one may arrive twice: the first attempt can reach the relying party and
	// still fail on the way back), plus those that were already being sent.
	if n := got.Load(); n < int64(bcQueueMax) || n > int64(bcQueueMax+2*bcWorkersMax) || retries.Queued() > 0 {
		t.Fatalf("%d logouts sent, want the %d queued (plus those already being sent); %d waiting to retry", n,
			bcQueueMax, retries.Queued())
	}
}

// A logout the relying party refuses is tried again from the retry queue until it is taken.
func TestBackchannelRetried(t *testing.T) {
	var calls atomic.Int64
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer rp.Close()
	h := setup(t, nil)
	saved := logoutBackoff
	logoutBackoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	defer func() { logoutBackoff = saved }()
	retries, err := h.p.OpenLogoutQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer retries.Close()
	cl, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	ce, err := h.p.client(t.Context(), cl.ID)
	if err != nil {
		t.Fatal(err)
	}
	h.p.dispatch([]bcTarget{{client: ce.c, sub: "user", sid: "s"}})
	h.p.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for (calls.Load() < 3 || retries.Queued() > 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() != 3 || retries.Queued() != 0 {
		t.Fatalf("%d attempts, %d still queued", calls.Load(), retries.Queued())
	}
}
