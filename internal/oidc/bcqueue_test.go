package oidc

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// A sign-out of very many sessions queues their back-channel logouts for a bounded number of senders: it does not
// start a goroutine per logout, and what the queue cannot hold is dropped, not kept in memory.
func TestBackchannelFanOutBounded(t *testing.T) {
	release := make(chan struct{})
	var got atomic.Int64
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		got.Add(1)
	}))
	defer rp.Close()
	h := setup(t, nil)
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
	if n := got.Load(); n < int64(bcQueueMax) || n > int64(bcQueueMax+bcWorkersMax) {
		t.Fatalf("%d logouts sent, want the %d queued (plus those already being sent)", n, bcQueueMax)
	}
}
