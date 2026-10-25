package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Requests that need a client's keys while nobody has fetched them yet wait for one fetch, rather than each making
// its own (from inside a token request, each up to the fetch timeout).
func TestRemoteKeysFetchedOnceAtATime(t *testing.T) {
	k := newAssertionKeys(t)[0]
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(k.jwks))
	}))
	defer srv.Close()
	h := setup(t, nil)
	h.p.HTTP = srv.Client()
	var wg sync.WaitGroup
	var empty atomic.Int32
	for range 12 {
		wg.Go(func() {
			if len(h.p.remoteKeys(context.Background(), srv.URL+"/jwks", false)) == 0 {
				empty.Add(1)
			}
		})
	}
	wg.Wait()
	if n := hits.Load(); n != 1 || empty.Load() != 0 {
		t.Fatalf("%d fetches for 12 concurrent requests (%d got no keys)", n, empty.Load())
	}
}
