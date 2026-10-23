package web_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/webtest"
)

// A node that a load balancer polls fails /readyz for server.shutdown_drain before it stops listening; one nobody
// polls stops at once.
func TestStopDrainsWhenProbed(t *testing.T) {
	for _, probed := range []bool{true, false} {
		env := webtest.New(t, webtest.Options{Configure: func(c *config.Config) {
			c.Server.Listen = "127.0.0.1:0"
			c.Server.ShutdownDrain = 1
		}})
		srv := env.Server
		if err := srv.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		hc := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		ready := func() int {
			resp, err := hc.Get("https://" + srv.Addr() + "/readyz")
			if err != nil {
				return 0
			}
			resp.Body.Close()
			return resp.StatusCode
		}
		if probed && ready() != 200 {
			t.Fatal("not ready before stopping")
		}
		start := time.Now()
		done := make(chan struct{})
		go func() { srv.Stop(); close(done) }()
		if probed {
			time.Sleep(200 * time.Millisecond)
			if got := ready(); got != http.StatusServiceUnavailable {
				t.Fatalf("draining /readyz: %d", got)
			}
		}
		<-done
		took := time.Since(start)
		if probed && took < time.Second || !probed && took > 500*time.Millisecond {
			t.Fatalf("probed=%v: stop took %v", probed, took)
		}
		if ready() != 0 {
			t.Fatalf("probed=%v: still listening after Stop", probed)
		}
		srv.Stop() // again: no effect
	}
}

// A response held open (a live-update stream) ends when the server stops, instead of holding the shutdown for
// server.shutdown_timeout.
func TestStopEndsOpenStreams(t *testing.T) {
	env := webtest.New(t, webtest.Options{Configure: func(c *config.Config) {
		c.Server.Listen = "127.0.0.1:0"
		c.Server.ShutdownTimeout = 30
	}})
	srv := env.Server
	started := make(chan struct{})
	srv.Mux.HandleFunc("GET /test-stream", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
		case <-srv.Stopping():
		}
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	go func() {
		if resp, err := hc.Get("https://" + srv.Addr() + "/test-stream"); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	<-started
	start := time.Now()
	srv.Stop()
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("an open stream held the shutdown for %v", took)
	}
}
