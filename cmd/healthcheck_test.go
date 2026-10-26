package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// healthcheck probes /healthz (or /readyz with --ready) of the listener over TLS and fails on anything but 200.
func TestHealthcheck(t *testing.T) {
	t.Run("probes", func(t *testing.T) {
		ready := false
		var paths []string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			if r.URL.Path == "/readyz" && !ready {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		addr := strings.TrimPrefix(srv.URL, "https://")
		e := newEnv(t, "")
		if _, _, err := e.run(t, "", "healthcheck", "--listen", addr); err != nil {
			t.Fatalf("alive: %v", err)
		}
		if _, _, err := e.run(t, "", "healthcheck", "--ready", "--listen", addr); err == nil || !strings.Contains(err.Error(), "not ready") {
			t.Fatalf("not ready: %v", err)
		}
		ready = true
		if _, _, err := e.run(t, "", "healthcheck", "--ready", "--listen", addr); err != nil {
			t.Fatalf("ready: %v", err)
		}
		if strings.Join(paths, ",") != "/healthz,/readyz,/readyz" {
			t.Fatalf("paths %v", paths)
		}
		// a wildcard listen address is probed on loopback
		port := addr[strings.LastIndex(addr, ":"):]
		if _, _, err := e.run(t, "", "healthcheck", "--listen", "0.0.0.0"+port); err != nil {
			t.Fatalf("wildcard: %v", err)
		}
		if _, _, err := e.run(t, "", "healthcheck", "--listen", port); err != nil {
			t.Fatalf("empty host: %v", err)
		}
	})
	t.Run("no server and bad address", func(t *testing.T) {
		e := newEnv(t, "")
		// nothing listens on port 1
		if _, _, err := e.run(t, "", "healthcheck", "--listen", "127.0.0.1:1"); err == nil {
			t.Fatal("healthcheck succeeded with no server")
		}
		if _, _, err := e.run(t, "", "healthcheck", "--ready", "--listen", "bad"); err == nil {
			t.Fatal("healthcheck accepted a bad listen address")
		}
	})
}
