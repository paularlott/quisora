package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/metrics"
)

// A client in server.deny_networks gets a bare 403 before anything else runs: no handler, no request id, no body.
// The address is the one ClientIP decides: behind a trusted proxy the client it names, while an X-Forwarded-For
// from anyone else is ignored. The probes and /metrics answer it still, and a new list applies to the next request.
func TestDenyNetworks(t *testing.T) {
	defer SetTrustedProxies(nil)
	SetTrustedProxies([]string{"10.0.0.0/8"})
	s := &Server{Cfg: config.Default(), Log: logger.NewNullLogger(), Mux: http.NewServeMux()}
	s.baseRoutes()
	ran := 0
	s.Mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) { ran++ })
	h := s.Handler()
	s.SetDenyNetworks([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")})
	do := func(path, remote, xff string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, nil)
		r.RemoteAddr = remote + ":1234"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	before := metrics.HTTPDenied.Value()
	for _, c := range []struct{ remote, xff string }{
		{"203.0.113.7", ""}, {"[2001:db8::1]", ""}, {"10.0.0.5", "203.0.113.9"}, {"10.0.0.5", "203.0.113.9, 10.0.0.6"},
	} {
		rec := do("/x", c.remote, c.xff)
		if rec.Code != http.StatusForbidden || rec.Body.Len() != 0 || rec.Header().Get("X-Request-ID") != "" {
			t.Errorf("%s via %q: %d %q %v, want a bare 403", c.remote, c.xff, rec.Code, rec.Body.String(), rec.Header())
		}
	}
	if ran != 0 {
		t.Fatalf("the handler ran %d times for denied clients", ran)
	}
	if n := metrics.HTTPDenied.Value() - before; n != 4 {
		t.Fatalf("quisora_http_denied_total counted %d, want 4", n)
	}
	for _, c := range []struct{ remote, xff string }{
		{"198.51.100.1", ""}, {"198.51.100.1", "203.0.113.9"}, {"10.0.0.5", "198.51.100.1"}, {"[2001:db9::1]", ""},
	} {
		if rec := do("/x", c.remote, c.xff); rec.Code == http.StatusForbidden {
			t.Errorf("%s via %q: denied", c.remote, c.xff)
		}
	}
	if ran != 4 {
		t.Fatalf("the handler ran %d times for allowed clients, want 4", ran)
	}
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		if rec := do(p, "203.0.113.7", ""); rec.Code == http.StatusForbidden {
			t.Errorf("%s denied to a client in deny_networks", p)
		}
	}

	s.SetDenyNetworks(nil) // a reload that empties the list
	if rec := do("/x", "203.0.113.7", ""); rec.Code == http.StatusForbidden || ran != 5 {
		t.Fatalf("after the list was emptied: %d, handler ran %d", rec.Code, ran)
	}
	s.SetDenyNetworks([]netip.Prefix{netip.MustParsePrefix("198.51.100.1/32")})
	if rec := do("/x", "198.51.100.1", ""); rec.Code != http.StatusForbidden || ran != 5 {
		t.Fatalf("after a new list: %d, handler ran %d", rec.Code, ran)
	}
}

// limits.max_in_flight is read at each request: a reload that lowers it sheds the next request while the ones in
// flight stay counted, and one that raises it lets requests through again.
func TestShedLimitReloads(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.MaxInFlight = 2
	release, busy := make(chan struct{}), make(chan struct{})
	h := shed(func() (int, int) { return cfg.LiveLimits().MaxInFlight, 1 << 20 }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(busy)
			<-release
		}
		w.WriteHeader(299)
	}))
	go h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/slow", nil))
	select {
	case <-busy:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow request did not start")
	}
	defer close(release)
	code := func() int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/orgs", nil))
		return rec.Code
	}
	if c := code(); c != 299 {
		t.Fatalf("one in flight of 2: %d", c)
	}
	l := cfg.LiveLimits()
	l.MaxInFlight = 1
	cfg.SetLiveLimits(l)
	if c := code(); c != http.StatusServiceUnavailable {
		t.Fatalf("one in flight of 1 after the reload: %d, want 503", c)
	}
	l.MaxInFlight = 2
	cfg.SetLiveLimits(l)
	if c := code(); c != 299 {
		t.Fatalf("one in flight of 2 after the second reload: %d", c)
	}
}
