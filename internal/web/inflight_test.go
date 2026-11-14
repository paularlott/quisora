package web

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
)

// One address cannot hold every request slot of limits.max_in_flight: a slot is taken before the body is read, and
// requests whose bodies come slowly (a byte now and then, up to the server's read timeout) would otherwise keep every
// other client out with 503. Past its share (limits.max_in_flight_per_ip; by default a sixteenth) the address's own
// requests are refused at once, and other addresses are served.
func TestInFlightSharePerAddress(t *testing.T) {
	cfg := config.Default()
	l := cfg.LiveLimits()
	l.MaxInFlight = 32
	cfg.SetLiveLimits(l)
	s := &Server{Cfg: cfg, Log: logger.NewNullLogger(), Mux: http.NewServeMux()}
	s.baseRoutes()
	var entered atomic.Int32
	s.Mux.HandleFunc("POST /x", func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		_, _ = io.ReadAll(r.Body) // a slow body: held until the test ends
		w.WriteHeader(299)
	})
	h := s.Handler()
	var wg sync.WaitGroup
	var refused atomic.Int32
	var bodies []*io.PipeWriter
	for range 32 {
		pr, pw := io.Pipe()
		bodies = append(bodies, pw)
		r := httptest.NewRequest("POST", "/x", pr)
		r.RemoteAddr = "203.0.113.7:1234"
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != 299 {
				refused.Add(1)
			}
		}()
	}
	defer func() {
		for _, pw := range bodies {
			pw.Close()
		}
		wg.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for entered.Load()+refused.Load() < 32 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if entered.Load()+refused.Load() != 32 {
		t.Fatalf("%d requests in the handler, %d refused", entered.Load(), refused.Load())
	}
	held := entered.Load()
	r := httptest.NewRequest("POST", "/x", nil)
	r.RemoteAddr = "198.51.100.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 299 {
		t.Fatalf("another address while one held %d slots: %d", held, rec.Code)
	}
	if held != 2 {
		t.Fatalf("the address held %d slots, want its share of 2", held)
	}
}

// The share is the /48's as well as each /64's: one allocation's /64s, each within its own share, cannot together
// hold every slot. Here the share is 2 of 32 slots: counted by /64 alone, 16 /64s of one /48 with slow bodies held all
// 32, and every other client got 503; with the /48's share (NetShareFactor times the address's) they hold 8, and
// another /48, and an IPv4 address, are served.
func TestInFlightSharePerSlash48(t *testing.T) {
	cfg := config.Default()
	l := cfg.LiveLimits()
	l.MaxInFlight = 32
	cfg.SetLiveLimits(l)
	s := &Server{Cfg: cfg, Log: logger.NewNullLogger(), Mux: http.NewServeMux()}
	s.baseRoutes()
	var entered atomic.Int32
	s.Mux.HandleFunc("POST /x", func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		_, _ = io.ReadAll(r.Body) // a slow body: held until the test ends
		w.WriteHeader(299)
	})
	h := s.Handler()
	var wg sync.WaitGroup
	var refused atomic.Int32
	var bodies []*io.PipeWriter
	const sent = 32
	for i := range sent {
		pr, pw := io.Pipe()
		bodies = append(bodies, pw)
		r := httptest.NewRequest("POST", "/x", pr)
		r.RemoteAddr = fmt.Sprintf("[2001:db8:1:%x::1]:1234", i/2+1) // two from each of 16 /64s of one /48
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != 299 {
				refused.Add(1)
			}
		}()
	}
	defer func() {
		for _, pw := range bodies {
			pw.Close()
		}
		wg.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for entered.Load()+refused.Load() < sent && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if entered.Load()+refused.Load() != sent {
		t.Fatalf("%d requests in the handler, %d refused", entered.Load(), refused.Load())
	}
	if held := entered.Load(); held != 2*NetShareFactor {
		t.Fatalf("one /48's /64s held %d slots, want the /48's share of %d", held, 2*NetShareFactor)
	}
	for _, addr := range []string{"[2001:db8:2::1]:1234", "198.51.100.1:1234"} {
		r := httptest.NewRequest("POST", "/x", nil)
		r.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != 299 {
			t.Fatalf("%s while one /48 held its share: %d", addr, rec.Code)
		}
	}
}
