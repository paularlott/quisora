package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// A request id is taken from X-Request-ID only when a trusted proxy sends a well-formed one; otherwise one is made.
// The response carries the id the request was handled under.
func TestRequestIDOnlyTrustedFromProxy(t *testing.T) {
	defer SetTrustedProxies(nil)
	var seen string
	h := requestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = service.RequestFrom(r.Context()).ID
	}))
	do := func(remote, id string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if id != "" {
			r.Header.Set("X-Request-ID", id)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Header().Get("X-Request-ID") != seen || seen == "" {
			t.Fatalf("response id %q, context id %q", rec.Header().Get("X-Request-ID"), seen)
		}
		return seen
	}
	SetTrustedProxies([]string{"10.0.0.0/8"})
	for id, kept := range map[string]bool{
		"upstream-id-1": true, "abc-DEF_1.2": true, strings.Repeat("a", 64): true,
		"": false, strings.Repeat("a", 65): false, "bad id!": false, "has space": false, "new\nline": false,
		"semi;colon": false, "ünï": false,
	} {
		if got := do("10.1.2.3:5", id); (got == id) != kept {
			t.Errorf("id %q from a trusted proxy: handled as %q, kept=%v", id, got, kept)
		}
	}
	if got := do("203.0.113.5:5", "spoofed"); got == "spoofed" {
		t.Fatalf("an untrusted client cannot choose its id: %q", got)
	}
	if got := do("not-an-address", "x"); got == "x" {
		t.Fatalf("an unparsable peer is untrusted: %q", got)
	}
	if !fromTrustedProxy(func() *http.Request { r := httptest.NewRequest("GET", "/", nil); r.RemoteAddr = "10.9.9.9"; return r }()) {
		t.Fatal("a peer without a port is still recognised")
	}
}

func TestClientIP(t *testing.T) {
	defer SetTrustedProxies(nil)
	SetTrustedProxies([]string{"10.0.0.0/8"})
	cases := []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},                       // untrusted peer: header ignored
		{"10.0.0.5:1234", "198.51.100.7", "198.51.100.7"},                    // one trusted proxy
		{"10.0.0.5:1234", "6.6.6.6, 198.51.100.7, 10.0.0.9", "198.51.100.7"}, // spoofed left part skipped
		{"10.0.0.5:1234", "", "10.0.0.5"},
		{"10.0.0.5:1234", "garbage", "10.0.0.5"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := ClientIP(r); got != c.want {
			t.Errorf("remote=%s xff=%q: got %s want %s", c.remote, c.xff, got, c.want)
		}
	}
}

// Rate limits count an IPv6 client by its /64, an IPv4 client by its address.
func TestRateKeyIP(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.7:1234":                  "192.0.2.7",
		"[2001:db8:1:2:aaaa::1]:443":      "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff:ffff::9]:443": "2001:db8:1:2::/64",
		"[::ffff:192.0.2.7]:443":          "::ffff:192.0.2.7",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		if got := RateKeyIP(r); got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
}
