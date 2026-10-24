package web

import (
	"net/http/httptest"
	"testing"
)

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
