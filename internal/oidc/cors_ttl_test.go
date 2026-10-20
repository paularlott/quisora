package oidc

import (
	"net/http/httptest"
	"testing"
	"time"
)

// Nodes sharing a database without gossip are never told about another node's client changes, so the CORS origin
// cache is bounded like the client cache there (ShortCaches); otherwise it lasts a minute, evicted by change hooks.
func TestOriginCacheTTL(t *testing.T) {
	for _, short := range []bool{false, true} {
		h := setup(t, nil)
		if short {
			h.p.ShortCaches()
		}
		r := httptest.NewRequest("OPTIONS", "/oauth/token", nil)
		first := h.p.publicOrigins(r)
		first.at = time.Now().Add(-shortTTL - time.Second)
		reloaded := h.p.publicOrigins(r) != first
		if reloaded != short {
			t.Errorf("short caches %v: reloaded after %v = %v", short, shortTTL+time.Second, reloaded)
		}
	}
}
