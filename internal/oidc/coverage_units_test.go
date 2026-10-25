package oidc

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCoverageVerifiedCacheBounds(t *testing.T) {
	var c verifiedCache
	now := time.Now()
	// every key lands in shard 0: a full shard drops expired entries first, then arbitrary ones
	key := func(i int) [32]byte { var k [32]byte; k[1], k[2] = byte(i>>8), byte(i); return k }
	for i := range verifiedPerShard {
		exp := now.Add(time.Hour)
		if i%2 == 0 {
			exp = now.Add(-time.Minute)
		}
		c.put(key(i), "kid", "ES256", &Claims{Sub: "s"}, exp, now)
	}
	c.put(key(5000), "kid", "ES256", &Claims{Sub: "s"}, now.Add(time.Hour), now)
	if n := len(c.shard(key(0)).m); n > verifiedPerShard/2+2 {
		t.Fatalf("expired entries kept: %d", n)
	}
	for i := range verifiedPerShard * 2 {
		c.put(key(10000+i), "kid", "ES256", &Claims{Sub: "s"}, now.Add(time.Hour), now)
	}
	if n := len(c.shard(key(0)).m); n > verifiedPerShard {
		t.Fatalf("shard grew to %d", n)
	}
	// an expired entry is dropped when read
	k := sha256.Sum256([]byte("t"))
	c.put(k, "kid", "ES256", &Claims{Sub: "s"}, now.Add(time.Second), now)
	if _, _, _, ok := c.get(k, now.Add(time.Minute)); ok {
		t.Fatal("expired entry served")
	}
	if _, _, _, ok := c.get(k, now); ok {
		t.Fatal("expired entry kept")
	}
}

// The cache holds at most two generations of max entries, serves the newest value of a key, and never an expired one.
func TestCoverageTTLCacheBounds(t *testing.T) {
	c := newTTLCache[int](time.Hour, 4)
	for i := range 20 {
		c.put(string(rune('a'+i)), i)
	}
	if n := len(c.m) + len(c.old); n > 8 {
		t.Fatalf("holds %d entries, more than two generations of 4", n)
	}
	if v, ok := c.get(string(rune('a' + 19))); !ok || v != 19 {
		t.Fatal("newest entry lost")
	}
	if _, ok := c.get("a"); ok {
		t.Fatal("an entry of a dropped generation served")
	}
	c.put("t", 100) // "t" was in a generation: the new value replaces it wherever it was
	if v, _ := c.get("t"); v != 100 {
		t.Fatalf("stale value %d", v)
	}
	c.del("t")
	if _, ok := c.get("t"); ok {
		t.Fatal("deleted entry served")
	}
	// expired entries are never served, in either generation
	d := newTTLCache[int](time.Nanosecond, 3)
	d.put("x", 1)
	time.Sleep(time.Millisecond)
	if _, ok := d.get("x"); ok {
		t.Fatal("expired entry served")
	}
	d.clear()
	if len(d.m) != 0 || len(d.old) != 0 {
		t.Fatal("clear left entries")
	}
}

func TestCoverageSmallHelpers(t *testing.T) {
	rec := httptest.NewRecorder()
	handlePreflight(rec, httptest.NewRequest(http.MethodOptions, "/oauth/token", nil))
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("preflight: %d %v", rec.Code, rec.Header())
	}
	if n := len(splitScope(strings.Repeat("s ", maxScopes+10))); n != maxScopes {
		t.Fatalf("scopes not capped: %d", n)
	}
	if _, err := parseClaimsParam(strings.Repeat("x", maxClaimsParam+1), nil); err == nil {
		t.Fatal("long claims")
	}
	cp, err := parseClaimsParam(`{"id_token":{"acr":{"essential":true,"value":"urn:a","values":["urn:b",7,""]}}}`, nil)
	if err != nil || !cp.ACREssential || len(cp.ACR) != 2 || cp.ACR[0] != "urn:a" || cp.ACR[1] != "urn:b" {
		t.Fatalf("%+v %v", cp, err)
	}
}

func TestCoverageInvalidateAndRegister(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	if _, err := h.p.client(t.Context(), cl.ID); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient("")
	h.p.InvalidateTenant("none")
	if _, ok := h.p.clients.get(cl.ID); ok {
		t.Fatal("clients not cleared")
	}
	// registration refuses a body that is not a JSON object
	if r := h.postJSON("/oauth/register", "not an object"); r.status != 400 || r.str("error") != "invalid_client_metadata" {
		t.Fatalf("%d %v", r.status, r.m)
	}
	_ = secret
}
