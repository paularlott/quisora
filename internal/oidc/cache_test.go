package oidc

import (
	"context"
	"crypto/sha256"
	"net/url"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A fill that began before an eviction must not be stored after it: the copy it read may be the one the eviction was
// for, and would be served until it expired.
func TestTTLCacheFillBeforeEvictionIsNotStored(t *testing.T) {
	t.Parallel()
	c := newTTLCache[int](time.Hour, 10)
	tok := c.token("k")
	c.del("k") // the eviction lands while the store is being read
	c.putIf("k", 1, tok)
	if _, ok := c.get("k"); ok {
		t.Fatal("a fill that began before the eviction was stored")
	}
	c.putIf("k", 2, c.token("k")) // a fill that began after it is
	if v, ok := c.get("k"); !ok || v != 2 {
		t.Fatalf("fill after the eviction: %v %v", v, ok)
	}
	tok = c.token("k")
	c.clear()
	c.putIf("k", 3, tok)
	if _, ok := c.get("k"); ok {
		t.Fatal("a fill that began before a clear was stored")
	}
}

func TestProviderCachesDoNotKeepAFillThatRacedAnEviction(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := t.Context()
	cl, _ := h.newClient(nil)
	users, orgs, clients := &faultStore{Store: h.p.svc.Users.S}, &faultStore{Store: h.p.svc.Orgs.S}, &faultStore{Store: h.p.svc.Clients.S}
	h.p.svc.Users.S, h.p.svc.Orgs.S, h.p.svc.Clients.S = users, orgs, clients
	cases := []struct {
		name  string
		store *faultStore
		evict func(id string)
		read  func() error
		id    string
	}{
		{"user", users, h.p.InvalidateUser, func() error { _, err := h.p.user(ctx, h.user.ID); return err }, h.user.ID},
		{"organization", orgs, h.p.InvalidateOrg, func() error { _, err := h.p.org(ctx, h.env.Primary.ID); return err }, h.env.Primary.ID},
		{"client", clients, h.p.InvalidateClient, func() error { _, err := h.p.client(ctx, cl.ID); return err }, cl.ID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.store.afterGet = func(_ model.Kind, id string) {
				if id == tc.id {
					tc.evict(id)
				}
			}
			if err := tc.read(); err != nil {
				t.Fatal(err)
			}
			tc.store.afterGet = nil
			before := tc.store.gets.Load()
			if err := tc.read(); err != nil {
				t.Fatal(err)
			}
			if tc.store.gets.Load() == before {
				t.Fatal("the copy read before the eviction was cached and served after it")
			}
			before = tc.store.gets.Load()
			if err := tc.read(); err != nil || tc.store.gets.Load() != before {
				t.Fatalf("a fill with no eviction is not cached: %v", err)
			}
		})
	}
	// invalidating the client with no id clears the whole client cache
	if _, err := h.p.client(ctx, cl.ID); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient("")
	if _, ok := h.p.clients.get(cl.ID); ok {
		t.Fatal("clients not cleared")
	}
}

// A verified access token is cached (no second signature check), but everything that can change is checked on every
// use: a disabled user, a revoked grant. A token differing in one byte is never served from the cache.
func TestVerifiedTokenCache(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	ctx := context.Background()
	if _, err := h.p.VerifyAccessToken(ctx, at); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := h.p.verified.get(tokenKey(at), time.Now()); !ok {
		t.Fatal("a verified token was not cached")
	}
	if _, err := h.p.VerifyAccessToken(ctx, at); err != nil {
		t.Fatalf("from the cache: %v", err)
	}
	// one byte off (in the signature): a different token, verified in full and refused
	b := []byte(at)
	if b[len(b)-2] == 'A' {
		b[len(b)-2] = 'B'
	} else {
		b[len(b)-2] = 'A'
	}
	if _, err := h.p.VerifyAccessToken(ctx, string(b)); err == nil {
		t.Fatal("a tampered token was accepted")
	}
	// the user disabled: refused although the token is cached
	off := false
	if _, err := h.env.Svc.UpdateUser(ctx, service.System, h.user.ID, service.UserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID) // as the change hook does
	if _, err := h.p.VerifyAccessToken(ctx, at); err == nil {
		t.Fatal("a cached token of a disabled user was accepted")
	}
	// enabled again, then its grant revoked: refused
	on := true
	if _, err := h.env.Svc.UpdateUser(ctx, service.System, h.user.ID, service.UserInput{Active: &on}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	r2, _ := h.login(cl, secret, nil)
	at2 := r2.str("access_token")
	if _, err := h.p.VerifyAccessToken(ctx, at2); err != nil {
		t.Fatal(err)
	}
	gid, _ := claimsOf(t, at2)["gid"].(string)
	if rv := h.clientPost("/oauth/revoke", url.Values{"token": {r2.str("refresh_token")}}, cl, secret); rv.status != 200 {
		t.Fatalf("revoke: %d", rv.status)
	}
	h.p.InvalidateGrant(gid)
	if _, err := h.p.VerifyAccessToken(ctx, at2); err == nil {
		t.Fatal("a cached token of a revoked grant was accepted")
	}
	// keys reloaded: the cache starts again
	h.p.Invalidate()
	if _, _, _, ok := h.p.verified.get(tokenKey(at), time.Now()); ok {
		t.Fatal("the cache survived a key reload")
	}
}

func TestGroupsCacheInvalidation(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	cl, secret := h.newClient(nil)
	grp, err := h.env.Svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("devs")})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid groups offline_access"}})
	rt := r.str("refresh_token")
	groups := func() []any {
		t.Helper()
		x := h.refreshWith(cl, secret, rt)
		if x.status != 200 {
			t.Fatal(x.m)
		}
		g, _ := claimsOf(t, x.str("access_token"))["groups"].([]any)
		return g
	}
	if g := groups(); len(g) != 1 || g[0] != "devs" {
		t.Fatalf("groups %v", g)
	}
	// removed membership: still cached until invalidated, then gone at once
	if err := h.env.Svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, false); err != nil {
		t.Fatal(err)
	}
	if g := groups(); len(g) != 1 {
		t.Fatalf("expected the cached list, got %v", g)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	if g := groups(); len(g) != 0 {
		t.Fatalf("membership still present after invalidation: %v", g)
	}
	// another org's invalidation does not matter; the TTL backstop does
	if err := h.env.Svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership("other-org")
	if g := groups(); len(g) != 0 {
		t.Fatalf("unrelated invalidation dropped the cache: %v", g)
	}
	h.p.InvalidateMembership("")
	if g := groups(); len(g) != 1 {
		t.Fatalf("global invalidation: %v", g)
	}
}

func TestVerifiedCacheBounds(t *testing.T) {
	t.Parallel()
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
func TestTTLCacheBounds(t *testing.T) {
	t.Parallel()
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
	d := newTTLCache[int](-time.Minute, 3) // a negative lifetime: every entry is born expired
	d.put("x", 1)
	if _, ok := d.get("x"); ok {
		t.Fatal("expired entry served")
	}
	d.clear()
	if len(d.m) != 0 || len(d.old) != 0 {
		t.Fatal("clear left entries")
	}
}

// An evicted tenant is read again.
func TestInvalidateTenantEvictsItsEntry(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.p.tenants.put("t1", &model.Tenant{})
	h.p.InvalidateTenant("t1")
	if _, ok := h.p.tenants.get("t1"); ok {
		t.Fatal("the tenant stayed cached")
	}
}

// A cached client counts for at most the cache's bound: past it the store is asked (and here refuses), so the request
// is answered unavailable, never as if the client were fine or invalid.
func TestClientCacheBoundedByItsTTL(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	form := url.Values{"grant_type": {"client_credentials"}}
	if r := h.token(form, cl, secret); r.status != 200 {
		t.Fatalf("control: %d %v", r.status, r.m)
	}
	good := h.env.Svc.Clients.S
	t.Cleanup(func() { h.env.Svc.Clients.S = good })
	h.env.Svc.Clients.S = &faultStore{Store: good, getKind: model.KindClient}
	if r := h.token(form, cl, secret); r.status != 200 {
		t.Fatalf("control: the cached client should serve within its bound: %d %v", r.status, r.m)
	}
	h.p.clients.mu.Lock()
	if h.p.clients.ttl > 5*time.Second {
		t.Errorf("clients are cached for %v, more than the 5s bound", h.p.clients.ttl)
	}
	for k, it := range h.p.clients.m { // (the bound passed)
		it.exp = time.Now().UnixNano() - 1
		h.p.clients.m[k] = it
	}
	h.p.clients.mu.Unlock()
	expectUnavailable(t, "cached client past its bound, the store refusing", h.token(form, cl, secret))
}
