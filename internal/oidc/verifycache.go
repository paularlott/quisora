package oidc

import (
	"crypto/sha256"
	"sync"
	"time"
)

// verifiedCache remembers access tokens whose signature has been checked and whose claims have been decoded, so a
// token presented again (a resource server introspecting it on every call, an application calling userinfo) does
// not pay for an ECDSA verification each time — the bulk of the cost of those endpoints.
//
// Only what cannot change is cached: a signature over the exact bytes of a token stays valid, and its claims are
// those bytes. Everything that can change is still checked on every use by the caller: that the signing key is
// still published (a retired key's tokens stop working), the expiry, the client being enabled, the user being
// active and the grant or session being alive. Entries go when the token expires; the cache is bounded and keyed by
// the token's SHA-256, so it holds no token itself.
type verifiedCache struct {
	shards [verifiedShards]verifiedShard
}

const (
	verifiedShards   = 16
	verifiedPerShard = 1250 // 20,000 tokens in all
)

type verifiedShard struct {
	mu sync.Mutex
	m  map[[32]byte]verifiedEntry
}

type verifiedEntry struct {
	kid, alg string
	claims   *Claims
	exp      time.Time
}

func (c *verifiedCache) shard(k [32]byte) *verifiedShard { return &c.shards[k[0]%verifiedShards] }

// get returns the cached claims of tok (a copy the caller may keep), and the key id and algorithm it was verified
// with; ok is false when the token is not cached or has expired.
func (c *verifiedCache) get(k [32]byte, now time.Time) (cl *Claims, kid, alg string, ok bool) {
	s := c.shard(k)
	s.mu.Lock()
	e, found := s.m[k]
	if found && !now.Before(e.exp) {
		delete(s.m, k)
		found = false
	}
	s.mu.Unlock()
	if !found {
		return nil, "", "", false
	}
	cp := *e.claims
	return &cp, e.kid, e.alg, true
}

// put remembers a verified token until exp. A full shard first drops its expired entries, then arbitrary ones.
func (c *verifiedCache) put(k [32]byte, kid, alg string, cl *Claims, exp, now time.Time) {
	cp := *cl
	s := c.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[[32]byte]verifiedEntry, verifiedPerShard)
	}
	if len(s.m) >= verifiedPerShard {
		for key, e := range s.m {
			if !now.Before(e.exp) {
				delete(s.m, key)
			}
		}
		for key := range s.m {
			if len(s.m) < verifiedPerShard*3/4 {
				break
			}
			delete(s.m, key)
		}
	}
	s.m[k] = verifiedEntry{kid: kid, alg: alg, claims: &cp, exp: exp}
}

// clear forgets every token (signing keys reloaded).
func (c *verifiedCache) clear() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.m = nil
		s.mu.Unlock()
	}
}

func tokenKey(tok string) [32]byte { return sha256.Sum256([]byte(tok)) }
