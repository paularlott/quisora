// Package ttlcache is a small read-through cache of stored records with a lifetime: a change made on another node
// (which this one may not hear of) counts here within the lifetime, and an eviction (a change this node hears of)
// counts at once, including against a fill that was under way when it came (evictgen).
package ttlcache

import (
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/evictgen"
)

type item[T any] struct {
	v   T
	exp int64 // unix nanos
}

// Cache keeps entries for ttl in two generations: puts go to m, and once a ttl period (or when m holds max) m
// becomes old and the old one is dropped. Everything in old is at least that old, so what is expired goes without a
// sweep (a sweep would hold the lock, and every reader, for the whole map), and the cache holds at most 2×max.
type Cache[T any] struct {
	mu      sync.RWMutex
	m, old  map[string]item[T]
	ttl     time.Duration
	max     int
	rotated int64 // unix nanos when m was started (mu)
	gens    evictgen.Gens
}

// New returns a cache whose entries live for ttl, of at most 2×max entries.
func New[T any](ttl time.Duration, max int) *Cache[T] {
	return &Cache[T]{m: map[string]item[T]{}, ttl: ttl, max: max, rotated: time.Now().UnixNano()}
}

// Get returns the entry of k, if there is one that has not expired.
func (c *Cache[T]) Get(k string) (v T, ok bool) {
	c.mu.RLock()
	it, found := c.m[k]
	if !found {
		it, found = c.old[k]
	}
	c.mu.RUnlock()
	if !found || time.Now().UnixNano() > it.exp {
		return v, false
	}
	return it.v, true
}

// Token is taken before the store is read for a miss of k; PutIf puts the copy read only if k was not deleted (or the
// cache cleared) since, so a fill that began before an eviction cannot store the copy that eviction was for.
func (c *Cache[T]) Token(k string) uint64 { return c.gens.Token(k) }

// PutIf stores v under k unless k was evicted since Token returned tok.
func (c *Cache[T]) PutIf(k string, v T, tok uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gens.Valid(k, tok) {
		c.putLocked(k, v)
	}
}

// Put stores v whatever happened meanwhile: for a value known to be current (a grant just revoked).
func (c *Cache[T]) Put(k string, v T) {
	c.mu.Lock()
	c.putLocked(k, v)
	c.mu.Unlock()
}

func (c *Cache[T]) putLocked(k string, v T) {
	now := time.Now().UnixNano()
	if len(c.m) >= c.max || now-c.rotated > int64(c.ttl) {
		c.old, c.m, c.rotated = c.m, make(map[string]item[T], len(c.m)), now
	}
	delete(c.old, k) // the new value is the only one
	c.m[k] = item[T]{v: v, exp: now + int64(c.ttl)}
}

// Del evicts k.
func (c *Cache[T]) Del(k string) {
	c.mu.Lock()
	c.gens.Bump(k)
	delete(c.m, k)
	delete(c.old, k)
	c.mu.Unlock()
}

// Clear evicts every entry.
func (c *Cache[T]) Clear() {
	c.mu.Lock()
	c.gens.BumpAll()
	clear(c.m)
	c.old = nil
	c.mu.Unlock()
}
