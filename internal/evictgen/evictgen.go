// Package evictgen closes the race between filling a cache and evicting from it: a reader that missed, read the store
// and is about to put its copy must not put it if the key was evicted after the read began (the copy may predate the
// change that evicted it, and would then be served until it expires).
//
// A reader takes a token for the key before it reads the store, and puts only if Valid still holds, under the lock
// that also guards the eviction (Bump is called under it, so either the eviction comes first and Valid fails, or the
// put comes first and the eviction drops the entry). The counters are striped by hash of the key, so memory is
// constant and nothing has to be pruned; an eviction of another key in the same stripe during a fill only makes
// that fill skip its put, which costs one more read later and never serves anything stale.
package evictgen

import (
	"hash/maphash"
	"sync/atomic"
)

const stripes = 256

var seed = maphash.MakeSeed()

// Gens is a set of eviction counters. The zero value is ready.
type Gens struct{ n [stripes]atomic.Uint64 }

func stripe(key string) int { return int(maphash.String(seed, key) % stripes) }

// Token returns the key's current generation; take it before reading the store.
func (g *Gens) Token(key string) uint64 { return g.n[stripe(key)].Load() }

// Valid reports whether key has not been evicted since Token returned tok.
func (g *Gens) Valid(key string, tok uint64) bool { return g.n[stripe(key)].Load() == tok }

// Bump records an eviction of key. Call it with the lock that guards the cache held, together with the drop.
func (g *Gens) Bump(key string) { g.n[stripe(key)].Add(1) }

// BumpAll records an eviction of every key (a cache cleared).
func (g *Gens) BumpAll() {
	for i := range g.n {
		g.n[i].Add(1)
	}
}
