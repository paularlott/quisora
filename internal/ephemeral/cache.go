package ephemeral

import (
	"time"

	"github.com/paularlott/quisora/internal/metrics"
)

// Cache namespaces (IsCache) on a Local. Their values count against the caches' cap (cacheBudget), never Budget, and
// a full cache makes room rather than refusing: a new entry evicts the oldest ones kept. A cache's callers rely on the
// entry just kept being there for the next caller (a document read once a minute is shared through it: one not kept
// would leave the next caller with nothing to answer from until the minute is up), so the newest entries are the ones
// a cap must never drop. For a cache whose entries all live as long (nsCIMD's minute), the oldest kept is also the
// first to expire.
//
// cacheOrder lists the keys of the cache values in the order they were kept, each item holding its element (elem),
// so keeping, replacing, removing and evicting one is O(1). Accounting is exact: an entry is evicted by the same
// removal (release) as one deleted or expired, under its shard's lock, and only while it is still the entry the list
// named (a removal or replacement meanwhile took it out of the list already).

// setCache keeps it, a value of cache namespace ns under key k, evicting the oldest cache values while it would not
// fit under the caches' cap. Only a value larger than the whole cap is refused (ErrFull, counted as "cache").
func (l *Local) setCache(ns, k string, it *item) error {
	limit := l.cacheBudget()
	grow := it.size(k)
	if grow > limit {
		return l.cacheRefused(ns, grow)
	}
	s := l.sh(k)
	for {
		l.evictCache(ns, grow, limit) // outside any shard's lock: an eviction takes the evicted key's
		s.mu.Lock()
		g := grow
		old, had := s.m[k]
		if had && old.cache {
			g -= old.size(k) // a value it replaces gives its room back
		}
		if !l.reserveCache(g, limit) {
			s.mu.Unlock() // others kept entries meanwhile: evict again
			continue
		}
		if had {
			delete(s.m, k)
			if old.cache {
				l.unlinkCache(old) // its room is in g already
			} else {
				l.release(k, old) // a counter's: the counters' room
			}
		}
		l.cacheMu.Lock()
		it.elem = l.cacheOrder.PushBack(k)
		l.cacheMu.Unlock()
		s.m[k] = it
		s.mu.Unlock()
		return nil
	}
}

// reserveCache adds g bytes to what the caches take, when that stays within limit (or g gives room back), and reports
// whether it did (reserve: checked and added in one step).
func (l *Local) reserveCache(g, limit int64) bool { return reserve(&l.cache, g, limit) }

// evictCache removes the oldest cache values until need more bytes fit under limit, or none is left.
func (l *Local) evictCache(ns string, need, limit int64) {
	for l.cache.Load()+need > limit {
		l.cacheMu.Lock()
		e := l.cacheOrder.Front()
		l.cacheMu.Unlock()
		if e == nil {
			return
		}
		k := e.Value.(string)
		s := l.sh(k)
		s.mu.Lock()
		if v, ok := s.m[k]; ok && v.elem == e {
			delete(s.m, k)
			l.release(k, v)
			l.cacheEvicting(ns)
		}
		// else it was removed or replaced since it was read from the list (and taken out of it then): go on with
		// the next oldest
		s.mu.Unlock()
	}
}

// unlinkCache takes v, a cache value just removed, out of the order of eviction.
func (l *Local) unlinkCache(v *item) {
	if v.elem == nil {
		return
	}
	l.cacheMu.Lock()
	l.cacheOrder.Remove(v.elem)
	l.cacheMu.Unlock()
	v.elem = nil
}

// cacheEvicting warns, at most once a minute, that the caches are at their cap and their oldest entries go to make
// room. Nothing is refused: an entry evicted only saves a read, which the next caller that needs it does again.
func (l *Local) cacheEvicting(ns string) {
	now, last := time.Now().UnixNano(), l.cacheLogged.Load()
	if l.Log != nil && now-last >= int64(time.Minute) && l.cacheLogged.CompareAndSwap(last, now) {
		l.Log.Warn("this node's short-lived caches are at their cap: the oldest entries make room for new ones",
			"namespace", ns, "cache_bytes", l.cache.Load(), "cap_bytes", l.cacheBudget())
	}
}

// cacheRefused counts a cache entry not kept because it is larger than the caches' whole cap. Nothing was refused:
// the next caller reads again what the entry would have saved.
func (l *Local) cacheRefused(ns string, size int64) error {
	metrics.EphemeralRefused.Inc("cache")
	now, last := time.Now().UnixNano(), l.cacheLogged.Load()
	if l.Log != nil && now-last >= int64(time.Minute) && l.cacheLogged.CompareAndSwap(last, now) {
		l.Log.Warn("a short-lived cache entry is larger than this node's caches' cap: not kept",
			"namespace", ns, "bytes", size, "cap_bytes", l.cacheBudget())
	}
	return ErrFull
}
