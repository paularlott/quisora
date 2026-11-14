// Package ephemeral holds short-lived, single-node state: login flows, authorization codes, WebAuthn challenges,
// rate-limit counters. In a cluster the cluster package routes each id to the node that owns it, so state is never
// written to the database.
package ephemeral

import (
	"container/list"
	"context"
	"errors"
	"hash/maphash"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/secure"
)

var ErrNotFound = errors.New("ephemeral: not found or expired")

// ErrFull is returned by Set and New when the node's short-lived state has reached its budget (Local.Budget): the
// request that wanted to keep something is refused (503 with Retry-After, never a server error) rather than the node
// running out of memory. The store counts each refusal (metrics.EphemeralRefused) and logs them once a minute, so the
// callers that answer it neither count nor log it again.
var ErrFull = errors.New("ephemeral: this node's short-lived state is full")

// DefaultBudget is a Local's budget when none is set: 1 GiB of values.
const DefaultBudget = 1 << 30

// CachePrefix begins the name of a namespace that holds a cache: what a value there saves is a read done again, never
// a sign-in, so losing it, or never keeping it, refuses nobody. A Local counts such values apart from the others,
// under a cap of their own (Local.CacheBudget), so that a cache filled by requests nobody has admitted yet (a
// document read for an unauthenticated request) can never take the room sign-in flows and codes need.
const CachePrefix = "cache."

// IsCache reports whether namespace ns holds a cache (CachePrefix).
func IsCache(ns string) bool { return strings.HasPrefix(ns, CachePrefix) }

// GuardPrefix begins the name of a namespace that holds what a protection rests on: the record that an authorization
// code was used (so that its replay ends what it issued), the poll times of a device sign-in (slow_down), the record
// that an organization is under a password spray. A Local counts such values apart from the others, under a cap of
// their own (Local.GuardBudget), so that sign-in state filled by requests nobody has admitted (flows, challenges)
// never takes their room: a full store must not switch a protection off. Only what is bounded by something real may
// be kept there (a code that was issued, a device sign-in that was started and charged to its requester, an
// organization), never a key whoever asks can make up, and what one requester may have kept there is bounded apart
// from the rest of what it holds (Budget.ChargeGuard: a sixteenth of limits.held_kb), so that filling the cap takes
// many hundreds of accounts or addresses, not a few. Past the cap Set refuses (ErrFull) and the callers fail closed:
// the protection refuses rather than lapses.
const GuardPrefix = "guard."

// IsGuard reports whether namespace ns holds a protection's records (GuardPrefix).
func IsGuard(ns string) bool { return strings.HasPrefix(ns, GuardPrefix) }

// Store is implemented by the local store and by the cluster router.
type Store interface {
	// New stores value under a fresh unguessable id (which encodes the owning node) and returns the id.
	New(ctx context.Context, ns string, value []byte, ttl time.Duration) (string, error)
	// Set replaces the value of an existing or new id (ids from New, or keys routed by hash).
	Set(ctx context.Context, ns, id string, value []byte, ttl time.Duration) error
	// Replace gives an entry that is there a new value and keeps its expiry: read, changed and written back, an entry
	// lives no longer for it. One that is not there (expired, taken or deleted since the caller read it) is
	// ErrNotFound and nothing is written: what another request ended is never made again by a request that read it
	// before. So a caller that changes an entry it read uses Replace, never Set, and ends its request on
	// ErrNotFound; of two that replace the same entry at once the later value stays.
	Replace(ctx context.Context, ns, id string, value []byte) error
	// Get returns the value.
	Get(ctx context.Context, ns, id string) ([]byte, error)
	// Take returns the value and deletes it atomically: exactly one caller ever gets it.
	Take(ctx context.Context, ns, id string) ([]byte, error)
	// Delete removes the id.
	Delete(ctx context.Context, ns, id string) error
	// Incr adds delta to a counter that resets window after its first increment, returning the new value. Only a
	// positive delta starts a counter: on a counter that does not exist (or has expired) a zero delta (a read) or a
	// negative one (an attempt given back after the counter was cleared) does nothing and returns 0. A counter never
	// goes below zero: giving back more than it holds (what was counted before it started again, or before its owner
	// node changed) leaves it at zero, so nothing given back twice ever buys room above a limit. A counter too
	// contended to update, or a new one past the store's caps on counters (Local), reports a value above any limit
	// (Contended) rather than an error: callers fail closed.
	Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error)
}

// Owner extracts the owner prefix from an id made by New ("<owner>.<random>").
func Owner(id string) string {
	o, _, ok := strings.Cut(id, ".")
	if !ok {
		return ""
	}
	return o
}

type item struct {
	val     []byte
	n       int64
	expires time.Time
	counter bool // made by Incr: counted against the counters' caps as well
	cache   bool // a value of a cache namespace (IsCache): counted against the caches' cap, not Budget
	// elem is a cache value's place in Local.cacheOrder (the oldest first), from which it is evicted (cache.go).
	elem  *list.Element
	guard bool // a value of a guard namespace (IsGuard): counted against the guards' cap, not Budget
}

const shards = 64

// Local is an in-memory Store for one node. Prefix is the node's short id embedded in ids. Values (flows, codes,
// pushed requests, challenges) count against Budget bytes (0: DefaultBudget), keys included; past it Set refuses
// (ErrFull) until expiries make room. Counters (Incr, the rate limits) are kept apart: they never count against the
// values' Budget, so however many there are they cannot refuse a sign-in its flow, and filled values never refuse a
// counter (a limit must not fail open, nor refuse everyone because the store is full); reading one (delta 0) creates
// nothing. Their keys are often chosen by whoever is limited (an address, a login that names no account), so their
// memory has a cap of its own, Budget again (at least minCounterBudget, so a small Budget never stops the limits
// counting): past it a new counter is not made and Incr reports Contended, so the limit fails closed for that key
// (counters that exist go on counting), and the node's memory stays bounded (Budget for values plus the counters'
// cap). The cap is not lower, nor split by namespace, because a refused counter refuses whoever it limits: a cap that
// a flood of keys could reach sooner would make denying everyone sign-in (lockout counters of logins that name no
// account) cheaper. Values of a cache namespace (IsCache) are kept apart as well: they never count against Budget,
// but against a cap of their own, CacheBudget (0: Budget/16, at least minCacheBudget); at it a new cache entry takes
// the room of the oldest ones, which go (setCache), so the newest entries are always kept and a full cache refuses
// nothing. A cache's callers keep what a sign-in needs in the sign-in's own state, so a cache refuses no sign-in
// either. Values of a guard namespace (IsGuard: the records protections rest on) are kept apart in the same way,
// under GuardBudget (0: Budget/4, at least minGuardBudget): filled sign-in state never refuses them, and past their
// own cap Set refuses (ErrFull) and their callers fail closed. Log, when set, gets a warning at most once a minute
// while Set refuses, once a minute while counters are refused, once a minute while cache entries are evicted to make
// room, and once a minute while guard records are refused.
type Local struct {
	Prefix string
	Budget int64
	// CacheBudget is the memory the values of cache namespaces may take (0: cacheBudget's default).
	CacheBudget int64
	// GuardBudget is the memory the values of guard namespaces may take (0: guardBudget's default).
	GuardBudget int64
	Log         logger.Logger
	used        atomic.Int64 // the memory the values take (checked against Budget)
	logged      atomic.Int64 // unix nanos of the last warning that the store is full
	// counters is the memory the counters take (checked against counterBudget), apart from used.
	counters       atomic.Int64
	countersLogged atomic.Int64 // unix nanos of the last warning that counters were refused
	// cache is the memory the values of cache namespaces take (checked against cacheBudget), apart from used.
	cache       atomic.Int64
	cacheLogged atomic.Int64 // unix nanos of the last warning that cache entries were evicted (or refused)
	// guard is the memory the values of guard namespaces take (checked against guardBudget), apart from used.
	guard       atomic.Int64
	guardLogged atomic.Int64 // unix nanos of the last warning that guard records were refused
	// cacheOrder holds the keys of the cache values, the oldest kept first (cache.go); cacheMu guards it, and is taken
	// under a shard's lock, never the other way round.
	cacheMu    sync.Mutex
	cacheOrder list.List
	seed       maphash.Seed
	shard      [shards]struct {
		mu sync.Mutex
		m  map[string]*item
	}
	stop chan struct{}
}

// NewLocal returns a local store and starts its reaper; call Close to stop it.
func NewLocal(prefix string) *Local {
	l := &Local{Prefix: prefix, seed: maphash.MakeSeed(), stop: make(chan struct{})}
	for i := range l.shard {
		l.shard[i].m = map[string]*item{}
	}
	go l.reap()
	return l
}

func (l *Local) Close() { close(l.stop) }

func (l *Local) sh(k string) *struct {
	mu sync.Mutex
	m  map[string]*item
} {
	return &l.shard[maphash.String(l.seed, k)%shards]
}

func (l *Local) reap() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-t.C:
			for i := range l.shard {
				s := &l.shard[i]
				s.mu.Lock()
				for k, v := range s.m {
					if now.After(v.expires) {
						delete(s.m, k)
						l.release(k, v)
					}
				}
				s.mu.Unlock()
			}
		}
	}
}

// NewID returns a fresh id owned by this node.
func (l *Local) NewID() string { return l.Prefix + "." + secure.RandomToken(24) }

func (l *Local) New(ctx context.Context, ns string, value []byte, ttl time.Duration) (string, error) {
	id := l.NewID()
	return id, l.Set(ctx, ns, id, value, ttl)
}

// itemOverhead approximates what an entry costs beyond its key and value (map slot, item, slice header).
const itemOverhead = 96

func (v *item) size(k string) int64 { return int64(len(k)+len(v.val)) + itemOverhead }

// release gives back what the entry k, just removed, took.
func (l *Local) release(k string, v *item) {
	switch {
	case v.counter:
		l.counters.Add(-v.size(k))
	case v.cache:
		l.cache.Add(-v.size(k))
		l.unlinkCache(v)
	case v.guard:
		l.guard.Add(-v.size(k))
	default:
		l.used.Add(-v.size(k))
	}
}

// minCacheBudget is the least memory the caches may take by default, whatever Budget is.
const minCacheBudget = 4 << 20

// cacheBudget is the memory the values of cache namespaces may take: CacheBudget, else a sixteenth of Budget (at
// least minCacheBudget), on top of Budget. A cache holds what saves a read, so it needs far less room than the state
// it serves.
func (l *Local) cacheBudget() int64 {
	if l.CacheBudget > 0 {
		return l.CacheBudget
	}
	return max(l.budget()/16, minCacheBudget)
}

// guardFull counts a protection's record that was not kept because the guard namespaces reached their cap, and warns
// of it at most once a minute. The caller fails closed (the code is not redeemed, the poll is told to slow down).
func (l *Local) guardFull(ns string) error {
	metrics.EphemeralRefused.Inc("guard")
	now, last := time.Now().UnixNano(), l.guardLogged.Load()
	if l.Log != nil && now-last >= int64(time.Minute) && l.guardLogged.CompareAndSwap(last, now) {
		l.Log.Warn("this node's records of used codes and device polls are at their cap (a quarter of "+
			"limits.ephemeral_mb): requests that need a new one are refused until expiries make room",
			"namespace", ns, "guard_bytes", l.guard.Load(), "cap_bytes", l.guardBudget())
	}
	return ErrFull
}

// minGuardBudget is the least memory the guard namespaces may take by default, whatever Budget is.
const minGuardBudget = 16 << 20

// guardBudget is the memory the values of guard namespaces may take: GuardBudget, else a quarter of Budget (at least
// minGuardBudget), on top of Budget. A record there is a few hundred bytes for each code redeemed in the last hour
// or device sign-in being polled, so a quarter of the default Budget holds about a million of them.
func (l *Local) guardBudget() int64 {
	if l.GuardBudget > 0 {
		return l.GuardBudget
	}
	return max(l.budget()/4, minGuardBudget)
}

// countersFull counts a counter that was not made because counters reached their cap, and warns of it at most once
// a minute.
func (l *Local) countersFull(ns string) {
	metrics.EphemeralRefused.Inc("counters")
	now, last := time.Now().UnixNano(), l.countersLogged.Load()
	if l.Log != nil && now-last >= int64(time.Minute) && l.countersLogged.CompareAndSwap(last, now) {
		l.Log.Warn("this node's rate-limit counters are at their cap (limits.ephemeral_mb): limits on new "+
			"keys refuse until expiries make room", "namespace", ns, "counter_bytes", l.counters.Load(), "cap_bytes", l.counterBudget())
	}
}

// minCounterBudget is the least memory counters may take, whatever Budget is.
const minCounterBudget = 16 << 20

// counterBudget is the memory counters may take: Budget, but at least minCounterBudget.
func (l *Local) counterBudget() int64 { return max(l.budget(), minCounterBudget) }

func (l *Local) budget() int64 {
	if l.Budget > 0 {
		return l.Budget
	}
	return DefaultBudget
}

func (l *Local) Set(_ context.Context, ns, id string, value []byte, ttl time.Duration) error {
	k := ns + "/" + id
	if IsCache(ns) { // a cache's values have room of their own, never the sign-in state's
		return l.setCache(ns, k, &item{val: value, expires: time.Now().Add(ttl), cache: true})
	}
	it := &item{val: value, expires: time.Now().Add(ttl), guard: IsGuard(ns)}
	pool, limit := &l.used, l.budget()
	if it.guard { // the records protections rest on have room of their own too
		pool, limit = &l.guard, l.guardBudget()
	}
	s := l.sh(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	grow := it.size(k)
	old, had := s.m[k]
	if had && !old.counter { // a counter it replaces was never the values' (a value it replaces is of its namespace: the same room)
		grow -= old.size(k)
	}
	// Checked and counted in one step (reserve): entries kept at once under other shards' locks never pass the cap
	// between them.
	if !reserve(pool, grow, limit) {
		if it.guard {
			return l.guardFull(ns)
		}
		return l.full()
	}
	if had && old.counter { // a counter's key given a value: no longer a counter
		l.release(k, old)
	}
	s.m[k] = it
	return nil
}

// reserve adds g bytes to what pool counts, when that stays within limit (or g gives room back), and reports whether
// it did. Checked and added in one step (compare-and-swap), so that writers under different shards' locks, each of
// which would fit alone, never overrun the cap together.
func reserve(pool *atomic.Int64, g, limit int64) bool {
	for {
		cur := pool.Load()
		if g > 0 && cur+g > limit {
			return false
		}
		if pool.CompareAndSwap(cur, cur+g) {
			return true
		}
	}
}

// Replace gives the entry a new value under its shard's lock, keeping its expiry (Store.Replace). Its room is its
// namespace's, as Set's is: a value that grows past the cap is refused (ErrFull) and the entry stays as it was.
func (l *Local) Replace(_ context.Context, ns, id string, value []byte) error {
	k := ns + "/" + id
	s := l.sh(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.m[k]
	if ok && time.Now().After(old.expires) {
		delete(s.m, k)
		l.release(k, old)
		ok = false
	}
	if !ok || old.counter { // gone, or never a value: nothing to replace
		return ErrNotFound
	}
	grow := int64(len(value) - len(old.val))
	switch {
	case old.cache:
		if !reserve(&l.cache, grow, l.cacheBudget()) {
			return l.cacheRefused(ns, grow)
		}
	case old.guard:
		if !reserve(&l.guard, grow, l.guardBudget()) {
			return l.guardFull(ns)
		}
	default:
		if !reserve(&l.used, grow, l.budget()) {
			return l.full()
		}
	}
	old.val = value // the same item: its expiry, and a cache value's place in the order of eviction, stay
	return nil
}

// full counts a refusal of Set and warns of it, at most once a minute however many requests are refused.
func (l *Local) full() error {
	metrics.EphemeralRefused.Inc("full")
	now, last := time.Now().UnixNano(), l.logged.Load()
	if l.Log != nil && now-last >= int64(time.Minute) && l.logged.CompareAndSwap(last, now) {
		l.Log.Warn("this node's short-lived state is full (limits.ephemeral_mb): new sign-ins and other requests that "+
			"would add to it get 503 until expiries make room", "used_bytes", l.Used(), "budget_bytes", l.budget())
	}
	return ErrFull
}

// Used is the memory the values take, by the estimate Budget is checked against (cache namespaces' apart: Cached).
func (l *Local) Used() int64 { return l.used.Load() }

// Cached is the memory the values of cache namespaces take, by the estimate their cap (CacheLimit) is checked against.
func (l *Local) Cached() int64 { return l.cache.Load() }

// CacheLimit is the caches' cap: CacheBudget, else Budget/16 (at least minCacheBudget).
func (l *Local) CacheLimit() int64 { return l.cacheBudget() }

// Guarded is the memory the values of guard namespaces take, by the estimate their cap (GuardLimit) is checked
// against.
func (l *Local) Guarded() int64 { return l.guard.Load() }

// GuardLimit is the guard namespaces' cap: GuardBudget, else Budget/4 (at least minGuardBudget).
func (l *Local) GuardLimit() int64 { return l.guardBudget() }

// Counters is the memory the counters take, by the estimate their cap (CounterLimit) is checked against.
func (l *Local) Counters() int64 { return l.counters.Load() }

// CounterLimit is the counters' cap: Budget, but at least minCounterBudget.
func (l *Local) CounterLimit() int64 { return l.counterBudget() }

// Limit is the budget the values are checked against (Budget, or DefaultBudget).
func (l *Local) Limit() int64 { return l.budget() }

// Len is the number of entries held (values and counters), expired ones the reaper has not removed yet included.
func (l *Local) Len() int {
	n := 0
	for i := range l.shard {
		s := &l.shard[i]
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}

func (l *Local) get(ns, id string, take bool) ([]byte, error) {
	k := ns + "/" + id
	s := l.sh(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok || time.Now().After(v.expires) {
		if ok {
			delete(s.m, k)
			l.release(k, v)
		}
		return nil, ErrNotFound
	}
	if take {
		delete(s.m, k)
		l.release(k, v)
	}
	return v.val, nil
}

func (l *Local) Get(_ context.Context, ns, id string) ([]byte, error)  { return l.get(ns, id, false) }
func (l *Local) Take(_ context.Context, ns, id string) ([]byte, error) { return l.get(ns, id, true) }

func (l *Local) Delete(_ context.Context, ns, id string) error {
	k := ns + "/" + id
	s := l.sh(k)
	s.mu.Lock()
	if v, ok := s.m[k]; ok {
		delete(s.m, k)
		l.release(k, v)
	}
	s.mu.Unlock()
	return nil
}

func (l *Local) Incr(_ context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	k := ns + "/" + key
	s := l.sh(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	v, ok := s.m[k]
	if !ok || now.After(v.expires) {
		if delta <= 0 { // a read, or a give-back: nothing to count yet, and nothing to keep
			if ok {
				delete(s.m, k)
				l.release(k, v)
			}
			return 0, nil
		}
		if ok { // expired: made again below, within the caps like any new counter
			delete(s.m, k)
			l.release(k, v)
		}
		sz := (&item{}).size(k)
		if !reserve(&l.counters, sz, l.counterBudget()) { // checked and counted in one step, as Set's room is
			l.countersFull(ns)
			return Contended, nil // fail closed: the caller's limit trips for this key
		}
		v = &item{expires: now.Add(window), counter: true}
		s.m[k] = v
	}
	if v.n += delta; v.n < 0 { // given back more than it holds: never below zero (Store.Incr)
		v.n = 0
	}
	return v.n, nil
}
