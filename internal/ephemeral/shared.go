package ephemeral

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash/maphash"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// Shared is a Store kept in a database that every node uses (clusters without gossip, on PostgreSQL, MySQL or
// MariaDB), so a sign-in started on one node can finish on any other. Single use and counters rely on the
// store's CompareAndPut: of two nodes taking the same code, exactly one wins. Records expire with their TTL and are
// purged with the other expired records.
//
// Every write is a row in the database until it expires, so the budgets of a Local apply here too, to the rows each
// node writes: Budget (limits.ephemeral_mb) for values, the counters' cap for the counters it makes, and CacheBudget
// for values of cache namespaces (IsCache), GuardBudget for those of guard namespaces (IsGuard), with the same
// defaults, the same refusals (ErrFull from New and Set, Contended from an Incr that would make a counter past its
// cap) and the same metrics and warnings. A full cache makes room here as it does in a Local: the oldest cache rows
// this node wrote are deleted for a new one (evictCache), so a cache refuses nothing but a row larger than its whole
// cap. Without them,
// requests that keep something (a sign-in started and never finished, a counter keyed by whoever is limited) would
// grow the database without a bound as fast as they were sent. Each node counts what it wrote itself, with its
// expiry (a ledger of sizes, never the values), the way a Local counts what it holds: approximate, as a Local's is.
// The nodes together may write up to their number times the budgets; a row another node takes or deletes is still
// counted by the node that wrote it until it expires; a row written over by another node is counted by both.
type Shared struct {
	st store.Store
	t  *store.Table[model.Ephemeral, *model.Ephemeral]
	// Budget, CacheBudget, GuardBudget and Log are a Local's (Local.Budget, Local.CacheBudget, Local.GuardBudget,
	// Local.Log), for the rows this node writes.
	Budget      int64
	CacheBudget int64
	GuardBudget int64
	Log         logger.Logger
	led         ledger
}

var _ Store = (*Shared)(nil)

// NewShared returns a Shared store over st.
func NewShared(st store.Store) *Shared {
	return &Shared{st: st, t: store.NewTable[model.Ephemeral](st)}
}

// Kinds of row a ledger counts, each against a budget of its own.
const (
	rowValue = iota
	rowCounter
	rowCache
	rowGuard
	rowKinds
)

// ledger is what a Shared node wrote and has not seen expire or go: each row's size, kind and expiry, by record id.
// It holds no value, so its memory is a fixed hundred-odd bytes a row, less than each row is counted as (rowSize):
// the budgets bound the ledger too.
type ledger struct {
	once  sync.Once
	shard [shards]struct {
		mu sync.Mutex
		m  map[string]ledgerRow
	}
	seed maphash.Seed
	pool [rowKinds]atomic.Int64 // the bytes counted, by kind
	// cacheOrder holds the ids of the cache rows counted, the oldest written first, and cacheElem each one's place
	// in it: what a full cache evicts (evictCache). cacheMu guards both, and is taken under a shard's lock, never the
	// other way round.
	cacheMu    sync.Mutex
	cacheOrder list.List
	cacheElem  map[string]*list.Element
	logged     [rowKinds]atomic.Int64 // unix nanos of the last warning that a kind was refused
	swept      atomic.Int64           // unix nanos of the last sweep of expired rows
	sweeping   atomic.Bool
}

type ledgerRow struct {
	size    int64
	expires time.Time
	kind    int
}

// ledgerSweep is how often expired rows leave the ledger, as often as a Local's reaper runs.
const ledgerSweep = 10 * time.Second

func (l *ledger) of(id string) *struct {
	mu sync.Mutex
	m  map[string]ledgerRow
} {
	l.once.Do(func() {
		l.seed = maphash.MakeSeed()
		l.cacheElem = map[string]*list.Element{}
		for i := range l.shard {
			l.shard[i].m = map[string]ledgerRow{}
		}
		l.swept.Store(time.Now().UnixNano())
	})
	return &l.shard[maphash.String(l.seed, id)%shards]
}

// forget stops counting row r of id, which its shard's lock is held for: its bytes, and a cache row's place in the
// order of eviction.
func (l *ledger) forget(id string, r ledgerRow) {
	l.pool[r.kind].Add(-r.size)
	if r.kind == rowCache {
		l.cacheMu.Lock()
		if e := l.cacheElem[id]; e != nil {
			l.cacheOrder.Remove(e)
			delete(l.cacheElem, id)
		}
		l.cacheMu.Unlock()
	}
}

// rowSize is what a row of value under record id is counted as: as a Local counts an entry.
func rowSize(id string, value []byte) int64 { return int64(len(id)+len(value)) + itemOverhead }

// limit is the budget of a kind of row: the same as a Local's with the same settings.
func (s *Shared) limit(kind int) int64 {
	l := Local{Budget: s.Budget, CacheBudget: s.CacheBudget, GuardBudget: s.GuardBudget}
	switch kind {
	case rowCounter:
		return l.counterBudget()
	case rowCache:
		return l.cacheBudget()
	case rowGuard:
		return l.guardBudget()
	}
	return l.budget()
}

// reserve counts the row id, of kind, size bytes until expires, before it is written, and reports false when that
// would take its kind past its budget (nothing is counted then). A row it already counts is replaced: one of the
// same kind gives back its size.
func (s *Shared) reserve(id string, kind int, size int64, expires time.Time) bool {
	s.sweep()
	sh := s.led.of(id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := time.Now()
	grow := size
	old, had := sh.m[id]
	if had && (now.After(old.expires) || old.kind != kind) {
		s.led.forget(id, old) // gone by now, or of another budget: not this one's
		delete(sh.m, id)
		had = false
	}
	if had {
		grow -= old.size
	}
	// Checked and counted in one step (reserve), as a Local's room is: rows written at once never pass the budget
	// between them.
	if !reserve(&s.led.pool[kind], grow, s.limit(kind)) {
		return false // a row of the same kind it would have replaced stays counted
	}
	sh.m[id] = ledgerRow{size: size, expires: expires, kind: kind}
	if kind == rowCache { // the newest written: the last to be evicted
		s.led.cacheMu.Lock()
		if e := s.led.cacheElem[id]; e != nil {
			s.led.cacheOrder.Remove(e)
		}
		s.led.cacheElem[id] = s.led.cacheOrder.PushBack(id)
		s.led.cacheMu.Unlock()
	}
	return true
}

// evictCache deletes the oldest cache row this node wrote and still counts, to make room for a new one, and reports
// whether there was one. A cache's value only saves a read, so the row goes from the database as an expired one
// would: the next caller that needs it reads again. A row that could not be deleted is no longer counted either (it
// expires by itself within its minute): the cache must not refuse for it.
func (s *Shared) evictCache(ctx context.Context) bool {
	s.led.cacheMu.Lock()
	e := s.led.cacheOrder.Front()
	s.led.cacheMu.Unlock()
	if e == nil {
		return false
	}
	id := e.Value.(string)
	_ = s.st.Put(context.WithoutCancel(ctx), store.Tombstone(model.KindEphemeral, id))
	s.drop(id)
	return true
}

// drop stops counting the row id: it was taken or deleted, or the write counted for it did not happen.
func (s *Shared) drop(id string) {
	sh := s.led.of(id)
	sh.mu.Lock()
	if r, ok := sh.m[id]; ok {
		delete(sh.m, id)
		s.led.forget(id, r)
	}
	sh.mu.Unlock()
}

// sweep starts a pass that takes the expired rows out of the ledger, at most once every ledgerSweep, from a write
// (in a goroutine of its own: the write does not wait for it).
func (s *Shared) sweep() {
	s.led.of("") // set up
	now, last := time.Now().UnixNano(), s.led.swept.Load()
	if now-last < int64(ledgerSweep) || !s.led.swept.CompareAndSwap(last, now) || !s.led.sweeping.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.led.sweeping.Store(false)
		now := time.Now()
		for i := range s.led.shard {
			sh := &s.led.shard[i]
			sh.mu.Lock()
			for id, r := range sh.m {
				if now.After(r.expires) {
					delete(sh.m, id)
					s.led.forget(id, r)
				}
			}
			sh.mu.Unlock()
		}
	}()
}

// refused counts a write refused for its kind's budget and warns of it at most once a minute per kind; it returns
// what the caller answers (ErrFull for a value, nil for a counter, which reports Contended).
func (s *Shared) refused(kind int, ns string) error {
	reason, msg := "full", "this node's short-lived state in the shared database is at its budget (limits.ephemeral_mb): "+
		"new sign-ins and other requests that would add to it get 503 until expiries make room"
	switch kind {
	case rowCounter:
		reason, msg = "counters", "this node's rate-limit counters in the shared database are at their cap "+
			"(limits.ephemeral_mb): limits on new keys refuse until expiries make room"
	case rowCache:
		reason, msg = "cache", "a short-lived cache entry is larger than this node's caches' cap in the shared "+
			"database: not kept"
	case rowGuard:
		reason, msg = "guard", "this node's guard records (used codes, device polls, password sprays) in the shared "+
			"database are at their cap: what needs one is refused until expiries make room"
	}
	metrics.EphemeralRefused.Inc(reason)
	now, last := time.Now().UnixNano(), s.led.logged[kind].Load()
	if s.Log != nil && now-last >= int64(time.Minute) && s.led.logged[kind].CompareAndSwap(last, now) {
		s.Log.Warn(msg, "namespace", ns, "bytes", s.led.pool[kind].Load(), "cap_bytes", s.limit(kind))
	}
	if kind == rowCounter {
		return nil
	}
	return ErrFull
}

// valueKind is the kind of a value of namespace ns.
func valueKind(ns string) int {
	switch {
	case IsCache(ns):
		return rowCache
	case IsGuard(ns):
		return rowGuard
	}
	return rowValue
}

// Used is the bytes of values this node wrote and has not seen expire or go, by the estimate Budget is checked
// against (Local.Used).
func (s *Shared) Used() int64 { return s.led.pool[rowValue].Load() }

// Cached is Used for the values of cache namespaces (Local.Cached).
func (s *Shared) Cached() int64 { return s.led.pool[rowCache].Load() }

// Counters is the bytes of the counters this node made (Local.Counters).
func (s *Shared) Counters() int64 { return s.led.pool[rowCounter].Load() }

// Limit, CounterLimit and CacheLimit are the budgets (Local.Limit, Local.CounterLimit, Local.CacheLimit).
func (s *Shared) Limit() int64        { return s.limit(rowValue) }
func (s *Shared) CounterLimit() int64 { return s.limit(rowCounter) }
func (s *Shared) CacheLimit() int64   { return s.limit(rowCache) }

// Len is the number of rows this node counts (values and counters), expired ones not swept yet included.
func (s *Shared) Len() int {
	s.led.of("") // set up
	n := 0
	for i := range s.led.shard {
		sh := &s.led.shard[i]
		sh.mu.Lock()
		n += len(sh.m)
		sh.mu.Unlock()
	}
	return n
}

// casRetries bounds the retries of a counter update that lost a race with another node; between attempts the
// caller backs off for a random 0.5–5 ms, so writers on one hot key spread out.
const casRetries = 40

// Contended is what Incr reports for a counter it could not update after casRetries attempts: more than any limit,
// so every caller fails closed (a rate limit trips, a jti counts as replayed). Only a key hammered by many writers
// at once gets there — which is what a rate limit is for.
const Contended = int64(1) << 40

// rid is the record id of ns/key: a hash, so ids have a fixed length and the key never appears in the database.
func rid(ns, key string) string {
	h := sha256.Sum256([]byte(ns + "\x00" + key))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *Shared) New(ctx context.Context, ns string, value []byte, ttl time.Duration) (string, error) {
	id := secure.RandomToken(24)
	return id, s.write(ctx, ns, id, value, ttl, s.t.Create)
}

func (s *Shared) Set(ctx context.Context, ns, id string, value []byte, ttl time.Duration) error {
	return s.write(ctx, ns, id, value, ttl, s.t.Put)
}

// write writes the row of ns/id with put, counted against its kind's budget first (reserve).
func (s *Shared) write(ctx context.Context, ns, id string, value []byte, ttl time.Duration,
	put func(context.Context, *model.Ephemeral) error) error {
	e := &model.Ephemeral{Meta: model.Meta{ID: rid(ns, id)}, Value: value, Expires: time.Now().Add(ttl)}
	kind := valueKind(ns)
	for !s.reserve(e.ID, kind, rowSize(e.ID, value), e.Expires) {
		// A full cache makes room, the oldest rows first, as a Local's does (setCache): only a row larger than the
		// whole cap, with nothing left to evict, is refused.
		if kind != rowCache || !s.evictCache(ctx) {
			return s.refused(kind, ns)
		}
	}
	if err := put(ctx, e); err != nil {
		s.drop(e.ID)
		return err
	}
	return nil
}

// Replace writes the row's new value on the condition that nobody changed the row since it was read, with the
// expiry it had (Store.Replace): a row another node took or deleted meanwhile is ErrNotFound, and one another node
// replaced is read again. The row counts against its kind's budget on this node from now on, as one it wrote.
func (s *Shared) Replace(ctx context.Context, ns, id string, value []byte) error {
	rid, kind := rid(ns, id), valueKind(ns)
	for range casRetries {
		e, err := s.t.Get(ctx, rid)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.drop(rid) // gone: not counted here any longer either
			}
			return notFound(err)
		}
		if !s.reserve(rid, kind, rowSize(rid, value), e.Expires) {
			return s.refused(kind, ns)
		}
		e.Value = value
		if err = s.t.Update(ctx, e); err == nil {
			return nil
		}
		if errors.Is(err, store.ErrNotFound) {
			s.drop(rid)
			return ErrNotFound
		}
		if !errors.Is(err, store.ErrStale) {
			return err
		}
		// Changed since it was read: gone (the next read says so), or replaced by another node. Read again, a
		// little later.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(500+rand.IntN(4500)) * time.Microsecond):
		}
	}
	return errors.New("ephemeral: the entry is changed too often to replace")
}

func (s *Shared) Get(ctx context.Context, ns, id string) ([]byte, error) {
	e, err := s.t.Get(ctx, rid(ns, id))
	if err != nil {
		return nil, notFound(err)
	}
	return e.Value, nil
}

// Take reads the item and deletes it on the condition that nobody changed it since: the one node whose delete
// succeeds gets the value. An item that changed in between (replaced by another request: Replace) is read again, so
// a take loses only to another take or a delete, never to a save: the item is then gone for whoever saves it next.
func (s *Shared) Take(ctx context.Context, ns, id string) ([]byte, error) {
	for range casRetries {
		r, err := s.st.Get(ctx, model.KindEphemeral, rid(ns, id))
		if err != nil {
			return nil, notFound(err)
		}
		e := &model.Ephemeral{}
		if err := store.Decode(r, e); err != nil {
			return nil, err
		}
		err = s.st.CompareAndPut(ctx, store.Tombstone(model.KindEphemeral, r.ID), r.Version)
		if err == nil {
			s.drop(r.ID)
			return e.Value, nil
		}
		if !errors.Is(err, store.ErrStale) {
			return nil, notFound(err)
		}
	}
	return nil, ErrNotFound
}

func (s *Shared) Delete(ctx context.Context, ns, id string) error {
	err := s.st.Put(ctx, store.Tombstone(model.KindEphemeral, rid(ns, id)))
	if err == nil {
		s.drop(rid(ns, id))
	}
	if errors.Is(err, store.ErrStale) {
		return nil
	}
	return err
}

func (s *Shared) Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	id := rid(ns, key)
	for range casRetries {
		e, err := s.t.Get(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if delta <= 0 {
				return 0, nil
			}
			e = &model.Ephemeral{Meta: model.Meta{ID: id}, N: delta, Expires: time.Now().Add(window)}
			// A new row: within the counters' cap, as a Local's new counter (past it the limit refuses this key).
			if !s.reserve(id, rowCounter, rowSize(id, nil), e.Expires) {
				_ = s.refused(rowCounter, ns)
				return Contended, nil
			}
			if err = s.t.Create(ctx, e); err != nil {
				s.drop(id) // not made here: another node's, or none
			}
		case err != nil:
			return 0, err
		case delta == 0:
			return e.N, nil
		default:
			if e.N += delta; e.N < 0 { // never below zero (Store.Incr)
				e.N = 0
			}
			err = s.t.Update(ctx, e)
		}
		if err == nil {
			return e.N, nil
		}
		if !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
			return 0, err
		}
		// another node changed the counter (or created it, or it just expired): read it again, a little later
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Duration(500+rand.IntN(4500)) * time.Microsecond):
		}
	}
	return Contended, nil
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStale) {
		return ErrNotFound
	}
	return err
}
