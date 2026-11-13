// Package ephemeral holds short-lived, single-node state: login flows, authorization codes, WebAuthn challenges,
// rate-limit counters. In a cluster the cluster package routes each id to the node that owns it, so state is never
// written to the database.
package ephemeral

import (
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

// Store is implemented by the local store and by the cluster router.
type Store interface {
	// New stores value under a fresh unguessable id (which encodes the owning node) and returns the id.
	New(ctx context.Context, ns string, value []byte, ttl time.Duration) (string, error)
	// Set replaces the value of an existing or new id (ids from New, or keys routed by hash).
	Set(ctx context.Context, ns, id string, value []byte, ttl time.Duration) error
	// Get returns the value.
	Get(ctx context.Context, ns, id string) ([]byte, error)
	// Take returns the value and deletes it atomically: exactly one caller ever gets it.
	Take(ctx context.Context, ns, id string) ([]byte, error)
	// Delete removes the id.
	Delete(ctx context.Context, ns, id string) error
	// Incr adds delta to a counter that resets window after its first increment, returning the new value. Only a
	// positive delta starts a counter: on a counter that does not exist (or has expired) a zero delta (a read) or a
	// negative one (an attempt given back after the counter was cleared) does nothing and returns 0. A counter too
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
// account) cheaper. Log, when set, gets a warning at most once a minute while Set refuses, and once a minute while
// counters are refused.
type Local struct {
	Prefix string
	Budget int64
	Log    logger.Logger
	used   atomic.Int64 // the memory the values take (checked against Budget)
	logged atomic.Int64 // unix nanos of the last warning that the store is full
	// counters is the memory the counters take (checked against counterBudget), apart from used.
	counters       atomic.Int64
	countersLogged atomic.Int64 // unix nanos of the last warning that counters were refused
	seed           maphash.Seed
	shard          [shards]struct {
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
	if v.counter {
		l.counters.Add(-v.size(k))
	} else {
		l.used.Add(-v.size(k))
	}
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
	it := &item{val: value, expires: time.Now().Add(ttl)}
	s := l.sh(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	grow := it.size(k)
	old, had := s.m[k]
	if had && !old.counter { // a counter it replaces was never the values'
		grow -= old.size(k)
	}
	if grow > 0 && l.used.Load()+grow > l.budget() {
		return l.full()
	}
	if had && old.counter { // a counter's key given a value: no longer a counter
		l.release(k, old)
	}
	s.m[k] = it
	l.used.Add(grow)
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

// Used is the memory the values take, by the estimate Budget is checked against.
func (l *Local) Used() int64 { return l.used.Load() }

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
		if l.counters.Load()+sz > l.counterBudget() {
			l.countersFull(ns)
			return Contended, nil // fail closed: the caller's limit trips for this key
		}
		l.counters.Add(sz)
		v = &item{expires: now.Add(window), counter: true}
		s.m[k] = v
	}
	v.n += delta
	return v.n, nil
}
