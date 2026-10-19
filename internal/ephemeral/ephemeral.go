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
	"time"

	"github.com/paularlott/quisora/internal/secure"
)

var ErrNotFound = errors.New("ephemeral: not found or expired")

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
	// Incr adds delta to a counter that resets window after its first increment, returning the new value. A counter
	// too contended to update reports a value above any limit (Contended) rather than an error: callers fail closed.
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
}

const shards = 64

// Local is an in-memory Store for one node. Prefix is the node's short id embedded in ids.
type Local struct {
	Prefix string
	seed   maphash.Seed
	shard  [shards]struct {
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

func (l *Local) Set(_ context.Context, ns, id string, value []byte, ttl time.Duration) error {
	k := ns + "/" + id
	s := l.sh(k)
	s.mu.Lock()
	s.m[k] = &item{val: value, expires: time.Now().Add(ttl)}
	s.mu.Unlock()
	return nil
}

func (l *Local) get(ns, id string, take bool) ([]byte, error) {
	k := ns + "/" + id
	s := l.sh(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok || time.Now().After(v.expires) {
		delete(s.m, k)
		return nil, ErrNotFound
	}
	if take {
		delete(s.m, k)
	}
	return v.val, nil
}

func (l *Local) Get(_ context.Context, ns, id string) ([]byte, error)  { return l.get(ns, id, false) }
func (l *Local) Take(_ context.Context, ns, id string) ([]byte, error) { return l.get(ns, id, true) }

func (l *Local) Delete(_ context.Context, ns, id string) error {
	k := ns + "/" + id
	s := l.sh(k)
	s.mu.Lock()
	delete(s.m, k)
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
		v = &item{expires: now.Add(window)}
		s.m[k] = v
	}
	v.n += delta
	return v.n, nil
}
