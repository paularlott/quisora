package web

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// slowWrites holds every write of a kind until release is closed, and counts them: a store whose writes take long.
type slowWrites struct {
	store.Store
	kind    model.Kind
	started chan struct{}
	release chan struct{}
	writes  atomic.Int64
}

func (s *slowWrites) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == s.kind {
		s.writes.Add(1)
		s.started <- struct{}{}
		<-s.release
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A session's last-use stamp is written in the background: the request that finds it old does not wait for the
// write, and the requests that follow while it runs start none (one write at a time per session).
func TestSessionTouchRunsInTheBackgroundOneAtATime(t *testing.T) {
	ctx := context.Background()
	slow := &slowWrites{Store: memstore.New(), started: make(chan struct{}, 8), release: make(chan struct{})}
	old := time.Now().Add(-10 * time.Minute).UTC()
	svc, _, s := sessionFixture(t, slow, time.Now().UTC())
	if err := svc.Sessions.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	slow.kind = model.KindSession // (creating it is not the write under test)
	m := NewSessions(svc)
	// Cached first (just used: no write), then made old, so that every lookup below shares the cached copy the write
	// starts from.
	if got, _ := m.Lookup(ctx, s.ID); got == nil {
		t.Fatal("session missing")
	}
	m.mu.Lock()
	m.cache[s.ID].sess.LastSeen = old
	m.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for range 64 {
			wg.Go(func() {
				if got, _ := m.Lookup(ctx, s.ID); got == nil {
					t.Error("session missing")
				}
			})
		}
		wg.Wait()
	}()
	select {
	case <-done: // every lookup returned while the write is held
	case <-time.After(5 * time.Second):
		t.Fatal("a lookup waited for the last-use write")
	}
	select {
	case <-slow.started:
	case <-time.After(5 * time.Second):
		t.Fatal("no last-use write started")
	}
	close(slow.release)
	svc.WaitBackground()
	if n := slow.writes.Load(); n != 1 {
		t.Fatalf("%d writes for one session's lookups, want 1", n)
	}
	if cur, _ := svc.Sessions.Get(ctx, s.ID); !cur.LastSeen.After(old) {
		t.Fatal("the last use was not recorded")
	}
}

// failWrites fails every write of a kind: a store that cannot take the write now.
type failWrites struct {
	store.Store
	kind model.Kind
}

func (s *failWrites) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == s.kind {
		return errors.New("write failed")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A last-use write that fails only delays it: the lookup is served all the same, and the next lookup that finds the
// stamp old writes it.
func TestSessionTouchFailureIsRetriedLater(t *testing.T) {
	ctx := context.Background()
	failing := &failWrites{Store: memstore.New()}
	old := time.Now().Add(-10 * time.Minute).UTC()
	svc, _, s := sessionFixture(t, failing, old)
	if err := svc.Sessions.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	failing.kind = model.KindSession
	m := NewSessions(svc)
	if got, _ := m.Lookup(ctx, s.ID); got == nil {
		t.Fatal("a lookup failed with its last-use write")
	}
	svc.WaitBackground()
	failing.kind = ""
	if got, _ := m.Lookup(ctx, s.ID); got == nil {
		t.Fatal("session missing")
	}
	svc.WaitBackground()
	if cur, _ := svc.Sessions.Get(ctx, s.ID); !cur.LastSeen.After(old) {
		t.Fatal("the last use was not recorded after a failed write")
	}
}

// afterGets runs after each read of a record, as the store answers: an eviction that lands between the read and the put
// into the cache.
type afterGets struct {
	store.Store
	after func(kind model.Kind, id string)
	gets  atomic.Int64
}

func (a *afterGets) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	r, err := a.Store.Get(ctx, kind, id)
	if kind == model.KindSession || kind == model.KindUser {
		a.gets.Add(1)
	}
	if a.after != nil {
		a.after(kind, id)
	}
	return r, err
}

// A session read from the store before it was evicted (or its user was) is not cached after the eviction: it may be the
// copy the eviction was for. The next lookup reads the store again.
func TestSessionFillBeforeEvictionIsNotCached(t *testing.T) {
	ctx := context.Background()
	recs := &afterGets{Store: memstore.New()}
	svc, u, s := sessionFixture(t, recs, time.Now())
	if err := svc.Sessions.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	m := NewSessions(svc)
	for name, evict := range map[string]struct {
		kind model.Kind
		fn   func()
	}{
		"session": {model.KindSession, func() { m.Evict(s.ID, "") }},
		"user":    {model.KindUser, func() { m.Evict("", u.ID) }},
	} {
		t.Run(name, func(t *testing.T) {
			m.Evict(s.ID, u.ID)
			recs.after = func(kind model.Kind, _ string) {
				if kind == evict.kind {
					evict.fn()
				}
			}
			if got, _ := m.Lookup(ctx, s.ID); got == nil {
				t.Fatal("the request that read it is served")
			}
			recs.after = nil
			before := recs.gets.Load()
			if got, _ := m.Lookup(ctx, s.ID); got == nil {
				t.Fatal("session missing")
			}
			if recs.gets.Load() == before {
				t.Fatal("a copy read before the eviction was cached and served after it")
			}
			before = recs.gets.Load()
			if got, _ := m.Lookup(ctx, s.ID); got == nil || recs.gets.Load() != before {
				t.Fatal("a fill with no eviction is not cached")
			}
		})
	}
}
