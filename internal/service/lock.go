package service

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A lease is a cluster-wide lock this request holds: a lock record (model.Lock) written with a compare-and-swap (a
// quorum one in a gossip cluster), so whatever it guards is serialised across every node, on every backend. It lasts
// ttl unless released or extended, so a holder that dies blocks the others for at most ttl; a holder is sure of it
// only while held reports so, and a long change calls extend as it goes. It guards a decision that needs more than
// one record read consistently (the admin lock, signin.go); a change of several records is not made under one, as a
// lease fences no write: see ChangeGroup for how a group and its members commit on one record instead.
type lease struct {
	s      *Service
	id     string
	holder string
	ttl    time.Duration
	until  time.Time // by this node's clock
}

// leaseMargin is the clock skew allowed between nodes (store.MaxSkew): another node reads the lease's expiry by its
// own clock, so this holder counts the lease as gone that much before it.
const leaseMargin = 5 * time.Second

var (
	errLockBusy = errors.New("lock held")
	// errLockLost is a lease that lapsed before its holder was done: another holder may have the lock now.
	errLockLost = errors.New("lock lapsed")
)

// lock takes the lock id for ttl, waiting up to wait for another holder; still held then, it fails with
// ErrUnavailable and busy as the reason. Only a store failure fails it otherwise.
func (s *Service) lock(ctx context.Context, id string, ttl, wait time.Duration, busy string) (*lease, error) {
	l := &lease{s: s, id: id, holder: model.NewID(), ttl: ttl}
	deadline := time.Now().Add(wait)
	for attempt := 1; ; attempt++ {
		now := time.Now()
		r, err := s.Locks.Get(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			err = s.Locks.Create(ctx, &model.Lock{Meta: model.Meta{ID: id}, Holder: l.holder, Until: now.Add(ttl)})
		case err != nil:
		case r.Holder != "" && r.Until.After(now):
			err = errLockBusy
		default:
			r.Holder, r.Until = l.holder, now.Add(ttl)
			err = s.Locks.Update(ctx, r)
		}
		if err == nil {
			l.until = now.Add(ttl)
			return l, nil
		}
		if !errors.Is(err, errLockBusy) && !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound) {
			return nil, mapStore(err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: %s", ErrUnavailable, busy)
		}
		time.Sleep(time.Duration(10+rand.IntN(20*min(attempt, 10))) * time.Millisecond)
	}
}

// held reports whether the lease is still certainly this holder's.
func (l *lease) held() bool { return time.Now().Add(leaseMargin).Before(l.until) }

// extend renews the lease once less than half of it is left, so a holder still working keeps the lock; it fails with
// errLockLost when the lease has lapsed (or another holder took the lock), and the holder must then neither go on
// nor undo anything: a newer holder may have changed what it guards.
func (l *lease) extend(ctx context.Context) error {
	if !l.held() {
		return errLockLost
	}
	if time.Until(l.until) > l.ttl/2 {
		return nil
	}
	for range 8 {
		now := time.Now()
		r, err := l.s.Locks.Get(ctx, l.id)
		if err != nil || r.Holder != l.holder {
			return errLockLost
		}
		r.Until = now.Add(l.ttl)
		if err := l.s.Locks.Update(ctx, r); err == nil {
			l.until = r.Until
			return nil
		} else if !errors.Is(err, store.ErrStale) {
			return errLockLost
		}
	}
	return errLockLost
}

// release gives the lock up (best effort: an unreleased lock lapses on its own). The lock record is deleted, as this
// holder wrote it (a conditional deletion: never another holder's), so locks of the many groups ever changed do not
// pile up; the next holder creates it again.
func (l *lease) release(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	for range 8 {
		r, err := l.s.Locks.Get(ctx, l.id)
		if err != nil || r.Holder != l.holder {
			return
		}
		if err := l.s.Locks.DeleteIf(ctx, l.id, r.Version); !errors.Is(err, store.ErrStale) {
			return
		}
	}
}
