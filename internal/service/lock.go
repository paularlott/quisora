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
// ttl unless released, so a holder that dies blocks the others for at most ttl. It guards a decision that needs more than
// one record read consistently (the admin lock, signin.go); a change of several records is not made under one, as a
// lease fences no write: see ChangeGroup for how a group and its members commit on one record instead.
type lease struct {
	s      *Service
	id     string
	holder string
}

var errLockBusy = errors.New("lock held")

// lock takes the lock id for ttl, waiting up to wait for another holder; still held then, it fails with
// ErrUnavailable and busy as the reason. Only a store failure fails it otherwise.
func (s *Service) lock(ctx context.Context, id string, ttl, wait time.Duration, busy string) (*lease, error) {
	l := &lease{s: s, id: id, holder: model.NewID()}
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
