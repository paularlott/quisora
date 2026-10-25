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
// lease fences no write by itself: a holder that pauses, or a store that is slow, can land its write after the lease
// lapsed and another holder decided on the records as they were before it. A change of several records is not made
// under one: see ChangeGroup for how a group and its members commit on one record instead. A decision over several
// records that commits on one (the admin lock) has fence as its commit boundary: once the write has landed, a lease
// no longer held makes the decision again, on the records as they are now, and undoes a change it would now refuse.
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
		if err := pause(ctx, time.Duration(10+rand.IntN(20*min(attempt, 10)))*time.Millisecond); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrUnavailable, busy, err)
		}
	}
}

// pause waits d, or until ctx ends (its error).
func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// leaseSkew is how much earlier than its Until a lease is treated as lapsed by held: another node's clock may be that
// much ahead, and have let a new holder in while this node's still saw the lease as live.
const leaseSkew = time.Second

// held reports whether this holder still holds the lease: the lock record is its own and has not lapsed (clock skew
// allowed for, leaseSkew). A lock that cannot be read is not known to be held.
func (l *lease) held(ctx context.Context) (bool, error) {
	r, err := l.s.Locks.Get(ctx, l.id)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, mapStore(err)
	}
	return r.Holder == l.holder && r.Until.After(time.Now().Add(leaseSkew)), nil
}

// fence is the commit boundary of a change decided under the lease, called once its write has landed. A lease
// serialises its holders' decisions, not their writes: a write that lands after the lease lapsed may have raced a
// later holder's, whose decision counted on the record as it was before this write (two disables of the last two
// super admins, each judged while the other was still usable). If the lease is still this holder's, the write landed
// within it and the decision stands. Otherwise the decision is made again with recheck, on the records as they are
// now: nil keeps the change; any other result (the refusal, or a failure to decide, which must not keep a change
// that may have left none) has undo put the record back as it was, and is returned. The change was visible
// meanwhile — the fence is not atomic — but nothing irreversible follows a write before its fence. An undo that
// fails is logged; the change then stands as made, and nil is returned. The write has landed whatever became of the
// caller, so recheck and undo run on ctx without its cancellation: a client gone must not have its change undone.
func (l *lease) fence(ctx context.Context, recheck, undo func(context.Context) error) error {
	ctx = context.WithoutCancel(ctx)
	ok, err := l.held(ctx)
	if ok {
		return nil
	}
	if err != nil {
		l.s.Log.WithError(err).Warn("lock could not be read after a write: deciding the change again", "lock", l.id)
	}
	if err := recheck(ctx); err != nil {
		if uerr := undo(ctx); uerr != nil {
			l.s.Log.WithError(uerr).Error("a change made after its lock lapsed could not be undone", "lock", l.id, "refusal", err.Error())
			return nil
		}
		return err
	}
	return nil
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
