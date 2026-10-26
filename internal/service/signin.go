package service

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// Sign-in stamps live in each user's SignIn record (model.SignIn), never on the user: a sign-in writes only that
// record, so it can neither overwrite nor be overwritten by an administrator's change of the user. In a gossip
// cluster both kinds are written with a compare-and-swap that the owner of their partition checks.

// WithSignIn fills in the users' LastLogin from their sign-in records (one batch read; a user without one, or a
// failed read, keeps the zero value).
func (s *Service) WithSignIn(ctx context.Context, users ...*model.User) {
	if len(users) == 0 {
		return
	}
	ids := make([]string, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	sis, err := s.SignIns.GetMany(ctx, ids)
	if err != nil {
		return
	}
	byUser := make(map[string]*model.SignIn, len(sis))
	for _, si := range sis {
		byUser[si.ID] = si
	}
	for _, u := range users {
		if si, ok := byUser[u.ID]; ok {
			u.LastLogin = si.LastLogin
		}
	}
}

// updateSignIn applies fn to the user's sign-in record (created when the user has none) and writes it with a
// compare-and-swap, re-reading and re-applying fn when another write got there first. fn returns false to write
// nothing.
func (s *Service) updateSignIn(ctx context.Context, u *model.User, fn func(si *model.SignIn) bool) error {
	var err error
	for attempt := range 8 {
		si, gerr := s.SignIns.Get(ctx, u.ID)
		create := errors.Is(gerr, store.ErrNotFound)
		if gerr != nil && !create {
			return gerr
		}
		if create {
			si = &model.SignIn{Meta: model.Meta{ID: u.ID}, OrgID: u.OrgID}
		}
		if !fn(si) {
			return nil
		}
		if create {
			err = s.SignIns.Create(ctx, si)
		} else {
			err = s.SignIns.Update(ctx, si)
		}
		if !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		// Changed meanwhile (perhaps on another node): read the newer copy and apply fn to it.
		if err := pause(ctx, time.Duration(1+rand.IntN(5*(attempt+1)))*time.Millisecond); err != nil {
			return err
		}
	}
	return err
}

// TouchLogin records a successful sign-in on the user's sign-in record (at most once a minute per user, to keep
// writes down) and sets u.LastLogin. Best effort: a failure is not the sign-in's.
func (s *Service) TouchLogin(ctx context.Context, u *model.User) {
	if !s.CanWrite() {
		return
	}
	now := time.Now().UTC()
	err := s.updateSignIn(ctx, u, func(si *model.SignIn) bool {
		if now.Sub(si.LastLogin) < time.Minute {
			u.LastLogin = si.LastLogin
			return false
		}
		si.LastLogin = now
		return true
	})
	if err == nil && u.LastLogin.IsZero() {
		u.LastLogin = now
	}
}

// ConsumeTOTP verifies a TOTP code and records its time step on the user's sign-in record with a compare-and-swap
// — cluster-wide in a gossip cluster, confirmed by a majority — before it says yes: a code is accepted once, on
// whichever node, and two nodes presented the same code at once accept it at most once. It fails closed: when the
// step cannot be recorded the code is refused, with an error saying so (ErrUnavailable; ErrOutcomeUnknown when the step
// may have been recorded: the code is used up then): not a wrong code, which is no error.
func (s *Service) ConsumeTOTP(ctx context.Context, u *model.User, secret, code string) (bool, error) {
	return s.ConsumeTOTPAt(ctx, u, secret, code, time.Now())
}

// ConsumeTOTPAt is ConsumeTOTP with the time the code is checked against.
func (s *Service) ConsumeTOTPAt(ctx context.Context, u *model.User, secret, code string, now time.Time) (bool, error) {
	ok := false
	err := s.updateSignIn(ctx, u, func(si *model.SignIn) bool {
		step, good := secure.VerifyTOTP(secret, code, now, si.TOTPLastStep)
		ok = good
		if good {
			si.TOTPLastStep = step
		}
		return good
	})
	if err != nil {
		s.Log.WithError(err).Warn("could not record a TOTP step: code refused", "user", u.ID)
		return false, mapStore(err)
	}
	return ok, nil
}

// NoteTOTPStep records that the TOTP step was used (setting up an authenticator verifies a code), so the same code
// cannot sign in.
func (s *Service) NoteTOTPStep(ctx context.Context, u *model.User, step int64) error {
	return s.updateSignIn(ctx, u, func(si *model.SignIn) bool {
		if si.TOTPLastStep >= step {
			return false
		}
		si.TOTPLastStep = step
		return true
	})
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
