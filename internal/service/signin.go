package service

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// Sign-in stamps live in each user's SignIn record (model.SignIn), never on the user: a sign-in writes only that
// record, so it can neither overwrite nor be overwritten by an administrator's change of the user. In a gossip
// cluster both kinds are written with a quorum compare-and-swap (model.QuorumCAS).

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
		// Changed meanwhile (perhaps on another node): the newer copy is here now (read repair); apply fn to it.
		time.Sleep(time.Duration(1+rand.IntN(5*(attempt+1))) * time.Millisecond)
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
// step cannot be recorded the code is refused.
func (s *Service) ConsumeTOTP(ctx context.Context, u *model.User, secret, code string) bool {
	return s.ConsumeTOTPAt(ctx, u, secret, code, time.Now())
}

// ConsumeTOTPAt is ConsumeTOTP with the time the code is checked against.
func (s *Service) ConsumeTOTPAt(ctx context.Context, u *model.User, secret, code string, now time.Time) bool {
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
		return false
	}
	return ok
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

// adminLockTTL bounds how long an organization's admin lock is held when its holder dies.
const adminLockTTL = 30 * time.Second

// lockAdmins takes the organization's admin lock (a lease, lock.go), so changes that could remove a super admin the
// server needs are serialised across every node. It waits up to ten seconds for another holder. The returned
// function releases it.
func (s *Service) lockAdmins(ctx context.Context, orgID string) (func(), error) {
	l, err := s.lock(ctx, "admins/"+orgID, adminLockTTL, 10*time.Second,
		"another change of this organization's administrators is in progress")
	if err != nil {
		return nil, err
	}
	return func() { l.release(ctx) }, nil
}

// FreshUser reads user id from a quorum's copies (store.QuorumReader; a local read without a cluster): a change of
// the account that a majority confirmed anywhere is seen, even before it has reached this node.
func (s *Service) FreshUser(ctx context.Context, id string) (*model.User, error) {
	qr, ok := s.Store.(store.QuorumReader)
	if !ok {
		u, err := s.Users.Get(ctx, id)
		return u, mapStore(err)
	}
	recs, err := qr.Fresh(ctx, model.KindUser, []string{id})
	if err != nil {
		return nil, mapStore(err)
	}
	r, ok := recs[id]
	if !ok || !r.Live(time.Now()) {
		return nil, ErrNotFound
	}
	u := &model.User{}
	if err := store.Decode(r, u); err != nil {
		return nil, err
	}
	return u, nil
}

// usableAdmins returns the users of org with the role that are usable now (active and not past their end date), from
// a quorum's copies (store.QuorumReader) of the users this node lists with it: a demotion, disabling, end date or
// deletion confirmed by a majority anywhere is counted, even if it has not reached this node yet. (A promotion that
// has not reached this node is missed: the count can only be too low, which refuses a change rather than allowing a
// wrong one.)
func (s *Service) usableAdmins(ctx context.Context, orgID string, role model.Role) ([]*model.User, error) {
	// admin_rank is indexed (administrators and super admins: a handful), so this reads only them, not the
	// organization; role and active are checked on each below.
	l, _, err := s.Users.List(ctx, store.ListQuery{Scope: orgID, Filters: []store.Filter{{Field: "admin_rank", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	now := time.Now()
	qr, ok := s.Store.(store.QuorumReader)
	if !ok {
		out := l[:0:0]
		for _, u := range l {
			if u.OrgID == orgID && u.Role == role && u.Enabled(now) {
				out = append(out, u)
			}
		}
		return out, nil
	}
	ids := make([]string, len(l))
	for i, u := range l {
		ids[i] = u.ID
	}
	recs, err := qr.Fresh(ctx, model.KindUser, ids)
	if err != nil {
		return nil, mapStore(err)
	}
	var out []*model.User
	for _, r := range recs {
		u := &model.User{}
		if !r.Live(now) || store.Decode(r, u) != nil {
			continue
		}
		if u.OrgID == orgID && u.Role == role && u.Enabled(now) {
			out = append(out, u)
		}
	}
	return out, nil
}

// ResolveUniqueClash handles a record that lost a unique value to another record created before it (the cluster
// replicated two records claiming one email address, username, name...): the value is removed from it (or, where
// it cannot be, the record is disabled), it is flagged for administrators (model.Meta.Conflict) and the change is
// audited. Nothing is deleted. Every node that sees the clash calls it; the compare-and-swap lets one of them make
// the change and the others find it done.
func (s *Service) ResolveUniqueClash(ctx context.Context, kind model.Kind, id string) {
	if !s.CanWrite() {
		return
	}
	for range 5 {
		r, err := s.Store.Get(ctx, kind, id)
		if err != nil {
			return
		}
		e := model.NewEntity(kind)
		if e == nil || store.Decode(r, e) != nil {
			return
		}
		var lost []string
		for _, u := range e.Index().Unique {
			if h, err := s.Store.GetByUnique(ctx, kind, u); err == nil && h.ID != id {
				lost = append(lost, u)
			}
		}
		if len(lost) == 0 {
			return // resolved (elsewhere, or the other record changed)
		}
		changed := false
		for _, u := range lost {
			if model.ReleaseUnique(e, u) {
				changed = true
			}
		}
		if !changed {
			return
		}
		e.GetMeta().Conflict = "a unique value (" + strings.Join(lost, ", ") + ") was claimed first by another " +
			"record of the same kind: it was removed from this one on " + time.Now().UTC().Format(time.RFC3339)
		rec, err := store.Encode(e)
		if err != nil {
			return
		}
		err = s.Store.CompareAndPut(ctx, rec, r.Version)
		if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrConflict) {
			continue
		}
		if !store.Applied(err) {
			s.Log.WithError(err).Warn("could not resolve a unique value clash", "kind", string(kind), "id", id)
			return
		}
		org := orgOf(e)
		s.Audit(ctx, System, org, "unique.conflict", string(kind)+" "+id, map[string]string{
			"values": strings.Join(lost, ", "), "resolution": "removed from the record created later"})
		return
	}
}

// orgOf is the organization an entity belongs to (for the audit log), "" when it has none.
func orgOf(e model.Entity) string {
	switch v := e.(type) {
	case *model.Org:
		return v.ID
	case *model.User:
		return v.OrgID
	case *model.Group:
		return v.OrgID
	case *model.Tenant:
		return v.OrgID
	case *model.Provider:
		return v.OrgID
	case *model.Passkey:
		return v.OrgID
	case *model.Identity:
		return v.OrgID
	}
	return ""
}
