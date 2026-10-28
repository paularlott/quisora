package service

import (
	"context"
	"errors"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// OutcomeUnknown is the outcome of the audit event of a change whose outcome is not known (audited).
const OutcomeUnknown = "unknown"

type outcomeKey struct{}

// change is the audit event of one change: what it records when the change takes effect.
type change struct {
	org, action, target string
	detail              map[string]string
	// user is the user the change targets, if it targets one (userChange): the event names them by its username and id
	// as they are when it is recorded, in place of target.
	user *model.User
}

// userChange is the change of action to the user u.
func userChange(u *model.User, action string, detail map[string]string) change {
	return change{u.OrgID, action, "", detail, u}
}

// audited is how every audited change of the service is made: it runs write (the store write that is the change) and
// records the change's audit event by how it ended. Written, the event; unavailable with the store's mark that it may
// have been applied (store.ErrUnconfirmed: the store could not settle its outcome before its deadline, a long outage),
// the same event with outcome "unknown", so a change that did take effect is never missing from the audit log; any
// other error records nothing (nothing was changed). It returns write's error as it is. What a change ends goes in its
// own transaction (writeUser), never in a follow-up that the outcome decides.
//
// detail is read once write has returned, so write may add to it what only the written change knows (the side effects
// that followed it, a count). A change that is several events (a group's fields and members) or several writes uses
// auditOutcome directly.
func (s *Service) audited(ctx context.Context, a *Actor, orgID, action, target string, detail map[string]string, write func() error) error {
	err := write()
	s.auditOutcome(ctx, a, err, change{orgID, action, target, detail, nil})
	return err
}

// Audited is audited for the changes made outside the service (the console's session revocations, signing key
// changes): the same rule, from the one implementation.
func (s *Service) Audited(ctx context.Context, a *Actor, orgID, action, target string, detail map[string]string, write func() error) error {
	return s.audited(ctx, a, orgID, action, target, detail, write)
}

// AuditedUser is audited for a change to the user u (AuditUser): u is read for the event once write has returned, so
// write may fill it in (the id of a user it creates).
func (s *Service) AuditedUser(ctx context.Context, a *Actor, u *model.User, action string, detail map[string]string, write func() error) error {
	err := write()
	s.auditOutcome(ctx, a, err, userChange(u, action, detail))
	return err
}

// auditOutcome records the events of a change whose write ended with err, as audited does for one.
func (s *Service) auditOutcome(ctx context.Context, a *Actor, err error, events ...change) {
	switch {
	case err == nil:
	case outcomeUnknown(err):
		ctx = context.WithValue(ctx, outcomeKey{}, OutcomeUnknown)
	default:
		return
	}
	for _, e := range events {
		s.auditChange(ctx, a, e)
	}
}

// outcomeUnknown reports whether err leaves a write's outcome unknown: it may have landed, or land yet.
func outcomeUnknown(err error) bool {
	return errors.Is(err, store.ErrUnconfirmed) || errors.Is(err, ErrOutcomeUnknown)
}
