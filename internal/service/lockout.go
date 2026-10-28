package service

import (
	"context"
	"errors"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// LockOutUser disables a user and removes every way they had to sign in, for a compromised account or a leaver:
// their sessions and refresh grants end (applications are told, and remembered consent goes with the grants), and
// their password, authenticator app, passkeys, linked sign-in providers, personal API tokens and unused invitation,
// reset and verification links go. The account stays, for the audit log. Enabling it again brings none of that back:
// it then needs a new invitation. The rules are those of removing someone's password and of disabling them.
func (s *Service) LockOutUser(ctx context.Context, a *Actor, userID, reason string) (*model.User, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !s.canManageUser(a, u) {
		return nil, s.denied(a, u)
	}
	if a.UserID == u.ID {
		return nil, Invalid("reason", "you cannot lock yourself out")
	}
	if err := s.mayResetSignIn(ctx, a, u, "reason"); err != nil {
		return nil, err
	}
	// Disabling first: from here the account is refused everywhere, whatever happens to the rest.
	if u, err = s.UpdateUser(ctx, a, userID, UserInput{Active: ptrBool(false), StatusReason: &reason}); err != nil {
		return nil, err
	}
	errs := []error{s.ResetCredentials(ctx, userID)}
	links, _, lerr := s.Links.List(ctx, store.ListQuery{Scope: userID})
	errs = append(errs, lerr)
	for _, l := range links {
		if !l.Used {
			if err := s.Links.Delete(ctx, l.ID); err != nil && !errors.Is(err, store.ErrStale) {
				errs = append(errs, err)
			}
		}
	}
	err = errors.Join(errs...)
	detail := map[string]string{}
	if reason != "" {
		detail["reason"] = reason
	}
	if err != nil {
		detail["result"] = "incomplete"
		detail["error"] = err.Error()
	}
	s.AuditUser(ctx, a, u, "user.locked_out", detail)
	if err != nil {
		return nil, mapStore(err)
	}
	if fresh, gerr := s.Users.Get(ctx, userID); gerr == nil {
		u = fresh
	}
	return u, nil
}
