package service

import (
	"context"
	"errors"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// The sign-in of a manager or administrator (privileged: they administer other people) is reset only by a super
// admin. An invitation replaces every way its user signs in once accepted, so an administrator who could issue one
// for a peer could take the peer's account over, and act as them; removing the password first, or lowering the role
// to a plain user's, invitation, then raising it again, would get there too. So for a privileged account: issuing an
// invitation, removing the password and lowering the role are super admin only. An account that has never signed in
// and has no way to yet (one just created) gets its first invitation from whoever may manage it, as any other.

const msgPrivilegedReset = "only a super admin can reset the sign-in of a manager or administrator"

func privileged(u *model.User) bool { return u.Role.Rank() >= model.RoleManager.Rank() }

// established reports whether u has a way to sign in (a password, an authenticator app, a passkey, a sign-in
// provider) or has signed in before.
func (s *Service) established(ctx context.Context, u *model.User) (bool, error) {
	if u.PasswordHash != "" || u.HasTOTP() {
		return true, nil
	}
	for _, k := range []model.Kind{model.KindPasskey, model.KindIdentity} {
		n, err := s.Store.Count(ctx, k, u.ID)
		if err != nil {
			return false, mapStore(err)
		}
		if n > 0 {
			return true, nil
		}
	}
	si, err := s.SignIns.Get(ctx, u.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, mapStore(err)
	}
	return !si.LastLogin.IsZero(), nil
}

// mayResetSignIn refuses a (not a super admin) resetting the sign-in of a privileged, established account u. The
// caller has checked that a may manage u.
func (s *Service) mayResetSignIn(ctx context.Context, a *Actor, u *model.User, field string) error {
	if a == System || a.IsSuper() || !privileged(u) {
		return nil
	}
	est, err := s.established(ctx, u)
	if err != nil {
		return err
	}
	if est {
		return Invalid(field, msgPrivilegedReset)
	}
	return nil
}

// mayReplaceInvite refuses a (not a super admin) issuing an invitation for a privileged account that is not set up yet
// but holds a live invitation from someone else: the new one would revoke it, and its issuer could accept it as the
// user. The issuer (or a super admin) issues the next one.
func (s *Service) mayReplaceInvite(ctx context.Context, a *Actor, u *model.User) error {
	if a == System || a.IsSuper() || !privileged(u) {
		return nil
	}
	links, _, err := s.Links.List(ctx, store.ListQuery{Scope: u.ID, Filters: []store.Filter{{Field: "purpose", Value: LinkInvite}}})
	if err != nil {
		return mapStore(err)
	}
	now := time.Now()
	for _, l := range links {
		if !l.Used && now.Before(l.Expires) && l.IssuedBy != a.UserID {
			return Invalid("user", "this account has an invitation from someone else that has not been used yet: "+
				"only they or a super admin can issue a new one")
		}
	}
	return nil
}

// CanResetSignIn reports whether a may issue an invitation for u or remove its password (for what to show).
func (s *Service) CanResetSignIn(ctx context.Context, a *Actor, u *model.User) bool {
	return (a == System || s.canManageUser(a, u)) && s.mayResetSignIn(ctx, a, u, "user") == nil
}
