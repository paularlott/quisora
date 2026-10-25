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
	if a == System || a.IsSuper() || !u.Role.Privileged() {
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

// mayReplaceInvite returns the check of the invitation a new one by a would replace (issueLink runs it on the very
// record it overwrites, on every try): a, not a super admin, may not replace the live invitation of a privileged
// account from someone else, or its issuer could accept it as the user. The issuer (or a super admin) issues the next
// one.
func mayReplaceInvite(a *Actor, u *model.User) func(cur *model.LinkToken) error {
	return func(cur *model.LinkToken) error {
		if a == System || a.IsSuper() || !u.Role.Privileged() {
			return nil
		}
		if !cur.Used && time.Now().Before(cur.Expires) && cur.IssuedBy != a.UserID {
			return Invalid("user", "this account has an invitation from someone else that has not been used yet: "+
				"only they or a super admin can issue a new one")
		}
		return nil
	}
}

// CanResetSignIn reports whether a may issue an invitation for u or remove its password (for what to show).
func (s *Service) CanResetSignIn(ctx context.Context, a *Actor, u *model.User) bool {
	return (a == System || s.canManageUser(a, u)) && s.mayResetSignIn(ctx, a, u, "user") == nil
}
