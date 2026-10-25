package service

import (
	"context"
	"strings"

	"github.com/paularlott/quisora/internal/model"
)

// The security generation (model.User.SecurityGen) is how everything in flight about an account — a sign-in between
// its steps, an authenticator app being confirmed, a passkey ceremony, a re-authentication, a reset or invitation
// link — learns that the account's credentials changed under it, and must be begun again against the account as it
// is now. It moves on in exactly two ways: a change of the user record that alters securityState (every write
// through updateUser or modifyUser compares before and after, so no path that changes one of those fields can
// forget), and an explicit AdvanceSecurity (or BumpSecurity before a write) for credentials kept in other records: a
// passkey added, removed or disabled, a sign-in provider connected or disconnected. The authenticator secret and
// recovery codes are on the user, so they are in securityState, as are the password and whether the account is
// disabled (a lock-out). It never moves for a sign-in itself (sign-in stamps live on the SignIn record), a profile
// edit, or a password hash upgraded to today's settings (rehashPassword: the same password, encoded afresh).
//
// What is not a credential is not in it, and is judged afresh from the live user at every step instead, which is
// both sharper and kinder: the role (whether a second factor is required, whether codes by email are allowed, who
// may invite: emailOK, Role.Privileged, issuerMayInvite), the primary address and whether it is verified (a code is
// sent to the address on file now; a link proves the address it was mailed to only while that is still the one on
// file), and the end date (Enabled). An invitation for an account that was promoted after it went out is therefore
// judged on those rules, not simply dead. A change of address does end invitation and reset links (LinkToken.For):
// they set credentials, and the one mailed to the old address may be in a stranger's mailbox.

// securityState is the part of a user that SecurityGen tracks, in a comparable form.
type securityState struct {
	password, totp, codes string
	active                bool
}

func stateOf(u *model.User) securityState {
	return securityState{password: u.PasswordHash, totp: u.TOTPSecret, codes: strings.Join(u.RecoveryCodes, ","), active: u.Active}
}

// noteSecurity moves u on to its next security generation when its state differs from was, taken before the change.
func noteSecurity(was securityState, u *model.User) {
	if was != stateOf(u) {
		u.BumpSecurity()
	}
}

// AdvanceSecurity moves userID on to its next security generation for a credential that lives outside the user
// record (a passkey, a connected provider), durably and retried over a concurrent change of the user. Callers do it
// after the other record is written: the generation moving on is what ends every flow that validated against the
// account before it, so a flow that read the user between the two writes still sees the change at its commit, which
// is a compare-and-swap on the version it read.
func (s *Service) AdvanceSecurity(ctx context.Context, userID string) (*model.User, error) {
	return s.modifyUser(ctx, userID, func(u *model.User) error {
		u.BumpSecurity()
		return nil
	})
}
