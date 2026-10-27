package service

import (
	"context"

	"github.com/paularlott/quisora/internal/model"
)

// applyRole is the only place the role of an existing user changes (TestRoleIsSetOnlyByApplyRole holds the code to
// that): UpdateUser (the console, the management API and SCIM), and the break-glass promotion of "quisora invite
// --super-admin" all come here, so a change in privilege has the same consequences whichever
// way it was made. It sets the role on u, the copy about to be written, and returns what completes the change: finish
// is called right after the write with its error, and does what follows from the new role, once, whether the write
// confirmed or its outcome is not known (a rerun of a change that landed finds nothing to change, so would never do
// it). It does nothing for a write that failed.
//
// What follows from a change in privilege today: a user who becomes a manager or administrator loses the sign-in
// links nobody chose (dropEmailLinks), as privileged accounts are never linked by email address. Demotion has no
// follow-up: what a session or token may do is decided by the user's role at each request, not by one held in it.
// (A new account has no links, so creation sets its role in the record.)
func (s *Service) applyRole(u *model.User, role model.Role) (finish func(ctx context.Context, a *Actor, err error)) {
	before := u.Role
	u.Role = role
	return func(ctx context.Context, a *Actor, err error) {
		if landed(err) && !before.Privileged() && role.Privileged() {
			s.dropEmailLinks(ctx, a, u)
		}
	}
}
