package service

import (
	"context"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// applyRole is the only place the role of an existing user changes (TestRoleIsSetOnlyByApplyRole holds the code to
// that): UpdateUser (the console, the management API and SCIM) and the break-glass promotion of "quisora invite
// --super-admin" both come here, so a change in privilege has the same consequences whichever way it was made. It sets
// the role on u, the copy about to be written, and returns the writes that go with it in the same transaction
// (writeUser), and finish, which audits them once the write has ended (with its error).
//
// What goes with a change in privilege today: a user who becomes a manager or administrator loses the sign-in links
// they did not make themselves from their own account page (unchosenLinks: made by email address, by an account
// created at a provider's first sign-in, or by an administrator), as privileged accounts are never linked by email
// address or created by a provider, and a provider that an organization administrator controls could otherwise
// keep the first factor of the account while it has no second one enrolled. They are deleted in the
// transaction that promotes the user, so no copy of the account is ever privileged and linked by email address at
// once, and, as with any provider link removed, the account's security generation moves on in that write
// (model.User.SecurityGen): a sign-in begun through one of them and still between its steps (enrolling the second
// factor the account lacks) is dead, rather than finished by whoever holds the provider's account. Its sessions and refresh grants end too, in the same write: a new session epoch (model.User.SessionEpoch).
// A session may have met its second factor only through rules for plain users (an upstream provider trusted for it,
// or a code mailed to the address: both count for users below manager only), and what a session holds is not judged
// again by the user's role at each request, so a promotion must not carry such a session over to a privileged
// account. Whoever held the provider's account could also have set up credentials of the account's own before the
// promotion, while it had no second factor (model.User.SetUpBy): whatever links it keeps, the
// same write takes every way in from it (clearSignIn: its password, authenticator app, recovery codes, passkeys,
// connected providers and API tokens), and the manager or administrator sets their own from an invitation or a sign-in
// link, as after any reset of the account's sign-in. Demotion has none: what a session or token may do is decided by
// the user's role at each request, not by one held in it. (A new account has no links, so creation sets its role in
// the record.)
func (s *Service) applyRole(ctx context.Context, u *model.User, role model.Role) (also []store.Op,
	finish func(ctx context.Context, a *Actor, err error), err error) {
	before := u.Role
	u.Role = role
	finish = func(context.Context, *Actor, error) {}
	if before.Privileged() || !role.Privileged() {
		return nil, finish, nil
	}
	sessWas := u.SessionEpoch
	u.SessionEpoch = NewCredEpoch()
	links, err := s.unchosenLinks(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	for _, l := range links {
		also = append(also, store.Op{Rec: store.Tombstone(model.KindIdentity, l.ID)})
	}
	if len(links) > 0 {
		u.BumpSecurity()
	}
	setUpBy, cred := u.SetUpBy, uint64(0)
	// Marked, the account is reset whatever links it keeps: one connected under that provider's own sign-in was not the
	// user's choice either (the provider's holder could connect another subject of it), and the reset's new credential
	// epoch ends every connected link with the rest.
	reset := setUpBy != ""
	if reset {
		cred, _ = clearSignIn(u)
	}
	return also, func(ctx context.Context, a *Actor, err error) {
		for _, l := range links {
			s.auditOutcome(ctx, a, err, userChange(u, "identity.unlink",
				map[string]string{"provider": l.ProviderID, "reason": "promoted to " + string(role)}))
		}
		if !reset {
			return
		}
		s.auditOutcome(ctx, a, err, userChange(u, "user.signin.reset",
			map[string]string{"provider": setUpBy, "reason": "promoted to " + string(role)}))
		if err == nil { // tidying, of the epochs the write replaced
			_ = s.clearCredentials(ctx, u.ID, cred, sessWas)
		}
	}, nil
}
