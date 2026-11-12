package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

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
	if u.SetUpBy == "" { // not marked yet: until the pass that marks old accounts has finished, judged here as it would be
		done, err := s.legacyMarked(ctx)
		if err != nil {
			return nil, nil, err
		}
		if !done {
			if u.SetUpBy, err = s.legacySetUpBy(ctx, u); err != nil {
				return nil, nil, err
			}
		}
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
		if reset {
			s.auditOutcome(ctx, a, err, userChange(u, "user.signin.reset",
				map[string]string{"provider": setUpBy, "reason": "promoted to " + string(role)}))
		}
		switch {
		case err != nil:
		case reset: // tidying, of the epochs the write replaced
			_ = s.clearCredentials(ctx, u.ID, cred, sessWas)
		default: // the sessions ended all the same (a new session epoch): tidied, and their applications told
			_ = s.endSessionsOf(ctx, u.ID, sessWas)
		}
	}, nil
}

// legacySetUpByID is the record (a lock whose lease never runs out) saying that MarkLegacySetUpBy has gone through
// every account once: it is not done again. Its "-3" makes a store where an earlier pass ran (which went through
// links, not accounts, and took a second factor for the account's own) go through them all again under the rule as it
// is now.
const legacySetUpByID = "user-setupby-marked-3"

// LegacySetUpBy is where MarkLegacySetUpBy has got to: the last account it went through.
type LegacySetUpBy struct{ after string }

// MarkLegacySetUpBy brings accounts from before the provider whose sign-in set up their credentials was recorded
// (model.User.SetUpBy, which their records read as "") under the same rules as the rest (legacySetUpBy), so that a
// promotion, or disconnecting the provider, resets their sign-in (applyRole, removeWay). It goes through at most
// limit accounts from where m got to, and returns how many it marked and whether it has gone through them all; then it
// records that it has (legacySetUpByID) and does nothing again. Marking an account again changes nothing (one that
// records a provider keeps it). Only the housekeeping leader runs it; until it has finished, a promotion judges the
// account by the same rule itself (applyRole). An account promoted before the provider was recorded at all (a build
// before any release) lost its links then and is left as it is: nothing says any more which provider it had.
func (s *Service) MarkLegacySetUpBy(ctx context.Context, m *LegacySetUpBy, limit int) (marked int, done bool, err error) {
	if done, err := s.legacyMarked(ctx); done || err != nil {
		return 0, done, err
	}
	seen := 0
	all, err := walk(ctx, s.Users, &m.after, func(u *model.User) (bool, error) {
		seen++
		ok, err := s.markSetUpBy(ctx, u.ID)
		if err != nil {
			return false, err
		}
		if ok {
			marked++
		}
		return seen >= limit, nil
	})
	if err != nil || !all {
		return marked, false, err
	}
	return marked, true, s.putLock(ctx, legacySetUpByID, "done", time.Now().AddDate(100, 0, 0))
}

// legacyMarked reports whether MarkLegacySetUpBy has gone through every account.
func (s *Service) legacyMarked(ctx context.Context) (bool, error) {
	switch _, err := s.Locks.Get(ctx, legacySetUpByID); {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	default:
		return false, mapStore(err)
	}
}

// legacySetUpBy is the provider an account from before SetUpBy was recorded is taken to have been set up through:
// that of a live link to a provider (one it did not connect itself first, else one it did: connected under that
// provider's own sign-in, the provider's holder could have connected it) when the account has anything to sign in
// with (a password, a live API token, an authenticator app or a passkey: any of them may have been set up by the
// provider's holder while it had no second factor, the second factor included, at the step that enrols it). ""
// when u records a provider already, has no live link, or nothing to sign in with.
func (s *Service) legacySetUpBy(ctx context.Context, u *model.User) (string, error) {
	if u.SetUpBy != "" {
		return "", nil
	}
	ids, err := s.Identities.All(ctx, u.ID)
	if err != nil {
		return "", mapStore(err)
	}
	ids = slices.DeleteFunc(ids, func(l *model.Identity) bool { return !u.Counts(l) })
	if len(ids) == 0 {
		return "", nil
	}
	slices.SortFunc(ids, func(a, b *model.Identity) int { // one not connected first, then by id: the same each time
		if (a.Via == "connect") != (b.Via == "connect") {
			if a.Via == "connect" {
				return 1
			}
			return -1
		}
		return strings.Compare(a.ID, b.ID)
	})
	armed := u.PasswordHash != "" || u.HasTOTP()
	if !armed {
		held, err := s.HeldPasskeys(ctx, u)
		if err != nil {
			return "", err
		}
		armed = held > 0
	}
	if !armed {
		toks, err := s.APITokens.All(ctx, u.ID)
		if err != nil {
			return "", mapStore(err)
		}
		now := time.Now()
		armed = slices.ContainsFunc(toks, func(t *model.APIToken) bool {
			return u.Counts(t) && (t.Expires.IsZero() || now.Before(t.Expires))
		})
	}
	if !armed {
		return "", nil
	}
	return ids[0].ProviderID, nil
}

// markSetUpBy records on account userID the provider legacySetUpBy finds for it, as the account is written (a
// compare-and-swap of the copy it was judged on, judged again when it changed meanwhile).
func (s *Service) markSetUpBy(ctx context.Context, userID string) (bool, error) {
	for range 4 {
		u, err := s.Users.Get(ctx, userID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, mapStore(err)
		}
		by, err := s.legacySetUpBy(ctx, u)
		if err != nil || by == "" {
			return false, err
		}
		u.SetUpBy = by
		if err = s.Users.Update(ctx, u); !errors.Is(err, store.ErrStale) {
			return err == nil, mapStore(err)
		}
	}
	return false, ErrStale
}
