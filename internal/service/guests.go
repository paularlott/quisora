package service

import (
	"context"
	"errors"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Guest accounts: a user's accounts in other organizations reached through an organization provider
// (model.ProviderOrganization) whose source is the user's organization. Each signed in, and signs in again, as that
// user. So when the user's sessions end - signed out everywhere, disabled, locked out, past their end date, deleted,
// or signing out their other sessions - their guest accounts' sessions and refresh grants end too. Leaver detection
// cannot do it: an organization provider asks for no refresh token, as both organizations are on this server.
//
// The binding does it: a guest's session records the accounts its sign-in stands on (model.GuestSource: the source
// user and the epoch of the session it signed in with, Session.Sources), its refresh grants and SSH certificates take
// them from it, and every check of their use refuses them once a source no longer stands (SourcesHold), as it refuses
// the session's own user's. That is a check of the user records alone, which every write of them settles at once, so
// nothing has to reach the guest's records in time: a failed lookup below, a sign-in racing the change, a node that
// has not heard of it, all end where the check finds the source's epoch moved. What follows here is only tidying:
// the guests' records are removed and those organizations' applications told (back-channel logout), best effort.

// UserGetter reads a user by id, as the caller reads users (through its cache): a user that is not there is
// store.ErrNotFound or ErrNotFound, any other error a read that failed.
type UserGetter func(ctx context.Context, id string) (*model.User, error)

// SourcesHold reports whether the accounts a guest's sign-in stands on (a session's, grant's or SSH certificate's
// Sources) still stand: each user there, usable (UserUsable) and in the session epoch recorded (model.GuestSource).
// users reads them: the caller's cache, as the check runs with every use. An error is a read that failed: no verdict.
func (s *Service) SourcesHold(ctx context.Context, sources []model.GuestSource, users UserGetter) (bool, error) {
	return s.sourcesHold(ctx, sources, users, false)
}

// sourcesHold is SourcesHold holding each source to its session epoch or, cred, to its credential epoch (a guest's
// personal API token, model.APIToken.Sources).
func (s *Service) sourcesHold(ctx context.Context, sources []model.GuestSource, users UserGetter, cred bool) (bool, error) {
	for _, src := range sources {
		u, err := users(ctx, src.UserID)
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, mapStore(err)
		}
		if u.ID != src.UserID || cred && !u.Holds(src.Epoch) || !cred && !u.SessionHolds(src.Epoch) {
			return false, nil
		}
		if ok, err := s.UserUsable(ctx, u); err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// tokenSources are what a personal API token that a made now stands on (model.APIToken.Sources): the accounts a's
// session stands on (Actor.Sources), each held to its credential epoch as read now. That read checks the session's
// hold too (SourcesHold), so a reset that ended the session finds no token made with the new epoch: a reset moves
// both epochs in one write. A source that no longer holds is a sign-in that has ended (ErrForbidden).
func (s *Service) tokenSources(ctx context.Context, a *Actor) ([]model.GuestSource, error) {
	var out []model.GuestSource
	for _, src := range a.Sources {
		var cred uint64
		users := func(ctx context.Context, id string) (*model.User, error) {
			u, err := s.storeUser(ctx, id)
			if err == nil {
				cred = u.CredEpoch
			}
			return u, err
		}
		if ok, err := s.SourcesHold(ctx, []model.GuestSource{src}, users); err != nil {
			return nil, err
		} else if !ok {
			return nil, ErrForbidden
		}
		out = append(out, model.GuestSource{UserID: src.UserID, Epoch: cred})
	}
	return out, nil
}

// storeUser reads a user from the store (a UserGetter for the checks that run once a sign-in, not with every request).
func (s *Service) storeUser(ctx context.Context, id string) (*model.User, error) {
	return s.Users.Get(ctx, id)
}

// endGuestSessions removes the sessions of u's guest accounts (and of theirs, in turn), recording each in the guest
// organization's audit log. Best effort: a failure is logged and the rest go on; the sessions it misses stopped
// counting already, as they stand on u (SourcesHold).
func (s *Service) endGuestSessions(ctx context.Context, u *model.User) {
	s.endGuestSessionsFrom(ctx, u.OrgID, u.ID, map[string]bool{u.ID: true}, 0)
}

func (s *Service) endGuestSessionsFrom(ctx context.Context, orgID, userID string, seen map[string]bool, depth int) {
	if depth >= model.MaxGuestDepth {
		return
	}
	for _, guest := range s.guestsOf(ctx, orgID, userID) {
		if seen[guest.ID] {
			continue
		}
		seen[guest.ID] = true
		was, _, err := s.moveSessionEpoch(ctx, guest.ID, nil)
		if err == nil {
			err = s.endSessionsOf(ctx, guest.ID, was)
		}
		detail := map[string]string{"source_org": orgID, "source_user": userID}
		if err != nil {
			detail["result"], detail["error"] = "incomplete", err.Error()
			s.Log.WithError(err).Error("a guest account's sessions could not all be ended", "user", guest.ID,
				"source_user", userID)
		}
		s.AuditUser(ctx, System, guest, "user.sessions.revoke", detail)
		s.endGuestSessionsFrom(ctx, guest.OrgID, guest.ID, seen, depth+1)
	}
}

// guestsOf returns the guest accounts of the user userID of orgID: the users linked to them through the organization
// providers whose source is orgID, found by the sign-in clients orgID holds for those providers (Client.ProviderID).
func (s *Service) guestsOf(ctx context.Context, orgID, userID string) []*model.User {
	var out []*model.User
	q := store.ListQuery{Scope: orgID, Limit: 100}
	for {
		clients, total, err := s.Clients.List(ctx, q)
		if err != nil {
			s.Log.WithError(err).Error("guest accounts not found: the organization's clients could not be listed",
				"org", orgID, "user", userID)
			return out
		}
		for _, c := range clients {
			if g := s.guestThrough(ctx, c, orgID, userID); g != nil {
				out = append(out, g)
			}
		}
		q.Offset += len(clients)
		if len(clients) == 0 || q.Offset >= total {
			return out
		}
	}
}

// guestThrough is the guest account of userID that the sign-in client c of orgID leads to, or nil when c is no
// organization provider's sign-in client or the user has no account through it.
func (s *Service) guestThrough(ctx context.Context, c *model.Client, orgID, userID string) *model.User {
	if c.ProviderID == "" {
		return nil
	}
	p, err := s.Providers.Get(ctx, c.ProviderID)
	if err != nil || p.Type != model.ProviderOrganization || p.SourceOrg != orgID || p.ClientID != c.ID {
		return nil
	}
	id, err := s.Identities.GetByUnique(ctx, model.IdentityKey(p.ID, userID))
	if err != nil {
		return nil
	}
	g, err := s.Users.Get(ctx, id.UserID)
	if err != nil || g.OrgID != p.OrgID {
		return nil
	}
	return g
}
