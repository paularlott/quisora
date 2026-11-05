package service

import (
	"context"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Guest accounts: a user's accounts in other organizations reached through an organization provider
// (model.ProviderOrganization) whose source is the user's organization. Each signed in, and signs in again, as that
// user. So when the user's sessions end - signed out everywhere, disabled, locked out, past their end date, deleted,
// or signing out their other sessions - their guest accounts' sessions and refresh grants end too, here, and those
// organizations' applications are told (back-channel logout). Leaver detection cannot do it: an organization provider
// asks for no refresh token, as both organizations are on this server.

// maxGuestDepth bounds how far guest accounts are followed: a guest can be the source of a guest of its own in a third
// organization.
const maxGuestDepth = 4

// endGuestSessions ends the sessions of u's guest accounts (and of theirs, in turn), recording each in the guest
// organization's audit log. Best effort: a failure is logged and the rest go on.
func (s *Service) endGuestSessions(ctx context.Context, u *model.User) {
	s.endGuestSessionsFrom(ctx, u.OrgID, u.ID, map[string]bool{u.ID: true}, 0)
}

func (s *Service) endGuestSessionsFrom(ctx context.Context, orgID, userID string, seen map[string]bool, depth int) {
	if depth >= maxGuestDepth {
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
