package service

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// What a user is connected to: the applications they granted access to and the sign-in providers linked to their
// account. The user sees and ends both from the account page; managers and up see and end them on the admin user page
// for the users they manage (to sort things out for someone in a mess) and for themselves.

// AppGrant is an application the user granted access to: their live refresh grants for one client, together.
type AppGrant struct {
	ClientID string    `json:"client_id"`
	Name     string    `json:"name"`
	Scopes   []string  `json:"scopes"`
	Since    time.Time `json:"since"`
	LastUsed time.Time `json:"last_used"`
	Grants   int       `json:"grants"`
}

// ConnectedApps lists the applications the user granted access to (live refresh grants grouped by client), by name.
func (s *Service) ConnectedApps(ctx context.Context, userID string) ([]AppGrant, error) {
	grants, err := s.Grants.All(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	now := time.Now()
	by := map[string]*AppGrant{}
	for _, g := range grants {
		if g.Revoked || (!g.Expires.IsZero() && now.After(g.Expires)) {
			continue
		}
		it := by[g.ClientID]
		if it == nil {
			it = &AppGrant{ClientID: g.ClientID, Name: "Removed application", Scopes: []string{}, Since: g.Created}
			if c, err := s.Clients.Get(ctx, g.ClientID); err == nil {
				it.Name = c.Name
			}
			by[g.ClientID] = it
		}
		it.Grants++
		if g.Created.Before(it.Since) {
			it.Since = g.Created
		}
		if g.Updated.After(it.LastUsed) {
			it.LastUsed = g.Updated
		}
		for _, sc := range g.Scopes {
			if !slices.Contains(it.Scopes, sc) {
				it.Scopes = append(it.Scopes, sc)
			}
		}
	}
	out := make([]AppGrant, 0, len(by))
	for _, it := range by {
		slices.Sort(it.Scopes)
		out = append(out, *it)
	}
	slices.SortFunc(out, func(a, b AppGrant) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

// ProviderLink is a sign-in provider account linked to the user.
type ProviderLink struct {
	ProviderID string    `json:"provider_id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Enabled    bool      `json:"enabled"`         // the provider is on (a link to a disabled one signs nothing in)
	Email      string    `json:"email,omitempty"` // the address the provider gave when it was linked
	Via        string    `json:"via,omitempty"`   // how it was linked: email, provision, connect or admin
	Linked     time.Time `json:"linked"`
}

// LinkedProviders lists the sign-in providers linked to the user (one entry per provider, the latest link), by name.
func (s *Service) LinkedProviders(ctx context.Context, userID string) ([]ProviderLink, error) {
	ids, err := s.Identities.All(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	by := map[string]*ProviderLink{}
	for _, id := range ids {
		if l := by[id.ProviderID]; l != nil && !id.Created.After(l.Linked) {
			continue
		}
		l := &ProviderLink{ProviderID: id.ProviderID, Name: "Removed provider", Email: id.Email, Via: id.Via, Linked: id.Created}
		if p, err := s.Providers.Get(ctx, id.ProviderID); err == nil {
			l.Name, l.Type, l.Enabled = p.Name, p.Type, p.Enabled
		}
		by[id.ProviderID] = l
	}
	out := make([]ProviderLink, 0, len(by))
	for _, l := range by {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b ProviderLink) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

// manageConnections checks that a may end u's connections: someone who can manage u, or u themselves self-service
// (the caller checked a recent re-authentication where the change needs one).
func (s *Service) manageConnections(ctx context.Context, a *Actor, u *model.User) error {
	if a == nil {
		a = System
	}
	if a != System && a.UserID == u.ID {
		if !isSelfService(ctx) {
			return ErrForbidden
		}
		return nil
	}
	if a != System && !s.canManageUser(a, u) {
		return s.denied(a, u)
	}
	return nil
}

// RemoveUserApp ends a user's access to one application for them (RevokeAppAccess: the application is told to sign
// the user out, then the grants go). It returns how many grants it removed; 0 means none.
func (s *Service) RemoveUserApp(ctx context.Context, a *Actor, userID, clientID string) (int, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return 0, mapStore(err)
	}
	if err := s.manageConnections(ctx, a, u); err != nil {
		return 0, err
	}
	n, err := s.RevokeAppAccess(ctx, userID, clientID)
	if err != nil || n == 0 {
		return n, err
	}
	name := clientID
	if c, err := s.Clients.Get(ctx, clientID); err == nil {
		name = c.Name
	}
	s.Audit(ctx, a, u.OrgID, "user.app.revoke", u.Username, map[string]string{"client": name, "client_id": clientID})
	return n, nil
}

// DisconnectProvider unlinks every identity the user has at one provider. Done for someone else it may take away
// their last way to sign in (whoever sorts the account out then sends an invitation); done to yourself it may not.
// It returns how many links it removed; 0 means none.
func (s *Service) DisconnectProvider(ctx context.Context, a *Actor, userID, providerID string) (int, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return 0, mapStore(err)
	}
	if err := s.manageConnections(ctx, a, u); err != nil {
		return 0, err
	}
	ids, err := s.Identities.All(ctx, userID)
	if err != nil {
		return 0, mapStore(err)
	}
	if a != nil && a != System && a.UserID == u.ID {
		// Your own last way to sign in stays: someone else can take it away (and send you an invitation).
		others := 0
		for _, id := range ids {
			if id.ProviderID != providerID {
				others++
			}
		}
		if pk, _ := s.UsablePasskeys(ctx, u.ID, ""); u.PasswordHash == "" && pk == 0 && others == 0 {
			return 0, &conflictErr{Invalid("provider", "is your only way to sign in; add a passkey first, or ask another administrator")}
		}
	}
	n := 0
	for _, id := range ids {
		if id.ProviderID != providerID {
			continue
		}
		if err := s.Identities.Delete(Durable(ctx), id.ID); err != nil {
			return n, mapStore(err)
		}
		n++
	}
	if n == 0 {
		return 0, nil
	}
	name := providerID
	if p, err := s.Providers.Get(ctx, providerID); err == nil {
		name = p.Name
	}
	s.Audit(ctx, a, u.OrgID, "user.provider.disconnect", u.Username, map[string]string{"provider": name})
	return n, nil
}

// UserPasskeys returns the user's passkeys, oldest first, for whoever may manage their connections.
func (s *Service) UserPasskeys(ctx context.Context, a *Actor, userID string) ([]*model.Passkey, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	if err := s.manageConnections(ctx, a, u); err != nil {
		return nil, err
	}
	list, err := s.Passkeys.All(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	slices.SortFunc(list, func(x, y *model.Passkey) int { return x.Created.Compare(y.Created) })
	return list, nil
}

// RemovePasskey deletes one of the user's passkeys (a lost or replaced device, a suspected copy) and ends the
// sessions that signed in with it, with their refresh grants (applications are told by back-channel logout). It
// returns how many sessions ended. Your own last way to sign in stays, as for DisconnectProvider.
func (s *Service) RemovePasskey(ctx context.Context, a *Actor, userID, passkeyID string) (int, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return 0, mapStore(err)
	}
	if err := s.manageConnections(ctx, a, u); err != nil {
		return 0, err
	}
	p, err := s.Passkeys.Get(ctx, passkeyID)
	if err != nil || p.UserID != u.ID {
		return 0, ErrNotFound
	}
	if a != nil && a != System && a.UserID == u.ID && p.Usable() && u.PasswordHash == "" {
		others, _ := s.UsablePasskeys(ctx, u.ID, p.ID)
		if ids, _ := s.Identities.Count(ctx, u.ID); others == 0 && ids == 0 {
			return 0, &conflictErr{Invalid("passkey", "is your only way to sign in; set a password first, or ask another administrator")}
		}
	}
	if err := s.Passkeys.Delete(Durable(ctx), p.ID); err != nil {
		return 0, mapStore(err)
	}
	ended := s.EndPasskeySessions(ctx, u.ID, p.ID)
	s.Audit(ctx, a, u.OrgID, "user.passkey.remove", u.Username, map[string]string{"name": p.Name,
		"sessions_ended": strconv.Itoa(ended)})
	return ended, nil
}
