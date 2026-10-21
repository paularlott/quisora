package service

import (
	"context"
	"slices"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Who may see whom. Nobody needs the details of someone above them: a manager sees an administrator only as a directory
// entry (who they are, not how to reach or sign in as them), and super admins, who operate the server rather than
// belong to an organization, are invisible below them. Everyone else of the actor's organization, up to their own
// rank, is seen in full.

// Visibility is how much of a user an actor may see.
type Visibility int

const (
	// Hidden: the user does not exist for the actor (not found, never listed).
	Hidden Visibility = iota
	// Directory: id, name, role and status only (DirectoryEntry).
	Directory
	// Full: everything the management API shows.
	Full
)

// viewerRank is the rank an actor sees with: its role's, or an administrator's for a provisioning client.
func viewerRank(a *Actor) int {
	if a.ClientID != "" {
		return model.RoleAdmin.Rank()
	}
	return a.Role.Rank()
}

// seesSuperAdmins reports whether a may see super admins at all.
func seesSuperAdmins(a *Actor) bool { return a == nil || a == System || a.IsSuper() }

// Visibility returns how much of u the actor sees (nil: the system, inside the service).
func (s *Service) Visibility(a *Actor, u *model.User) Visibility {
	switch {
	case seesSuperAdmins(a) || a.UserID == u.ID:
		return Full
	case a.OrgID != u.OrgID || u.Role == model.RoleSuperAdmin:
		return Hidden
	case viewerRank(a) >= u.Role.Rank():
		return Full
	}
	return Directory
}

// DirectoryEntry is the part of u everyone in its organization may see: its id, name, role and whether it is active.
func DirectoryEntry(u *model.User) *model.User {
	return &model.User{Meta: model.Meta{ID: u.ID, Created: u.Created}, OrgID: u.OrgID, GivenName: u.GivenName,
		FamilyName: u.FamilyName, Role: u.Role, Active: u.Active}
}

// visibleQuery narrows a listing of users to those a may see at all (super admins are only listed for super admins).
func visibleQuery(a *Actor, q store.ListQuery) store.ListQuery {
	if !seesSuperAdmins(a) {
		q.Filters = append(slices.Clone(q.Filters), store.Filter{Field: "super_admin", Value: false})
	}
	return q
}

// FullViewQuery narrows a listing of users to those a sees in full: what a provisioning client (SCIM), which has no use
// for directory entries, is given.
func FullViewQuery(a *Actor, q store.ListQuery) store.ListQuery {
	q = visibleQuery(a, q)
	if !seesSuperAdmins(a) && viewerRank(a) < model.RoleAdmin.Rank() {
		q.Filters = append(slices.Clone(q.Filters), store.Filter{Field: "admin_rank", Value: false})
	}
	return q
}

// NotSeenInFull returns the ids of org's users that a does not see in full (super admins below them, administrators to
// managers): only users of administrator rank can be, and they are few.
func (s *Service) NotSeenInFull(ctx context.Context, a *Actor, orgID string) (map[string]bool, error) {
	if seesSuperAdmins(a) {
		return nil, nil
	}
	l, _, err := s.Users.List(ctx, store.ListQuery{Scope: orgID, Filters: []store.Filter{{Field: "admin_rank", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	out := map[string]bool{}
	for _, u := range l {
		if s.Visibility(a, u) != Full {
			out[u.ID] = true
		}
	}
	return out, nil
}

// present returns users as a sees them: hidden ones dropped, directory entries cut down.
func (s *Service) present(a *Actor, users []*model.User) []*model.User {
	out := users[:0:0]
	for _, u := range users {
		switch s.Visibility(a, u) {
		case Full:
			out = append(out, u)
		case Directory:
			out = append(out, DirectoryEntry(u))
		}
	}
	return out
}

// searchLeaks returns the users that a listing's search finds (with its filters) but that a sees only as directory
// entries and that match it other than by name: their email address, username or tags would be confirmed by the
// match, so they are left out of the results.
func (s *Service) searchLeaks(ctx context.Context, a *Actor, q store.ListQuery) (map[string]bool, error) {
	if q.Search == "" || seesSuperAdmins(a) || viewerRank(a) >= model.RoleAdmin.Rank() {
		return nil, nil // nobody is a directory entry to them
	}
	aq := q
	aq.Filters = append(slices.Clone(q.Filters), store.Filter{Field: "admin_rank", Value: true})
	aq.Offset, aq.Limit, aq.Sort, aq.Desc, aq.After = 0, 0, "", false, ""
	above, _, err := s.Users.List(ctx, aq)
	if err != nil {
		return nil, mapStore(err)
	}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	var leaks map[string]bool
	for _, u := range above {
		if s.Visibility(a, u) == Directory && !strings.Contains(strings.ToLower(u.FullName()), needle) {
			if leaks == nil {
				leaks = map[string]bool{}
			}
			leaks[u.ID] = true
		}
	}
	return leaks, nil
}

// denied is the error for a change a may not make to u: not found when a may not even see u (the answer for a user
// that does not exist), forbidden otherwise.
func (s *Service) denied(a *Actor, u *model.User) error {
	if s.canManageUsers(a, u.OrgID) && s.Visibility(a, u) != Hidden {
		return ErrForbidden
	}
	return ErrNotFound
}
