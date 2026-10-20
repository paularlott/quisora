package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// orgCache remembers the primary org id (it never changes once created).
type orgCache struct {
	mu        sync.Mutex
	primaryID string
}

// ---------------------------------------------------------------------------------------------------------------
// Permission predicates

// canAdminOrg: org settings, clients, providers, groups, roles up to admin.
func (s *Service) canAdminOrg(a *Actor, orgID string) bool {
	return a.IsSuper() || (a.Role == model.RoleAdmin && a.OrgID == orgID)
}

// canManageUsers: create/edit users in the org (managers only for plain users; see canManageUser).
func (s *Service) canManageUsers(a *Actor, orgID string) bool {
	return a.IsSuper() || (a.Role.Rank() >= model.RoleManager.Rank() && a.OrgID == orgID)
}

// canManageUser reports whether a may modify target.
func (s *Service) canManageUser(a *Actor, target *model.User) bool {
	switch {
	case a.IsSuper():
		return true
	case a.OrgID != target.OrgID:
		return false
	case a.ClientID != "":
		// Provisioning clients manage plain users and managers only: never an admin's password, status or role.
		return target.Role.Rank() <= model.RoleManager.Rank()
	case a.Role == model.RoleAdmin:
		return target.Role != model.RoleSuperAdmin
	case a.Role == model.RoleManager:
		return target.Role == model.RoleUser
	}
	return false
}

// canAssignRole reports whether a may give role to a user of org.
func (s *Service) canAssignRole(ctx context.Context, a *Actor, org *model.Org, role model.Role) bool {
	if a.ClientID != "" && role.Rank() > model.RoleManager.Rank() {
		return false // provisioning clients never grant admin roles
	}
	switch role {
	case model.RoleSuperAdmin:
		return a.IsSuper() && org.Primary
	case model.RoleAdmin, model.RoleManager:
		return s.canAdminOrg(a, org.ID)
	case model.RoleUser:
		return s.canManageUsers(a, org.ID)
	}
	return false
}

// CanAdminOrg is exported for handlers deciding what to show.
func (s *Service) CanAdminOrg(a *Actor, orgID string) bool    { return s.canAdminOrg(a, orgID) }
func (s *Service) CanManageUsers(a *Actor, orgID string) bool { return s.canManageUsers(a, orgID) }

func (s *Service) CanManageUser(a *Actor, u *model.User) bool { return s.canManageUser(a, u) }

// ---------------------------------------------------------------------------------------------------------------
// Organizations

// OrgInput is the editable part of an organization.
type OrgInput struct {
	Name        *string            `json:"name"`
	DisplayName *string            `json:"display_name"`
	Settings    *model.OrgSettings `json:"settings"`
}

func validateOrgName(name string) error {
	if !model.ValidOrgName(name) {
		return Invalid("name", "use 1–63 lowercase letters, digits and hyphens, not starting or ending with a hyphen, and not a reserved word")
	}
	return nil
}

// orgConflict turns a unique clash on the organization name into a field error.
func orgConflict(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return &conflictErr{Invalid("name", "an organization with this name already exists")}
	}
	return mapStore(err)
}

// PrimaryOrg returns the primary organization.
func (s *Service) PrimaryOrg(ctx context.Context) (*model.Org, error) {
	s.primary.mu.Lock()
	id := s.primary.primaryID
	s.primary.mu.Unlock()
	if id != "" {
		// Still primary? ("quisora set-primary" may have moved it, from another process or node.)
		if o, err := s.Orgs.Get(ctx, id); err == nil && o.Primary {
			return o, nil
		}
	}
	orgs, _, err := s.Orgs.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "primary", Value: true}}, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(orgs) == 0 {
		return nil, ErrNotFound
	}
	s.primary.mu.Lock()
	s.primary.primaryID = orgs[0].ID
	s.primary.mu.Unlock()
	return orgs[0], nil
}

// SetPrimaryOrg makes orgID the primary organization ("quisora set-primary"; the system acts). Super admins belong to
// the primary organization only, so superAdminID — a user of orgID — becomes its super admin, and the old primary's
// super admins become administrators of their organization. Returns the old primary and the demoted users.
func (s *Service) SetPrimaryOrg(ctx context.Context, orgID, superAdminID string) (old *model.Org, demoted []*model.User, err error) {
	ctx = Durable(ctx)
	target, err := s.Orgs.Get(ctx, orgID)
	if err != nil {
		return nil, nil, mapStore(err)
	}
	if target.Primary {
		return nil, nil, Invalid("org", "it is the primary organization already")
	}
	admin, err := s.Users.Get(ctx, superAdminID)
	if err != nil || admin.OrgID != target.ID {
		return nil, nil, Invalid("super_admin", "must be a user of "+target.Name)
	}
	if !admin.Enabled(time.Now()) {
		return nil, nil, Invalid("super_admin", "the account is disabled")
	}
	old, err = s.PrimaryOrg(ctx)
	if err != nil {
		return nil, nil, err
	}
	supers, _, err := s.Users.List(ctx, store.ListQuery{Scope: old.ID,
		Filters: []store.Filter{{Field: "role", Value: string(model.RoleSuperAdmin)}}})
	if err != nil {
		return nil, nil, mapStore(err)
	}
	// The new primary first: there is never a moment without one (two for a moment is harmless: the cached
	// primary is re-checked, and the old one is cleared next).
	target.Primary = true
	if err := s.Orgs.Update(ctx, target); !store.Applied(err) {
		return nil, nil, mapStore(err)
	}
	admin.Role = model.RoleSuperAdmin
	if err := s.Users.Update(ctx, admin); !store.Applied(err) {
		return nil, nil, mapStore(err)
	}
	old.Primary = false
	if err := s.Orgs.Update(ctx, old); !store.Applied(err) {
		return nil, nil, mapStore(err)
	}
	for _, u := range supers {
		u.Role = model.RoleAdmin
		if err := s.Users.Update(ctx, u); !store.Applied(err) {
			return nil, nil, mapStore(err)
		}
		demoted = append(demoted, u)
	}
	s.primary.mu.Lock()
	s.primary.primaryID = target.ID
	s.primary.mu.Unlock()
	names := make([]string, len(demoted))
	for i, u := range demoted {
		names[i] = u.Username
	}
	s.Audit(ctx, System, target.ID, "org.primary", target.Name, map[string]string{"previous": old.Name,
		"super_admin": admin.Username, "demoted": strings.Join(names, " ")})
	s.Audit(ctx, System, old.ID, "org.primary", target.Name, map[string]string{"previous": old.Name,
		"super_admin": admin.Username, "demoted": strings.Join(names, " ")})
	return old, demoted, nil
}

// GetOrg returns an org the actor may see (its own, or any for super admins). a == nil skips the check (internal).
func (s *Service) GetOrg(ctx context.Context, a *Actor, id string) (*model.Org, error) {
	if a != nil && !a.IsSuper() && a.OrgID != id {
		return nil, ErrNotFound
	}
	o, err := s.Orgs.Get(ctx, id)
	return o, mapStore(err)
}

// OrgByName looks up an organization by its URL name (public: used by /login/<org>).
func (s *Service) OrgByName(ctx context.Context, name string) (*model.Org, error) {
	o, err := s.Orgs.GetByUnique(ctx, model.OrgNameKey(name))
	return o, mapStore(err)
}

// ListOrgs lists organizations visible to the actor.
func (s *Service) ListOrgs(ctx context.Context, a *Actor, q store.ListQuery) ([]*model.Org, int, error) {
	if !a.IsSuper() {
		o, err := s.Orgs.Get(ctx, a.OrgID)
		if err != nil {
			return nil, 0, mapStore(err)
		}
		return []*model.Org{o}, 1, nil
	}
	q.Scope = ""
	l, n, err := s.Orgs.List(ctx, q)
	return l, n, mapStore(err)
}

// CreateOrg creates an organization (super admins only).
func (s *Service) CreateOrg(ctx context.Context, a *Actor, in OrgInput) (*model.Org, error) {
	if !a.IsSuper() {
		return nil, ErrForbidden
	}
	if in.Name == nil {
		return nil, Invalid("name", "required")
	}
	o := &model.Org{Name: strings.TrimSpace(*in.Name), Settings: model.DefaultOrgSettings()}
	if err := validateOrgName(o.Name); err != nil {
		return nil, err
	}
	o.DisplayName = o.Name
	if in.DisplayName != nil && strings.TrimSpace(*in.DisplayName) != "" {
		o.DisplayName = strings.TrimSpace(*in.DisplayName)
	}
	if in.Settings != nil {
		if err := s.validOrgSettings(*in.Settings, nil); err != nil {
			return nil, err
		}
		o.Settings = *in.Settings
	}
	if err := s.Orgs.Create(ctx, o); err != nil {
		return nil, orgConflict(err)
	}
	if _, err := s.DefaultTenant(ctx, o.ID); err != nil {
		return nil, err
	}
	s.Audit(ctx, a, o.ID, "org.create", o.Name, nil)
	return o, nil
}

// UpdateOrg changes name, display name or settings (super admins only).
func (s *Service) UpdateOrg(ctx context.Context, a *Actor, id string, in OrgInput) (*model.Org, error) {
	if !a.IsSuper() {
		return nil, ErrForbidden
	}
	o, err := s.Orgs.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	was := snapshot(o)
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if err := validateOrgName(name); err != nil {
			return nil, err
		}
		o.Name = name
	}
	if in.DisplayName != nil {
		if strings.TrimSpace(*in.DisplayName) == "" {
			return nil, Invalid("display_name", "required")
		}
		o.DisplayName = strings.TrimSpace(*in.DisplayName)
	}
	if in.Settings != nil {
		if err := s.validOrgSettings(*in.Settings, &o.Settings); err != nil {
			return nil, err
		}
		o.Settings = *in.Settings
	}
	if err := s.Orgs.Update(ctx, o); err != nil {
		return nil, orgConflict(err)
	}
	s.Audit(ctx, a, o.ID, "org.update", o.Name, addChanges(nil, was, o))
	return o, nil
}

// DeleteOrg deletes a non-primary organization. Without cascade the org must have no users; with cascade every
// user, group, membership, client and provider of the org is deleted first.
func (s *Service) DeleteOrg(ctx context.Context, a *Actor, id string, cascade bool) error {
	if !a.IsSuper() {
		return ErrForbidden
	}
	o, err := s.Orgs.Get(ctx, id)
	if err != nil {
		return mapStore(err)
	}
	if o.Primary {
		return ErrPrimaryOrg
	}
	n, err := s.Users.Count(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 && !cascade {
		return ErrNotEmpty
	}
	ctx = Durable(ctx)
	users, err := s.Users.All(ctx, id)
	if err != nil {
		return err
	}
	for _, u := range users {
		if err := s.deleteUserData(ctx, u); err != nil {
			return err
		}
	}
	for _, k := range []model.Kind{model.KindMember, model.KindGroup, model.KindClient, model.KindTenant, model.KindProvider} {
		res, err := s.Store.List(ctx, k, store.ListQuery{Scope: id})
		if err != nil {
			return err
		}
		for _, r := range res.Records {
			if err := s.Store.Put(ctx, store.Tombstone(k, r.ID)); err != nil && !errors.Is(err, store.ErrStale) {
				return err
			}
		}
	}
	if err := s.Orgs.Delete(ctx, id); err != nil {
		return mapStore(err)
	}
	s.Audit(ctx, a, id, "org.delete", o.Name, map[string]string{"users": itoa(len(users))})
	return nil
}

// validOrgSettings checks an organization's settings: session lifetimes are not negative and not longer than the
// server's (session.ttl and session.idle are the most an organization may set; 0 keeps the server's).
func (s *Service) validOrgSettings(st model.OrgSettings, old *model.OrgSettings) error {
	if st.SessionTTL < 0 || st.SessionIdle < 0 {
		return Invalid("settings", "lifetimes cannot be negative")
	}
	// Only a lifetime being changed is held to the server's: one saved before the limit (or before the server's
	// was lowered) does not block saving other settings; sessions are capped at the server's anyway.
	if st.SessionTTL > s.Cfg.Session.TTL && (old == nil || st.SessionTTL != old.SessionTTL) {
		return Invalid("session_ttl", "at most "+itoa(s.Cfg.Session.TTL)+" seconds (the server's session.ttl)")
	}
	if s.Cfg.Session.Idle > 0 && st.SessionIdle > s.Cfg.Session.Idle && (old == nil || st.SessionIdle != old.SessionIdle) {
		return Invalid("session_idle", "at most "+itoa(s.Cfg.Session.Idle)+" seconds (the server's session.idle)")
	}
	return nil
}
