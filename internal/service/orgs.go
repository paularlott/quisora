package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// ---------------------------------------------------------------------------------------------------------------
// Permission predicates

// canAdminOrg: org settings, clients, providers, groups, roles up to admin.
func (s *Service) canAdminOrg(a *Actor, orgID string) bool {
	return a.IsSuper() || (a.Role == model.RoleAdmin && a.OrgID == orgID)
}

// canManageUsers: create/edit users in the org (managers only for plain users; see canManageUser).
func (s *Service) canManageUsers(a *Actor, orgID string) bool {
	return a.IsSuper() || (a.Role.Privileged() && a.OrgID == orgID)
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
		return a.IsSuper() && org.Primary()
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

// PrimaryOrg returns the primary organization (model.PrimaryOrgID): ErrNotFound before "quisora bootstrap" made it (or
// before the store holds it here).
func (s *Service) PrimaryOrg(ctx context.Context) (*model.Org, error) {
	o, err := s.Orgs.Get(ctx, model.PrimaryOrgID)
	return o, mapStore(err)
}

// GetOrg returns an org the actor may see (its own, or any for super admins). a == nil skips the check (internal).
func (s *Service) GetOrg(ctx context.Context, a *Actor, id string) (*model.Org, error) {
	if a != nil && !a.IsSuper() && a.OrgID != id {
		return nil, ErrNotFound
	}
	o, err := s.Orgs.Get(ctx, id)
	return o, mapStore(err)
}

// OrgByName looks up an organization by its URL name.
func (s *Service) OrgByName(ctx context.Context, name string) (*model.Org, error) {
	o, err := s.Orgs.GetByUnique(ctx, model.OrgNameKey(name))
	return o, mapStore(err)
}

// orgTTL bounds how long a change made on another node (which this one may not hear of: a shared database) can take to
// count here; a change this node hears of counts at once (InvalidateOrgs).
const orgTTL = 5 * time.Second

// Org returns organization id as read within orgTTL. Every request under /o/<org>, every token issued and every check
// of a sign-out stamp reads one, and a store read may wait for the writes in flight (BadgerDB's read timestamp):
// uncached, they would queue behind every sign-in. A read that fails is not kept: the next one asks the store again.
// The organization returned is shared: it must not be changed.
func (s *Service) Org(ctx context.Context, id string) (*model.Org, error) {
	return s.cachedOrg(ctx, id, func() (*model.Org, error) { return s.Orgs.Get(ctx, id) })
}

// OrgByRef looks up the organization a URL names (public: /o/<org>/...): by id when ref is one (model.IsID), by name
// otherwise, as Org does.
func (s *Service) OrgByRef(ctx context.Context, ref string) (*model.Org, error) {
	if model.IsID(ref) {
		return s.Org(ctx, ref)
	}
	return s.cachedOrg(ctx, ref, func() (*model.Org, error) { return s.Orgs.GetByUnique(ctx, model.OrgNameKey(ref)) })
}

// cachedOrg returns the organization ref names from the cache, or read and kept. It is kept under ref only when ref is
// the organization's id or its name exactly as stored, so the cache is bounded by the number of organizations however a
// client spells a name (one is matched in any case and Unicode form: every spelling would be an entry of its own);
// another spelling is read from the store each time.
func (s *Service) cachedOrg(ctx context.Context, ref string, read func() (*model.Org, error)) (*model.Org, error) {
	if o, ok := s.orgCache.Get(ref); ok {
		return o, nil
	}
	tok := s.orgCache.Token(ref)
	o, err := read()
	if err != nil {
		return nil, mapStore(err)
	}
	if ref == o.ID || ref == o.Name {
		s.orgCache.PutIf(ref, o, tok)
	}
	return o, nil
}

// InvalidateOrgs forgets every organization read (Org, OrgByRef): call it when one changes, here or on another node. All
// of them go, as a name may have moved from one to another.
func (s *Service) InvalidateOrgs() { s.orgCache.Clear() }

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
	if err := s.audited(ctx, a, o.ID, "org.create", o.Name, nil, func() error { return s.Orgs.Create(ctx, o) }); err != nil {
		return nil, orgConflict(err)
	}
	if _, err := s.DefaultTenant(ctx, o.ID); err != nil {
		return nil, err
	}
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
	err = s.audited(ctx, a, o.ID, "org.update", o.Name, addChanges(nil, was, o), func() error { return s.Orgs.Update(ctx, o) })
	s.InvalidateOrgs() // the change counts at once here, as it did when this node wrote it (also a write that may have landed)
	if err != nil {
		return nil, orgConflict(err)
	}
	return o, nil
}

// DeleteOrg deletes a non-primary organization. Without cascade the org must have no users; with cascade it may, and
// they go with it (with its groups, applications, tenants and providers: they stop counting at once, and the orphan
// sweep removes them).
func (s *Service) DeleteOrg(ctx context.Context, a *Actor, id string, cascade bool) error {
	if !a.IsSuper() {
		return ErrForbidden
	}
	o, err := s.Orgs.Get(ctx, id)
	if err != nil {
		return mapStore(err)
	}
	if o.Primary() {
		return ErrPrimaryOrg
	}
	n, err := s.Users.Count(ctx, id) // gated by the organization's partition: a node trailing it refuses
	if err != nil {
		return mapStore(err)
	}
	if n > 0 && !cascade {
		return ErrNotEmpty
	}
	// The organization record is the one thing deleted: its users, groups, applications, tenants and providers stand
	// on it, so none counts any more from this write (service.UserUsable, and an application of a deleted organization
	// is unknown), and the orphan sweep removes their records (sweep.go). No back-channel logout is sent: a user signs
	// in only to applications of their own organization, and those are deleted with it (their tokens stop working at
	// once). So the deletion is one write, whatever the organization's size.
	err = s.audited(ctx, a, id, "org.delete", o.Name, map[string]string{"users": itoa(n)}, func() error { return s.Orgs.Delete(ctx, id) })
	s.InvalidateOrgs() // its users stop counting at once here (also after a write that may have landed)
	return mapStore(err)
}

// validOrgSettings checks an organization's settings: session lifetimes are not negative and not longer than the
// server's (session.ttl and session.idle are the most an organization may set; 0 keeps the server's).
func (s *Service) validOrgSettings(st model.OrgSettings, old *model.OrgSettings) error {
	if st.SessionTTL < 0 || st.SessionIdle < 0 {
		return Invalid("settings", "lifetimes cannot be negative")
	}
	if st.EmailCodes && !s.Cfg.Mail.Enabled() && (old == nil || !old.EmailCodes) {
		return Invalid("email_codes", "needs the server to send email (mail.smtp_host)")
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
