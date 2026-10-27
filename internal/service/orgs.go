package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
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

// primaryOrgs returns every organization marked primary, ordered by id: one, but two while SetPrimaryOrg is between
// its writes (or was interrupted there).
func (s *Service) primaryOrgs(ctx context.Context) ([]*model.Org, error) {
	orgs, _, err := s.Orgs.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "primary", Value: true}}})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(orgs, func(a, b *model.Org) int { return strings.Compare(a.ID, b.ID) })
	return orgs, nil
}

// PrimaryOrg returns the primary organization. Should two be marked primary (a "quisora set-primary" that stopped
// between its writes: running it again finishes it) every node chooses the same, the one with the lowest id, and logs
// at error level every time; the choice is not remembered while it is in doubt.
func (s *Service) PrimaryOrg(ctx context.Context) (*model.Org, error) {
	// The choice is remembered for primaryChoiceTTL at most (finding the primary reads every organization): servers
	// that remembered different primaries of two agree again within it. The organization itself is read every time.
	s.primary.mu.Lock()
	id, at := s.primary.id, s.primary.at
	s.primary.mu.Unlock()
	if id != "" && time.Since(at) < primaryChoiceTTL {
		if o, err := s.Orgs.Get(ctx, id); err == nil && o.Primary {
			return o, nil
		}
	}
	orgs, err := s.primaryOrgs(ctx)
	if err != nil {
		return nil, err
	}
	if len(orgs) == 0 {
		return nil, ErrNotFound
	}
	if len(orgs) > 1 {
		names := make([]string, len(orgs))
		for i, o := range orgs {
			names[i] = o.Name
		}
		s.Log.Error("more than one organization is marked primary (an interrupted set-primary): using "+orgs[0].Name+
			"; run quisora set-primary again for the organization that should be primary to finish it",
			"organizations", strings.Join(names, " "))
	}
	s.primary.mu.Lock()
	s.primary.id, s.primary.at = orgs[0].ID, time.Now()
	s.primary.mu.Unlock()
	return orgs[0], nil
}

// primaryChoiceTTL bounds how long PrimaryOrg remembers which organization is primary. A variable for tests.
var primaryChoiceTTL = time.Second

// primaryChoice is PrimaryOrg's remembered choice (an id and when it was made).
type primaryChoice struct {
	mu sync.Mutex
	id string
	at time.Time
}

// updateFresh changes entity e of table t and writes it with a compare-and-swap. A write refused as stale (another
// change of the record landed first, on any node) is made again on the record as its owner has it now (freshMany),
// up to 8 times. change edits the copy and reports whether it needs writing at all (false: it is as wanted
// already); an error from it ends the attempt. part is the record's partition key ("" for global data). It returns the
// copy it left, written or not.
func updateFresh[T any, PT interface {
	*T
	model.Entity
}](ctx context.Context, s *Service, t *store.Table[T, PT], part string, e PT, change func(PT) (bool, error)) (PT, error) {
	for attempt := 0; ; attempt++ {
		if write, err := change(e); err != nil || !write {
			return e, err
		}
		err := t.Update(ctx, e)
		if err == nil {
			return e, nil
		}
		if !errors.Is(err, store.ErrStale) || attempt >= 7 {
			return e, mapStore(err)
		}
		id := e.GetMeta().ID
		recs, err := s.freshMany(ctx, t.Kind, part, []string{id})
		if err != nil {
			return e, err
		}
		r, ok := recs[id]
		if !ok {
			return e, ErrNotFound
		}
		fresh := PT(new(T))
		if err := store.Decode(r, fresh); err != nil {
			return e, err
		}
		e = fresh
	}
}

// SetPrimaryOrg makes orgID the primary organization ("quisora set-primary"; the system acts). Super admins belong to
// the primary organization only, so superAdminID — a user of orgID — becomes its super admin, and every other super
// admin (the old primary's) becomes an administrator of their organization. Returns the old primary (nil when
// nothing says which it was: an interrupted change finished by a rerun) and the users demoted by this call.
//
// The change is four kinds of writes across the global partition and two organizations' partitions, and no
// transaction covers them, so it is written to be run again: it reads what is done (the organizations marked
// primary, the super admins outside orgID) and finishes the rest, in an order whose every prefix is safe: the new
// primary is marked first (there is never a moment without one; two for a moment is harmless, PrimaryOrg chooses one
// the same way everywhere), then its super admin, then the old primary's super admins are demoted, and the old primary
// is unmarked last: a change that stopped part-way leaves two organizations marked primary, which every node logs at
// error level until it is run again. A change that stopped after some of its writes took effect is audited as
// incomplete (auditPartial). The server's sign-out counters are the highest of the organizations marked primary
// (serverSignOut), and are copied to the new primary in the compare-and-swap loop that unmarks the old one, so a
// server-wide sign-out counted on the old one meanwhile is never lost.
// Each write that is refused as stale is made again on a fresh copy. When nothing is left to do it refuses: the
// organization is the primary already.
func (s *Service) SetPrimaryOrg(ctx context.Context, orgID, superAdminID string) (old *model.Org, demoted []*model.User, err error) {
	target, err := s.Orgs.Get(ctx, orgID)
	if err != nil {
		return nil, nil, mapStore(err)
	}
	admin, err := s.Users.Get(ctx, superAdminID)
	if err != nil || admin.OrgID != target.ID {
		return nil, nil, Invalid("super_admin", "must be a user of "+target.Name)
	}
	if !admin.Enabled(time.Now()) {
		return nil, nil, Invalid("super_admin", "the account is disabled")
	}
	marked, err := s.primaryOrgs(ctx)
	if err != nil {
		return nil, nil, mapStore(err)
	}
	var others []*model.Org
	for _, o := range marked {
		if o.ID != target.ID {
			others = append(others, o)
		}
	}
	// Super admins outside the new primary: the old primary's, whether or not it is still marked.
	supers, _, err := s.Users.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "super_admin", Value: true}}})
	if err != nil {
		return nil, nil, mapStore(err)
	}
	// The listing above is of every organization, which the staleness gate cannot vouch for; the marked old primaries'
	// own are listed by organization, through it, so a node trailing one of them refuses instead of missing a super admin.
	for _, o := range others {
		own, _, err := s.Users.List(ctx, store.ListQuery{Scope: o.ID, Filters: []store.Filter{{Field: "super_admin", Value: true}}})
		if err != nil {
			return nil, nil, mapStore(err)
		}
		for _, u := range own {
			if !slices.ContainsFunc(supers, func(x *model.User) bool { return x.ID == u.ID }) {
				supers = append(supers, u)
			}
		}
	}
	supers = slices.DeleteFunc(supers, func(u *model.User) bool { return u.OrgID == target.ID })
	switch {
	case len(others) > 0:
		old = others[0]
	case len(supers) > 0: // the old primary is no longer marked: its super admins say which it was
		old, _ = s.Orgs.Get(ctx, supers[0].OrgID)
	}
	if target.Primary && len(others) == 0 && len(supers) == 0 {
		return nil, nil, Invalid("org", "it is the primary organization already")
	}
	if !target.Primary && len(others) == 0 {
		return nil, nil, ErrNotFound // there is no primary to replace
	}

	// The audit event of the change: what it did when it ended, or its outcome unknown, so far as it got.
	detail := map[string]string{"super_admin": admin.Username}
	if old != nil {
		detail["previous"] = old.Name
	}
	progressed, err := s.setPrimary(ctx, target, admin, others, supers, &demoted)
	s.primary.mu.Lock()
	s.primary.id = "" // chosen afresh at the next read
	s.primary.mu.Unlock()
	s.InvalidateSignOut()
	names := make([]string, len(demoted))
	for i, u := range demoted {
		names[i] = u.Username
	}
	detail["demoted"] = strings.Join(names, " ")
	events := []change{{target.ID, "org.primary", target.Name, detail}}
	if old != nil && old.ID != target.ID {
		events = append(events, change{old.ID, "org.primary", target.Name, detail})
	}
	s.auditPartial(ctx, System, err, progressed, events...)
	if err != nil {
		return nil, nil, err
	}
	return old, demoted, nil
}

// setPrimary writes the changes of SetPrimaryOrg (see there for their order), each made again on a fresh copy when it
// is refused as stale; demoted collects the super admins that became administrators, and progressed says whether any
// write may have taken effect. The promotion and the demotions are changes of a user's role: they go through
// applyRole, as every other.
func (s *Service) setPrimary(ctx context.Context, target *model.Org, admin *model.User, others []*model.Org, supers []*model.User,
	demoted *[]*model.User) (progressed bool, err error) {
	step := func(err error) error {
		progressed = progressed || landed(err)
		return err
	}
	// The new primary first. The server's emergency sign-out counters move with the role: starting again from the
	// new primary's would bring back everything a server-wide sign-out ended.
	target, err = updateFresh(ctx, s, s.Orgs, "", target, func(t *model.Org) (bool, error) {
		write := !t.Primary
		t.Primary = true
		for _, o := range others {
			write = raiseServerSignOut(t, o) || write
		}
		return write, nil
	})
	if err = step(err); err != nil {
		return progressed, err
	}
	promoted := func(context.Context, *Actor, error) {}
	_, err = updateFresh(ctx, s, s.Users, target.ID, admin, func(u *model.User) (bool, error) {
		if !u.Enabled(time.Now()) {
			return false, Invalid("super_admin", "the account is disabled")
		}
		write := u.Role != model.RoleSuperAdmin
		promoted = s.applyRole(u, model.RoleSuperAdmin)
		return write, nil
	})
	promoted(ctx, System, err) // a promotion is finished as any other (links made by email address go)
	if err = step(err); err != nil {
		return progressed, err
	}
	for _, u := range supers {
		changed := false
		demotion := func(context.Context, *Actor, error) {}
		got, err := updateFresh(ctx, s, s.Users, u.OrgID, u, func(u *model.User) (bool, error) {
			changed = u.Role == model.RoleSuperAdmin
			if changed {
				demotion = s.applyRole(u, model.RoleAdmin)
			}
			return changed, nil
		})
		demotion(ctx, System, err)
		if err = step(err); err != nil {
			return progressed, err
		}
		if changed {
			*demoted = append(*demoted, got)
		}
	}
	// The old primary stops counting only once the new one holds its sign-out counters as they are at the unmark: a
	// server-wide sign-out counted on it after they were copied changes its version, so the unmark is refused as stale
	// and made again on the newer copy, copying again first.
	for _, o := range others {
		_, err := updateFresh(ctx, s, s.Orgs, "", o, func(o *model.Org) (bool, error) {
			if !o.Primary {
				return false, nil
			}
			t, err := updateFresh(ctx, s, s.Orgs, "", target, func(t *model.Org) (bool, error) {
				return raiseServerSignOut(t, o), nil
			})
			if step(err) != nil {
				return false, err
			}
			target = t
			o.Primary = false
			return true, nil
		})
		if err = step(err); err != nil {
			return progressed, err
		}
	}
	return progressed, nil
}

// raiseServerSignOut raises t's server sign-out counters (and last event) to o's where o's are higher, and reports
// whether it changed t.
func raiseServerSignOut(t, o *model.Org) bool {
	changed := false
	if t.ServerSignOut.Sessions < o.ServerSignOut.Sessions {
		t.ServerSignOut.Sessions, changed = o.ServerSignOut.Sessions, true
	}
	if t.ServerSignOut.APITokens < o.ServerSignOut.APITokens {
		t.ServerSignOut.APITokens, changed = o.ServerSignOut.APITokens, true
	}
	if o.LastServerSignOut != nil && (t.LastServerSignOut == nil || t.LastServerSignOut.At.Before(o.LastServerSignOut.At)) {
		t.LastServerSignOut, changed = o.LastServerSignOut, true
	}
	return changed
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
	if err := s.audited(ctx, a, o.ID, "org.update", o.Name, addChanges(nil, was, o), func() error { return s.Orgs.Update(ctx, o) }); err != nil {
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
	if o.Primary {
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
	return mapStore(s.audited(ctx, a, id, "org.delete", o.Name, map[string]string{"users": itoa(n)}, func() error { return s.Orgs.Delete(ctx, id) }))
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
