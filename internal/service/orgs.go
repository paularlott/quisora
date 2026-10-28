package service

import (
	"context"
	"errors"
	"fmt"
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

// PrimaryOrgID returns the primary organization's id (model.Org.Primary): ErrNotFound before "quisora bootstrap" made
// it (or before this node can read it: a gossip node still copying its data set), or the store's error. Never a
// guess: whatever needs the primary organization fails until it is known. The store is the one place it is kept, in
// every mode (standalone, shared database, gossip, restored from a backup); once read it is remembered, since a data
// set's primary organization never changes (it cannot be deleted, and a second one clashes on model.PrimaryOrgKey).
func (s *Service) PrimaryOrgID(ctx context.Context) (string, error) {
	if id := s.primaryID.Load(); id != nil {
		return *id, nil
	}
	o, err := s.Orgs.GetByUnique(ctx, model.PrimaryOrgKey)
	if err != nil {
		return "", mapStore(err)
	}
	s.primaryID.Store(&o.ID)
	return o.ID, nil
}

// PrimaryOrg returns the primary organization as stored now (PrimaryOrgID).
func (s *Service) PrimaryOrg(ctx context.Context) (*model.Org, error) {
	id, err := s.PrimaryOrgID(ctx)
	if err != nil {
		return nil, err
	}
	o, err := s.Orgs.Get(ctx, id)
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
// sweep removes them). Either way it first closes the organization to new users (closeOrg), so no user is created in
// it, and reported made, once it is about to go.
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
	n, err := s.closeOrg(ctx, id, cascade)
	if err != nil {
		return err
	}
	return s.deleteOrgRecord(ctx, a, o, map[string]string{"users": itoa(n)})
}

// deleteOrgRecord makes the last write of org's deletion, once its guard is committed (see orgDeleting): the
// organization record is the one thing deleted. Its users, groups, applications, tenants and providers stand on it, so
// none counts any more from this write (service.UserUsable, and an application of a deleted organization is unknown),
// and the orphan sweep removes their records (sweep.go). No back-channel logout is sent: a user signs in only to
// applications of their own organization, and those are deleted with it (their tokens stop working at once). So the
// deletion is one write, whatever the organization's size.
func (s *Service) deleteOrgRecord(ctx context.Context, a *Actor, org *model.Org, detail map[string]string) error {
	err := s.audited(ctx, a, org.ID, "org.delete", org.Name, detail, func() error { return s.Orgs.Delete(ctx, org.ID) })
	s.InvalidateOrgs() // its users stop counting at once here (also after a write that may have landed)
	return mapStore(err)
}

// OrgDeletionGrace is how long housekeeping leaves a deletion of an organization that has decided to its own caller
// before it finishes it (FinishOrgDeletions).
const OrgDeletionGrace = orgDeletingFor

// FinishOrgDeletions finishes the deletions of organizations that decided (their guard committed, see orgDeleting) at
// least grace ago and whose last write, the organization record's deletion, did not land (a store outage): such an
// organization refuses new users, and its deletion was decided, so it is made, as the caller asked. It returns how
// many it finished. Only the housekeeping leader runs it, every minute, so an organization is left in that state for
// a minute or two, not until someone deletes it again.
func (s *Service) FinishOrgDeletions(ctx context.Context, grace time.Duration) (int, error) {
	// (the guards stay committed until the sweep removes them, model.TombstoneRetention and a day after their
	// deletion: those of organizations deleted in the last week or so are read, and few are)
	gs, _, err := s.Locks.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "org_deleted", Value: true}}})
	if err != nil {
		return 0, mapStore(err)
	}
	n := 0
	for _, g := range gs {
		if time.Since(g.Updated) < grace {
			continue
		}
		o, err := s.Orgs.Get(ctx, g.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue // finished
		}
		if err != nil {
			return n, mapStore(err)
		}
		if err := s.deleteOrgRecord(ctx, System, o, map[string]string{"finished": "a deletion that had decided"}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// An organization's deletion guard keeps the creation of its users and its deletion apart. The organization record is
// in the global partition and its users in the organization's own, so no one transaction can make a user and check
// that the organization is staying; without the guard a deletion could count no users, a user be created, and the
// organization be deleted, both reporting success (the orphan sweep then removing the user). The guard is a lease
// (model.Lock) whose id is the organization's id, so it is in the organization's partition, and:
//
//   - every creation of a user asserts it open, at the version it found, in the transaction that creates the user
//     (store.Op.Assert: read, not written, so creations never conflict with each other), and is refused while a
//     deletion holds it (errOrgDeleting); it writes the guard only when there is none yet, or to open it again once a
//     deletion's lease has run out (openOrgGuard), and asserts what it wrote;
//   - a deletion takes it (Holder orgDeleting, a compare-and-swap) before it counts the users, then commits (Holder
//     model.OrgDeleted, a compare-and-swap on the version it took) before it deletes the organization record.
//
// The store orders every write of the guard and every creation's transaction (all in the organization's partition),
// and a creation's assertion holds only if no write of the guard comes between the version it read and its commit. So
// a creation ordered before the deletion took the guard is in its count (read from a copy that holds the guard, so
// every write before it); one ordered after it asserted a version the taking replaced, and is refused, or read the
// taken guard and is refused, or found its lease run out and opened it again, a write that makes the deletion's commit
// fail (try again). None commits once the deletion has committed: the committed guard is never asserted. Neither step
// depends on clocks for this: the leases only end what a deletion that died left. One that died holding the guard
// leaves new users refused for orgDeletingFor. One that died after it committed, with the organization record still
// there, has decided: housekeeping finishes it (FinishOrgDeletions), as does the deletion made again, and its guard
// stays committed for model.TombstoneRetention, so a creation that read the organization before it went is refused.
// While a guard is open (no deletion holds it) it is kept, whatever its age: the sweep removes it only once its
// organization is gone (sweep.go), so creations do not have to write it again.
const (
	orgDeleting    = "org.deleting"
	orgDeletingFor = time.Minute
)

// errOrgDeleting refuses a user's creation while the organization's deletion holds its guard: the deletion may yet be
// refused (its organization not empty), so the creation is to be tried again.
var errOrgDeleting = fmt.Errorf("%w: the organization is being deleted", ErrStale)

// orgOpen reports whether guard g lets a user be created now: no deletion holds it, or the lease of one that did has
// run out.
func orgOpen(g *model.Lock, now time.Time) bool { return g.Holder == "" || !now.Before(g.Until) }

// openOrgGuard returns organization orgID's deletion guard open, for a creation of a user to assert (see orgDeleting):
// as it is when no deletion holds it, and written open when there is none (the organization's first user) or a
// deletion's lease on it has run out. errOrgDeleting while a deletion holds it.
func (s *Service) openOrgGuard(ctx context.Context, orgID string) (*model.Lock, error) {
	for attempt := 0; ; attempt++ {
		g, err := s.Locks.Get(ctx, orgID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			g = &model.Lock{Meta: model.Meta{ID: orgID}} // none yet: created (version 0)
		case err != nil:
			return nil, err
		case g.Holder == "":
			return g, nil
		case !orgOpen(g, time.Now()):
			return nil, errOrgDeleting
		}
		g.Holder, g.Until = "", time.Time{}
		err = s.Locks.Update(ctx, g)
		if (errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound)) && attempt < 7 {
			continue // written meanwhile (another creation made it, a deletion took it): read again
		}
		return g, err
	}
}

// closeOrg takes organization orgID's deletion guard for its deletion (see orgDeleting) and returns how many users the
// organization has; without cascade, one that has some is not closed (ErrNotEmpty, the guard given back). A guard a
// deletion committed and did not finish is taken as it is: no user has been created since. Such a deletion with users
// was a cascade, and a deletion without cascade is still refused (ErrNotEmpty): it leaves that decision as it is (the
// cascade made again, or housekeeping, finishes it).
func (s *Service) closeOrg(ctx context.Context, orgID string, cascade bool) (int, error) {
	g, committed, err := s.takeOrgGuard(ctx, orgID)
	if err != nil {
		return 0, mapStore(err)
	}
	n, err := s.Users.Count(ctx, orgID) // gated by the organization's partition: a node trailing it refuses
	switch {
	case err != nil:
		return 0, mapStore(err)
	case n > 0 && !cascade:
		if !committed {
			g.Holder, g.Until = "", time.Time{}
			_ = s.Locks.Update(ctx, g) // open now, not when the lease runs out
		}
		return 0, ErrNotEmpty
	case committed:
		return n, nil
	}
	g.Holder, g.Until = model.OrgDeleted, time.Now().Add(model.TombstoneRetention)
	return n, mapStore(s.Locks.Update(ctx, g)) // stale: a creation found the lease run out and opened it again
}

// takeOrgGuard takes organization orgID's deletion guard for a deletion (Holder orgDeleting), or finds it committed by
// one that did not finish (committed: left as it is). A guard written meanwhile (a creation made it, or opened it once
// a lease ran out) is read and taken again: the creations before the taking are in the count that follows.
func (s *Service) takeOrgGuard(ctx context.Context, orgID string) (g *model.Lock, committed bool, err error) {
	for attempt := 0; ; attempt++ {
		g, err = s.Locks.Get(ctx, orgID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			g = &model.Lock{Meta: model.Meta{ID: orgID}} // none yet: created (version 0)
		case err != nil:
			return nil, false, err
		case g.Holder == model.OrgDeleted && !orgOpen(g, time.Now()):
			return g, true, nil
		}
		g.Holder, g.Until = orgDeleting, time.Now().Add(orgDeletingFor)
		err = s.Locks.Update(ctx, g)
		if (errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound)) && attempt < 7 {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		// The count must see every user created before the guard was taken: a copy that holds the guard holds every
		// write of the partition before it (a cluster node may not have applied its own write yet).
		if held, err := s.Locks.Get(ctx, orgID); err != nil || held.Version != g.Version {
			return nil, false, fmt.Errorf("%w: the organization's guard is not here yet", store.ErrUnavailable)
		}
		return g, false, nil
	}
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
