package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// GroupInput is the editable part of a group.
type GroupInput struct {
	DisplayName *string   `json:"display_name"`
	ExternalID  *string   `json:"external_id"`
	Tags        *[]string `json:"tags"`
}

// Group management needs the org admin role; SCIM provisioning clients act as org admins.

func (s *Service) ListGroups(ctx context.Context, a *Actor, orgID string, q store.ListQuery) ([]*model.Group, int, error) {
	if !s.canManageUsers(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope = orgID
	l, n, err := s.Groups.List(ctx, q)
	return l, n, mapStore(err)
}

func (s *Service) GetGroup(ctx context.Context, a *Actor, id string) (*model.Group, error) {
	g, err := s.Groups.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if !s.canManageUsers(a, g.OrgID) {
		return nil, ErrNotFound
	}
	return g, nil
}

func applyGroup(g *model.Group, in GroupInput) error {
	if in.DisplayName != nil {
		v := strings.TrimSpace(*in.DisplayName)
		if v == "" || len(v) > 200 {
			return Invalid("display_name", "required, at most 200 characters")
		}
		g.DisplayName = v
	}
	if in.ExternalID != nil {
		g.ExternalID = strings.TrimSpace(*in.ExternalID)
	}
	return applyTags(&g.Tags, in.Tags)
}

// groupConflict turns a unique clash into a field error naming the clashing field.
func (s *Service) groupConflict(ctx context.Context, err error, g *model.Group) error {
	if !errors.Is(err, store.ErrConflict) {
		return mapStore(err)
	}
	if g.ExternalID != "" {
		if o, e := s.Groups.GetByUnique(ctx, model.GroupExternalIDKey(g.OrgID, g.ExternalID)); e == nil && o.ID != g.ID {
			return &conflictErr{Invalid("external_id", "is already used by another group")}
		}
	}
	return &conflictErr{Invalid("display_name", "a group with this name already exists")}
}

func (s *Service) CreateGroup(ctx context.Context, a *Actor, orgID string, in GroupInput) (*model.Group, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, ErrForbidden
	}
	if in.DisplayName == nil {
		return nil, Invalid("display_name", "required")
	}
	g := &model.Group{OrgID: orgID}
	if err := applyGroup(g, in); err != nil {
		return nil, err
	}
	if err := s.Groups.Create(ctx, g); err != nil {
		return nil, s.groupConflict(ctx, err, g)
	}
	s.Audit(ctx, a, orgID, "group.create", g.DisplayName, tagDetail(g, in))
	return g, nil
}

func (s *Service) UpdateGroup(ctx context.Context, a *Actor, id string, in GroupInput) (*model.Group, error) {
	g, err := s.Groups.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if !s.canAdminOrg(a, g.OrgID) {
		return nil, ErrForbidden
	}
	if in.Tags != nil && !slices.Equal(model.NormTags(*in.Tags), model.NormTags(g.Tags)) {
		// A group's tags reach every member's tokens: a provisioning client changes them only on a group whose
		// members it could manage one by one.
		if err := s.clientMayAffectMembers(ctx, a, g); err != nil {
			return nil, err
		}
	}
	was := snapshot(g)
	if err := applyGroup(g, in); err != nil {
		return nil, err
	}
	if err := s.Groups.Update(ctx, g); err != nil {
		return nil, s.groupConflict(ctx, err, g)
	}
	s.Audit(ctx, a, g.OrgID, "group.update", g.DisplayName, addChanges(tagDetail(g, in), was, g))
	return g, nil
}

func (s *Service) DeleteGroup(ctx context.Context, a *Actor, id string) error {
	g, err := s.Groups.Get(ctx, id)
	if err != nil {
		return mapStore(err)
	}
	if !s.canAdminOrg(a, g.OrgID) {
		return ErrForbidden
	}
	// The group's lock (see ChangeGroup): no change of the group runs while its members are removed, so none leaves
	// a member under a deleted group, or re-adds one to it undoing a failed change.
	lk, err := s.lockGroup(ctx, id)
	if err != nil {
		return err
	}
	defer lk.release(ctx)
	if err := s.clientMayAffectMembers(ctx, a, g); err != nil {
		return err // deleting the group removes every member from it
	}
	ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: g.OrgID, Filters: []store.Filter{{Field: "group_id", Value: id}}})
	if err != nil {
		return err
	}
	for _, m := range ms {
		_ = s.Members.Delete(ctx, m.ID)
	}
	s.deleteAccessWhere(ctx, g.OrgID, "subject_id", id)
	if err := s.Groups.Delete(ctx, id); err != nil {
		return mapStore(err)
	}
	s.Audit(ctx, a, g.OrgID, "group.delete", g.DisplayName, nil)
	return nil
}

// GroupMemberCount returns how many of group g's users a may see (no permission check: the caller has read g). One
// indexed count, less the super admins among them for those who may not see super admins.
func (s *Service) GroupMemberCount(ctx context.Context, a *Actor, g *model.Group) (int, error) {
	_, n, err := s.Members.List(ctx, store.ListQuery{Scope: g.OrgID, Limit: 1, Filters: []store.Filter{{Field: "group_id", Value: g.ID}}})
	if err != nil || seesSuperAdmins(a) {
		return n, mapStore(err)
	}
	hidden, err := s.hiddenSuperAdmins(ctx, a, g.OrgID)
	if err != nil || len(hidden) == 0 {
		return n, err
	}
	for id := range hidden {
		if _, err := s.Members.Get(ctx, model.MemberID(g.ID, id)); err == nil {
			n--
		}
	}
	return n, nil
}

// hiddenSuperAdmins returns the ids of the super admins of org that a may not see (only the primary organization has
// any, and few).
func (s *Service) hiddenSuperAdmins(ctx context.Context, a *Actor, orgID string) (map[string]bool, error) {
	if seesSuperAdmins(a) {
		return nil, nil
	}
	l, _, err := s.Users.List(ctx, store.ListQuery{Scope: orgID, Filters: []store.Filter{{Field: "super_admin", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	out := make(map[string]bool, len(l))
	for _, u := range l {
		out[u.ID] = true
	}
	return out, nil
}

// GroupMembers returns the user ids in a group.
func (s *Service) GroupMembers(ctx context.Context, a *Actor, groupID string) ([]string, error) {
	g, err := s.GetGroup(ctx, a, groupID)
	if err != nil {
		return nil, err
	}
	ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: g.OrgID, Filters: []store.Filter{{Field: "group_id", Value: groupID}}})
	if err != nil {
		return nil, err
	}
	hidden, err := s.hiddenSuperAdmins(ctx, a, g.OrgID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		if !hidden[m.UserID] {
			ids = append(ids, m.UserID)
		}
	}
	return ids, nil
}

// SetMembership adds (member=true) or removes a user from a group. Idempotent.
func (s *Service) SetMembership(ctx context.Context, a *Actor, groupID, userID string, member bool) error {
	var add, remove []string
	if member {
		add = []string{userID}
	} else {
		remove = []string{userID}
	}
	for range 5 {
		g, err := s.Groups.Get(ctx, groupID)
		if err != nil {
			return mapStore(err)
		}
		if _, err = s.ChangeGroup(ctx, a, g, GroupInput{}, add, remove); !errors.Is(err, ErrStale) {
			return err
		}
	}
	return ErrStale
}

// ChangeGroup changes group g (as read: a group changed since then is ErrStale) and its members as one change. It
// is checked in full before anything is written, and a write that fails part-way undoes the writes before it, so a
// refused or failed change leaves the group as it was (a SCIM PATCH is atomic, RFC 7644 §3.5.2).
//
// The whole change — checks, the writes and any undo — holds the group's lock (lockGroup), a cluster-wide lease,
// so no two changes of one group, on any node or backend, interleave: a change sees the members the one before it
// left, and a failed change undoes only its own writes, never one that came after. A change from a stale copy is
// ErrStale: g is checked against the group under the lock, and the group's record is written first with a version
// compare-and-swap, also when only its members change (its version is a SCIM ETag and moves with its member list).
// Neither isolates the member writes, which the version of a parent record cannot do; the lock does. A holder that
// dies leaves at most a partial change behind for the lease's term (groupLockTTL); one that outlives its lease
// stops where it is, and undoes nothing.
func (s *Service) ChangeGroup(ctx context.Context, a *Actor, g *model.Group, in GroupInput, add, remove []string) (*model.Group, error) {
	if !s.canAdminOrg(a, g.OrgID) {
		return nil, ErrForbidden
	}
	next := *g
	next.Tags = slices.Clone(g.Tags)
	if err := applyGroup(&next, in); err != nil {
		return nil, err
	}
	lk, err := s.lockGroup(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	defer lk.release(ctx)
	// Under the lock, g is current or the change is stale: the checks below (the members g has) then read the state
	// the change is made from, and a change with nothing left to do is still refused when made from an old copy.
	if cur, err := s.Groups.Get(ctx, g.ID); err != nil {
		return nil, mapStore(err)
	} else if cur.Version != g.Version {
		return nil, ErrStale
	}
	tagsChanged := !slices.Equal(model.NormTags(next.Tags), model.NormTags(g.Tags))
	if tagsChanged {
		// A group's tags reach every member's tokens: a provisioning client changes them only on a group whose
		// members it could manage one by one.
		if err := s.clientMayAffectMembers(ctx, a, g); err != nil {
			return nil, err
		}
	}
	var requested, changes, done []memberChange
	for _, uid := range add {
		requested = append(requested, memberChange{uid, true})
	}
	for _, uid := range remove {
		requested = append(requested, memberChange{uid, false})
	}
	for _, c := range requested {
		if err := s.checkMembership(ctx, a, g, c.user, c.member); err != nil {
			return nil, err
		}
		member, err := s.isMember(ctx, g, c.user)
		if err != nil {
			return nil, err
		}
		if member != c.member {
			changes = append(changes, c)
		}
	}
	fieldsChanged := next.DisplayName != g.DisplayName || next.ExternalID != g.ExternalID || tagsChanged
	if !fieldsChanged && len(changes) == 0 {
		return g, nil
	}
	if err := s.Groups.Update(ctx, &next); err != nil {
		return nil, s.groupConflict(ctx, err, &next)
	}
	for _, c := range changes {
		if err := lk.extend(ctx); err != nil {
			// This node stalled past the lease: another change may hold the lock and have moved on from these
			// members, so neither going on nor undoing is safe. What was written stands, as after a holder died.
			s.Log.Error("group change interrupted: its lock lapsed; the group may be partly changed", "group", g.ID)
			return nil, fmt.Errorf("%w: this change of the group was interrupted", ErrUnavailable)
		}
		changed, err := s.putMembership(ctx, g, c.user, c.member)
		if err != nil {
			s.undoGroupChange(context.WithoutCancel(ctx), lk, g, &next, done)
			return nil, err
		}
		if changed {
			done = append(done, c)
		}
	}
	if fieldsChanged {
		s.Audit(ctx, a, g.OrgID, "group.update", next.DisplayName, addChanges(tagDetail(&next, in), snapshot(g), &next))
	}
	for _, c := range done {
		action := "group.member.remove"
		if c.member {
			action = "group.member.add"
		}
		s.Audit(ctx, a, g.OrgID, action, next.DisplayName, map[string]string{"user": c.user})
	}
	return &next, nil
}

// memberChange is one user's membership a group change sets.
type memberChange struct {
	user   string
	member bool
}

// undoGroupChange reverses a change of g (written as next) whose member writes failed part-way, under the group's
// lock lk, which the change still holds: the group's record goes back to g and the members written (done) are put
// back. Nothing else changes the group while the lock is held, so every write here undoes one of this change's own;
// should the lease lapse part-way (a stalled node), the undo stops, as a newer holder may have changed the group
// since, and what is left stands as a partial change. The restore of the group's record is still a compare-and-swap
// on the version this change wrote: it can only fail on a store failure, or a lease lapsed on another node's clock.
func (s *Service) undoGroupChange(ctx context.Context, lk *lease, g, next *model.Group, done []memberChange) {
	lapsed := func() {
		s.Log.Error("group change failed part-way and its lock lapsed before it was undone: the group may be partly changed",
			"group", g.ID)
	}
	if err := lk.extend(ctx); err != nil {
		lapsed()
		return
	}
	back := *g
	back.Version = next.Version
	if err := s.Groups.Update(ctx, &back); err != nil {
		s.Log.Error("group change failed part-way and its record could not be restored: the group may be partly changed",
			"group", g.ID, "error", err)
		return
	}
	for _, c := range done {
		if err := lk.extend(ctx); err != nil {
			lapsed()
			return
		}
		_, _ = s.putMembership(ctx, g, c.user, !c.member)
	}
}

// groupLockTTL bounds how long a group's lock is held by a holder that died (a live one extends it as it works).
const groupLockTTL = 30 * time.Second

// lockGroup takes the lock of group id (a lease, lock.go), which every change of its members and its deletion hold;
// a membership removed because its user is deleted (deleteUserData) needs none, see there.
func (s *Service) lockGroup(ctx context.Context, id string) (*lease, error) {
	return s.lock(ctx, "group/"+id, groupLockTTL, 10*time.Second, "another change of this group is in progress")
}

// isMember reports whether userID is a member of g.
func (s *Service) isMember(ctx context.Context, g *model.Group, userID string) (bool, error) {
	_, err := s.Members.Get(ctx, model.MemberID(g.ID, userID))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, mapStore(err)
}

// checkMembership refuses a change to a user's membership of g that a may not make.
func (s *Service) checkMembership(ctx context.Context, a *Actor, g *model.Group, userID string, member bool) error {
	u, uerr := s.Users.Get(ctx, userID)
	if uerr == nil && u.OrgID == g.OrgID && s.Visibility(a, u) == Hidden {
		return ErrNotFound // a super admin, to anyone but a super admin
	}
	// Group membership carries access and tags: a provisioning client changes it only for users it may manage
	// (never an administrator), like their other attributes. (A membership of a user who no longer exists can go.)
	if a.ClientID != "" && uerr == nil && !s.canManageUser(a, u) {
		return ErrForbidden
	}
	if member && (uerr != nil || u.OrgID != g.OrgID) {
		return Invalid("members", "user "+userID+" is not in this organization")
	}
	return nil
}

// putMembership writes a user's membership of g, reporting whether it changed anything.
func (s *Service) putMembership(ctx context.Context, g *model.Group, userID string, member bool) (bool, error) {
	id := model.MemberID(g.ID, userID)
	_, err := s.Members.Get(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, mapStore(err)
	}
	if exists := err == nil; exists == member {
		return false, nil
	}
	if !member {
		if err := s.Members.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrStale) {
			return false, mapStore(err)
		}
		return true, nil
	}
	// The id is deterministic: after a removal a tombstone holds it, and adding the user again is a create, which
	// starts a new generation of the record whose epoch is the removal this node has seen (a plain put over the
	// tombstone is refused: store.ErrDeleted). A removal made elsewhere that this node had not seen yet still wins:
	// the add is then refused (ErrDeleted from the quorum), reported as a concurrent change to retry.
	m := &model.Member{Meta: model.Meta{ID: id}, GroupID: g.ID, UserID: userID, OrgID: g.OrgID}
	if err := s.Members.Create(ctx, m); errors.Is(err, store.ErrDeleted) {
		return false, ErrStale
	} else if errors.Is(err, store.ErrStale) {
		return false, nil // added concurrently by someone else
	} else if err != nil {
		return false, mapStore(err)
	}
	return true, nil
}

// clientMayAffectMembers refuses a provisioning client (a client actor) a change that affects every member of g (its
// tags, or deleting it) unless the client may manage each member: administrators are out of its reach.
func (s *Service) clientMayAffectMembers(ctx context.Context, a *Actor, g *model.Group) error {
	if a.ClientID == "" {
		return nil
	}
	ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: g.OrgID, Filters: []store.Filter{{Field: "group_id", Value: g.ID}}})
	if err != nil {
		return mapStore(err)
	}
	for _, m := range ms {
		u, err := s.Users.Get(ctx, m.UserID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return mapStore(err)
		}
		if !s.canManageUser(a, u) {
			return ErrForbidden
		}
	}
	return nil
}

// UserGroups returns the groups a user belongs to, in id order (no permission check: used to build tokens, SCIM and
// admin views). The user's memberships are one indexed read (user_id is indexed), their groups one batch load; a
// membership whose group is gone (a group's deletion removes them afterwards) names no group.
func (s *Service) UserGroups(ctx context.Context, u *model.User) ([]*model.Group, error) {
	ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.GroupID)
	}
	slices.Sort(ids) // (memberships list in id order: group id then user id, so this is already their order)
	gs, err := s.Groups.GetMany(ctx, ids)
	if err != nil {
		return nil, mapStore(err)
	}
	if gs == nil {
		gs = []*model.Group{}
	}
	return gs, nil
}

// tagDetail is the audit detail recording a tag change.
func tagDetail(g *model.Group, in GroupInput) map[string]string {
	if in.Tags == nil {
		return nil
	}
	return map[string]string{"tags": strings.Join(g.Tags, " ")}
}
