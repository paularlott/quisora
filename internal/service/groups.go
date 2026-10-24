package service

import (
	"context"
	"errors"
	"slices"
	"strings"

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
// refused or failed change leaves the group as it was (a SCIM PATCH is atomic, RFC 7644 §3.5.2). The group's record
// is written first, also when only its members change: its version (a SCIM ETag) moves with its member list, and is
// the lock on the change. A concurrent change made from the same copy fails there, before it has written a member,
// so a failed change never has anything of its own to undo over a concurrent change that succeeded.
func (s *Service) ChangeGroup(ctx context.Context, a *Actor, g *model.Group, in GroupInput, add, remove []string) (*model.Group, error) {
	if !s.canAdminOrg(a, g.OrgID) {
		return nil, ErrForbidden
	}
	next := *g
	next.Tags = slices.Clone(g.Tags)
	if err := applyGroup(&next, in); err != nil {
		return nil, err
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
		changed, err := s.putMembership(ctx, g, c.user, c.member)
		if err != nil {
			s.undoGroupChange(context.WithoutCancel(ctx), g, &next, done)
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

// undoGroupChange reverses a change of g (written as next) whose member writes failed part-way: the group's record
// goes back to g, and only then (no change of the group came after this one) are the members written (done) put
// back. A change made since was based on this one's members, and stands with them.
func (s *Service) undoGroupChange(ctx context.Context, g, next *model.Group, done []memberChange) {
	back := *g
	back.Version = next.Version
	if err := s.Groups.Update(ctx, &back); err != nil {
		s.Log.Warn("group change failed part-way and was changed again since: its member changes stand", "group",
			g.ID, "error", err)
		return
	}
	for _, c := range done {
		_, _ = s.putMembership(ctx, g, c.user, !c.member)
	}
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

// UserGroups returns the groups a user belongs to (no permission check: used to build tokens, SCIM and admin
// views). A membership's id is deterministic (MemberID), so this pages through the organization's groups and probes
// one key per group. Groups are far fewer than memberships, and a plain paged scan never loads a whole scope, where
// filtering memberships by user loads every membership of the organization on the key-value backends.
func (s *Service) UserGroups(ctx context.Context, u *model.User) ([]*model.Group, error) {
	out := []*model.Group{}
	q := store.ListQuery{Scope: u.OrgID, Limit: 500}
	for {
		page, _, err := s.Groups.List(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, g := range page {
			if _, err := s.Members.Get(ctx, model.MemberID(g.ID, u.ID)); err == nil {
				out = append(out, g)
			} else if !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
		if len(page) < q.Limit {
			return out, nil
		}
		q.After = page[len(page)-1].ID
	}
}

// tagDetail is the audit detail recording a tag change.
func tagDetail(g *model.Group, in GroupInput) map[string]string {
	if in.Tags == nil {
		return nil
	}
	return map[string]string{"tags": strings.Join(g.Tags, " ")}
}
