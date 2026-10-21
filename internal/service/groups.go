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
	g, err := s.Groups.Get(ctx, groupID)
	if err != nil {
		return mapStore(err)
	}
	if !s.canAdminOrg(a, g.OrgID) {
		return ErrForbidden
	}
	id := model.MemberID(groupID, userID)
	u, uerr := s.Users.Get(ctx, userID)
	if uerr == nil && u.OrgID == g.OrgID && s.Visibility(a, u) == Hidden {
		return ErrNotFound // a super admin, to anyone but a super admin
	}
	// Group membership carries access and tags: a provisioning client changes it only for users it may manage
	// (never an administrator), like their other attributes. (A membership of a user who no longer exists can go.)
	if a.ClientID != "" && uerr == nil && !s.canManageUser(a, u) {
		return ErrForbidden
	}
	if !member {
		if err := s.Members.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrStale) {
			return mapStore(err)
		}
		s.Audit(ctx, a, g.OrgID, "group.member.remove", g.DisplayName, map[string]string{"user": userID})
		return nil
	}
	if uerr != nil || u.OrgID != g.OrgID {
		return Invalid("members", "user "+userID+" is not in this organization")
	}
	if _, err := s.Members.Get(ctx, id); err == nil {
		return nil
	}
	// The id is deterministic: after a removal a tombstone holds it, and adding the user again is a create, which
	// starts a new generation of the record whose epoch is the removal this node has seen (a plain put over the
	// tombstone is refused: store.ErrDeleted). A removal made elsewhere that this node had not seen yet still wins:
	// the add is then refused (ErrDeleted from the quorum), reported as a concurrent change to retry.
	m := &model.Member{Meta: model.Meta{ID: id}, GroupID: groupID, UserID: userID, OrgID: g.OrgID}
	if err := s.Members.Create(ctx, m); errors.Is(err, store.ErrDeleted) {
		return ErrStale
	} else if err != nil && !errors.Is(err, store.ErrStale) {
		return mapStore(err)
	}
	s.Audit(ctx, a, g.OrgID, "group.member.add", g.DisplayName, map[string]string{"user": userID})
	return nil
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

// maxProbeGroups bounds how many groups UserGroups probes one by one; larger orgs fall back to scanning memberships.
const maxProbeGroups = 64

// UserGroups returns the groups a user belongs to (no permission check: used to build tokens, SCIM and admin
// views). A membership's id is deterministic (MemberID), so for the usual handful of groups per organization this
// probes one key per group instead of scanning every membership of the organization (hundreds to thousands of
// records) on each token, SCIM user or user-detail request.
func (s *Service) UserGroups(ctx context.Context, u *model.User) ([]*model.Group, error) {
	all, _, err := s.Groups.List(ctx, store.ListQuery{Scope: u.OrgID, Limit: maxProbeGroups + 1})
	if err != nil {
		return nil, err
	}
	if len(all) <= maxProbeGroups {
		out := make([]*model.Group, 0, 2)
		for _, g := range all {
			if _, err := s.Members.Get(ctx, model.MemberID(g.ID, u.ID)); err == nil {
				out = append(out, g)
			} else if !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
		return out, nil
	}
	ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	if err != nil {
		return nil, err
	}
	out := make([]*model.Group, 0, len(ms))
	for _, m := range ms {
		if g, err := s.Groups.Get(ctx, m.GroupID); err == nil {
			out = append(out, g)
		}
	}
	return out, nil
}

// tagDetail is the audit detail recording a tag change.
func tagDetail(g *model.Group, in GroupInput) map[string]string {
	if in.Tags == nil {
		return nil
	}
	return map[string]string{"tags": strings.Join(g.Tags, " ")}
}
