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

// MaxMembersPerChange bounds the memberships one change of a group may add and remove, so the change entry kept in
// the group's record (model.Group.Pending) stays small. A larger change is refused with ErrTooLarge; make it in parts.
const MaxMembersPerChange = 1000

// GroupChangeGrace is how long a committed member change may stay pending before housekeeping finishes it for its
// writer (a live writer finishes its own within milliseconds).
const GroupChangeGrace = 30 * time.Second

// ErrTooLarge: the change adds and removes more memberships than MaxMembersPerChange; make it in parts.
var ErrTooLarge = fmt.Errorf("a change may add or remove at most %d members at once", MaxMembersPerChange)

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

// CreateGroup creates a group without members (CreateGroupWithMembers).
func (s *Service) CreateGroup(ctx context.Context, a *Actor, orgID string, in GroupInput) (*model.Group, error) {
	return s.CreateGroupWithMembers(ctx, a, orgID, in, nil)
}

// CreateGroupWithMembers creates a group with its first members as one change: the group's record is created
// carrying the change entry that adds them (see ChangeGroup), so the group either exists with every member or does
// not exist at all; a refused create leaves nothing behind and needs no undoing (a SCIM POST with members).
func (s *Service) CreateGroupWithMembers(ctx context.Context, a *Actor, orgID string, in GroupInput, members []string) (*model.Group, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, ErrForbidden
	}
	if in.DisplayName == nil {
		return nil, Invalid("display_name", "required")
	}
	g := &model.Group{Meta: model.Meta{ID: model.NewID()}, OrgID: orgID}
	if err := applyGroup(g, in); err != nil {
		return nil, err
	}
	members = dedupe(members)
	if len(members) > MaxMembersPerChange {
		return nil, ErrTooLarge
	}
	for _, uid := range members {
		if err := s.checkMembership(ctx, a, g, uid, true); err != nil {
			return nil, err
		}
	}
	var entry *model.GroupChange
	if len(members) > 0 {
		g.Seq = 1
		entry = &model.GroupChange{Op: model.NewID(), Seq: 1, At: time.Now().UTC(), Add: members}
		g.Pending = []model.GroupChange{*entry}
	}
	if err := s.Groups.Create(ctx, g); err != nil {
		return nil, s.groupConflict(ctx, err, g)
	}
	s.Audit(ctx, a, orgID, "group.create", g.DisplayName, tagDetail(g, in))
	if entry != nil {
		s.auditMembers(ctx, a, g, entry)
		g = s.finishGroupChange(ctx, g)
	}
	return g, nil
}

// UpdateGroup changes a group's fields (not its members): a ChangeGroup from the group's current record, retried
// should it change meanwhile, so it serialises with changes of the members on the group's record like any change.
func (s *Service) UpdateGroup(ctx context.Context, a *Actor, id string, in GroupInput) (*model.Group, error) {
	for range 5 {
		g, err := s.Groups.Get(ctx, id)
		if err != nil {
			return nil, mapStore(err)
		}
		if !s.canAdminOrg(a, g.OrgID) {
			return nil, ErrForbidden
		}
		if g, err = s.ChangeGroup(ctx, a, g, in, nil, nil); !errors.Is(err, ErrStale) {
			return g, err
		}
	}
	return nil, ErrStale
}

// DeleteGroup deletes a group and its memberships. The removal of every member is committed first, as a change
// entry (Clear) on the group's record, so from that moment no reader counts anyone as a member, whatever is still
// materialized; the group's record then goes with a compare-and-swap on the version that commit gave it, once its
// memberships are materialized as removed, and their records are tombstoned after it (nothing is left to fence). A
// deleter that dies between the two leaves an empty group (the deletion did not happen), never memberships of a
// group that is gone; a deletion racing another change of the group is ErrStale and may be retried from the
// group's current state.
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
		return mapStore(err)
	}
	remaining, err := s.applyGroupChanges(ctx, g)
	if err != nil && len(remaining) >= maxPendingChanges {
		return s.unfinished(g, err)
	}
	next := *g
	next.Tags = slices.Clone(g.Tags)
	next.Seq = g.Seq + 1
	next.Pending = append(remaining, model.GroupChange{Op: model.NewID(), Seq: next.Seq, At: time.Now().UTC(), Clear: true})
	if err := s.Groups.Update(ctx, &next); err != nil {
		return mapStore(err)
	}
	// Committed: the group has no members for any reader. Materialize that, then remove the group itself.
	ctx = context.WithoutCancel(ctx)
	if _, err := s.applyGroupChanges(ctx, &next); err != nil {
		s.Log.Warn("group deletion: its memberships could not all be marked removed yet; housekeeping finishes them",
			"group", g.ID, "error", err)
		return err // the group stays, empty; the deletion is retried
	}
	if err := s.Groups.DeleteIf(ctx, id, next.Version); err != nil {
		return mapStore(err)
	}
	// The group is gone: its membership records (marked removed above) have nothing left to fence and go too.
	for _, m := range ms {
		_ = s.Members.Delete(ctx, m.ID)
	}
	if err := s.deleteAccessWhere(ctx, g.OrgID, "subject_id", id); err != nil {
		// Cleanup of entries nothing reads once the group is gone: the deletion stands, and the leftovers are
		// logged (a member's access decision looks up their current groups, never a deleted one's entry).
		s.Log.WithError(err).Warn("group deleted; some of its access entries were not removed", "group", id)
	}
	s.Audit(ctx, a, g.OrgID, "group.delete", g.DisplayName, nil)
	return nil
}

// GroupMemberCount returns how many of group g's users a may see (no permission check: the caller has read g). One
// indexed count, less the super admins among them for those who may not see super admins; a group with pending
// changes is counted from its member list (rare: a writer died mid-change).
func (s *Service) GroupMemberCount(ctx context.Context, a *Actor, g *model.Group) (int, error) {
	if len(g.Pending) > 0 {
		ids, err := s.memberIDs(ctx, g)
		if err != nil {
			return 0, err
		}
		hidden, err := s.hiddenSuperAdmins(ctx, a, g.OrgID)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, id := range ids {
			if !hidden[id] {
				n++
			}
		}
		return n, nil
	}
	_, n, err := s.Members.List(ctx, store.ListQuery{Scope: g.OrgID, Limit: 1, Filters: []store.Filter{{Field: "group_id", Value: g.ID}}})
	if err != nil || seesSuperAdmins(a) {
		return n, mapStore(err)
	}
	hidden, err := s.hiddenSuperAdmins(ctx, a, g.OrgID)
	if err != nil || len(hidden) == 0 {
		return n, err
	}
	for id := range hidden {
		if m, err := s.Members.Get(ctx, model.MemberID(g.ID, id)); err == nil && m.Active() {
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

// GroupMembers returns the user ids in a group: its committed members (memberIDs), less those a may not see.
func (s *Service) GroupMembers(ctx context.Context, a *Actor, groupID string) ([]string, error) {
	g, err := s.GetGroup(ctx, a, groupID)
	if err != nil {
		return nil, err
	}
	ids, err := s.memberIDs(ctx, g)
	if err != nil {
		return nil, err
	}
	hidden, err := s.hiddenSuperAdmins(ctx, a, g.OrgID)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(ids, func(id string) bool { return hidden[id] }), nil
}

// memberIDs returns the ids of g's committed members, in id order: the materialized memberships (one indexed read)
// with g's pending changes applied over them, so a committed change is seen whether or not it is materialized yet.
func (s *Service) memberIDs(ctx context.Context, g *model.Group) ([]string, error) {
	// Ids only: the key-value stores answer from the group_id index without reading a membership record.
	ids, _, err := s.Members.IDs(ctx, store.ListQuery{Scope: g.OrgID, Filters: []store.Filter{{Field: "group_id", Value: g.ID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	for i, id := range ids {
		ids[i] = strings.TrimPrefix(id, g.ID+":") // model.MemberID
	}
	return CommittedMembers(g, ids), nil
}

// CommittedMembers applies g's pending changes to the materialized member ids, returning the committed members in id
// order.
func CommittedMembers(g *model.Group, ids []string) []string {
	if len(g.Pending) == 0 {
		slices.Sort(ids)
		return ids
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	for _, c := range g.Pending {
		if c.Clear {
			clear(set)
		}
		for _, id := range c.Remove {
			delete(set, id)
		}
		for _, id := range c.Add {
			set[id] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
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
// is checked in full before anything is written and committed by one write, so a refused or failed change leaves
// the group as it was (a SCIM PATCH is atomic, RFC 7644 §3.5.2) and a committed one is never undone.
//
// The group's record is the commit point. The change of the fields and a change entry (model.GroupChange: the
// members added and removed, with the next sequence number) are written together by one compare-and-swap on the
// version of g, which fails (ErrStale) if anything — a rename, another member change, a deletion, on any node or
// backend — has changed the group since it was read: the change then did not happen. Once the write succeeds the
// change is committed: every reader of memberships sees it (they apply the record's pending entries over the
// membership records), and the group's version, its SCIM ETag, has moved. The membership records are a materialized
// view, written next (applyGroupChanges): each carries the sequence of the change that wrote it and a write with an
// older sequence is refused, so a writer that stalled, however long, never overwrites what a later change wrote
// (materializeMember). A writer that dies after the commit leaves its entry pending, visible all the same; the next
// change of the group, or housekeeping (FinishGroupChanges), finishes it. The pending entry is removed from the
// record by a second compare-and-swap once materialized, which moves the version once more (the version returned).
// A change touching more than MaxMembersPerChange memberships is refused (ErrTooLarge).
func (s *Service) ChangeGroup(ctx context.Context, a *Actor, g *model.Group, in GroupInput, add, remove []string) (*model.Group, error) {
	if !s.canAdminOrg(a, g.OrgID) {
		return nil, ErrForbidden
	}
	next := *g
	next.Tags = slices.Clone(g.Tags)
	if err := applyGroup(&next, in); err != nil {
		return nil, err
	}
	add, remove = dedupe(add), dedupe(remove)
	if len(add)+len(remove) > MaxMembersPerChange {
		return nil, ErrTooLarge
	}
	// A change another writer left pending is finished first: its entries are committed and the writes idempotent,
	// so finishing them changes nothing a reader could see; it lets the commit below drop them from the record. One
	// that cannot be materialized now (a store failure) stays pending, carried forward by the commit, and keeps
	// being seen through the record meanwhile; only a record full of such entries refuses further changes.
	remaining, err := s.applyGroupChanges(ctx, g)
	if err != nil && len(remaining) >= maxPendingChanges {
		return nil, s.unfinished(g, err)
	}
	tagsChanged := !slices.Equal(model.NormTags(next.Tags), model.NormTags(g.Tags))
	if tagsChanged {
		// A group's tags reach every member's tokens: a provisioning client changes them only on a group whose
		// members it could manage one by one.
		if err := s.clientMayAffectMembers(ctx, a, g); err != nil {
			return nil, err
		}
	}
	entry := model.GroupChange{Op: model.NewID(), Seq: g.Seq + 1, At: time.Now().UTC()}
	for _, c := range []struct {
		ids    []string
		member bool
		into   *[]string
	}{{add, true, &entry.Add}, {remove, false, &entry.Remove}} {
		for _, uid := range c.ids {
			if err := s.checkMembership(ctx, a, g, uid, c.member); err != nil {
				return nil, err
			}
			member, err := s.isMember(ctx, g, uid)
			if err != nil {
				return nil, err
			}
			if member != c.member {
				*c.into = append(*c.into, uid)
			}
		}
	}
	fieldsChanged := next.DisplayName != g.DisplayName || next.ExternalID != g.ExternalID || tagsChanged
	membersChanged := len(entry.Add)+len(entry.Remove) > 0
	if !fieldsChanged && !membersChanged && len(remaining) == len(g.Pending) {
		// Nothing to do, but a change made from an old copy is still refused.
		if cur, err := s.Groups.Get(ctx, g.ID); err != nil {
			return nil, mapStore(err)
		} else if cur.Version != g.Version {
			return nil, ErrStale
		}
		return g, nil
	}
	next.Pending = remaining // the entries materialized above are dropped
	if membersChanged {
		next.Seq = entry.Seq
		next.Pending = append(slices.Clip(remaining), entry)
	}
	if err := s.Groups.Update(ctx, &next); err != nil {
		return nil, s.groupConflict(ctx, err, &next)
	}
	// Committed. Nothing below can fail the change; a client gone away does not stop it being finished.
	if fieldsChanged {
		s.Audit(ctx, a, g.OrgID, "group.update", next.DisplayName, addChanges(tagDetail(&next, in), snapshot(g), &next))
	}
	if membersChanged {
		s.auditMembers(ctx, a, &next, &entry)
	}
	return s.finishGroupChange(context.WithoutCancel(ctx), &next), nil
}

// auditMembers records a committed change of members.
func (s *Service) auditMembers(ctx context.Context, a *Actor, g *model.Group, c *model.GroupChange) {
	for _, uid := range c.Add {
		s.Audit(ctx, a, g.OrgID, "group.member.add", g.DisplayName, map[string]string{"user": uid})
	}
	for _, uid := range c.Remove {
		s.Audit(ctx, a, g.OrgID, "group.member.remove", g.DisplayName, map[string]string{"user": uid})
	}
}

// finishGroupChange materializes the pending entries of g (just committed) and removes them from its record,
// returning the group as it is then. A failure leaves the entries pending, for the next writer or housekeeping: the
// change is committed and visible either way, so the caller is not told of one.
func (s *Service) finishGroupChange(ctx context.Context, g *model.Group) *model.Group {
	if len(g.Pending) == 0 {
		return g
	}
	remaining, err := s.applyGroupChanges(ctx, g)
	if err != nil {
		s.Log.Warn("group change committed but not yet materialized; housekeeping finishes it", "group", g.ID, "error", err)
	}
	if len(remaining) == len(g.Pending) {
		return g
	}
	done := *g
	done.Pending = remaining
	switch err := s.Groups.Update(ctx, &done); {
	case err == nil:
		return &done
	case errors.Is(err, store.ErrStale), errors.Is(err, store.ErrNotFound):
		return g // another change (or the deletion) moved the group on: it took the entries with it
	default:
		s.Log.Warn("group change materialized but still listed as pending; housekeeping clears it", "group", g.ID, "error", err)
		return g
	}
}

// maxPendingChanges bounds the entries a group's record carries: a writer dies with at most one left, and only a
// store that keeps refusing membership writes while accepting the group's lets more build up. Beyond it, changes of
// the group are refused (ErrUnavailable) until housekeeping or a writer materializes them.
const maxPendingChanges = 8

// unfinished is the refusal of a change of g whose record is full of entries that could not be materialized.
func (s *Service) unfinished(g *model.Group, err error) error {
	s.Log.Error("group has unfinished member changes that cannot be materialized; refusing further changes", "group", g.ID, "error", err)
	return fmt.Errorf("%w: earlier changes of this group are still being applied", ErrUnavailable)
}

// applyGroupChanges materializes g's pending entries, oldest first, into membership records (materializeMember):
// idempotent, so any number of writers may do it at once or again. It returns the entries not applied: on a
// failure, the failed entry and those after it (they are applied in order), with the error.
func (s *Service) applyGroupChanges(ctx context.Context, g *model.Group) ([]model.GroupChange, error) {
	for i, c := range g.Pending {
		if err := s.applyGroupChange(ctx, g, c); err != nil {
			return g.Pending[i:], err
		}
	}
	return nil, nil
}

func (s *Service) applyGroupChange(ctx context.Context, g *model.Group, c model.GroupChange) error {
	if c.Clear {
		ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: g.OrgID, Filters: []store.Filter{{Field: "group_id", Value: g.ID}}})
		if err != nil {
			return mapStore(err)
		}
		for _, m := range ms {
			if err := s.materializeMember(ctx, g, m.UserID, false, c.Seq); err != nil {
				return err
			}
		}
	}
	for _, uid := range c.Remove {
		if err := s.materializeMember(ctx, g, uid, false, c.Seq); err != nil {
			return err
		}
	}
	for _, uid := range c.Add {
		if err := s.materializeMember(ctx, g, uid, true, c.Seq); err != nil {
			return err
		}
	}
	return nil
}

// materializeMember writes the membership of userID in g as change seq left it: a member, or removed. The record
// keeps the sequence that last wrote it; one at or past seq is left alone (a later change has had its say, or this
// one was applied already), and an older one is replaced by a compare-and-swap on its version, so of any number of
// writers applying any entries in any order, the newest change wins on every record, and a stalled writer can at
// most repeat a write that was made. A removed membership stays as a record (model.Member.Removed) to keep the fence.
func (s *Service) materializeMember(ctx context.Context, g *model.Group, userID string, member bool, seq uint64) error {
	id := model.MemberID(g.ID, userID)
	var err error
	for range 8 {
		var m *model.Member
		m, err = s.Members.Get(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if !member {
				return nil // nothing to remove: no record, or one removed so long ago that it expired
			}
			m = &model.Member{Meta: model.Meta{ID: id}, GroupID: g.ID, UserID: userID, OrgID: g.OrgID, Seq: seq}
			err = s.Members.Create(ctx, m)
		case err != nil:
			return mapStore(err)
		case m.Seq >= seq:
			return nil
		default:
			m.Seq = seq
			if member {
				m.Removed = time.Time{}
			} else if m.Active() {
				m.Removed = time.Now().UTC()
			}
			err = s.Members.Update(ctx, m)
		}
		if store.Applied(err) {
			return nil
		}
		if !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound) {
			return mapStore(err)
		}
		// Written concurrently (another writer of this or a later change, or a deletion): read it again.
	}
	return fmt.Errorf("%w: membership %s keeps changing under this writer: %v", ErrUnavailable, id, err)
}

// FinishGroupChanges materializes the member changes committed on groups whose writer did not finish them (an entry
// pending for longer than grace), everywhere: housekeeping runs it. It returns how many groups it finished.
func (s *Service) FinishGroupChanges(ctx context.Context, grace time.Duration) (int, error) {
	n := 0
	for {
		gs, _, err := s.Groups.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "pending", Value: true}}, Limit: 200})
		if err != nil {
			return n, mapStore(err)
		}
		done := 0
		for _, g := range gs {
			if len(g.Pending) == 0 || time.Since(g.Pending[0].At) < grace {
				continue
			}
			if fin := s.finishGroupChange(ctx, g); len(fin.Pending) < len(g.Pending) {
				done++
			}
		}
		n += done
		if len(gs) < 200 || done == 0 {
			return n, nil
		}
	}
}

// isMember reports whether userID is a committed member of g.
func (s *Service) isMember(ctx context.Context, g *model.Group, userID string) (bool, error) {
	if member, decided := g.PendingMember(userID); decided {
		return member, nil
	}
	m, err := s.Members.Get(ctx, model.MemberID(g.ID, userID))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, mapStore(err)
	}
	return m.Active(), nil
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

// clientMayAffectMembers refuses a provisioning client (a client actor) a change that affects every member of g (its
// tags, or deleting it) unless the client may manage each member: administrators are out of its reach.
func (s *Service) clientMayAffectMembers(ctx context.Context, a *Actor, g *model.Group) error {
	if a.ClientID == "" {
		return nil
	}
	ids, err := s.memberIDs(ctx, g)
	if err != nil {
		return err
	}
	for _, id := range ids {
		u, err := s.Users.Get(ctx, id)
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
// membership whose group is gone names no group. The groups' pending changes (committed, not yet materialized) are
// applied: a committed removal is never granted, a committed addition is seen before its membership record exists
// (the organization's groups with pending changes are one indexed read, normally empty).
func (s *Service) UserGroups(ctx context.Context, u *model.User) ([]*model.Group, error) {
	ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.GroupID)
	}
	pending, _, err := s.Groups.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "pending", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	for _, g := range pending {
		if member, decided := g.PendingMember(u.ID); decided && member && !slices.Contains(ids, g.ID) {
			ids = append(ids, g.ID)
		}
	}
	slices.Sort(ids) // (memberships list in id order: group id then user id, so this is already their order)
	gs, err := s.Groups.GetMany(ctx, ids)
	if err != nil {
		return nil, mapStore(err)
	}
	gs = slices.DeleteFunc(gs, func(g *model.Group) bool {
		member, decided := g.PendingMember(u.ID)
		return decided && !member
	})
	if gs == nil {
		gs = []*model.Group{}
	}
	return gs, nil
}

// dedupe returns ids without repeats, in their first order.
func dedupe(ids []string) []string {
	if len(ids) < 2 {
		return ids
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// tagDetail is the audit detail recording a tag change.
func tagDetail(g *model.Group, in GroupInput) map[string]string {
	if in.Tags == nil {
		return nil
	}
	return map[string]string{"tags": strings.Join(g.Tags, " ")}
}
