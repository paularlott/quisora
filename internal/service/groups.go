package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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
	users, err := s.membersToJudge(ctx, a, members)
	if err != nil {
		return nil, err
	}
	for _, uid := range members {
		if err := s.checkMembership(a, g, uid, users[uid], true); err != nil {
			return nil, err
		}
	}
	var entry *model.GroupChange
	if len(members) > 0 {
		g.Seq = 1
		entry = &model.GroupChange{Seq: 1, At: time.Now().UTC(), Add: members}
		g.Pending = []model.GroupChange{*entry}
	}
	err = s.Groups.Create(ctx, g)
	s.auditOutcome(ctx, a, err, append([]change{{orgID, "group.create", g.DisplayName, tagDetail(g, in), nil}}, memberChanges(g, entry)...)...)
	if err != nil {
		return nil, s.groupConflict(ctx, err, g)
	}
	if entry != nil {
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

// DeleteGroup deletes a group: one compare-and-swap on the group's record as read (a deletion racing another change
// of the group is ErrStale, and may be retried from the group's current state). Every reader of memberships reads the
// group first, so its memberships count for nothing from that write, materialized or pending; the orphan sweep
// removes their records (and the tenant access given to the group) later.
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
	return mapStore(s.audited(ctx, a, g.OrgID, "group.delete", g.DisplayName, nil, func() error { return s.Groups.DeleteIf(ctx, id, g.Version) }))
}

// GroupMemberCount returns how many of group g's users a may see (no permission check: the caller has read g): its
// committed members that are users (memberIDs), less the super admins among them for those who may not see super
// admins.
func (s *Service) GroupMemberCount(ctx context.Context, a *Actor, g *model.Group) (int, error) {
	ids, err := s.visibleMembers(ctx, a, g)
	return len(ids), err
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
	return s.visibleMembers(ctx, a, g)
}

// visibleMembers is memberIDs less the super admins a may not see.
func (s *Service) visibleMembers(ctx context.Context, a *Actor, g *model.Group) ([]string, error) {
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

// memberIDs returns the ids of g's committed members that are users of its organization, in id order: committedIDs,
// and only those whose user exists (liveUsers): a membership stands on its user as on its group, so a deleted user
// is no member, whatever the clean-up of their memberships has done.
func (s *Service) memberIDs(ctx context.Context, g *model.Group) ([]string, error) {
	ids, err := s.committedIDs(ctx, g)
	if err != nil {
		return nil, err
	}
	// Load-bearing: liveUsers is the read side of "a membership stands on its user".
	return s.liveUsers(ctx, g.OrgID, ids)
}

// committedIDs returns the user ids of g's committed memberships, in id order, without reading a user: the
// materialized memberships (one indexed read, ids only: the key-value stores answer from the group_id index without
// reading a membership record) with g's pending changes applied over them, so a committed change is seen whether or
// not it is materialized yet (load-bearing: CommittedMembers is the read side of the group commit log).
func (s *Service) committedIDs(ctx context.Context, g *model.Group) ([]string, error) {
	ids, _, err := s.Members.IDs(ctx, store.ListQuery{Scope: g.OrgID, Filters: []store.Filter{{Field: "group_id", Value: g.ID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	for i, id := range ids {
		ids[i] = strings.TrimPrefix(id, g.ID+":") // model.MemberID
	}
	return CommittedMembers(g, ids), nil
}

// GroupMembershipIDs returns the user ids of g's committed memberships that a may see, without reading a user (so
// one of a user deleted meanwhile may be among them): what a change of the group's members is worked out against,
// at the cost of an index read whatever the size of the organization. For the members themselves: GroupMembers.
func (s *Service) GroupMembershipIDs(ctx context.Context, a *Actor, g *model.Group) ([]string, error) {
	ids, err := s.committedIDs(ctx, g)
	if err != nil {
		return nil, err
	}
	hidden, err := s.hiddenSuperAdmins(ctx, a, g.OrgID)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(ids, func(id string) bool { return hidden[id] }), nil
}

// liveUsers returns those of ids (in their order) that are users of org, reading the users liveBatch at a time
// (one read each on the backends that read many at once): the cost follows the group, not the organization.
func (s *Service) liveUsers(ctx context.Context, org string, ids []string) ([]string, error) {
	const liveBatch = 1000
	out := ids[:0]
	for start := 0; start < len(ids); start += liveBatch {
		users, err := s.Users.GetMany(ctx, ids[start:min(start+liveBatch, len(ids))])
		if err != nil {
			return nil, mapStore(err)
		}
		for _, u := range users {
			if u.OrgID == org {
				out = append(out, u.ID)
			}
		}
	}
	return out, nil
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
// A change touching more than MaxMembersPerChange memberships is refused (ErrTooLarge). A manager may only add and
// remove members, and only plain users (checkMembership); the group's fields are for administrators.
func (s *Service) ChangeGroup(ctx context.Context, a *Actor, g *model.Group, in GroupInput, add, remove []string) (*model.Group, error) {
	if !s.canManageUsers(a, g.OrgID) {
		return nil, ErrForbidden
	}
	next := *g
	next.Tags = slices.Clone(g.Tags)
	if err := applyGroup(&next, in); err != nil {
		return nil, err
	}
	tagsChanged := !slices.Equal(model.NormTags(next.Tags), model.NormTags(g.Tags))
	fieldsChanged := next.DisplayName != g.DisplayName || next.ExternalID != g.ExternalID || tagsChanged
	if fieldsChanged && !s.canAdminOrg(a, g.OrgID) {
		return nil, ErrForbidden // a manager adds and removes members, and changes nothing else
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
	if tagsChanged {
		// A group's tags reach every member's tokens: a provisioning client changes them only on a group whose
		// members it could manage one by one.
		if err := s.clientMayAffectMembers(ctx, a, g); err != nil {
			return nil, err
		}
	}
	users, err := s.membersToJudge(ctx, a, slices.Concat(add, remove))
	if err != nil {
		return nil, err
	}
	entry := model.GroupChange{Seq: g.Seq + 1, At: time.Now().UTC()}
	for _, c := range []struct {
		ids    []string
		member bool
		into   *[]string
	}{{add, true, &entry.Add}, {remove, false, &entry.Remove}} {
		for _, uid := range c.ids {
			if err := s.checkMembership(a, g, uid, users[uid], c.member); err != nil {
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
	var events []change
	if fieldsChanged {
		events = append(events, change{g.OrgID, "group.update", next.DisplayName, addChanges(tagDetail(&next, in), snapshot(g), &next), nil})
	}
	if membersChanged {
		events = append(events, memberChanges(&next, &entry)...)
	}
	err = s.Groups.Update(ctx, &next)
	s.auditOutcome(ctx, a, err, events...)
	if err != nil {
		return nil, s.groupConflict(ctx, err, &next)
	}
	// Committed. Nothing below can fail the change; a client gone away does not stop it being finished.
	return s.finishGroupChange(context.WithoutCancel(ctx), &next), nil
}

// memberChanges are the audit events of a change of members (none for a nil change).
func memberChanges(g *model.Group, c *model.GroupChange) []change {
	if c == nil {
		return nil
	}
	var out []change
	for _, uid := range c.Add {
		out = append(out, change{g.OrgID, "group.member.add", g.DisplayName, map[string]string{"user": uid}, nil})
	}
	for _, uid := range c.Remove {
		out = append(out, change{g.OrgID, "group.member.remove", g.DisplayName, map[string]string{"user": uid}, nil})
	}
	return out
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
		if err == nil {
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

// membersToJudge reads the users (by id) whose memberships a change by a touches, as a's reach is judged on them
// (checkMembership, clientMayAffectMembers): a user who no longer exists is left out, and one who cannot be read
// refuses the change — a rank that could not be read is never taken as plain.
func (s *Service) membersToJudge(ctx context.Context, a *Actor, ids []string) (map[string]*model.User, error) {
	users := make(map[string]*model.User, len(ids))
	for _, id := range ids {
		u, err := s.Users.Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, mapStore(err)
		}
		users[id] = u
	}
	return users, nil
}

// checkMembership refuses a change to the membership of g of the user userID — u as membersToJudge read them, nil
// for one who no longer exists — that a may not make.
func (s *Service) checkMembership(a *Actor, g *model.Group, userID string, u *model.User, member bool) error {
	if u != nil && u.OrgID == g.OrgID && s.Visibility(a, u) == Hidden {
		return ErrNotFound // a super admin, to anyone but a super admin
	}
	// Group membership carries access and tags: a provisioning client or a manager changes it only for users they may
	// manage (a client never an administrator, a manager plain users only), like their other attributes. (A
	// membership of a user who no longer exists can go.)
	if (a.ClientID != "" || !s.canAdminOrg(a, g.OrgID)) && u != nil && !s.canManageUser(a, u) {
		return ErrForbidden
	}
	if member && (u == nil || u.OrgID != g.OrgID) {
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
	users, err := s.membersToJudge(ctx, a, ids)
	if err != nil {
		return err
	}
	for _, u := range users {
		if !s.canManageUser(a, u) {
			return ErrForbidden
		}
	}
	return nil
}

// UserGroups returns the groups a user belongs to (no permission check: used to build tokens, SCIM and admin
// views), each group as it is at a moment when the user is a member of it: a result never pairs a membership with a
// group from another moment (a user removed from a group that was given a tag in the same change must not get the
// tag, nor one re-added after a change that took a tag away keep it). Each group is matched with the user's
// membership by the group's change numbers (memberAt); the user's memberships and the groups with pending changes
// are read from this node, and fresh reads settle what they cannot.
func (s *Service) UserGroups(ctx context.Context, u *model.User) ([]*model.Group, error) {
	ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	mine := make(map[string]*model.Member, len(ms))
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		mine[m.GroupID] = m
		ids = append(ids, m.GroupID)
	}
	pending, _, err := s.Groups.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "pending", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	for _, g := range pending {
		if member, decided := g.PendingMember(u.ID); decided && member && mine[g.ID] == nil {
			ids = append(ids, g.ID)
		}
	}
	slices.Sort(ids)
	gs, err := s.Groups.GetMany(ctx, ids)
	if err != nil {
		return nil, mapStore(err)
	}
	return s.membersAt(ctx, u.ID, gs, mine)
}

// membersAt returns the groups of gs the user is a member of, each as it is at a moment it says so, starting from
// copies of the groups and of the user's memberships (mine, by group id). A group's changes are numbered (Group.Seq);
// a membership record carries the number of the change that last wrote it, and a change is materialized (its
// membership records written and confirmed) before it leaves the group's pending log. So, for each group: its
// pending log decides the user's membership in the group as read; a membership written by the group's latest change
// matches it; a membership read through the owners after the group, written by a change no later than the group's latest,
// is the membership as of that group (a later change of the user's membership would have written a later number);
// and one written by a later change than the group's means the group read is older, and the group is read again from
// the owner. The reads a round needs are made together: one fresh read of the memberships to read again, one of the
// groups.
func (s *Service) membersAt(ctx context.Context, userID string, gs []*model.Group, mine map[string]*model.Member) ([]*model.Group, error) {
	type pair struct {
		g     *model.Group
		m     *model.Member
		fresh bool // m was read through the owners after g
	}
	open := make([]*pair, 0, len(gs))
	for _, g := range gs {
		open = append(open, &pair{g: g, m: mine[g.ID]})
	}
	out := []*model.Group{}
	for range 8 {
		var readM, readG []*pair
		next := open[:0]
		for _, p := range open {
			if member, decided := p.g.PendingMember(userID); decided {
				if member {
					out = append(out, p.g)
				}
				continue
			}
			key := model.MemberID(p.g.ID, userID)
			if c, ok := s.members.confirmed(key); ok && c.seq == p.g.Seq {
				// decided by a fresh read against this very change of the group before: still so
				if c.active {
					out = append(out, p.g)
				}
				continue
			}
			var seq uint64
			if p.m != nil {
				seq = p.m.Seq
			}
			switch {
			case seq == p.g.Seq && p.m != nil, seq < p.g.Seq && p.fresh, seq == 0 && p.g.Seq == 0:
				active := p.m != nil && p.m.Active()
				if active {
					out = append(out, p.g)
				}
				if p.fresh {
					s.members.confirm(key, p.g.Seq, active)
				}
				continue
			case seq < p.g.Seq: // the group has moved past this copy: read the membership again, after the group
				readM = append(readM, p)
			default: // the membership is newer than the group read: read the group again
				readG = append(readG, p)
			}
			next = append(next, p)
		}
		open = next
		if len(open) == 0 {
			slices.SortFunc(out, func(a, b *model.Group) int { return strings.Compare(a.ID, b.ID) })
			return out, nil
		}
		ids := make([]string, len(readM))
		for i, p := range readM {
			ids[i] = model.MemberID(p.g.ID, userID)
		}
		recs, err := s.getMany(ctx, model.KindMember, ids)
		if err != nil {
			return nil, err
		}
		for _, p := range readM {
			p.m, p.fresh = nil, true
			if r, ok := recs[model.MemberID(p.g.ID, userID)]; ok {
				m := &model.Member{}
				if err := store.Decode(r, m); err != nil {
					return nil, err
				}
				p.m = m
			}
		}
		ids = make([]string, len(readG))
		for i, p := range readG {
			ids[i] = p.g.ID
		}
		if recs, err = s.getMany(ctx, model.KindGroup, ids); err != nil {
			return nil, err
		}
		kept := open[:0]
		for _, p := range open {
			if slices.Contains(readG, p) {
				r, ok := recs[p.g.ID]
				if !ok {
					continue // deleted since
				}
				g := &model.Group{}
				if err := store.Decode(r, g); err != nil {
					return nil, err
				}
				p.g, p.fresh = g, false
			}
			kept = append(kept, p)
		}
		open = kept
	}
	return nil, fmt.Errorf("%w: the user's groups keep changing", ErrUnavailable)
}

// confirmedMembers remembers what fresh reads of memberships decided (membersAt), against the group change they were
// decided for (Group.Seq). A group's changes are numbered, and any later change of a user's membership in it is a
// later number, so while the group is at that change the answer stands: without it, every group change that did not
// touch a user (a rename, another member) would cost each later token of theirs a fresh read for good. An entry is
// used only while its group is at its number; a change makes it obsolete, nothing has to remove it.
type confirmedMembers struct {
	mu sync.Mutex
	m  map[string]memberConfirmed // by membership id (model.MemberID)
}

type memberConfirmed struct {
	seq    uint64
	active bool
}

// confirmedMembersMax bounds the entries kept (past it they all go: later tokens read again).
const confirmedMembersMax = 200_000

func (c *confirmedMembers) confirmed(id string) (memberConfirmed, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[id]
	return v, ok
}

func (c *confirmedMembers) confirm(id string, seq uint64, active bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= confirmedMembersMax {
		c.m = map[string]memberConfirmed{}
	}
	c.m[id] = memberConfirmed{seq: seq, active: active}
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
