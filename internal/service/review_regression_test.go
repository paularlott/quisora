package service_test

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestDeepReviewPrivilegedLinkedEmailCannotBypassResetGuard(t *testing.T) {
	e := newEnv(t)
	org := e.org("deepreview")
	admin := e.user(org.ID, "issuer", model.RoleAdmin)
	target := e.user(org.ID, "target", model.RoleManager)
	password := "correct horse battery staple 9"
	if _, err := e.svc.UpdateUser(e.ctx, service.System, target.ID, service.UserInput{Password: &password}); err != nil {
		t.Fatal(err)
	}
	address := "attacker@controlled.example"
	if _, err := e.svc.AddLinkedEmail(e.ctx, actor(admin), target.ID, address, true); err == nil {
		t.Fatal("control: guarded email API unexpectedly allowed the change")
	}
	_, err := e.svc.UpdateUser(e.ctx, actor(admin), target.ID, service.UserInput{LinkedEmails: &[]string{address}})
	if err == nil {
		matched, lookupErr := e.svc.UsersByVerifiedEmail(e.ctx, org.ID, []string{address})
		t.Fatalf("bulk email update bypassed privileged reset guard; verified upstream matches=%d lookup error=%v", len(matched), lookupErr)
	}
}

type deepManagerClearGate struct {
	store.Store
	reportID        string
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (g *deepManagerClearGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindUser && r.ID == g.reportID && g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.resume
	}
	return g.Store.CompareAndPut(ctx, r, expect)
}

func TestDeepReviewDeleteManagerPreservesConcurrentReassignment(t *testing.T) {
	e := newEnv(t)
	org := e.org("manager-race")
	oldManager := e.user(org.ID, "oldmanager", model.RoleUser)
	newManager := e.user(org.ID, "newmanager", model.RoleUser)
	report := e.user(org.ID, "report", model.RoleUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, report.ID, service.UserInput{Work: &service.WorkInput{ManagerID: &oldManager.ID}}); err != nil {
		t.Fatal(err)
	}
	rawUsers := store.NewTable[model.User](e.svc.Store)
	gate := &deepManagerClearGate{Store: e.svc.Users.S, reportID: report.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Users.S = gate
	gate.armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- e.svc.DeleteUser(e.ctx, service.System, oldManager.ID) }()
	<-gate.entered
	fresh, err := rawUsers.Get(e.ctx, report.ID)
	if err != nil {
		close(gate.resume)
		<-done
		t.Fatal(err)
	}
	fresh.Work.ManagerID = newManager.ID
	err = rawUsers.Update(e.ctx, fresh)
	close(gate.resume)
	deletionErr := <-done
	if err != nil {
		t.Fatal(err)
	}
	if deletionErr != nil {
		t.Fatal(deletionErr)
	}
	final, err := rawUsers.Get(e.ctx, report.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Work.ManagerID != newManager.ID {
		t.Fatalf("deleting former manager erased concurrent reassignment: got manager %q", final.Work.ManagerID)
	}
}

// deepGroupGate pauses the first write of a group's record (the commit of a change; written against the lease
// design it paused the taking of the group's lock, the equivalent point: nothing is written yet).
type deepGroupGate struct {
	store.Store
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (s *deepGroupGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindGroup && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.resume
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A request that loses the commit to a concurrent successful request fails as stale and touches nothing the
// successful request set.
func TestDeepGroupRollbackPreservesConcurrentSuccess(t *testing.T) {
	e := newEnv(t)
	org := e.org("deep-group")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Original"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	gate := &deepGroupGate{Store: e.svc.Groups.S, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Groups.S = gate
	gate.armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, []string{u.ID}, nil)
		done <- err
	}()
	<-gate.entered // the first request is about to commit; nothing written yet
	fresh, err := e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil {
		close(gate.resume)
		<-done
		t.Fatal(err)
	}
	renamed := "Committed"
	_, err = e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &renamed}, []string{u.ID}, nil)
	close(gate.resume)
	firstErr := <-done
	if err != nil {
		t.Fatalf("concurrent update failed: %v", err)
	}
	if !errors.Is(firstErr, service.ErrStale) {
		t.Fatalf("first update should be stale: %v", firstErr)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || !m.Active() {
		t.Fatalf("successful concurrent change lost its requested membership to a stale request: %v", err)
	}
	if cur, _ := e.svc.Groups.Get(e.ctx, g.ID); cur.DisplayName != renamed || len(cur.Pending) != 0 {
		t.Fatalf("group: %+v", cur)
	}
}

// failRecord fails every compare-and-swap of records whose id ends in suffix.
type failRecord struct {
	store.Store
	suffix string
}

func (s failRecord) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if strings.HasSuffix(r.ID, s.suffix) {
		return errors.New("disk on fire")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A change that fails leaves the group as it was: it can only fail at its commit, the group record's
// compare-and-swap, before which nothing is written (written against the lease design, this failed a membership
// write and checked the undo; a membership write no longer fails a change, see below).
func TestGroupChangeFailingPartWayIsUndone(t *testing.T) {
	e := newEnv(t)
	org := e.org("undo-group")
	ok := e.user(org.ID, "ok", model.RoleUser)
	bad := e.user(org.ID, "bad", model.RoleUser)
	name := "Before"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Groups.S = failRecord{Store: e.svc.Groups.S, suffix: g.ID}
	renamed := "After"
	if _, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{DisplayName: &renamed}, []string{ok.ID, bad.ID}, nil); err == nil {
		t.Fatal("a change whose commit failed succeeded")
	}
	for _, u := range []*model.User{ok, bad} {
		if _, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a membership was written by a change that failed: %v", err)
		}
	}
	if cur, err := e.svc.Groups.Get(e.ctx, g.ID); err != nil || cur.DisplayName != "Before" || len(cur.Pending) != 0 {
		t.Errorf("the group's record changed: %v %+v", err, cur)
	}
}

// A change whose membership write fails after its commit is committed: every reader sees it whole from the record,
// and the membership is written later (the next change of the group, or housekeeping).
func TestGroupChangeCommittedDespiteMembershipWriteFailure(t *testing.T) {
	e := newEnv(t)
	org := e.org("commit-group")
	ok := e.user(org.ID, "ok", model.RoleUser)
	bad := e.user(org.ID, "bad", model.RoleUser)
	name := "Before"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	inner := e.svc.Members.S
	e.svc.Members.S = failRecord{Store: inner, suffix: bad.ID}
	renamed := "After"
	res, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{DisplayName: &renamed}, []string{ok.ID, bad.ID}, nil)
	if err != nil {
		t.Fatalf("a committed change reported failure: %v", err)
	}
	if res.DisplayName != renamed || len(res.Pending) != 1 {
		t.Fatalf("returned group: %+v", res)
	}
	if ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID); err != nil || !equalIDs(ids, sortedIDs(ok.ID, bad.ID)) {
		t.Fatalf("members seen: %v %v", ids, err)
	}
	if gs, err := e.svc.UserGroups(e.ctx, bad); err != nil || len(gs) != 1 {
		t.Fatalf("bad's groups: %v %v", gs, err)
	}
	if _, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, bad.ID)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bad's membership record: %v", err)
	}
	// The next change of the group finishes it.
	e.svc.Members.S = inner
	if err := e.svc.SetMembership(e.ctx, service.System, g.ID, ok.ID, true); err != nil { // a no-op change
		t.Fatal(err)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, bad.ID)); err != nil || !m.Active() {
		t.Fatalf("bad's membership not materialized by the next change: %v", err)
	}
	if cur, _ := e.svc.Groups.Get(e.ctx, g.ID); len(cur.Pending) != 0 {
		t.Fatalf("still pending: %+v", cur.Pending)
	}
}

type fresh2MemberSnapshot struct {
	store.Store
	blocked         atomic.Bool
	entered, resume chan struct{}
}

func (g *fresh2MemberSnapshot) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	r, err := g.Store.List(ctx, kind, q)
	if kind == model.KindMember && g.blocked.CompareAndSwap(false, true) {
		close(g.entered)
		<-g.resume
	}
	return r, err
}

// A group update atomically removes a user while granting the group a new tag.
// A concurrent token lookup must not combine membership from before the commit
// with tags from after the commit: the user never possessed that tag.
func TestFreshUserGroupsCannotGrantTagsAfterAtomicRemoval(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-read-snapshot")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Group"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	gate := &fresh2MemberSnapshot{Store: e.svc.Store, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Members.S = gate
	type result struct {
		gs  []*model.Group
		err error
	}
	done := make(chan result, 1)
	go func() { gs, err := e.svc.UserGroups(e.ctx, u); done <- result{gs, err} }()
	<-gate.entered
	tags := []string{"admin"}
	_, err = e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, nil, []string{u.ID})
	close(gate.resume)
	r := <-done
	if err != nil {
		t.Fatal(err)
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	for _, group := range r.gs {
		if group.ID == g.ID && slices.Contains(group.Tags, "admin") {
			t.Fatalf("removed user received newly privileged group: %+v", group)
		}
	}
}

// Cleanup belongs to the epoch it replaced; a later acceptance can commit while
// its session enumeration is slow, and must retain its own new credentials.
func TestFresh3OlderInviteCleanupPreservesLaterEpochCredentials(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "epoch-cleanup", model.RoleUser)
	first, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	gate := &reviewInviteCleanupGate{Store: e.svc.Store, id: u.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Store = gate
	t.Cleanup(func() {
		select {
		case <-gate.resume:
		default:
			close(gate.resume)
		}
	})
	done := make(chan error, 1)
	go func() {
		_, _, err := e.svc.UseSignInLink(e.ctx, tokenFrom(first), service.LinkInvite, "", service.NewCredEpoch())
		done <- err
	}()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first acceptance did not reach cleanup")
	}
	second, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	epoch := service.NewCredEpoch()
	pk := &model.Passkey{Meta: model.Meta{ID: model.NewID()}, UserID: u.ID, OrgID: u.OrgID, Epoch: epoch, Name: "second acceptance", CredentialID: []byte("fresh3-credential")}
	if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
		t.Fatal(err)
	}
	_, current, err := e.svc.UseSignInLink(e.ctx, tokenFrom(second), service.LinkInvite, "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Holds(epoch) {
		t.Fatal("second acceptance did not commit its epoch")
	}
	if _, err := e.svc.Passkeys.Get(e.ctx, pk.ID); err != nil {
		t.Fatalf("credential absent before old cleanup: %v", err)
	}
	close(gate.resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Passkeys.Get(e.ctx, pk.ID); err != nil {
		t.Fatalf("cleanup from earlier accepted invitation removed the current epoch's credential: %v", err)
	}
}

type fresh3GroupSnapshot struct {
	store.Store
	members, groups                                  atomic.Bool
	memberRead, memberResume, groupRead, groupResume chan struct{}
}

func (g *fresh3GroupSnapshot) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	r, err := g.Store.List(ctx, kind, q)
	if kind == model.KindMember && g.members.CompareAndSwap(false, true) {
		close(g.memberRead)
		<-g.memberResume
	}
	return r, err
}

func (g *fresh3GroupSnapshot) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	var r []*store.Record
	var err error
	for _, id := range ids {
		var rec *store.Record
		rec, err = g.Store.Get(ctx, kind, id)
		if err != nil {
			break
		}
		r = append(r, rec)
	}
	if kind == model.KindGroup && g.groups.CompareAndSwap(false, true) {
		close(g.groupRead)
		<-g.groupResume
	}
	return r, err
}

// The recheck must match the group version whose tags it authorizes: a newer
// active membership cannot authorize a group snapshot under which it was removed.
func TestFreshGroupRecheckCannotAuthorizeAnOlderPrivilegeSnapshot(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-recheck-snapshot")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Group"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	gate := &fresh3GroupSnapshot{Store: e.svc.Store, memberRead: make(chan struct{}), memberResume: make(chan struct{}), groupRead: make(chan struct{}), groupResume: make(chan struct{})}
	e.svc.Members.S, e.svc.Groups.S = gate, gate
	type result struct {
		gs  []*model.Group
		err error
	}
	done := make(chan result, 1)
	go func() { gs, err := e.svc.UserGroups(e.ctx, u); done <- result{gs, err} }()
	<-gate.memberRead // reader holds initial membership, seq 1
	tags := []string{"admin"}
	g, err = e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, nil, []string{u.ID})
	if err != nil {
		close(gate.memberResume)
		close(gate.groupResume)
		t.Fatal(err)
	}
	close(gate.memberResume)
	<-gate.groupRead // reader holds group seq 2: admin tag, user removed
	tags = nil
	_, err = e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, []string{u.ID}, nil)
	close(gate.groupResume) // recheck sees membership seq 3: user re-added, admin tag gone
	r := <-done
	if err != nil {
		t.Fatal(err)
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	for _, group := range r.gs {
		if group.ID == g.ID && slices.Contains(group.Tags, "admin") {
			t.Fatalf("user received a privilege they never held: %+v", group)
		}
	}
}

// Old-epoch records may remain after best-effort cleanup. They are not another
// way to sign in and must not permit removal of the last current credential.
func TestFresh4LastPasskeyGuardIgnoresPassedEpoch(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "epoch-last-passkey", model.RoleUser)
	u.CredEpoch = service.NewCredEpoch()
	if err := e.svc.Users.Update(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	makeKey := func(name string, epoch uint64) *model.Passkey {
		p := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, Epoch: epoch, UserVerified: true, CredentialID: []byte(name)}
		if err := e.svc.Passkeys.Create(e.ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	current := makeKey("current", u.CredEpoch)
	makeKey("superseded", 0)
	_, err := e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, current.ID, "")
	if err == nil {
		remaining, readErr := e.svc.Passkeys.All(e.ctx, u.ID)
		if readErr != nil {
			t.Fatal(readErr)
		}
		usable := 0
		for _, p := range remaining {
			if u.Holds(p.Epoch) && p.Usable() {
				usable++
			}
		}
		t.Fatalf("self-service removed the last usable passkey because a passed-epoch record counted as an alternative: usable credentials remaining=%d", usable)
	}
	if !errors.Is(err, service.ErrConflict) {
		t.Fatalf("expected last-credential conflict, got %v", err)
	}
}

type fresh4ReadCounter struct {
	store.Store
	calls atomic.Int64
}

func (c *fresh4ReadCounter) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	c.calls.Add(1)
	out := map[string]*store.Record{}
	for _, id := range ids {
		r, err := c.Store.Lookup(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, nil
}

// Measurement: changes to other members leave this user's membership at an older
// sequence. Every such group currently requires its own serialized quorum read.
func TestFresh4UserGroupsQuorumReadFanout(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-quorum-fanout")
	u := e.user(org.ID, "member", model.RoleUser)
	other := e.user(org.ID, "other", model.RoleUser)
	const groups = 12
	for i := range groups {
		name := fmt.Sprintf("Group %02d", i)
		g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.svc.SetMembership(e.ctx, service.System, g.ID, other.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	counter := &fresh4ReadCounter{Store: e.svc.Store}
	e.svc.Store = counter
	gs, err := e.svc.UserGroups(e.ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != groups {
		t.Fatalf("got %d groups, want %d", len(gs), groups)
	}
	t.Logf("%d unchanged memberships caused %d serial quorum read calls", groups, counter.calls.Load())
	if n := counter.calls.Load(); n > 1 { // one round: the memberships to read again, read together
		t.Fatalf("%d quorum reads for one round of reconciliation", n)
	}
}

// Deleting a user leaves its materialized membership for the orphan sweep, but
// that membership must stop appearing as a user in group counts and pagination.
func TestFresh5DeletedUserStopsCountingAsGroupMemberImmediately(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-deleted-member")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Group"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteUser(e.ctx, service.System, u.ID); err != nil {
		t.Fatal(err)
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.GroupMemberCount(e.ctx, service.System, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 || n != 0 {
		t.Fatalf("deleted user still appears before sweep: member IDs %v, count %d", ids, n)
	}
}

type fresh5WaysSnapshot struct {
	store.Store
	seen          atomic.Int32
	ready, resume chan struct{}
}

func (g *fresh5WaysSnapshot) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	r, err := g.Store.List(ctx, kind, q)
	if kind == model.KindPasskey {
		n := g.seen.Add(1)
		if n == 2 {
			close(g.ready)
		}
		if n <= 2 {
			select {
			case <-g.resume:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return r, err
}

// Each independent removal must preserve the final sign-in way, including when
// both requests start from a snapshot with two usable passkeys.
func TestFresh5ConcurrentRemovalsPreserveOneUsableWay(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "concurrent-ways", model.RoleUser)
	makeKey := func(name string) *model.Passkey {
		p := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, Epoch: u.CredEpoch, UserVerified: true, CredentialID: []byte(name)}
		if err := e.svc.Passkeys.Create(e.ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b := makeKey("way-a"), makeKey("way-b")
	g := &fresh5WaysSnapshot{Store: e.svc.Store, ready: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Passkeys.S = g
	t.Cleanup(func() {
		select {
		case <-g.resume:
		default:
			close(g.resume)
		}
	})
	done := make(chan error, 2)
	for _, p := range []*model.Passkey{a, b} {
		go func(id string) {
			_, err := e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, id, "")
			done <- err
		}(p.ID)
	}
	select {
	case <-g.ready:
	case <-time.After(500 * time.Millisecond):
		// A serialized implementation may keep the second reader outside the
		// snapshot while the first is paused; release it and check the result.
	}
	close(g.resume)
	first, second := <-done, <-done
	current, err := e.svc.Users.Get(e.ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	ways, err := e.svc.UserWays(e.ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(ways.Passkeys) == 0 && current.PasswordHash == "" && len(ways.Providers) == 0 {
		t.Fatalf("concurrent self-service removals left no sign-in way: results=%v / %v", first, second)
	}
}

type fresh6RemovalStall struct {
	store.Store
	id              string
	once            atomic.Bool
	entered, resume chan struct{}
}

// CompareAndPut pauses the first removal at its commit (the user record's compare-and-swap), after its guard has
// decided. (It paused at the passkey read that followed the guard when a lease guarded the removal; the removal now
// commits on the user record, and there is no lease to expire: the second removal runs while the first is paused.)
func (g *fresh6RemovalStall) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindUser && r.ID == g.id && g.once.CompareAndSwap(false, true) {
		close(g.entered)
		select {
		case <-g.resume:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return g.Store.CompareAndPut(ctx, r, expect)
}

func TestFresh6ExpiredWaysLeaseCannotRemoveLastCredential(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "expired-ways-lease", model.RoleUser)
	makeKey := func(name string) *model.Passkey {
		p := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, Epoch: u.CredEpoch, UserVerified: true, CredentialID: []byte(name)}
		if err := e.svc.Passkeys.Create(e.ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b := makeKey("fresh6-key-a"), makeKey("fresh6-key-b")
	g := &fresh6RemovalStall{Store: e.svc.Store, id: u.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Users.S = g
	t.Cleanup(func() {
		select {
		case <-g.resume:
		default:
			close(g.resume)
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, a.ID, "")
		done <- err
	}()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("removal did not reach its commit")
	}
	_, second := e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, b.ID, "")
	close(g.resume)
	first := <-done
	current, err := e.svc.Users.Get(e.ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	ways, err := e.svc.UserWays(e.ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(ways.Passkeys) == 0 && len(ways.Providers) == 0 && current.PasswordHash == "" {
		t.Fatalf("expired holder removed last credential after replacement holder completed: first=%v second=%v", first, second)
	}
}

type freshReviewMemberCleanupFailure struct{ store.Store }

func (s freshReviewMemberCleanupFailure) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindMember {
		return errors.New("review: membership cleanup storage failure")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func TestFreshReviewDeletedUserMembershipAfterCleanupFailure(t *testing.T) {
	e := newEnv(t)
	org := e.org("deleted-member-failed-cleanup")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Group"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Members.S = freshReviewMemberCleanupFailure{Store: e.svc.Members.S}
	if err := e.svc.DeleteUser(e.ctx, service.System, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Users.Get(e.ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted user get=%v", err)
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.GroupMemberCount(e.ctx, service.System, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 || n != 0 {
		t.Fatalf("successful deletion with failed cleanup leaves deleted user visible: ids=%v count=%d", ids, n)
	}
}

func TestFreshReviewPendingGroupAddSurvivesUserDeletion(t *testing.T) {
	e := newEnv(t)
	org := e.org("deleted-member-pending-add")
	u := e.user(org.ID, "member", model.RoleUser)
	original := e.svc.Members.S
	e.svc.Members.S = freshReviewMemberCleanupFailure{Store: original}
	name := "Pending Group"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Pending) == 0 {
		t.Fatal("expected committed, unmaterialized add")
	}
	e.svc.Members.S = original // storage is healthy throughout deletion and subsequent finishing
	if err := e.svc.DeleteUser(e.ctx, service.System, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil {
		t.Fatal(err)
	}
	g, err = e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.GroupMemberCount(e.ctx, service.System, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 || n != 0 {
		t.Fatalf("finishing pre-deletion committed add resurrected deleted user's membership: ids=%v count=%d", ids, n)
	}
}

// These tests were written against the lease design (a per-group lock, member writes one by one, an undo on
// failure). Groups now commit on their record (service.ChangeGroup): a change is committed by one compare-and-swap of
// the group's record and its membership records are written afterwards, fenced by sequence. The setups below keep
// each test's invariant and are adapted only where the lease made them meaningful:
//   - there is no lease to outlive, so the first test stalls the writer between its commit and its membership write
//     (where the lease used to lapse) and no longer sleeps out a 30 s lease: the fence is the sequence, not time;
//   - a membership write cannot fail a change any more (the change is committed before it), so "a failed change"
//     is one whose commit fails: the second test injects the failure there, and also checks the other half of the
//     invariant: a committed change whose membership write fails is seen whole, not half;
//   - the third test's metadata update now commits on the same record: the member change it races is committed,
//     never undone, so the invariant checked is that the update neither loses it nor leaves it half-applied.

type freshLeaseStall struct {
	store.Store
	groupID, memberID string
	parentWritten     atomic.Bool
	blocked           atomic.Bool
	entered, resume   chan struct{}
}

func (g *freshLeaseStall) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	err := g.Store.CompareAndPut(ctx, r, expected)
	if err == nil && r.Kind == model.KindGroup && r.ID == g.groupID {
		g.parentWritten.Store(true)
	}
	return err
}
func (g *freshLeaseStall) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	r, err := g.Store.Get(ctx, kind, id)
	if kind == model.KindMember && id == g.memberID && g.parentWritten.Load() && g.blocked.CompareAndSwap(false, true) {
		close(g.entered)
		<-g.resume
	}
	return r, err
}

// A membership operation that committed, then stalled before writing the membership, must not write it after
// another operation committed and materialized a conflicting change (the stalled write is fenced by sequence).
func TestFreshGroupWriteCannotOutliveItsLease(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-lease")
	user := e.user(org.ID, "member", model.RoleUser)
	original := "Original"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &original})
	if err != nil {
		t.Fatal(err)
	}
	gate := &freshLeaseStall{Store: e.svc.Store, groupID: group.ID, memberID: model.MemberID(group.ID, user.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	firstDone := make(chan error, 1)
	firstName := "First operation"
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{DisplayName: &firstName}, []string{user.ID}, nil)
		firstDone <- err
	}()
	<-gate.entered // the first operation is committed and about to write the membership: a delayed store/RPC call
	fresh, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		close(gate.resume)
		<-firstDone
		t.Fatal(err)
	}
	secondName := "Second operation"
	// The second operation finishes the first's pending entry (the user becomes a member), then commits and
	// materializes the removal.
	_, secondErr := e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &secondName}, nil, []string{user.ID})
	close(gate.resume)
	firstErr := <-firstDone
	if secondErr != nil {
		t.Fatalf("replacement operation could not complete: %v", secondErr)
	}
	if firstErr != nil {
		t.Fatalf("the first operation was committed; it must not report failure: %v", firstErr)
	}
	final, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.DisplayName != secondName || len(final.Pending) != 0 {
		t.Fatalf("final group: %+v", final)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(group.ID, user.ID)); err != nil || m.Active() {
		t.Fatalf("stalled operation committed membership after the replacement revoked it: %v %+v", err, m)
	}
	if ids, err := e.svc.GroupMembers(e.ctx, service.System, group.ID); err != nil || len(ids) != 0 {
		t.Fatalf("members: %v %v", ids, err)
	}
}

// freshFaultGate fails every compare-and-swap of a record (failID) while failing is set, pausing the first one
// until the test lets it go.
type freshFaultGate struct {
	store.Store
	failID          string
	failing, paused atomic.Bool
	entered, resume chan struct{}
}

func (g *freshFaultGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.ID == g.failID && g.failing.Load() {
		if g.paused.CompareAndSwap(false, true) {
			close(g.entered)
			<-g.resume
		}
		return errors.New("review: injected write failure")
	}
	return g.Store.CompareAndPut(ctx, r, expected)
}

// Permission lookups must never observe a member of a change that fails: a change fails only at its commit (the
// group record's compare-and-swap), before which nothing is written. A change whose membership write fails after
// the commit is committed: readers see every member of it, never only those written so far.
func TestFreshFailedGroupChangeIsInvisibleToPermissionReaders(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-visibility")
	first := e.user(org.ID, "first", model.RoleUser)
	second := e.user(org.ID, "second", model.RoleUser)
	name := "Privileged group"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	inGroup := func(u *model.User) bool {
		t.Helper()
		gs, err := e.svc.UserGroups(e.ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(gs, func(g *model.Group) bool { return g.ID == group.ID })
	}

	// The commit fails: nothing is visible, during or after.
	gate := &freshFaultGate{Store: e.svc.Store, failID: group.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	gate.failing.Store(true)
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, []string{first.ID, second.ID}, nil)
		done <- err
	}()
	<-gate.entered
	during := inGroup(first)
	close(gate.resume)
	if err := <-done; err == nil {
		t.Fatal("fault did not fail the change")
	}
	if during || inGroup(first) || inGroup(second) {
		t.Fatal("permission reader observed membership from a group change that failed")
	}
	gate.failing.Store(false)

	// A membership write fails after the commit: the change is committed, and seen whole.
	gate2 := &freshFaultGate{Store: e.svc.Store, failID: model.MemberID(group.ID, second.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	gate2.failing.Store(true)
	e.svc.Groups.S = gate2
	e.svc.Members.S = gate2
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, []string{first.ID, second.ID}, nil)
		done <- err
	}()
	<-gate2.entered // first's membership is written, second's write is failing
	firstSeen, secondSeen := inGroup(first), inGroup(second)
	close(gate2.resume)
	if err := <-done; err != nil {
		t.Fatalf("a committed change reported failure: %v", err)
	}
	if !firstSeen || !secondSeen {
		t.Fatalf("committed change seen in part by permission readers: first=%v second=%v", firstSeen, secondSeen)
	}
	gate2.failing.Store(false)
	if n, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil || n != 1 {
		t.Fatalf("housekeeping: %d %v", n, err)
	}
	if g, _ := e.svc.Groups.Get(e.ctx, group.ID); len(g.Pending) != 0 {
		t.Fatalf("still pending: %+v", g.Pending)
	}
	if !inGroup(first) || !inGroup(second) {
		t.Fatal("members lost once materialized")
	}
}

// A metadata edit commits on the same record as a member change: it can neither undo one nor leave it
// half-applied. Racing a member change whose membership write fails, the edit carries the committed change forward,
// and the change stays visible whole until it is materialized.
func TestFreshMetadataUpdateCannotPreventFailedMembershipRollback(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-metadata")
	first := e.user(org.ID, "first", model.RoleUser)
	second := e.user(org.ID, "second", model.RoleUser)
	name := "Original"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	gate := &freshFaultGate{Store: e.svc.Store, failID: model.MemberID(group.ID, second.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	gate.failing.Store(true)
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, []string{first.ID, second.ID}, nil)
		done <- err
	}()
	<-gate.entered
	newName := "Concurrent metadata edit"
	_, metadataErr := e.svc.UpdateGroup(e.ctx, service.System, group.ID, service.GroupInput{DisplayName: &newName})
	close(gate.resume)
	changeErr := <-done
	if metadataErr != nil {
		t.Fatalf("concurrent metadata edit: %v", metadataErr)
	}
	if changeErr != nil {
		t.Fatalf("the committed member change reported failure: %v", changeErr)
	}
	g, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.DisplayName != newName {
		t.Fatalf("metadata edit lost: %q", g.DisplayName)
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, group.ID)
	if err != nil || !slices.Equal(ids, sortedIDs(first.ID, second.ID)) {
		t.Fatalf("committed member change not seen whole after the metadata edit: %v %v (pending %+v)", ids, err, g.Pending)
	}
	for _, u := range []*model.User{first, second} {
		gs, err := e.svc.UserGroups(e.ctx, u)
		if err != nil || len(gs) != 1 || gs[0].ID != group.ID {
			t.Fatalf("user %s groups: %v %v", u.Username, gs, err)
		}
	}
	gate.failing.Store(false)
	if _, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil {
		t.Fatal(err)
	}
	if g, _ = e.svc.Groups.Get(e.ctx, group.ID); len(g.Pending) != 0 {
		t.Fatalf("still pending after housekeeping: %+v", g.Pending)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(group.ID, second.ID)); err != nil || !m.Active() {
		t.Fatalf("second's membership not materialized: %v", err)
	}
}

func sortedIDs(ids ...string) []string {
	slices.Sort(ids)
	return ids
}

func TestFreshReviewLastWayGuardRejectsDisabledProvider(t *testing.T) {
	e := newEnv(t)
	e.primary.Settings.RequireMFA = false
	if err := e.svc.Orgs.Update(e.ctx, e.primary); err != nil {
		t.Fatal(err)
	}
	u := e.user(e.primary.ID, "disabled-provider-last-way", model.RoleUser)
	p := &model.Provider{OrgID: u.OrgID, Name: "Disabled SSO", Type: model.ProviderOIDC, Issuer: "https://issuer.example", Enabled: false}
	if err := e.svc.Providers.Create(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(u, p, "last-way-sub", u.Email, "connect")); err != nil {
		t.Fatal(err)
	}
	pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: "Only working way", Epoch: u.CredEpoch, UserVerified: true, CredentialID: []byte("last-way-key")}
	if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, pk.ID, "")
	if !errors.Is(err, service.ErrConflict) {
		t.Fatalf("self-removal counted a disabled provider as another way in: %v", err)
	}
}

type freshReviewQuorumDisabledKey struct {
	store.Store
	key *store.Record
}

func (s freshReviewQuorumDisabledKey) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	out := make(map[string]*store.Record, len(ids))
	for _, id := range ids {
		if kind == model.KindPasskey && id == s.key.ID {
			out[id] = s.key
			continue
		}
		r, err := s.Store.Lookup(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, nil
}

func TestFreshReviewLastWayGuardUsesQuorumCredentialContents(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "quorum-disabled-key", model.RoleUser)
	keys := make([]*model.Passkey, 0, 2)
	for _, name := range []string{"working", "cloned"} {
		pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, Epoch: u.CredEpoch, UserVerified: true, CredentialID: []byte(name)}
		if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, pk)
	}
	newer := *keys[1]
	newer.Disabled = true
	r, err := store.Encode(&newer)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Store = freshReviewQuorumDisabledKey{Store: e.svc.Store, key: r}
	_, err = e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, keys[0].ID, "")
	if !errors.Is(err, service.ErrConflict) {
		t.Fatalf("self-removal counted a key disabled in the quorum's copy as another way in: %v", err)
	}
}

// round3GroupRollbackGate fails every write of one membership (failedMemberID) and pauses the first request once
// its commit (the first write of the group's record) has succeeded, before it writes any membership.
//
// Written against the lease design, where the pause came after the second group write (the undo of a failed
// change). A change now commits on the group's record and is never undone, so the request paused here is committed
// and the later, successful request must materialize it first; the invariant is unchanged: nothing the later
// request explicitly set is erased by the earlier one finishing (or not).
type round3GroupRollbackGate struct {
	store.Store
	groupID, failedMemberID string
	groupWrites             atomic.Int32
	entered, resume         chan struct{}
	resumeOnce              sync.Once
}

func (g *round3GroupRollbackGate) letResume() { g.resumeOnce.Do(func() { close(g.resume) }) }

func (g *round3GroupRollbackGate) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindMember && r.ID == g.failedMemberID {
		return errors.New("review: membership storage failure")
	}
	return g.Store.Put(ctx, r)
}

func (g *round3GroupRollbackGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.Kind == model.KindMember && r.ID == g.failedMemberID {
		return errors.New("review: membership storage failure")
	}
	err := g.Store.CompareAndPut(ctx, r, expected)
	if r.Kind == model.KindGroup && r.ID == g.groupID && err == nil && g.groupWrites.Add(1) == 1 {
		close(g.entered)
		<-g.resume
	}
	return err
}

func TestRound3GroupRollbackCannotEraseLaterSuccessfulMembership(t *testing.T) {
	for _, adding := range []bool{true, false} {
		name := "retain-added-membership"
		if !adding {
			name = "retain-revocation"
		}
		t.Run(name, func(t *testing.T) { round3GroupRollback(t, adding) })
	}
}

func round3GroupRollback(t *testing.T, adding bool) {
	e := newEnv(t)
	org := e.org("rollback-window")
	first := e.user(org.ID, "first", model.RoleUser)
	second := e.user(org.ID, "second", model.RoleUser)
	name := "Original"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	if !adding {
		for _, user := range []*model.User{first, second} {
			if err := e.svc.SetMembership(e.ctx, service.System, group.ID, user.ID, true); err != nil {
				t.Fatal(err)
			}
		}
		group, err = e.svc.Groups.Get(e.ctx, group.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	gate := &round3GroupRollbackGate{Store: e.svc.Store, groupID: group.ID, failedMemberID: model.MemberID(group.ID, second.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	done := make(chan error, 1)
	go func() {
		add, remove := []string{first.ID, second.ID}, []string(nil)
		if !adding {
			add, remove = nil, add
		}
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, add, remove)
		done <- err
	}()
	<-gate.entered // the first request is committed; none of its memberships is written yet
	fresh, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		gate.letResume()
		<-done
		t.Fatal(err)
	}
	renamed := "Concurrent success"
	add, remove := []string{first.ID}, []string(nil)
	if !adding {
		add, remove = nil, add
	}
	_, concurrentErr := e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &renamed}, add, remove)
	gate.letResume()
	failedErr := <-done
	if concurrentErr != nil {
		t.Fatal(concurrentErr)
	}
	if failedErr != nil {
		t.Fatalf("the first request was committed before its membership write failed; it must not report failure: %v", failedErr)
	}
	m, err := e.svc.Members.Get(e.ctx, model.MemberID(group.ID, first.ID))
	if adding && (err != nil || !m.Active()) {
		t.Fatalf("membership explicitly retained by later successful update was erased: %v", err)
	}
	if !adding && err == nil && m.Active() {
		t.Fatal("membership explicitly revoked by later successful update was restored")
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{}; adding {
		want = sortedIDs(first.ID, second.ID) // second is committed, seen until materialized
		if !equalIDs(ids, want) {
			t.Fatalf("members %v, want %v", ids, want)
		}
	} else if len(ids) != 0 {
		t.Fatalf("members %v, want none", ids)
	}
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type reviewInviteCleanupGate struct {
	store.Store
	id              string
	entered, resume chan struct{}
	once            atomic.Bool
}

func (g *reviewInviteCleanupGate) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindSession && q.Scope == g.id && g.once.CompareAndSwap(false, true) {
		close(g.entered)
		<-g.resume
	}
	return g.Store.List(ctx, kind, q)
}

func TestReviewInviteCleanupPreservesNewGenerationLink(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "cleanup-generation", model.RoleUser)
	old, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	g := &reviewInviteCleanupGate{Store: e.svc.Store, id: u.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Store = g
	t.Cleanup(func() {
		select {
		case <-g.resume:
		default:
			close(g.resume)
		}
	})
	done := make(chan error, 1)
	go func() {
		_, _, err := e.svc.UseSignInLink(e.ctx, tokenFrom(old), service.LinkInvite, "", service.NewCredEpoch())
		done <- err
	}()
	select { // The user CAS has committed; only tidying the old link remains.
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("redemption did not reach post-commit session cleanup")
	}
	newLink, _, issueErr := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if issueErr != nil {
		close(g.resume)
		<-done
		t.Fatal(issueErr)
	}
	_, _, before := e.svc.PeekLink(e.ctx, tokenFrom(newLink), service.LinkInvite)
	close(g.resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if before != nil {
		t.Fatalf("new link invalid before cleanup: %v", before)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(newLink), service.LinkInvite); err != nil {
		t.Fatalf("old redemption cleanup deleted a valid invitation issued for the next security generation: %v", err)
	}
}

type reviewInviteIssueGate struct {
	store.Store
	id              string
	entered, resume chan struct{}
	once            atomic.Bool
}

func (g *reviewInviteIssueGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.Kind == model.KindLink && r.ID == g.id && expected == 0 && g.once.CompareAndSwap(false, true) {
		close(g.entered)
		<-g.resume
	}
	return g.Store.CompareAndPut(ctx, r, expected)
}

func TestReviewInviteReplacementAuthorityRecheckedAfterConflict(t *testing.T) {
	e := newEnv(t)
	admin := e.user(e.primary.ID, "invite-admin", model.RoleAdmin)
	u := e.user(e.primary.ID, "new-manager", model.RoleManager)
	g := &reviewInviteIssueGate{Store: e.svc.Store, id: service.LinkInvite + ":" + u.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Links.S = g
	t.Cleanup(func() {
		select {
		case <-g.resume:
		default:
			close(g.resume)
		}
	})
	done := make(chan error, 1)
	go func() { _, _, err := e.svc.CreateInvite(e.ctx, actor(admin), u.ID); done <- err }()
	select { // Admin passed mayReplaceInvite while no invitation existed.
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("issuance did not reach its initial write")
	}
	superLink, _, err := e.svc.CreateInvite(e.ctx, actor(e.super), u.ID)
	close(g.resume)
	adminErr := <-done
	if err != nil {
		t.Fatal(err)
	}
	if adminErr == nil {
		_, _, peekErr := e.svc.PeekLink(e.ctx, tokenFrom(superLink), service.LinkInvite)
		t.Fatalf("admin replaced a privileged user's invitation from another issuer after a CAS conflict; original link result: %v", peekErr)
	}
}
