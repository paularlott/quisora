package service_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// stallMembershipWrite holds the first write of u's membership of g until the gate is released: a writer that
// stalled between its commit and the write (a slow store or RPC, a paused node).
func stallMembershipWrite(e *env, g *model.Group, u *model.User) *gate {
	gt := newGate(e.t)
	id := model.MemberID(g.ID, u.ID)
	e.svc.Members.S = &faultStore{Store: e.svc.Store, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind == model.KindMember && r.ID == id {
			gt.stall()
		}
		return nil
	}}
	return gt
}

// A writer stalled after its commit must not apply its membership write after a later change: the membership record's
// sequence fences the stale write.
func TestStalledGroupWriteIsFencedByALaterChange(t *testing.T) {
	t.Run("stalled_remove_then_later_add", func(t *testing.T) {
		e := newEnv(t)
		org := e.org("fence-remove")
		u := e.user(org.ID, "u", model.RoleUser)
		g := e.group(org.ID, "G", u)
		gt := stallMembershipWrite(e, g, u)
		done := e.changeGroupAsync(g, service.GroupInput{}, nil, []string{u.ID})
		gt.waitEntered(t, "the removal's membership write")
		fresh, err := e.svc.Groups.Get(e.ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		// Finishes the removal, then commits and materializes the add.
		if _, err := e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{}, []string{u.ID}, nil); err != nil {
			t.Fatal(err)
		}
		gt.release()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || !m.Active() {
			t.Fatalf("stale removal overwrote the later add: %v %+v", err, m)
		}
		if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 1 {
			t.Fatalf("user's groups: %v %v", gs, err)
		}
	})

	t.Run("stalled_add_then_later_remove", func(t *testing.T) {
		e := newEnv(t)
		org := e.org("fence-add")
		u := e.user(org.ID, "member", model.RoleUser)
		g := e.group(org.ID, "Original")
		gt := stallMembershipWrite(e, g, u)
		firstName := "First operation"
		done := e.changeGroupAsync(g, service.GroupInput{DisplayName: &firstName}, []string{u.ID}, nil)
		gt.waitEntered(t, "the add's membership write")
		fresh, err := e.svc.Groups.Get(e.ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		// Finishes the first's pending entry (the user becomes a member), then commits and materializes the removal.
		secondName := "Second operation"
		if _, err := e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &secondName}, nil, []string{u.ID}); err != nil {
			t.Fatalf("replacement operation could not complete: %v", err)
		}
		gt.release()
		if err := <-done; err != nil {
			t.Fatalf("the first operation was committed; it must not report failure: %v", err)
		}
		final, err := e.svc.Groups.Get(e.ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		if final.DisplayName != secondName || len(final.Pending) != 0 {
			t.Fatalf("final group: %+v", final)
		}
		if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || m.Active() {
			t.Fatalf("stalled operation committed membership after the replacement revoked it: %v %+v", err, m)
		}
		if ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID); err != nil || len(ids) != 0 {
			t.Fatalf("members: %v %v", ids, err)
		}
	})
}

// A request that loses the commit to a concurrent successful request fails as stale and touches nothing the
// successful request set.
func TestGroupChangeLosingTheCommitIsStaleAndWritesNothing(t *testing.T) {
	e := newEnv(t)
	org := e.org("lost-commit")
	u := e.user(org.ID, "member", model.RoleUser)
	g := e.group(org.ID, "Original")
	gt := newGate(t)
	e.svc.Groups.S = &faultStore{Store: e.svc.Groups.S, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind == model.KindGroup {
			gt.stall()
		}
		return nil
	}}
	done := e.changeGroupAsync(g, service.GroupInput{}, []string{u.ID}, nil)
	gt.waitEntered(t, "the first request's commit") // about to commit; nothing written yet
	fresh, err := e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	renamed := "Committed"
	_, err = e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &renamed}, []string{u.ID}, nil)
	gt.release()
	if err != nil {
		t.Fatalf("concurrent update failed: %v", err)
	}
	if err := <-done; !errors.Is(err, service.ErrStale) {
		t.Fatalf("first update should be stale: %v", err)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || !m.Active() {
		t.Fatalf("successful concurrent change lost its requested membership to a stale request: %v", err)
	}
	if cur, _ := e.svc.Groups.Get(e.ctx, g.ID); cur.DisplayName != renamed || len(cur.Pending) != 0 {
		t.Fatalf("group: %+v", cur)
	}
}

// A change fails only at its commit, the group record's compare-and-swap, before which nothing is written.
func TestGroupChangeWhoseCommitFailsWritesNothing(t *testing.T) {
	e := newEnv(t)
	org := e.org("failed-commit")
	ok := e.user(org.ID, "ok", model.RoleUser)
	bad := e.user(org.ID, "bad", model.RoleUser)
	g := e.group(org.ID, "Before")
	e.svc.Groups.S = failingCAS(e.svc.Groups.S, func(r *store.Record) bool { return r.ID == g.ID })
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

// brokenMembership is a group of an organization with two users, the second of whom cannot be given a membership
// (their write fails while failing is set). With pause, the first attempt to write it waits for the gate first.
type brokenMembership struct {
	e             *env
	g             *model.Group
	first, second *model.User
	failing       atomic.Bool
	gt            *gate
}

func newBrokenMembership(t *testing.T, name string, pause bool) *brokenMembership {
	e := newEnv(t)
	org := e.org(name)
	b := &brokenMembership{e: e, first: e.user(org.ID, "first", model.RoleUser), second: e.user(org.ID, "second", model.RoleUser), gt: newGate(t)}
	b.g = e.group(org.ID, "Original")
	secondID := model.MemberID(b.g.ID, b.second.ID)
	b.failing.Store(true)
	e.svc.Members.S = &faultStore{Store: e.svc.Store, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
		if r.ID != secondID || !b.failing.Load() {
			return nil
		}
		if pause {
			b.gt.stall()
		}
		return errInjected
	}}
	return b
}

// addBoth starts the change that adds both users.
func (b *brokenMembership) addBoth() <-chan error {
	return b.e.changeGroupAsync(b.g, service.GroupInput{}, []string{b.first.ID, b.second.ID}, nil)
}

func (b *brokenMembership) inGroup(u *model.User) bool {
	b.e.t.Helper()
	gs, err := b.e.svc.UserGroups(b.e.ctx, u)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return slices.ContainsFunc(gs, func(g *model.Group) bool { return g.ID == b.g.ID })
}

// finish repairs the store and checks that the membership of the second user is written and nothing is pending.
func (b *brokenMembership) finishedBy(t *testing.T, finish func()) {
	t.Helper()
	b.failing.Store(false)
	finish()
	if cur, err := b.e.svc.Groups.Get(b.e.ctx, b.g.ID); err != nil || len(cur.Pending) != 0 {
		t.Fatalf("still pending: %v %+v", err, cur)
	}
	if m, err := b.e.svc.Members.Get(b.e.ctx, model.MemberID(b.g.ID, b.second.ID)); err != nil || !m.Active() {
		t.Fatalf("the second user's membership was not materialized: %v", err)
	}
}

// A change whose membership write fails after its commit is committed, not failed: every reader sees it whole from
// the group's record, and the membership is written later, by the next change of the group or by housekeeping.
func TestCommittedGroupChangeSurvivesMembershipWriteFailure(t *testing.T) {
	t.Run("next_change_finishes_it", func(t *testing.T) {
		b := newBrokenMembership(t, "next-change", false)
		e := b.e
		renamed := "After"
		res, err := e.svc.ChangeGroup(e.ctx, service.System, b.g, service.GroupInput{DisplayName: &renamed}, []string{b.first.ID, b.second.ID}, nil)
		if err != nil {
			t.Fatalf("a committed change reported failure: %v", err)
		}
		if res.DisplayName != renamed || len(res.Pending) != 1 {
			t.Fatalf("returned group: %+v", res)
		}
		if ids, err := e.svc.GroupMembers(e.ctx, service.System, b.g.ID); err != nil || !slices.Equal(ids, sortedIDs(b.first.ID, b.second.ID)) {
			t.Fatalf("members seen: %v %v", ids, err)
		}
		if !b.inGroup(b.second) {
			t.Fatal("the user whose membership could not be written is not seen in the group")
		}
		if _, err := e.svc.Members.Get(e.ctx, model.MemberID(b.g.ID, b.second.ID)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the second user's membership record: %v", err)
		}
		b.finishedBy(t, func() {
			if err := e.svc.SetMembership(e.ctx, service.System, b.g.ID, b.first.ID, true); err != nil { // a no-op change
				t.Fatal(err)
			}
		})
	})

	t.Run("readers_see_it_whole_until_housekeeping_finishes_it", func(t *testing.T) {
		b := newBrokenMembership(t, "housekeeping", true)
		done := b.addBoth()
		b.gt.waitEntered(t, "the second membership write")
		firstSeen, secondSeen := b.inGroup(b.first), b.inGroup(b.second)
		b.gt.release()
		if err := <-done; err != nil {
			t.Fatalf("a committed change reported failure: %v", err)
		}
		if !firstSeen || !secondSeen {
			t.Fatalf("committed change seen in part by permission readers: first=%v second=%v", firstSeen, secondSeen)
		}
		b.finishedBy(t, func() {
			if n, err := b.e.svc.FinishGroupChanges(b.e.ctx, 0); err != nil || n != 1 {
				t.Fatalf("housekeeping: %d %v", n, err)
			}
		})
		if !b.inGroup(b.first) || !b.inGroup(b.second) {
			t.Fatal("members lost once materialized")
		}
	})

	t.Run("metadata_edit_carries_it", func(t *testing.T) {
		// A metadata edit commits on the same record as the member change: it neither undoes the change nor leaves it
		// half-applied.
		b := newBrokenMembership(t, "metadata", true)
		e := b.e
		done := b.addBoth()
		b.gt.waitEntered(t, "the second membership write")
		newName := "Concurrent metadata edit"
		_, metadataErr := e.svc.UpdateGroup(e.ctx, service.System, b.g.ID, service.GroupInput{DisplayName: &newName})
		b.gt.release()
		if err := <-done; err != nil {
			t.Fatalf("the committed member change reported failure: %v", err)
		}
		if metadataErr != nil {
			t.Fatalf("concurrent metadata edit: %v", metadataErr)
		}
		cur, err := e.svc.Groups.Get(e.ctx, b.g.ID)
		if err != nil || cur.DisplayName != newName {
			t.Fatalf("metadata edit lost: %v %+v", err, cur)
		}
		ids, err := e.svc.GroupMembers(e.ctx, service.System, b.g.ID)
		if err != nil || !slices.Equal(ids, sortedIDs(b.first.ID, b.second.ID)) {
			t.Fatalf("committed member change not seen whole after the metadata edit: %v %v (pending %+v)", ids, err, cur.Pending)
		}
		if !b.inGroup(b.first) || !b.inGroup(b.second) {
			t.Fatal("a member of the committed change is not seen in the group")
		}
		b.finishedBy(t, func() {
			if _, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil {
				t.Fatal(err)
			}
		})
	})
}

// Permission lookups never observe a member of a change that fails: it fails only at its commit, before which
// nothing is written.
func TestFailedGroupChangeIsInvisibleToPermissionReaders(t *testing.T) {
	e := newEnv(t)
	org := e.org("failed-visibility")
	first := e.user(org.ID, "first", model.RoleUser)
	second := e.user(org.ID, "second", model.RoleUser)
	g := e.group(org.ID, "Privileged group")
	inGroup := func(u *model.User) bool {
		t.Helper()
		gs, err := e.svc.UserGroups(e.ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(gs, func(x *model.Group) bool { return x.ID == g.ID })
	}
	gt := newGate(t)
	e.svc.Groups.S = &faultStore{Store: e.svc.Store, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
		if r.ID == g.ID {
			gt.stall()
			return errInjected
		}
		return nil
	}}
	done := e.changeGroupAsync(g, service.GroupInput{}, []string{first.ID, second.ID}, nil)
	gt.waitEntered(t, "the commit")
	during := inGroup(first)
	gt.release()
	if err := <-done; err == nil {
		t.Fatal("the injected failure did not fail the change")
	}
	if during || inGroup(first) || inGroup(second) {
		t.Fatal("a permission reader observed membership from a group change that failed")
	}
}

// A change paused after its commit, before it writes any membership, never erases what a later successful change
// set: it is committed, and the later change materializes it first. Its second membership cannot be written at all.
func TestEarlierGroupChangeFinishingNeverErasesALaterChange(t *testing.T) {
	for _, adding := range []bool{true, false} {
		name := "add"
		if !adding {
			name = "remove"
		}
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			org := e.org("earlier-change")
			first := e.user(org.ID, "first", model.RoleUser)
			second := e.user(org.ID, "second", model.RoleUser)
			group := e.group(org.ID, "Original")
			if !adding {
				for _, user := range []*model.User{first, second} {
					if err := e.svc.SetMembership(e.ctx, service.System, group.ID, user.ID, true); err != nil {
						t.Fatal(err)
					}
				}
				group = e.current(group)
			}
			gt := newGate(t)
			failed := model.MemberID(group.ID, second.ID)
			fs := &faultStore{Store: e.svc.Store}
			fs.beforeCAS = func(r *store.Record, _ hlc.Timestamp) error {
				if r.Kind == model.KindMember && r.ID == failed {
					return errInjected
				}
				return nil
			}
			fs.afterCAS = func(r *store.Record, err error) {
				if r.Kind == model.KindGroup && r.ID == group.ID && err == nil {
					gt.stall() // the first request is committed; none of its memberships is written yet
				}
			}
			e.svc.Groups.S, e.svc.Members.S = fs, fs
			both, one := []string{first.ID, second.ID}, []string{first.ID}
			var firstDone <-chan error
			if adding {
				firstDone = e.changeGroupAsync(group, service.GroupInput{}, both, nil)
			} else {
				firstDone = e.changeGroupAsync(group, service.GroupInput{}, nil, both)
			}
			gt.waitEntered(t, "the first request's commit")
			fresh := e.current(group)
			renamed := "Concurrent success"
			var err error
			if adding {
				_, err = e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &renamed}, one, nil)
			} else {
				_, err = e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &renamed}, nil, one)
			}
			gt.release()
			if firstErr := <-firstDone; firstErr != nil {
				t.Fatalf("the first request was committed before its membership write failed; it must not report failure: %v", firstErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			m, mErr := e.svc.Members.Get(e.ctx, model.MemberID(group.ID, first.ID))
			ids, err := e.svc.GroupMembers(e.ctx, service.System, group.ID)
			if err != nil {
				t.Fatal(err)
			}
			if adding {
				if mErr != nil || !m.Active() {
					t.Fatalf("membership explicitly retained by the later successful change was erased: %v", mErr)
				}
				// second is committed, and seen until it is materialized
				if want := sortedIDs(first.ID, second.ID); !slices.Equal(ids, want) {
					t.Fatalf("members %v, want %v", ids, want)
				}
				return
			}
			if mErr == nil && m.Active() {
				t.Fatal("membership explicitly revoked by the later successful change was restored")
			}
			if len(ids) != 0 {
				t.Fatalf("members %v, want none", ids)
			}
		})
	}
}

// A deleted user stops counting as a group member at once, though their materialized membership stays for the
// orphan sweep; a change committed before the deletion but not yet materialized does not bring them back.
func TestDeletedUserStopsCountingAsAGroupMember(t *testing.T) {
	t.Run("materialized_membership", func(t *testing.T) {
		e := newEnv(t)
		org := e.org("deleted-member")
		u := e.user(org.ID, "member", model.RoleUser)
		g := e.group(org.ID, "Group", u)
		if err := e.svc.DeleteUser(e.ctx, service.System, u.ID); err != nil {
			t.Fatal(err)
		}
		assertNoMembers(t, e, g)
	})

	t.Run("pending_add_is_not_resurrected_after_deletion", func(t *testing.T) {
		e := newEnv(t)
		org := e.org("deleted-pending")
		u := e.user(org.ID, "member", model.RoleUser)
		original := e.svc.Members.S
		e.svc.Members.S = failingCAS(original, func(r *store.Record) bool { return r.Kind == model.KindMember })
		g := e.group(org.ID, "Pending Group", u)
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
		assertNoMembers(t, e, e.current(g))
	})
}

func assertNoMembers(t *testing.T, e *env, g *model.Group) {
	t.Helper()
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.GroupMemberCount(e.ctx, service.System, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 || n != 0 {
		t.Fatalf("deleted user still a member: ids %v, count %d", ids, n)
	}
}

// A group created with members is one commit: the record is created carrying the change, so readers see the
// members at once, and a group whose creation is refused has nothing written for it.
func TestCreateGroupWithMembersIsOneCommit(t *testing.T) {
	e := newEnv(t)
	org := e.org("create-commit")
	a, b := e.user(org.ID, "a", model.RoleUser), e.user(org.ID, "b", model.RoleUser)
	other := e.org("other")
	stranger := e.user(other.ID, "s", model.RoleUser)
	name := "Team"
	if _, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{a.ID, stranger.ID}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("stranger accepted: %v", err)
	}
	if _, err := e.svc.Groups.GetByUnique(e.ctx, model.GroupNameKey(org.ID, name)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("group written by a refused create: %v", err)
	}
	if gs, _ := e.svc.UserGroups(e.ctx, a); len(gs) != 0 {
		t.Fatal("membership written by a refused create")
	}
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{a.ID, b.ID, a.ID})
	if err != nil {
		t.Fatal(err)
	}
	if g.Seq != 1 || len(g.Pending) != 0 {
		t.Fatalf("created group: %+v", g)
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil || !slices.Equal(ids, sortedIDs(a.ID, b.ID)) {
		t.Fatalf("members: %v %v", ids, err)
	}
	if n, err := e.svc.GroupMemberCount(e.ctx, service.System, g); err != nil || n != 2 {
		t.Fatalf("count: %d %v", n, err)
	}
	// A duplicate name with members: refused at the record, nothing written.
	if _, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{a.ID}); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if gs, _ := e.svc.UserGroups(e.ctx, a); len(gs) != 1 {
		t.Fatalf("a's groups: %v", gs)
	}
}

// Changes larger than MaxMembersPerChange are refused before anything is written.
func TestGroupChangeTooLarge(t *testing.T) {
	e := newEnv(t)
	org := e.org("too-large")
	name := "Big"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, service.MaxMembersPerChange+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("u%d", i)
	}
	if _, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, ids, nil); !errors.Is(err, service.ErrTooLarge) {
		t.Fatalf("add: %v", err)
	}
	if _, err := e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, ids[:600], ids[600:]); !errors.Is(err, service.ErrTooLarge) {
		t.Fatalf("add and remove: %v", err)
	}
	if _, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr("Bigger")}, ids); !errors.Is(err, service.ErrTooLarge) {
		t.Fatalf("create: %v", err)
	}
	if cur, _ := e.svc.Groups.Get(e.ctx, g.ID); cur.Version != g.Version {
		t.Fatal("a refused change wrote the group")
	}
}

// Housekeeping finishes a change whose writer died after committing it, once it is older than the grace period,
// and leaves a fresh one to its writer.
func TestHousekeepingFinishesAbandonedGroupChange(t *testing.T) {
	e := newEnv(t)
	org := e.org("housekeeping")
	u := e.user(org.ID, "u", model.RoleUser)
	name := "G"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	// A writer that died right after its commit: the record carries the entry, no membership exists.
	g.Seq, g.Pending = 1, []model.GroupChange{{Seq: 1, At: time.Now().Add(-time.Minute), Add: []string{u.ID}}}
	if err := e.svc.Groups.Update(e.ctx, g); err != nil {
		t.Fatal(err)
	}
	if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 1 {
		t.Fatalf("committed change not seen before it is materialized: %v %v", gs, err)
	}
	if n, err := e.svc.FinishGroupChanges(e.ctx, time.Hour); err != nil || n != 0 {
		t.Fatalf("finished within grace: %d %v", n, err)
	}
	if n, err := e.svc.FinishGroupChanges(e.ctx, 30*time.Second); err != nil || n != 1 {
		t.Fatalf("finished: %d %v", n, err)
	}
	if m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || !m.Active() || m.Seq != 1 {
		t.Fatalf("membership: %v %+v", err, m)
	}
	cur, err := e.svc.Groups.Get(e.ctx, g.ID)
	if err != nil || len(cur.Pending) != 0 {
		t.Fatalf("record: %v %+v", err, cur)
	}
	if n, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil || n != 0 {
		t.Fatalf("nothing left, finished %d: %v", n, err)
	}
}

// Deleting a group is one write, its record: its memberships stand on it, so they stop counting at once (none is
// written, so none can fail the deletion), and the orphan sweep marks them removed later.
func TestDeleteGroupIsOneWrite(t *testing.T) {
	e := newEnv(t)
	org := e.org("delete-commit")
	a, b := e.user(org.ID, "a", model.RoleUser), e.user(org.ID, "b", model.RoleUser)
	name := "Doomed"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{a.ID, b.ID})
	if err != nil {
		t.Fatal(err)
	}
	inner := e.svc.Members.S
	e.svc.Members.S = failingCAS(inner, func(*store.Record) bool { return true }) // no membership can be written
	if err := e.svc.DeleteGroup(e.ctx, service.System, g.ID); err != nil {
		t.Fatalf("deletion wrote a membership: %v", err)
	}
	e.svc.Members.S = inner
	if _, err := e.svc.Groups.Get(e.ctx, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("group: %v", err)
	}
	for _, u := range []*model.User{a, b} {
		if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 0 {
			t.Fatalf("%s still granted the group: %v %v", u.Username, gs, err)
		}
	}
	if activeMembers(t, e.svc, org.ID) != 2 {
		t.Fatal("the deletion touched a membership record")
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	if n := activeMembers(t, e.svc, org.ID); n != 0 {
		t.Fatalf("%d memberships survived the sweep", n)
	}
}

// A removed membership's record is kept (fencing stalled writers) but is out of every index and expires.
func TestRemovedMembershipLeavesIndexes(t *testing.T) {
	e := newEnv(t)
	org := e.org("removed")
	u := e.user(org.ID, "u", model.RoleUser)
	name := "G"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetMembership(e.ctx, service.System, g.ID, u.ID, false); err != nil {
		t.Fatal(err)
	}
	m, err := e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID))
	if err != nil || m.Active() || m.Seq != 2 {
		t.Fatalf("record: %v %+v", err, m)
	}
	ix := m.Index()
	if ix.Fields["group_id"] != "" || ix.Fields["user_id"] != "" || ix.Expires.IsZero() {
		t.Fatalf("index of a removed membership: %+v", ix)
	}
	if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 0 {
		t.Fatalf("user's groups: %v %v", gs, err)
	}
	if n, err := e.svc.GroupMemberCount(e.ctx, service.System, g); err != nil || n != 0 {
		t.Fatalf("count: %d %v", n, err)
	}
	// Added back: the same record, live again.
	if err := e.svc.SetMembership(e.ctx, service.System, g.ID, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if m, err = e.svc.Members.Get(e.ctx, model.MemberID(g.ID, u.ID)); err != nil || !m.Active() || m.Seq != 3 {
		t.Fatalf("record: %v %+v", err, m)
	}
	if gs, err := e.svc.UserGroups(e.ctx, u); err != nil || len(gs) != 1 {
		t.Fatalf("user's groups: %v %v", gs, err)
	}
}

// Concurrent changes of one group from the same copy: exactly one commits, the other is stale, and the record ends
// consistent with the memberships.
func TestConcurrentGroupChangesSerialiseOnTheRecord(t *testing.T) {
	e := newEnv(t)
	org := e.org("concurrent")
	users := make([]string, 6)
	for i := range users {
		users[i] = e.user(org.ID, fmt.Sprintf("u%d", i), model.RoleUser).ID
	}
	name := "G"
	g, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, len(users))
	for _, uid := range users {
		go func() {
			_, err := e.svc.ChangeGroup(context.Background(), service.System, g, service.GroupInput{}, []string{uid}, nil)
			errs <- err
		}()
	}
	okCount := 0
	for range users {
		switch err := <-errs; {
		case err == nil:
			okCount++
		case !errors.Is(err, service.ErrStale):
			t.Fatal(err)
		}
	}
	if okCount != 1 {
		t.Fatalf("%d changes from one copy committed", okCount)
	}
	for _, uid := range users { // the rest, retried from the current record
		if err := e.svc.SetMembership(e.ctx, service.System, g.ID, uid, true); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := e.svc.GroupMembers(e.ctx, service.System, g.ID)
	if err != nil || len(ids) != len(users) {
		t.Fatalf("members: %v %v", ids, err)
	}
	cur, _ := e.svc.Groups.Get(e.ctx, g.ID)
	if len(cur.Pending) != 0 || cur.Seq != uint64(len(users)) {
		t.Fatalf("record: %+v", cur)
	}
	if n, err := e.svc.FinishGroupChanges(e.ctx, 0); err != nil || n != 0 {
		t.Fatalf("housekeeping found work: %d %v", n, err)
	}
}
