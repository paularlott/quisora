package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

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
