package service_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

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
