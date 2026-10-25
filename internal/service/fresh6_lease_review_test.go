package service_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

type fresh6RemovalStall struct {
	store.Store
	id              string
	once            atomic.Bool
	entered, resume chan struct{}
}

func (g *fresh6RemovalStall) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	r, err := g.Store.Get(ctx, kind, id)
	if kind == model.KindPasskey && id == g.id && g.once.CompareAndSwap(false, true) {
		close(g.entered)
		select {
		case <-g.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r, err
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
	g := &fresh6RemovalStall{Store: e.svc.Store, id: a.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Passkeys.S = g
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
		t.Fatal("removal did not reach post-guard read")
	}
	time.Sleep(31 * time.Second) // production waysLockTTL=30s; no clock or lock-state edits
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
