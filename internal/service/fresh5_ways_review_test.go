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
