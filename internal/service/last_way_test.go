package service_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// The guard that leaves an account a way to sign in: a self-service removal that would take the last one is refused,
// however the other ways are counted, and two removals made together leave one.
func TestLastWayGuard(t *testing.T) {
	self := func(e *env, u *model.User, p *model.Passkey) error {
		_, err := e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, p.ID, "")
		return err
	}

	t.Run("passed_epoch_passkey_is_not_a_way_in", func(t *testing.T) {
		// Old-epoch records may remain after best-effort cleanup. They are not another way to sign in.
		e := newEnv(t)
		u := e.user(e.primary.ID, "epoch-last-passkey", model.RoleUser)
		u.CredEpoch = service.NewCredEpoch()
		if err := e.svc.Users.Update(e.ctx, u); err != nil {
			t.Fatal(err)
		}
		current := e.passkey(u, "current")
		old := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: "superseded", Epoch: 0, UserVerified: true, CredentialID: []byte("superseded")}
		if err := e.svc.Passkeys.Create(e.ctx, old); err != nil {
			t.Fatal(err)
		}
		if err := self(e, u, current); !errors.Is(err, service.ErrConflict) {
			t.Fatalf("the last current passkey was removed because a passed-epoch record counted as another way: %v", err)
		}
	})

	t.Run("disabled_provider_is_not_a_way_in", func(t *testing.T) {
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
		e.link(u, p, "last-way-sub")
		if err := self(e, u, e.passkey(u, "only-working-way")); !errors.Is(err, service.ErrConflict) {
			t.Fatalf("self-removal counted a disabled provider as another way in: %v", err)
		}
	})

	t.Run("both_read_before_either_commits", func(t *testing.T) {
		// Two removals that both start from a snapshot with two usable passkeys: one goes, the other is refused.
		e := newEnv(t)
		u := e.user(e.primary.ID, "concurrent-ways", model.RoleUser)
		a, b := e.passkey(u, "way-a"), e.passkey(u, "way-b")
		gt := newGate(t)
		var listed atomic.Int32
		bothRead := make(chan struct{})
		e.svc.Passkeys.S = &faultStore{Store: e.svc.Store, afterList: func(kind model.Kind) {
			if kind != model.KindPasskey {
				return
			}
			switch listed.Add(1) {
			case 1:
				gt.hold()
			case 2:
				close(bothRead)
				gt.hold()
			}
		}}
		errs := make(chan error, 2)
		for _, p := range []*model.Passkey{a, b} {
			go func() { errs <- self(e, u, p) }()
		}
		select {
		case <-bothRead:
		case <-time.After(500 * time.Millisecond):
			// A serialized implementation may keep the second reader outside the snapshot while the first is
			// paused: release it and check the result.
		}
		gt.release()
		assertOneRemovalRefused(t, <-errs, <-errs)
		if n := len(e.ways(u).Passkeys); n != 1 {
			t.Fatalf("%d usable passkeys left, want 1", n)
		}
	})

	t.Run("second_removal_while_first_is_at_its_commit", func(t *testing.T) {
		// The first removal has decided and waits to commit on the account's record; the second runs meanwhile.
		e := newEnv(t)
		u := e.user(e.primary.ID, "second-at-commit", model.RoleUser)
		a, b := e.passkey(u, "key-a"), e.passkey(u, "key-b")
		gt := newGate(t)
		e.svc.Users.S = &faultStore{Store: e.svc.Store, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
			if r.Kind == model.KindUser && r.ID == u.ID {
				gt.stall()
			}
			return nil
		}}
		first := make(chan error, 1)
		go func() { first <- self(e, u, a) }()
		gt.waitEntered(t, "the first removal's commit")
		second := self(e, u, b)
		gt.release()
		assertOneRemovalRefused(t, <-first, second)
		if n := len(e.ways(u).Passkeys); n != 1 {
			t.Fatalf("%d usable passkeys left, want 1", n)
		}
	})
}

// Of two removals of an account's two passkeys, one succeeds and the other is refused as the last way in.
func assertOneRemovalRefused(t *testing.T, x, y error) {
	t.Helper()
	if (x == nil) == (y == nil) || (x != nil && !errors.Is(x, service.ErrConflict)) || (y != nil && !errors.Is(y, service.ErrConflict)) {
		t.Fatalf("removals: %v and %v, want one to succeed and the other to be refused as the last way in", x, y)
	}
}

// Two removals at once, each of a different one of the account's two passkeys, cannot both succeed: each would
// leave the other as the last way in. One goes, the other is refused as the last way in.
func TestConcurrentRemovalsKeepALastWayIn(t *testing.T) {
	e := newEnv(t)
	for round := range 10 {
		u := e.user(e.primary.ID, fmt.Sprintf("two-keys-%d", round), model.RoleUser)
		keys := []*model.Passkey{e.passkey(u, fmt.Sprintf("a-%d", round)), e.passkey(u, fmt.Sprintf("b-%d", round))}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, p := range keys {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, p.ID, "")
			}()
		}
		wg.Wait()
		ok, refused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, service.ErrConflict):
				refused++
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if left := len(e.ways(u).Passkeys); ok != 1 || refused != 1 || left != 1 {
			t.Fatalf("round %d: %d removed, %d refused, %d passkeys left", round, ok, refused, left)
		}
	}
}
