package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// lapseAdminLease makes the primary organization's admin lease look expired, as it does adminLockTTL after a holder
// paused: the next lockAdmins takes it over.
func lapseAdminLease(t *testing.T, e *env) {
	t.Helper()
	l, err := e.svc.Locks.Get(e.ctx, "admins/"+e.primary.ID)
	if err != nil {
		t.Fatal(err)
	}
	l.Until = time.Now().Add(-time.Second)
	if err := e.svc.Locks.Update(e.ctx, l); err != nil {
		t.Fatal(err)
	}
}

// Writes that remove a super admin hold the organization's admin lease. One that lands after its lease lapsed, with
// another holder having removed the other super admin meanwhile, is undone and reported refused: the two cannot leave
// none. A write that is still safe is kept.
func TestAdminLeaseLapsedBeforeTheWriteLands(t *testing.T) {
	// setup stalls the write that disables a (or, with deleted, deletes them) after its guard has decided.
	setup := func(t *testing.T, deleted bool) (e *env, a, b *model.User, gt *gate) {
		e = newEnv(t)
		a = e.super
		b = e.user(e.primary.ID, "second-super", model.RoleSuperAdmin)
		gt = newGate(t)
		e.svc.Users.S = &faultStore{Store: e.svc.Store, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
			if r.Kind != model.KindUser || r.ID != a.ID || r.Deleted != deleted {
				return nil
			}
			if !deleted {
				var u model.User
				if err := store.Decode(r, &u); err != nil {
					return err
				}
				if u.Active {
					return nil
				}
			}
			gt.stall()
			return nil
		}}
		return e, a, b, gt
	}
	off := false

	t.Run("disable_is_undone", func(t *testing.T) {
		e, a, b, gt := setup(t, false)
		done := make(chan error, 1)
		go func() {
			_, err := e.svc.UpdateUser(e.ctx, service.System, a.ID, service.UserInput{Active: &off})
			done <- err
		}()
		gt.waitEntered(t, "the disable's guarded write")
		lapseAdminLease(t, e)
		if _, err := e.svc.UpdateUser(e.ctx, service.System, b.ID, service.UserInput{Active: &off}); err != nil {
			t.Fatalf("the replacement holder's disable (judged while a was usable): %v", err)
		}
		gt.release()
		if err := <-done; !errors.Is(err, service.ErrLastAdmin) {
			t.Fatalf("the disable that landed after its lease lapsed: err %v, want ErrLastAdmin", err)
		}
		got := e.fresh(a)
		if !got.Active || got.Role != model.RoleSuperAdmin || got.StatusChanged != nil {
			t.Fatalf("a not put back as it was: active=%v role=%s status=%+v", got.Active, got.Role, got.StatusChanged)
		}
		if e.fresh(b).Active {
			t.Fatal("the disable made within its lease did not stand")
		}
		// Audited as a refusal, not as a disable.
		for _, en := range e.audited(e.primary.ID, "user.update") {
			if en.Target == a.Username && en.Outcome == "success" {
				t.Fatalf("the undone disable was audited as made: %+v", en)
			}
		}
	})

	t.Run("delete_is_undone", func(t *testing.T) {
		// A super admin deleted by a write that landed after its lease lapsed is created again.
		e, a, b, gt := setup(t, true)
		done := make(chan error, 1)
		go func() { done <- e.svc.DeleteUser(e.ctx, service.System, a.ID) }()
		gt.waitEntered(t, "the delete's guarded write")
		lapseAdminLease(t, e)
		if err := e.svc.DeleteUser(e.ctx, service.System, b.ID); err != nil {
			t.Fatalf("the replacement holder's delete (judged while a was usable): %v", err)
		}
		gt.release()
		if err := <-done; !errors.Is(err, service.ErrLastAdmin) {
			t.Fatalf("the delete that landed after its lease lapsed: err %v, want ErrLastAdmin", err)
		}
		got, err := e.svc.Users.Get(e.ctx, a.ID)
		if err != nil {
			t.Fatalf("a was not created again: %v", err)
		}
		if !got.Active || got.Role != model.RoleSuperAdmin || got.Username != a.Username || got.Email != a.Email {
			t.Fatalf("a not created again as they were: %+v", got)
		}
		if _, err := e.svc.Users.Get(e.ctx, b.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the delete made within its lease did not stand: %v", err)
		}
	})

	t.Run("safe_change_is_kept", func(t *testing.T) {
		// A lapsed lease alone undoes nothing while enough super admins remain.
		e, a, _, gt := setup(t, false)
		done := make(chan error, 1)
		go func() {
			_, err := e.svc.UpdateUser(e.ctx, service.System, a.ID, service.UserInput{Active: &off})
			done <- err
		}()
		gt.waitEntered(t, "the disable's guarded write")
		lapseAdminLease(t, e)
		gt.release()
		if err := <-done; err != nil {
			t.Fatalf("a disable that leaves a super admin: %v", err)
		}
		if e.fresh(a).Active {
			t.Fatal("the disable was undone although a super admin remained")
		}
	})
}

// lostAck stalls the compare-and-swaps lose picks, then reports them ErrUnconfirmed: landed (lands is true) or not.
type lostAck struct {
	store.Store
	lose  func(r *store.Record) bool
	stall func()
	lands bool
}

func (l lostAck) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if !l.lose(r) {
		return l.Store.CompareAndPut(ctx, r, expect)
	}
	l.stall()
	if l.lands {
		if err := l.Store.CompareAndPut(ctx, r, expect); err != nil {
			return err
		}
	}
	return store.ErrUnconfirmed
}

// A guarded change whose outcome is unknown (the acknowledgement was lost) is judged at the commit boundary like a
// confirmed one: landed after its lease lapsed, it is undone; not landed, nothing is undone.
func TestAdminLeaseLapsedWriteWithUnknownOutcome(t *testing.T) {
	off := false
	setup := func(t *testing.T, deleted, lands bool) (e *env, a, b *model.User, gt *gate) {
		e = newEnv(t)
		a = e.super
		b = e.user(e.primary.ID, "second-super", model.RoleSuperAdmin)
		gt = newGate(t)
		guarded := func(r *store.Record) bool {
			if r.Kind != model.KindUser || r.ID != a.ID || r.Deleted != deleted {
				return false
			}
			var u model.User
			return deleted || store.Decode(r, &u) == nil && !u.Active
		}
		e.svc.Users.S = lostAck{Store: e.svc.Store, lose: guarded, stall: gt.stall, lands: lands}
		return e, a, b, gt
	}
	run := func(t *testing.T, e *env, gt *gate, change func() error, other func() error) error {
		done := make(chan error, 1)
		go func() { done <- change() }()
		gt.waitEntered(t, "the guarded write")
		lapseAdminLease(t, e)
		if err := other(); err != nil {
			t.Fatalf("the replacement holder's change (judged while a was usable): %v", err)
		}
		gt.release()
		return <-done
	}
	t.Run("disable_landed_is_undone", func(t *testing.T) {
		e, a, b, gt := setup(t, false, true)
		err := run(t, e, gt, func() error {
			_, err := e.svc.UpdateUser(e.ctx, service.System, a.ID, service.UserInput{Active: &off})
			return err
		}, func() error {
			_, err := e.svc.UpdateUser(e.ctx, service.System, b.ID, service.UserInput{Active: &off})
			return err
		})
		if !errors.Is(err, service.ErrLastAdmin) {
			t.Fatalf("err %v, want ErrLastAdmin", err)
		}
		if got := e.fresh(a); !got.Active || got.Role != model.RoleSuperAdmin {
			t.Fatalf("a not put back: active=%v role=%s", got.Active, got.Role)
		}
	})
	t.Run("delete_landed_is_undone", func(t *testing.T) {
		e, a, b, gt := setup(t, true, true)
		err := run(t, e, gt, func() error { return e.svc.DeleteUser(e.ctx, service.System, a.ID) },
			func() error { return e.svc.DeleteUser(e.ctx, service.System, b.ID) })
		if !errors.Is(err, service.ErrLastAdmin) {
			t.Fatalf("err %v, want ErrLastAdmin", err)
		}
		if got, err := e.svc.Users.Get(e.ctx, a.ID); err != nil || !got.Active {
			t.Fatalf("a not created again: %+v %v", got, err)
		}
	})
	t.Run("delete_not_landed_leaves_the_user", func(t *testing.T) {
		e, a, b, gt := setup(t, true, false)
		err := run(t, e, gt, func() error { return e.svc.DeleteUser(e.ctx, service.System, a.ID) },
			func() error { return e.svc.DeleteUser(e.ctx, service.System, b.ID) })
		if !errors.Is(err, service.ErrLastAdmin) {
			t.Fatalf("err %v, want ErrLastAdmin", err)
		}
		if got, err := e.svc.Users.Get(e.ctx, a.ID); err != nil || !got.Active {
			t.Fatalf("a should still be there: %+v %v", got, err)
		}
	})
}
