package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// landsOnce makes the next write of a kind land and report store.ErrUnconfirmed (the node that decided it was lost
// before it answered).
type landsOnce struct {
	store.Store
	mu   sync.Mutex
	kind model.Kind
}

func (l *landsOnce) arm(k model.Kind) { l.mu.Lock(); l.kind = k; l.mu.Unlock() }

func (l *landsOnce) take(k model.Kind) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.kind == "" || l.kind != k {
		return false
	}
	l.kind = ""
	return true
}

func (l *landsOnce) Put(ctx context.Context, r *store.Record) error {
	if l.take(r.Kind) {
		if err := l.Store.Put(ctx, r); err != nil {
			return err
		}
		return store.ErrUnconfirmed
	}
	return l.Store.Put(ctx, r)
}

func (l *landsOnce) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if l.take(r.Kind) {
		if err := l.Store.CompareAndPut(ctx, r, expect); err != nil {
			return err
		}
		return store.ErrUnconfirmed
	}
	return l.Store.CompareAndPut(ctx, r, expect)
}

func newLandsOnceEnv(t *testing.T) (*env, *landsOnce) {
	st := &landsOnce{Store: memstore.New()}
	t.Cleanup(func() { _ = st.Close() })
	return newEnvOn(t, st), st
}

// A deletion of a user whose outcome is unknown is followed through as one that is known: the applications are told and the users
// who reported to them lose their manager. (A retry of one that landed finds no user and would never do it.)
func TestDeleteUserOfUnknownOutcomeFollowsThrough(t *testing.T) {
	e, st := newLandsOnceEnv(t)
	org := e.org("acme")
	boss := e.user(org.ID, "boss", model.RoleUser)
	rep, err := e.svc.CreateUser(e.ctx, service.System, org.ID, service.UserInput{Email: ptr("rep@example.com"), GivenName: ptr("Rep"),
		Work: &service.WorkInput{ManagerID: &boss.ID}})
	if err != nil {
		t.Fatal(err)
	}
	var told []string
	e.svc.OnSessionsEnding = func(_ context.Context, userID string, _ []string) { told = append(told, userID) }
	st.arm(model.KindUser)
	if err := e.svc.DeleteUser(e.ctx, service.System, boss.ID); !errors.Is(err, service.ErrOutcomeUnknown) {
		t.Fatalf("the deletion: %v", err)
	}
	if _, err := e.svc.Users.Get(e.ctx, boss.ID); err == nil {
		t.Fatal("setup: the deletion did not land")
	}
	if len(told) != 1 || told[0] != boss.ID {
		t.Fatalf("the applications were not told of the deleted user's ended sessions: %v", told)
	}
	if got, err := e.svc.Users.Get(e.ctx, rep.ID); err != nil || got.Work.ManagerID != "" {
		t.Fatalf("the report still has the deleted user as manager: %+v %v", got, err)
	}
}

// Removing a password whose outcome is unknown ends the sessions as one that is known: a retry finds no password to
// remove and would never end them.
func TestRemovePasswordOfUnknownOutcomeEndsSessions(t *testing.T) {
	e, st := newLandsOnceEnv(t)
	org := e.org("acme")
	u := e.establish(e.user(org.ID, "pw", model.RoleUser))
	sess := e.session(u)
	st.arm(model.KindUser)
	if err := e.svc.RemovePassword(e.ctx, service.System, u.ID); !errors.Is(err, service.ErrOutcomeUnknown) {
		t.Fatalf("the removal: %v", err)
	}
	if got, _ := e.svc.Users.Get(e.ctx, u.ID); got.PasswordHash != "" {
		t.Fatal("setup: the removal did not land")
	}
	if e.sessionLive(sess) {
		t.Fatal("a session survives the removal of the password")
	}
}

// Disabling a user whose outcome is unknown ends the sessions too.
func TestDisableOfUnknownOutcomeEndsSessions(t *testing.T) {
	e, st := newLandsOnceEnv(t)
	org := e.org("acme")
	u := e.user(org.ID, "dis", model.RoleUser)
	sess := e.session(u)
	st.arm(model.KindUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Active: ptr(false)}); !errors.Is(err, service.ErrOutcomeUnknown) {
		t.Fatalf("the change: %v", err)
	}
	if e.sessionLive(sess) {
		t.Fatal("a session survives the disabling")
	}
}

// A code whose use the cluster did not confirm is neither accepted nor "wrong": the answer is an error the caller can
// ask to try again about (service.ErrOutcomeUnknown), for an authenticator code and a recovery code alike.
func TestCodesOfUnknownOutcomeAreErrorsNotWrongCodes(t *testing.T) {
	e, st := newLandsOnceEnv(t)
	org := e.org("acme")
	u := e.user(org.ID, "mfa", model.RoleUser)
	secret := secure.NewTOTPSecret()
	st.arm(model.KindSignIn)
	if ok, err := e.svc.ConsumeTOTP(e.ctx, u, secret, secure.TOTPCode(secret, timeNow())); ok || !errors.Is(err, service.ErrOutcomeUnknown) {
		t.Fatalf("an authenticator code whose step was not confirmed: %v %v", ok, err)
	}
	if err := e.svc.SetTOTP(e.ctx, e.fresh(u), secure.RandomBytes(20), 1000); err != nil {
		t.Fatal(err)
	}
	codes, err := e.svc.CreateRecoveryCodes(e.ctx, service.System, e.fresh(u))
	if err != nil {
		t.Fatal(err)
	}
	st.arm(model.KindSignIn)
	if ok, _, err := e.svc.ConsumeRecoveryCode(e.ctx, e.fresh(u), codes[0]); ok || !errors.Is(err, service.ErrOutcomeUnknown) {
		t.Fatalf("a recovery code whose use was not confirmed: %v %v", ok, err)
	}
	if ok, _, err := e.svc.ConsumeRecoveryCode(e.ctx, e.fresh(u), "AAAA-AAAA-AAAA-AAAA"); ok || err != nil {
		t.Fatalf("a wrong recovery code is no error: %v %v", ok, err)
	}
}

func timeNow() time.Time { return time.Now() }

// A user who has a deleted user as manager (the follow-up of the deletion did not run) is given none by the orphan sweep.
func TestSweepClearsADeletedManager(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	boss := e.user(org.ID, "boss", model.RoleUser)
	rep, err := e.svc.CreateUser(e.ctx, service.System, org.ID, service.UserInput{Email: ptr("rep@example.com"), GivenName: ptr("Rep"),
		Work: &service.WorkInput{ManagerID: &boss.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Users.Delete(e.ctx, boss.ID); err != nil { // the deletion alone, as an interrupted DeleteUser leaves it
		t.Fatal(err)
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.Users.Get(e.ctx, rep.ID); err != nil || got.Work.ManagerID != "" {
		t.Fatalf("the report keeps a deleted manager: %+v %v", got, err)
	}
	// a manager who exists stays
	live := e.user(org.ID, "live", model.RoleUser)
	rep2, err := e.svc.CreateUser(e.ctx, service.System, org.ID, service.UserInput{Email: ptr("rep2@example.com"), GivenName: ptr("Rep2"),
		Work: &service.WorkInput{ManagerID: &live.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.Users.Get(e.ctx, rep2.ID); got.Work.ManagerID != live.ID {
		t.Fatalf("the sweep removed the manager of a user whose manager exists: %q", got.Work.ManagerID)
	}
}
