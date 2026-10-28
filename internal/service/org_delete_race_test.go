package service_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

// afterUserCount runs after once, just after the first count of users (a deletion's check that the organization is
// empty) returns; an error it returns is the count's.
type afterUserCount struct {
	store.Store
	after func() error
	done  atomic.Bool
}

func (f *afterUserCount) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	n, err := f.Store.Count(ctx, kind, scope)
	if kind == model.KindUser && f.after != nil && f.done.CompareAndSwap(false, true) {
		if aerr := f.after(); aerr != nil {
			return 0, aerr
		}
	}
	return n, err
}

// A user created between a deletion's count of the organization's users and the deletion itself is not discarded
// with the organization: the creation is refused (try again), and the deletion goes ahead.
func TestDeleteOrgRefusesAUserCreatedAfterTheCount(t *testing.T) {
	f := &afterUserCount{Store: memstore.New()}
	t.Cleanup(func() { _ = f.Close() })
	e := newEnvOn(t, f)
	org := e.org("doomed")
	var created *model.User
	var createErr error
	f.after = func() error {
		created, createErr = e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("late"))
		return nil
	}
	delErr := e.svc.DeleteOrg(e.ctx, service.System, org.ID, false)
	if !f.done.Load() {
		t.Fatal("test set-up: the deletion counted no users")
	}
	checkOrgDeleteOutcome(t, e, org.ID, created, createErr, delErr)
	if createErr == nil || delErr != nil {
		t.Fatalf("want the creation refused and the deletion made: create %v, delete %v", createErr, delErr)
	}
	if !errors.Is(createErr, service.ErrStale) {
		t.Errorf("the creation's error does not say try again: %v", createErr)
	}
}

// orgRaceBackends opens a store of each backend the races of an organization's users are run on.
var orgRaceBackends = map[string]func(t *testing.T) store.Store{
	"memory": func(t *testing.T) store.Store { return memstore.New() },
	"badger": func(t *testing.T) store.Store {
		st, err := kvstore.OpenBadger(t.Context(), t.TempDir(), kvstore.BadgerOptions{NoSync: true})
		if err != nil {
			t.Fatal(err)
		}
		return st
	},
	"sqlite": func(t *testing.T) store.Store {
		st, err := sqlstore.Open(t.Context(), sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "q.db")})
		if err != nil {
			t.Fatal(err)
		}
		return st
	},
}

// A user's creation and its organization's deletion (not cascading) racing never both succeed, on every backend:
// either the user exists in its organization, or the creation failed and the organization is gone (or both failed).
func TestDeleteOrgAndCreateUserNeverBothSucceed(t *testing.T) {
	for name, open := range orgRaceBackends {
		t.Run(name, func(t *testing.T) {
			st := open(t)
			t.Cleanup(func() { _ = st.Close() })
			e := newEnvOn(t, st)
			for i := range 40 {
				org := e.org(e.next("race"))
				var wg sync.WaitGroup
				var created *model.User
				var createErr, delErr error
				wg.Add(2)
				go func() {
					defer wg.Done()
					created, createErr = e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("u"))
				}()
				go func() {
					defer wg.Done()
					delErr = e.svc.DeleteOrg(e.ctx, service.System, org.ID, false)
				}()
				wg.Wait()
				checkOrgDeleteOutcome(t, e, org.ID, created, createErr, delErr)
				if t.Failed() {
					t.Fatalf("round %d", i)
				}
			}
		})
	}
}

// Users created in parallel in one organization (a directory provisioning over SCIM) all succeed: a creation reads its
// organization's deletion guard and does not write it, so creations do not conflict with each other over it.
func TestParallelCreationsInOneOrgAllSucceed(t *testing.T) {
	const workers, each = 64, 20
	for name, open := range orgRaceBackends {
		t.Run(name, func(t *testing.T) {
			st := open(t)
			t.Cleanup(func() { _ = st.Close() })
			e := newEnvOn(t, st)
			org := e.org("busy")
			var mu sync.Mutex
			var failed []error
			var wg sync.WaitGroup
			for w := range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range each {
						if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput(fmt.Sprintf("u%d-%d", w, i))); err != nil {
							mu.Lock()
							failed = append(failed, err)
							mu.Unlock()
						}
					}
				}()
			}
			wg.Wait()
			n, err := e.svc.Users.Count(e.ctx, org.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(failed) != 0 || n != workers*each {
				t.Fatalf("%d users created, %d creations failed (the first: %v); want %d created", n, len(failed),
					append(failed, nil)[0], workers*each)
			}
		})
	}
}

// A deletion that fails part-way does not leave its organization closed to new users for good: one that failed before
// it decided (its count) leaves them refused only until its lease runs out, and one that failed after it decided (the
// organization record not deleted) is finished by the next deletion.
func TestDeleteOrgThatFailedPartWay(t *testing.T) {
	f := &afterUserCount{Store: &faultStore{Store: memstore.New()}}
	t.Cleanup(func() { _ = f.Close() })
	e := newEnvOn(t, f)
	org := e.org("doomed")
	f.after = func() error { return store.ErrUnavailable }
	if err := e.svc.DeleteOrg(e.ctx, service.System, org.ID, false); !service.IsUnavailable(err) {
		t.Fatalf("the deletion whose count failed: %v", err)
	}
	if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("early")); !errors.Is(err, service.ErrStale) {
		t.Fatalf("a creation while the failed deletion's lease runs: %v", err)
	}
	g, err := e.svc.Locks.Get(e.ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	g.Until = time.Now().Add(-time.Second) // the lease has run out
	if err := e.svc.Locks.Update(e.ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("later")); err != nil {
		t.Fatalf("a creation once the failed deletion's lease ran out: %v", err)
	}
	if err := e.svc.DeleteOrg(e.ctx, service.System, org.ID, false); !errors.Is(err, service.ErrNotEmpty) {
		t.Fatalf("the deletion of the organization with a user: %v", err)
	}
	if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("again")); err != nil {
		t.Fatalf("a creation after a refused deletion: %v", err)
	}

	// Decided, and the organization record not deleted: closed to new users until the deletion is made again.
	empty := e.org("empty")
	failOrgDeletion(f)
	if err := e.svc.DeleteOrg(e.ctx, service.System, empty.ID, false); !service.IsUnavailable(err) {
		t.Fatalf("the deletion whose last write failed: %v", err)
	}
	if _, err := e.svc.CreateUser(e.ctx, service.System, empty.ID, newUserInput("late")); !errors.Is(err, service.ErrStale) {
		t.Fatalf("a creation after the deletion decided: %v", err)
	}
	if err := e.svc.DeleteOrg(e.ctx, service.System, empty.ID, false); err != nil {
		t.Fatalf("the deletion made again: %v", err)
	}
	if _, err := e.svc.Orgs.Get(e.ctx, empty.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the organization is still there: %v", err)
	}
}

// checkOrgDeleteOutcome fails t unless the creation of a user (created, createErr) and the deletion of its
// organization (delErr) left a consistent state: never both made, a user made exists in its organization, and an
// organization deleted has no user.
func checkOrgDeleteOutcome(t *testing.T, e *env, orgID string, created *model.User, createErr, delErr error) {
	t.Helper()
	if createErr == nil && delErr == nil {
		t.Fatalf("both the creation of user %s and the deletion of its organization succeeded", created.ID)
	}
	_, orgErr := e.svc.Orgs.Get(e.ctx, orgID)
	if delErr == nil && !errors.Is(orgErr, store.ErrNotFound) {
		t.Fatalf("the deletion succeeded and the organization is still there: %v", orgErr)
	}
	if createErr == nil {
		if orgErr != nil {
			t.Fatalf("the user was created and its organization is gone: %v", orgErr)
		}
		if _, err := e.svc.Users.Get(e.ctx, created.ID); err != nil {
			t.Fatalf("the user created is not there: %v", err)
		}
	}
	if n, err := e.svc.Users.Count(e.ctx, orgID); err != nil || createErr != nil && n != 0 {
		t.Fatalf("a refused creation left %d users (%v)", n, err)
	}
}

// newUserInput is what a new user named name is created with.
func newUserInput(name string) service.UserInput {
	return service.UserInput{Username: &name, GivenName: &name, Email: ptr(name + "@example.com")}
}

// failOrgDeletion makes the next deletion of an organization record through f fail (a store outage), and only that.
func failOrgDeletion(f *afterUserCount) {
	var failed atomic.Bool
	f.Store.(*faultStore).beforePut = func(r *store.Record) error {
		if r.Kind == model.KindOrg && r.Deleted && failed.CompareAndSwap(false, true) {
			return store.ErrUnavailable
		}
		return nil
	}
}

// A deletion that decided and whose last write (the organization record's) failed does not leave its organization
// refusing new users until someone deletes it again: housekeeping finishes it.
func TestDecidedOrgDeletionIsFinishedByHousekeeping(t *testing.T) {
	f := &afterUserCount{Store: &faultStore{Store: memstore.New()}}
	t.Cleanup(func() { _ = f.Close() })
	e := newEnvOn(t, f)
	org := e.org("stuck")
	failOrgDeletion(f)
	if err := e.svc.DeleteOrg(e.ctx, service.System, org.ID, false); !service.IsUnavailable(err) {
		t.Fatalf("the deletion whose last write failed: %v", err)
	}
	if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("refused")); !errors.Is(err, service.ErrStale) {
		t.Fatalf("a creation after the deletion decided: %v", err)
	}
	if n, err := e.svc.FinishOrgDeletions(e.ctx, time.Hour); err != nil || n != 0 {
		t.Fatalf("a deletion within its grace was finished: %d %v", n, err)
	}
	if n, err := e.svc.FinishOrgDeletions(e.ctx, 0); err != nil || n != 1 {
		t.Fatalf("finishing the decided deletion: %d %v", n, err)
	}
	if _, err := e.svc.Orgs.Get(e.ctx, org.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the organization is still there: %v", err)
	}
	if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("late")); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("a creation in the deleted organization: %v", err)
	}
	if n, err := e.svc.FinishOrgDeletions(e.ctx, 0); err != nil || n != 0 {
		t.Fatalf("a finished deletion was finished again: %d %v", n, err)
	}
}

// A cascading deletion that decided and did not finish is not finished by a deletion without cascade while the
// organization has users: that one is refused (not empty), and the users are not left without their organization by
// it.
func TestNonCascadeDeletionAfterAnUnfinishedCascadeIsRefused(t *testing.T) {
	f := &afterUserCount{Store: &faultStore{Store: memstore.New()}}
	t.Cleanup(func() { _ = f.Close() })
	e := newEnvOn(t, f)
	org := e.org("peopled")
	if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("member")); err != nil {
		t.Fatal(err)
	}
	failOrgDeletion(f)
	if err := e.svc.DeleteOrg(e.ctx, service.System, org.ID, true); !service.IsUnavailable(err) {
		t.Fatalf("the cascading deletion whose last write failed: %v", err)
	}
	if err := e.svc.DeleteOrg(e.ctx, service.System, org.ID, false); !errors.Is(err, service.ErrNotEmpty) {
		t.Fatalf("a deletion without cascade of the organization with a user: %v", err)
	}
	if _, err := e.svc.Orgs.Get(e.ctx, org.ID); err != nil {
		t.Fatalf("the organization: %v", err)
	}
	if err := e.svc.DeleteOrg(e.ctx, service.System, org.ID, true); err != nil {
		t.Fatalf("the cascading deletion made again: %v", err)
	}
}

// The sweep keeps an organization's open deletion guard while the organization exists, whatever its age, so its
// creations of users go on asserting it without writing it; it removes the guard once the organization is gone.
func TestSweepKeepsTheOpenGuardOfAnOrganization(t *testing.T) {
	e := newEnv(t)
	org := e.org("kept")
	if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, newUserInput("first")); err != nil {
		t.Fatal(err)
	}
	g, err := e.svc.Locks.Get(e.ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	if kept, err := e.svc.Locks.Get(e.ctx, org.ID); err != nil || kept.Version != g.Version {
		t.Fatalf("the open guard of an organization that exists was swept or written: %+v %v", kept, err)
	}
	if err := e.svc.Orgs.Delete(e.ctx, org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SweepAll(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Locks.Get(e.ctx, org.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the open guard of a deleted organization: %v", err)
	}
}
