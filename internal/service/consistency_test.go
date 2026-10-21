package service_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// A1: a sign-in never rewrites the user record (its stamps live on the user's sign-in record), so it can neither
// erase nor be erased by an administrator's change of the user made at the same moment.
func TestSignInDoesNotRewriteUser(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	u := e.user(o.ID, "pat", model.RoleUser)
	before, _ := e.svc.Users.Get(e.ctx, u.ID)
	stale := *before // the copy a sign-in would hold

	// the administrator disables the user while the sign-in is under way
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	e.svc.TouchLogin(e.ctx, &stale)
	after, _ := e.svc.Users.Get(e.ctx, u.ID)
	if after.Active {
		t.Fatal("a sign-in undid the administrator's disabling")
	}
	got, _ := e.svc.GetUser(e.ctx, nil, u.ID)
	if got.LastLogin.IsZero() || stale.LastLogin.IsZero() {
		t.Fatal("the sign-in was not recorded")
	}
	// a second sign-in within the minute writes nothing
	si, _ := e.svc.SignIns.Get(e.ctx, u.ID)
	e.svc.TouchLogin(e.ctx, &stale)
	if again, _ := e.svc.SignIns.Get(e.ctx, u.ID); again.Version != si.Version {
		t.Fatal("a second sign-in within a minute wrote again")
	}
}

// A1: a TOTP code is accepted once: its step is recorded with a compare-and-swap before the answer, so the same code
// presented twice at the same moment (two requests, or two nodes) is accepted by exactly one.
func TestTOTPCodeAcceptedOnce(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	u := e.user(o.ID, "pat", model.RoleUser)
	secret := secure.NewTOTPSecret()
	now := time.Now()
	code := secure.TOTPCode(secret, now)
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.svc.ConsumeTOTPAt(e.ctx, u, secret, code, now) {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("one code accepted %d times", ok.Load())
	}
	if e.svc.ConsumeTOTPAt(e.ctx, u, secret, code, now) {
		t.Fatal("a used code was accepted again")
	}
	// a code verified while setting up the authenticator cannot sign in either
	next := now.Add(time.Minute)
	if err := e.svc.NoteTOTPStep(e.ctx, u, next.Unix()/30); err != nil {
		t.Fatal(err)
	}
	if e.svc.ConsumeTOTPAt(e.ctx, u, secret, secure.TOTPCode(secret, next), next) {
		t.Fatal("the enrolment code signed in")
	}
	if user, _ := e.svc.Users.Get(e.ctx, u.ID); user.Version != u.Version {
		t.Fatal("recording TOTP steps rewrote the user record")
	}
}

// A2: two records claiming one unique value (a replication clash): the one created first keeps it; the other is
// kept, the value removed from it, flagged and audited — never deleted.
func TestUniqueClashResolvedWithoutDeletion(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	first := e.user(o.ID, "pat", model.RoleUser)
	// a user created later on another node with the same address, as it arrives by replication
	later := &model.User{Meta: model.Meta{ID: model.NewID(), Created: time.Now()}, OrgID: o.ID, Username: "pat2",
		Email: first.Email, EmailVerified: true, Role: model.RoleUser, Active: true}
	later.Version = store.Clock.Now()
	rec, _ := store.EncodeAsIs(later)
	rec.Origin, rec.Created = "elsewhere", later.Version
	applied, losers, err := e.svc.Store.PutReplicated(e.ctx, rec)
	if err != nil || !applied || len(losers) != 1 || losers[0] != later.ID {
		t.Fatalf("clash: %v %v %v", applied, losers, err)
	}
	e.svc.ResolveUniqueClash(e.ctx, model.KindUser, later.ID)
	got, err := e.svc.Users.Get(e.ctx, later.ID)
	if err != nil {
		t.Fatal("the record that lost the value was deleted")
	}
	if got.Email != "" || got.EmailVerified || got.Conflict == "" {
		t.Fatalf("the losing record keeps the value or is not flagged: %+v", got)
	}
	if h, _ := e.svc.FindUserByEmail(e.ctx, o.ID, first.Email); h == nil || h.ID != first.ID {
		t.Fatal("the first claim lost the value")
	}
	audits, _, _ := e.svc.Audits.List(e.ctx, store.ListQuery{Scope: o.ID, Filters: []store.Filter{{Field: "action", Value: "unique.conflict"}}})
	if len(audits) != 1 {
		t.Fatalf("audit events: %d", len(audits))
	}
	e.svc.ResolveUniqueClash(e.ctx, model.KindUser, later.ID) // again (another node): nothing more to do
	if again, _ := e.svc.Users.Get(e.ctx, later.ID); again.Version != got.Version {
		t.Fatal("a resolved clash was changed again")
	}
}

// A9: concurrent removals of two super admins where the server keeps two (three with the bootstrap one): the admin
// lock serialises them and the count is fresh, so exactly one succeeds. The lock is released afterwards.
func TestLastAdminConcurrentDemotions(t *testing.T) {
	e := newEnv(t)
	e.svc.MinSuperAdmins = 2
	for round := range 10 {
		a := e.user(e.primary.ID, e.next("sa"), model.RoleSuperAdmin)
		b := e.user(e.primary.ID, e.next("sb"), model.RoleSuperAdmin)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, id := range []string{a.ID, b.ID} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if i == 0 {
					_, errs[i] = e.svc.UpdateUser(e.ctx, service.System, id, service.UserInput{Role: ptr(model.RoleUser)})
				} else {
					_, errs[i] = e.svc.UpdateUser(e.ctx, service.System, id, service.UserInput{Active: ptr(false)})
				}
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, service.ErrLastAdmin) {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d removals succeeded, want exactly 1", round, ok)
		}
		l, err := e.svc.Locks.Get(e.ctx, "admins/"+e.primary.ID)
		if err != nil || l.Holder != "" {
			t.Fatalf("round %d: the admin lock was not released: %+v %v", round, l, err)
		}
		for _, u := range []*model.User{a, b} { // back to the bootstrap super admin alone
			_ = e.svc.Users.Delete(e.ctx, u.ID)
		}
	}
}
