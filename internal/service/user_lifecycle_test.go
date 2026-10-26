package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/kvstore"
)

// Past their end date a user is not enabled at once; the sweep disables them (ending sessions) and leaves others.
func TestExpireUsers(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	gone := e.user(o.ID, "gone", model.RoleUser)
	later := e.user(o.ID, "later", model.RoleUser)
	stays := e.user(o.ID, "stays", model.RoleUser)
	e.endDate(gone, time.Now().Add(-time.Minute))
	e.endDate(later, time.Now().Add(time.Hour))
	if err := e.svc.Sessions.Create(e.ctx, &model.Session{Meta: model.Meta{ID: "s-gone"}, UserID: gone.ID, OrgID: o.ID,
		Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if u := e.fresh(gone); u.Enabled(time.Now()) || !u.Active {
		t.Fatal("past the end date: active, but not enabled, before the sweep")
	}
	n, err := e.svc.ExpireUsers(e.ctx)
	if err != nil || n != 1 {
		t.Fatalf("expired %d (%v), want 1", n, err)
	}
	for _, tc := range []struct {
		u    *model.User
		want bool
	}{{gone, false}, {later, true}, {stays, true}} {
		if u := e.fresh(tc.u); u.Active != tc.want {
			t.Errorf("%s active=%v, want %v", u.Username, u.Active, tc.want)
		}
	}
	// the sweep records itself and its reason
	if sc := e.fresh(gone).StatusChanged; sc == nil || sc.By != "system" || sc.Reason != "The end date was reached." {
		t.Fatalf("sweep: %+v", sc)
	}
	if s, _ := e.svc.Sessions.All(e.ctx, gone.ID); len(s) != 0 {
		t.Fatal("the expired user's sessions survived")
	}
}

// endDate gives u an end date.
func (e *env) endDate(u *model.User, at time.Time) {
	e.t.Helper()
	got := e.fresh(u)
	got.ValidUntil = &at
	if err := e.svc.Users.Update(e.ctx, got); err != nil {
		e.t.Fatal(err)
	}
}

// Disabling and enabling an account record who, when and why on the user (the latest change); a password set or
// removed records when.
func TestUserLifecycleFacts(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	admin := e.user(o.ID, "boss", model.RoleAdmin)
	u := e.user(o.ID, "pat", model.RoleUser)
	if u.StatusChanged != nil || u.PasswordChangedAt != nil || u.MFAEnrolledAt != nil {
		t.Fatalf("new user has lifecycle facts: %+v", u)
	}
	before := time.Now().Add(-time.Second)
	off := false
	got, err := e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{Active: &off, StatusReason: ptr("  Left the company  ")})
	if err != nil {
		t.Fatal(err)
	}
	sc := got.StatusChanged
	if sc == nil || sc.By != "boss" || sc.ByID != admin.ID || sc.Reason != "Left the company" || sc.At.Before(before) {
		t.Fatalf("disabled: %+v", sc)
	}
	// An edit that does not change the status keeps the record (and ignores a reason).
	got, err = e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{FamilyName: ptr("Lee"), StatusReason: ptr("ignored")})
	if err != nil || got.StatusChanged.Reason != "Left the company" {
		t.Fatalf("unrelated edit: %+v %v", got.StatusChanged, err)
	}
	on := true
	got, err = e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Active: &on})
	if err != nil || got.StatusChanged.By != "system" || got.StatusChanged.Reason != "" || !got.Active {
		t.Fatalf("enabled: %+v %v", got.StatusChanged, err)
	}
	long := make([]byte, model.MaxStatusReason+1)
	for i := range long {
		long[i] = 'x'
	}
	if _, err := e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{Active: &off, StatusReason: ptr(string(long))}); !errors.As(err, new(*service.FieldError)) {
		t.Fatalf("over-long reason: %v", err)
	}

	pw := "a long enough password"
	got, err = e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Password: &pw})
	if err != nil || got.PasswordChangedAt == nil || got.PasswordChangedAt.Before(before) {
		t.Fatalf("password set: %v %v", got.PasswordChangedAt, err)
	}
	set := *got.PasswordChangedAt
	for !time.Now().After(set) { // the removal must be stamped later than the set, however coarse the clock
	}
	if err := e.svc.RemovePassword(e.ctx, actor(admin), u.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.Users.Get(e.ctx, u.ID); got.PasswordChangedAt == nil || !got.PasswordChangedAt.After(set) {
		t.Fatalf("password removed: %v", got.PasswordChangedAt)
	}
}

// On a key-value store the end-date sweep reads the due index, never the whole user kind (5M users every minute).
func TestExpireUsersUsesDueIndex(t *testing.T) {
	kv, err := kvstore.OpenBadger(context.Background(), t.TempDir(), kvstore.BadgerOptions{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kv.Close() })
	e := newEnvOn(t, noUserScan{kv})
	o := e.org("acme")
	gone := e.user(o.ID, "gone", model.RoleUser)
	stays := e.user(o.ID, "stays", model.RoleUser)
	e.endDate(gone, time.Now().Add(-time.Minute))
	e.endDate(stays, time.Now().Add(time.Hour))
	if n, err := e.svc.ExpireUsers(e.ctx); err != nil || n != 1 {
		t.Fatalf("expired %d %v", n, err)
	}
	if e.fresh(gone).Active {
		t.Fatal("the user past their end date is still active")
	}
	if !e.fresh(stays).Active {
		t.Fatal("a user before their end date was disabled")
	}
	if n, err := e.svc.ExpireUsers(e.ctx); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v", n, err)
	}
}
