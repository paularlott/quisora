package service_test

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Deleting a user leaves its records to the orphan sweep: they stop counting at once and the sweep removes them,
// and only them.
func TestSweepRemovesOnlyRecordsOfDeletedOwners(t *testing.T) {
	c := newCast(t)
	gone, keep := c.user(c.a.ID, "leaver", model.RoleUser), c.aUser
	for _, u := range []*model.User{gone, keep} {
		c.session(u)
		c.passkey(u, "pk-"+u.Username)
		c.apiToken(u)
	}
	ten, _ := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{Name: ptr("staff")})
	if _, err := c.svc.AddAccess(c.ctx, service.System, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: gone.ID}); err != nil {
		t.Fatal(err)
	}
	grp, _ := c.svc.CreateGroup(c.ctx, service.System, c.a.ID, service.GroupInput{DisplayName: ptr("Ops")})
	if err := c.svc.SetMembership(c.ctx, service.System, grp.ID, gone.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.SetMembership(c.ctx, service.System, grp.ID, keep.ID, true); err != nil {
		t.Fatal(err)
	}
	// a long-expired lock goes; a live one stays
	if err := c.svc.Locks.Create(c.ctx, &model.Lock{Meta: model.Meta{ID: "dead-lock"}, Holder: "x", Until: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.Locks.Create(c.ctx, &model.Lock{Meta: model.Meta{ID: "live-lock"}, Holder: "x", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.Users.Delete(c.ctx, gone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.SweepAll(c.ctx); err != nil {
		t.Fatal(err)
	}
	count := func(k model.Kind, scope string) int {
		got, err := c.svc.Store.Count(c.ctx, k, scope)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, k := range []model.Kind{model.KindSession, model.KindPasskey, model.KindAPIToken} {
		if count(k, gone.ID) != 0 {
			t.Errorf("%v of the deleted user remain", k)
		}
		if count(k, keep.ID) != 1 {
			t.Errorf("%v of the kept user: %d", k, count(k, keep.ID))
		}
	}
	if l, _, _ := c.svc.ListAccess(c.ctx, service.System, ten.ID, store.ListQuery{}); len(l) != 0 {
		t.Errorf("access entries %d", len(l))
	}
	if n := activeMembers(t, c.svc, c.a.ID); n != 1 {
		t.Errorf("%d memberships left, want the kept user's", n)
	}
	if _, err := c.svc.Locks.Get(c.ctx, "live-lock"); err != nil {
		t.Error("a live lock was swept")
	}
	if _, err := c.svc.Locks.Get(c.ctx, "dead-lock"); err == nil {
		t.Error("a long-dead lock was kept")
	}
	if again, _ := c.svc.SweepAll(c.ctx); again != 0 {
		t.Errorf("second sweep removed %d", again)
	}
}
