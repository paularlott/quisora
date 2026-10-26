package service_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Organizations need no administrator (super admins administer every one): an organization's last administrator can
// be demoted, disabled or deleted.
func TestLastOrgAdminNotProtected(t *testing.T) {
	c := newCast(t)
	org := c.org("solo")
	for _, change := range []service.UserInput{{Role: ptr(model.RoleUser)}, {Active: ptr(false)}} {
		only := c.user(org.ID, c.next("only"), model.RoleAdmin)
		if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), only.ID, change); err != nil {
			t.Errorf("change of the last admin %+v: %v", change, err)
		}
	}
	only := c.user(org.ID, "last", model.RoleAdmin)
	if err := c.svc.DeleteUser(c.ctx, actor(c.super), only.ID); err != nil {
		t.Errorf("delete the last admin: %v", err)
	}
}

// Deactivating a super admin (disabling, locking out, or an end date in the past) is refused when fewer usable super
// admins than the server keeps would remain: one, or two in a gossip cluster.
func TestSuperAdminDeactivationThreshold(t *testing.T) {
	c := newCast(t)
	ghost := c.ghostSuper()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	deactivations := map[string]func(id string) error{
		"disable": func(id string) error {
			_, err := c.svc.UpdateUser(c.ctx, ghost, id, service.UserInput{Active: ptr(false)})
			return err
		},
		"lock out": func(id string) error { _, err := c.svc.LockOutUser(c.ctx, ghost, id, "x"); return err },
		"delete":   func(id string) error { return c.svc.DeleteUser(c.ctx, ghost, id) },
		"end date": func(id string) error {
			_, err := c.svc.UpdateUser(c.ctx, ghost, id, service.UserInput{ValidUntil: ptr(past)})
			return err
		},
	}
	// one super admin: none of them
	for name, f := range deactivations {
		if err := f(c.super.ID); !errors.Is(err, service.ErrLastAdmin) {
			t.Errorf("%s the only super admin: %v", name, err)
		}
	}
	// a server that keeps two: with two, still none
	c.svc.MinSuperAdmins = 2
	s2 := c.user(c.primary.ID, "s2", model.RoleSuperAdmin)
	for name, f := range deactivations {
		if err := f(s2.ID); !errors.Is(err, service.ErrLastAdmin) {
			t.Errorf("%s one of two super admins the server keeps two of: %v", name, err)
		}
	}
	if got, _ := c.svc.Users.Get(c.ctx, s2.ID); !got.Active || got.ValidUntil != nil {
		t.Error("a refused deactivation changed the super admin")
	}
	// with three, one may go
	c.user(c.primary.ID, "s3", model.RoleSuperAdmin)
	if err := deactivations["disable"](s2.ID); err != nil {
		t.Errorf("disable one of three super admins the server keeps two of: %v", err)
	}
}

// The server keeps as many super admins as it is told to (Service.MinSuperAdmins; the app leaves it at one), and the
// error says so.
func TestMinSuperAdmins(t *testing.T) {
	c := newCast(t)
	c.svc.MinSuperAdmins = 2
	s2 := c.user(c.primary.ID, "s2", model.RoleSuperAdmin)
	s3 := c.user(c.primary.ID, "s3", model.RoleSuperAdmin)
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), s3.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err != nil {
		t.Fatalf("three super admins, one demoted: %v", err)
	}
	_, err := c.svc.UpdateUser(c.ctx, actor(c.super), s2.ID, service.UserInput{Role: ptr(model.RoleAdmin)})
	if !errors.Is(err, service.ErrLastAdmin) || !strings.Contains(err.Error(), "at least 2 super admins") {
		t.Fatalf("two super admins the server keeps two of: %v", err)
	}
	c.svc.MinSuperAdmins = 0
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), s2.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err != nil {
		t.Fatalf("one super admin is enough by default: %v", err)
	}
	ghost := c.ghostSuper()
	_, err = c.svc.UpdateUser(c.ctx, ghost, c.super.ID, service.UserInput{Role: ptr(model.RoleAdmin)})
	if !errors.Is(err, service.ErrLastAdmin) || !strings.Contains(err.Error(), "last super admin") {
		t.Fatalf("the last super admin: %v", err)
	}
	// the system's own work is guarded the same way
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.super.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("the system demoting the last super admin: %v", err)
	}
}

// End dates count against the last-super-admin guard: two super admins cannot end-date each other (none would be left
// once the dates pass), one past their end date is not usable, and the only one cannot be given an end date.
func TestEndDatesCountAgainstTheLastSuperAdminGuard(t *testing.T) {
	c := newCast(t)
	root := c.super
	other := c.user(c.primary.ID, "esa", model.RoleSuperAdmin)
	next := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)

	if _, err := c.svc.UpdateUser(c.ctx, actor(root), other.ID, service.UserInput{ValidUntil: ptr(next)}); err != nil {
		t.Fatalf("end-date the other while one without an end date remains: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(other), root.ID, service.UserInput{ValidUntil: ptr(next)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("mutual end-dating: want ErrLastAdmin, got %v", err)
	}
	// Disabling the only one without an end date next to an end-dated one is refused too.
	if _, err := c.svc.UpdateUser(c.ctx, actor(other), root.ID, service.UserInput{Active: ptr(false)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("disable the last lasting super admin: want ErrLastAdmin, got %v", err)
	}
	// Moving the end date later, or clearing it, is always fine.
	later := time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := c.svc.UpdateUser(c.ctx, actor(root), other.ID, service.UserInput{ValidUntil: ptr(later)}); err != nil {
		t.Fatalf("extend end date: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(root), other.ID, service.UserInput{ValidUntil: ptr("")}); err != nil {
		t.Fatalf("clear end date: %v", err)
	}

	// One past their end date is not usable: with only such a colleague, the remaining one is the last.
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := c.svc.UpdateUser(c.ctx, actor(root), other.ID, service.UserInput{ValidUntil: ptr(past)}); err != nil {
		t.Fatalf("end-date the other in the past: %v", err)
	}
	ghost := c.ghostSuper()
	if _, err := c.svc.UpdateUser(c.ctx, ghost, root.ID, service.UserInput{Active: ptr(false)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("disable next to an expired super admin: want ErrLastAdmin, got %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, ghost, root.ID, service.UserInput{Role: ptr(model.RoleUser)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Fatalf("demote next to an expired super admin: want ErrLastAdmin, got %v", err)
	}

	t.Run("the_only_super_admin", func(t *testing.T) {
		c := newCast(t)
		next := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		if _, err := c.svc.UpdateUser(c.ctx, c.ghostSuper(), c.super.ID, service.UserInput{ValidUntil: ptr(next)}); !errors.Is(err, service.ErrLastAdmin) {
			t.Fatalf("end-date the last super admin: want ErrLastAdmin, got %v", err)
		}
	})
}

// Concurrent removals of two super admins, where the server keeps all but one of the super admins it has: the admin lock
// serialises them and the count is fresh, so exactly one succeeds and the server keeps its minimum. The lock is
// released afterwards.
func TestConcurrentSuperAdminRemovalsLeaveTheMinimum(t *testing.T) {
	for _, keep := range []int{1, 2} {
		t.Run(fmt.Sprintf("keeping_%d", keep), func(t *testing.T) {
			for round := range 20 {
				e := newEnv(t)
				e.svc.MinSuperAdmins = keep
				supers := []*model.User{e.super}
				for range keep {
					supers = append(supers, e.user(e.primary.ID, e.next("sa"), model.RoleSuperAdmin))
				}
				// the two removals are of the last two super admins, one by a demotion and the other by disabling
				targets := supers[len(supers)-2:]
				errs := make([]error, 2)
				var wg sync.WaitGroup
				for i, u := range targets {
					wg.Go(func() {
						in := service.UserInput{Role: ptr(model.RoleUser)}
						if i == 1 {
							in = service.UserInput{Active: ptr(false)}
						}
						_, errs[i] = e.svc.UpdateUser(e.ctx, service.System, u.ID, in)
					})
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
				_, n, err := e.svc.Users.List(e.ctx, store.ListQuery{Scope: e.primary.ID, Filters: []store.Filter{
					{Field: "role", Value: "super_admin"}, {Field: "active", Value: true}}})
				if err != nil || n != keep {
					t.Fatalf("round %d: %d active super admins left, want %d (%v)", round, n, keep, err)
				}
				// Released: the holder deletes the lock record (lease.release).
				if l, err := e.svc.Locks.Get(e.ctx, "admins/"+e.primary.ID); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("round %d: the admin lock was not released: %+v %v", round, l, err)
				}
			}
		})
	}
}

func TestCurbsAdmin(t *testing.T) {
	day := func(d int) *string { s := time.Now().UTC().AddDate(0, 0, d).Format(time.DateOnly); return &s }
	admin := &model.User{Role: model.RoleAdmin, Active: true}
	super := &model.User{Role: model.RoleSuperAdmin, Active: true}
	manager := &model.User{Role: model.RoleManager, Active: true}
	soon := &model.User{Role: model.RoleAdmin, Active: true, ValidUntil: ptr(time.Now().UTC().AddDate(0, 0, 10))}
	for _, tc := range []struct {
		name string
		u    *model.User
		in   service.UserInput
		want bool
	}{
		{"demote admin", admin, service.UserInput{Role: ptr(model.RoleManager)}, true},
		{"keep role", admin, service.UserInput{Role: ptr(model.RoleAdmin)}, false},
		{"promote manager", manager, service.UserInput{Role: ptr(model.RoleAdmin)}, false},
		{"disable admin", admin, service.UserInput{Active: ptr(false)}, true},
		{"disable super", super, service.UserInput{Active: ptr(false)}, true},
		{"disable manager", manager, service.UserInput{Active: ptr(false)}, false},
		{"enable disabled admin", &model.User{Role: model.RoleAdmin}, service.UserInput{Active: ptr(true)}, false},
		{"disable already disabled", &model.User{Role: model.RoleAdmin}, service.UserInput{Active: ptr(false)}, false},
		{"end date on admin with none", admin, service.UserInput{ValidUntil: day(5)}, true},
		{"earlier end date", soon, service.UserInput{ValidUntil: day(2)}, true},
		{"later end date", soon, service.UserInput{ValidUntil: day(30)}, false},
		{"clear end date", soon, service.UserInput{ValidUntil: ptr("")}, false},
		{"unparsable end date", admin, service.UserInput{ValidUntil: ptr("soon")}, false},
		{"end date on manager", manager, service.UserInput{ValidUntil: day(1)}, false},
		{"nothing", admin, service.UserInput{}, false},
	} {
		if got := service.CurbsAdmin(tc.u, tc.in); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
