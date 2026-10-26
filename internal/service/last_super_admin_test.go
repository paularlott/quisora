package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
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

// Nobody curbs their own account: a super admin cannot demote, disable, end-date, lock out or delete themselves, nor
// change their own end date at all.
func TestSuperAdminCannotCurbThemselves(t *testing.T) {
	c := newCast(t)
	c.user(c.primary.ID, "second", model.RoleSuperAdmin)
	me := actor(c.super)
	later := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for name, f := range map[string]func() error{
		"demote": func() error {
			_, err := c.svc.UpdateUser(c.ctx, me, c.super.ID, service.UserInput{Role: ptr(model.RoleAdmin)})
			return err
		},
		"disable": func() error {
			_, err := c.svc.UpdateUser(c.ctx, me, c.super.ID, service.UserInput{Active: ptr(false)})
			return err
		},
		"end date": func() error {
			_, err := c.svc.UpdateUser(c.ctx, me, c.super.ID, service.UserInput{ValidUntil: ptr(later)})
			return err
		},
		"lock out": func() error { _, err := c.svc.LockOutUser(c.ctx, me, c.super.ID, "x"); return err },
		"delete":   func() error { return c.svc.DeleteUser(c.ctx, me, c.super.ID) },
	} {
		if err := f(); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s yourself: want a refusal, got %v", name, err)
		}
	}
	if got, err := c.svc.Users.Get(c.ctx, c.super.ID); err != nil || got.Role != model.RoleSuperAdmin || !got.Active || got.ValidUntil != nil {
		t.Errorf("a refused change altered the super admin: %+v %v", got, err)
	}
}

// Only a super admin curbs a super admin: an administrator or manager, in the primary organization or not, cannot
// demote, disable, end-date, lock out or delete one. A super admin can curb another.
func TestOnlyASuperAdminCurbsASuperAdmin(t *testing.T) {
	c := newCast(t)
	target := c.user(c.primary.ID, "target", model.RoleSuperAdmin)
	later := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for _, role := range []model.Role{model.RoleAdmin, model.RoleManager} {
		by := actor(c.user(c.primary.ID, c.next("by"), role))
		for name, f := range map[string]func() error{
			"demote": func() error {
				_, err := c.svc.UpdateUser(c.ctx, by, target.ID, service.UserInput{Role: ptr(model.RoleUser)})
				return err
			},
			"disable": func() error {
				_, err := c.svc.UpdateUser(c.ctx, by, target.ID, service.UserInput{Active: ptr(false)})
				return err
			},
			"end date": func() error {
				_, err := c.svc.UpdateUser(c.ctx, by, target.ID, service.UserInput{ValidUntil: ptr(later)})
				return err
			},
			"lock out": func() error { _, err := c.svc.LockOutUser(c.ctx, by, target.ID, "x"); return err },
			"delete":   func() error { return c.svc.DeleteUser(c.ctx, by, target.ID) },
		} {
			if err := f(); !errors.Is(err, service.ErrForbidden) && !errors.Is(err, service.ErrNotFound) {
				t.Errorf("%s: %s a super admin: want a refusal, got %v", role, name, err)
			}
		}
	}
	if got, err := c.svc.Users.Get(c.ctx, target.ID); err != nil || got.Role != model.RoleSuperAdmin || !got.Active || got.ValidUntil != nil {
		t.Fatalf("a refused change altered the super admin: %+v %v", got, err)
	}
	// another super admin may
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), target.ID, service.UserInput{ValidUntil: ptr(later)}); err != nil {
		t.Errorf("a super admin end-dating another: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), target.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Errorf("a super admin disabling another: %v", err)
	}
	if err := c.svc.DeleteUser(c.ctx, actor(c.super), target.ID); err != nil {
		t.Errorf("a super admin deleting another: %v", err)
	}
}

// The system (housekeeping and the like) never demotes, disables, end-dates or deletes a super admin, and the end-date
// sweep leaves one whose end date has passed alone (the end date still stops its sign-in) while it disables others.
func TestSystemSparesSuperAdmins(t *testing.T) {
	c := newCast(t)
	target := c.user(c.primary.ID, "target", model.RoleSuperAdmin)
	later := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for name, f := range map[string]func() error{
		"demote": func() error {
			_, err := c.svc.UpdateUser(c.ctx, service.System, target.ID, service.UserInput{Role: ptr(model.RoleAdmin)})
			return err
		},
		"disable": func() error {
			_, err := c.svc.UpdateUser(c.ctx, service.System, target.ID, service.UserInput{Active: ptr(false)})
			return err
		},
		"end date": func() error {
			_, err := c.svc.UpdateUser(c.ctx, service.System, target.ID, service.UserInput{ValidUntil: ptr(later)})
			return err
		},
		"delete": func() error { return c.svc.DeleteUser(c.ctx, service.System, target.ID) },
	} {
		if err := f(); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("the system: %s a super admin: want a refusal, got %v", name, err)
		}
	}
	// what is not a curb is fine
	if _, err := c.svc.UpdateUser(c.ctx, service.System, target.ID, service.UserInput{ValidUntil: ptr("")}); err != nil {
		t.Errorf("the system clearing nothing: %v", err)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	plain := c.user(c.primary.ID, "plain", model.RoleUser)
	for _, id := range []string{target.ID, plain.ID} {
		if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), id, service.UserInput{ValidUntil: ptr(past)}); err != nil {
			t.Fatalf("end-date %s: %v", id, err)
		}
	}
	if n, err := c.svc.ExpireUsers(c.ctx); err != nil || n != 1 {
		t.Fatalf("the end-date sweep disabled %d, %v: want the plain user only", n, err)
	}
	if got, _ := c.svc.Users.Get(c.ctx, target.ID); !got.Active {
		t.Error("the end-date sweep disabled a super admin")
	}
	if got, _ := c.svc.Users.Get(c.ctx, plain.ID); got.Active {
		t.Error("the end-date sweep left a plain user active")
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
