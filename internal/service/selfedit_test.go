package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Editing yourself from the users page sends the whole form: fields left as they are are not changes, so the rules
// about changing yourself apply only to what differs. A super admin may set their own work details, user type and end
// date (nobody is above them); anyone else may not.
func TestSelfEditWholeForm(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	form := func(u *model.User, given string) service.UserInput {
		w := u.Work
		return service.UserInput{Username: ptr(u.Username), GivenName: ptr(given), FamilyName: ptr(u.FamilyName),
			Role: ptr(u.Role), Active: ptr(u.Active), Tags: ptr(append([]string{}, u.Tags...)), UserType: ptr(u.UserType),
			ValidUntil: ptr(""), Work: &service.WorkInput{Title: ptr(w.Title), Department: ptr(w.Department),
				Organization: ptr(w.Organization), Division: ptr(w.Division), CostCenter: ptr(w.CostCenter),
				EmployeeNumber: ptr(w.EmployeeNumber), ManagerID: ptr(w.ManagerID)}}
	}
	admin := e.user(acme.ID, "adm", model.RoleAdmin)
	mgr := e.user(acme.ID, "mgr", model.RoleManager)
	for _, c := range []struct {
		name string
		u    *model.User
	}{{"super admin", e.super}, {"admin", admin}, {"manager", mgr}} {
		cur, _ := e.svc.Users.Get(e.ctx, c.u.ID)
		got, err := e.svc.UpdateUser(e.ctx, actor(cur), cur.ID, form(cur, "Renamed"))
		if err != nil || got.GivenName != "Renamed" {
			t.Errorf("%s renames themselves with the whole form: %v", c.name, err)
		}
		cur, _ = e.svc.Users.Get(e.ctx, c.u.ID)
		in := form(cur, cur.GivenName)
		in.Work.Department = ptr("Platform")
		_, err = e.svc.UpdateUser(e.ctx, actor(cur), cur.ID, in)
		if c.u.Role == model.RoleSuperAdmin && err != nil {
			t.Errorf("super admin sets their own department: %v", err)
		}
		if c.u.Role != model.RoleSuperAdmin && outcome(err) != "invalid" {
			t.Errorf("%s sets their own department: %v", c.name, err)
		}
	}
	// a manager still cannot change their own tags
	cur, _ := e.svc.Users.Get(e.ctx, mgr.ID)
	in := form(cur, cur.GivenName)
	in.Tags = ptr([]string{"vip"})
	if _, err := e.svc.UpdateUser(e.ctx, actor(cur), cur.ID, in); outcome(err) != "forbidden" {
		t.Errorf("manager tags themselves: %v", err)
	}
	// nor can an administrator, who could set these on anyone else: tags, username and external id; a super admin can
	for _, c := range []struct {
		field string
		set   func(*service.UserInput)
	}{
		{"tags", func(in *service.UserInput) { in.Tags = ptr([]string{"vip"}) }},
		{"username", func(in *service.UserInput) { in.Username = ptr("chosen") }},
		{"external_id", func(in *service.UserInput) { in.ExternalID = ptr("ext-1") }},
	} {
		for _, u := range []*model.User{admin, e.super} {
			cur, _ := e.svc.Users.Get(e.ctx, u.ID)
			in := form(cur, cur.GivenName)
			c.set(&in)
			_, err := e.svc.UpdateUser(e.ctx, actor(cur), cur.ID, in)
			if u.Role == model.RoleSuperAdmin && err != nil {
				t.Errorf("super admin sets their own %s: %v", c.field, err)
			}
			if u.Role != model.RoleSuperAdmin && outcome(err) != "forbidden" {
				t.Errorf("admin sets their own %s: %v", c.field, err)
			}
		}
	}
	// the administrator still sets them on someone else
	other := e.user(acme.ID, "other", model.RoleUser)
	cur, _ = e.svc.Users.Get(e.ctx, admin.ID)
	if _, err := e.svc.UpdateUser(e.ctx, actor(cur), other.ID, service.UserInput{Tags: ptr([]string{"vip"}),
		Username: ptr("other2"), ExternalID: ptr("ext-2")}); err != nil {
		t.Errorf("admin sets another user's tags, username and external id: %v", err)
	}
}
