package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Editing yourself from the users page sends the whole form: fields left as they are are not changes, so the rules
// about changing yourself apply only to what differs. A super admin may set their own work details and user type
// (nobody is above them); anyone else may not, and nobody sets their own end date.
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

// Nobody changes their own role, disables or deletes themselves.
func TestSelfGuards(t *testing.T) {
	c := newCast(t)
	for _, ac := range c.actors() {
		a := actor(ac.u)
		// Nobody changes their own role.
		other := model.RoleUser
		if ac.u.Role == model.RoleUser {
			other = model.RoleManager
		}
		_, err := c.svc.UpdateUser(c.ctx, a, ac.u.ID, service.UserInput{Role: &other})
		if err == nil {
			t.Errorf("%s changed own role", ac.name)
		}
		// Nobody disables themselves.
		_, err = c.svc.UpdateUser(c.ctx, a, ac.u.ID, service.UserInput{Active: ptr(false)})
		if err == nil {
			t.Errorf("%s disabled self", ac.name)
		}
		// Nobody deletes themselves.
		err = c.svc.DeleteUser(c.ctx, a, ac.u.ID)
		if !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s delete self: %v", ac.name, err)
		}
		u, _ := c.svc.Users.Get(c.ctx, ac.u.ID)
		if u == nil || u.Role != ac.u.Role || !u.Active {
			t.Errorf("%s was modified", ac.name)
		}
		// Re-submitting the unchanged role (a whole-form save) is no change, whatever the role.
		same := ac.u.Role
		if _, err := c.svc.UpdateUser(c.ctx, a, ac.u.ID, service.UserInput{Role: &same}); err != nil {
			t.Errorf("%s resubmit own role: %v", ac.name, err)
		}
	}
}

// A plain user edits their profile and password but nothing privileged; a manager edits their profile.
func TestSelfServiceProfile(t *testing.T) {
	c := newCast(t)
	// A plain user may edit their profile and password, but nothing privileged.
	u := actor(c.aUser)
	got, err := c.svc.UpdateUser(service.SelfService(c.ctx), u, c.aUser.ID, service.UserInput{FamilyName: ptr("Me"),
		GivenName: ptr("A"), Password: ptr("my-new-password-1")})
	if err != nil || got.FamilyName != "Me" || got.PasswordHash == "" {
		t.Fatalf("self update: %v %+v", err, got)
	}
	for name, in := range map[string]service.UserInput{
		"username": {Username: ptr("renamed")},
		"active":   {Active: ptr(false)}, // a value equal to the stored one is no change (a whole-form save)
		"external": {ExternalID: ptr("x")},
		"verified": {Verified: ptr(true)},
		"role":     {Role: ptr(model.RoleAdmin)},
	} {
		if _, err := c.svc.UpdateUser(c.ctx, u, c.aUser.ID, in); err == nil {
			t.Errorf("plain user could set %s", name)
		}
	}
	// A manager editing their own profile.
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aManager), c.aManager.ID, service.UserInput{FamilyName: ptr("Boss")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aManager), c.aManager.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err == nil {
		t.Fatal("manager promoted self")
	}
}

// Own password and email change only through the account page (SelfService): the management API, sessions or
// tokens, cannot bypass the current-password / re-authentication check.
func TestSelfCredentialsNeedAccountPage(t *testing.T) {
	c := newCast(t)
	for _, u := range []*model.User{c.aUser, c.aAdmin} {
		if _, err := c.svc.UpdateUser(c.ctx, actor(u), u.ID, service.UserInput{Password: ptr("my-new-password-1")}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: self password via UpdateUser: %v", u.Username, err)
		}
		if _, err := c.svc.UpdateUser(c.ctx, actor(u), u.ID, service.UserInput{Email: ptr("new-" + u.Email)}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: self email via UpdateUser: %v", u.Username, err)
		}
		if _, err := c.svc.UpdateUser(c.ctx, actor(u), u.ID, service.UserInput{Email: ptr(u.Email), FamilyName: ptr("ok")}); err != nil {
			t.Errorf("%s: unchanged email must be accepted: %v", u.Username, err)
		}
	}
}
