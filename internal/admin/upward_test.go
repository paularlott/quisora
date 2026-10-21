package admin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Nobody changes a user of a higher role: a manager manages plain users, an administrator everyone but super admins.
// Every change through the management API is refused and leaves the user as it was, and the API tells the console so
// (can_manage), which then shows that user read-only.
func TestNoUpwardEdits(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	primary, _ := w.env.Svc.PrimaryOrg(ctx)
	mk := func(name string, role model.Role) *model.User {
		u, err := w.env.Svc.CreateUser(ctx, service.System, primary.ID, service.UserInput{GivenName: ptr("P"), Username: ptr(name),
			Email: ptr(name + "@p.example"), Role: &role, Password: ptr("correct horse battery")})
		if err != nil {
			t.Fatal(err)
		}
		w.users[name] = u
		return u
	}
	mk("pmgr", model.RoleManager)
	padmin := mk("padmin", model.RoleAdmin)
	super := w.env.Admin
	for _, u := range []*model.User{super, padmin} {
		if _, err := w.env.Svc.AddLinkedEmail(ctx, service.System, u.ID, "extra-"+strings.ReplaceAll(string(u.Role), "_", "-")+"@p.example", false); err != nil {
			t.Fatal(err)
		}
	}
	base := "/api/orgs/" + primary.Name + "/users/"
	for _, c := range []struct {
		who    string
		target *model.User
	}{{"pmgr", super}, {"pmgr", padmin}, {"padmin", super}} {
		caller := w.as(c.who)
		before, _ := w.env.Svc.Users.Get(ctx, c.target.ID)
		u := base + c.target.ID
		extra := "extra-" + strings.ReplaceAll(string(c.target.Role), "_", "-") + "@p.example"
		for name, call := range map[string]func() resp{
			"edit name":       func() resp { return caller.patch(u, map[string]any{"given_name": "Changed"}) },
			"edit phone":      func() resp { return caller.patch(u, map[string]any{"phone_number": "+441234567890"}) },
			"edit tags":       func() resp { return caller.patch(u, map[string]any{"tags": []string{"x"}}) },
			"edit email":      func() resp { return caller.patch(u, map[string]any{"email": "other@p.example"}) },
			"disable":         func() resp { return caller.patch(u, map[string]any{"active": false}) },
			"delete":          func() resp { return caller.delete(u) },
			"remove password": func() resp { return caller.delete(u + "/password") },
			"lock out":        func() resp { return caller.post(u+"/lock-out", map[string]any{}) },
			"invite":          func() resp { return caller.post(u+"/invite", map[string]any{}) },
			"add address":     func() resp { return caller.post(u+"/emails", map[string]any{"address": "new@p.example"}) },
			"remove address":  func() resp { return caller.delete(u + "/emails/" + extra) },
			"make primary":    func() resp { return caller.post(u+"/emails/"+extra+"/primary", nil) },
			"send verify":     func() resp { return caller.post(u+"/emails/"+extra+"/verify", nil) },
			"mark verified":   func() resp { return caller.post(u+"/emails/"+extra+"/mark-verified", nil) },
			"sign out":        func() resp { return caller.delete(u + "/sessions") },
			"one session":     func() resp { return caller.delete(u + "/sessions/x") },
			"remove app":      func() resp { return caller.delete(u + "/apps/x") },
			"unlink provider": func() resp { return caller.delete(u + "/providers/x") },
			"remove passkey":  func() resp { return caller.delete(u + "/passkeys/x") },
			"revoke token":    func() resp { return caller.delete(u + "/tokens/x") },
		} {
			if r := call(); r.Status != 403 && r.Status != 404 {
				t.Errorf("%s -> %s: %s answered %d %s", c.who, c.target.Role, name, r.Status, r.Raw)
			}
		}
		after, _ := w.env.Svc.Users.Get(ctx, c.target.ID)
		if after.GivenName != before.GivenName || after.Email != before.Email || after.PhoneNumber != before.PhoneNumber || !after.Active ||
			len(after.LinkedEmails) != len(before.LinkedEmails) || after.PasswordHash != before.PasswordHash {
			t.Errorf("%s -> %s: the user changed", c.who, c.target.Role)
		}
		// the console is told: a super admin does not exist below them; an administrator is a directory entry to a
		// manager, which cannot be managed
		r := caller.get(u)
		if c.target.Role == model.RoleSuperAdmin {
			want(t, r, 404)
		} else if r.JSON["can_manage"] != false || r.JSON["directory"] != true {
			t.Errorf("%s -> %s: can_manage %v, directory %v", c.who, c.target.Role, r.JSON["can_manage"], r.JSON["directory"])
		}
		for _, it := range caller.get(base[:len(base)-1] + "?limit=100").items() {
			if row := it.(map[string]any); row["id"] == c.target.ID && (c.target.Role == model.RoleSuperAdmin || row["can_manage"] != false) {
				t.Errorf("%s -> %s: listed as %v", c.who, c.target.Role, row)
			}
		}
	}
	// and true where the change is allowed
	if r := w.as("padmin").get(base + w.users["pmgr"].ID); r.JSON["can_manage"] != true {
		t.Errorf("admin -> manager: can_manage %v", r.JSON["can_manage"])
	}
}
