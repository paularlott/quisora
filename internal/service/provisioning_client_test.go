package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A provisioning (SCIM) service account acts as an admin of its own organization but cannot create or promote
// administrators, mint API tokens or reach other organizations.
func TestClientActorCannotGrantAdmin(t *testing.T) {
	c := newCast(t)
	cl, a := newServiceAccount(t, c, c.a.ID, "scim")
	if a.Role != model.RoleAdmin || !a.HasScope(service.ScopeSCIM) || a.HasScope(service.ScopeAdmin) || a.ClientID != cl.ID {
		t.Fatalf("unexpected client actor %+v", a)
	}
	n := c.next("c")
	if _, err := c.svc.CreateUser(c.ctx, a, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleAdmin)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client created admin: %v", err)
	}
	if _, err := c.svc.CreateUser(c.ctx, a, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleSuperAdmin)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client created super: %v", err)
	}
	m, err := c.svc.CreateUser(c.ctx, a, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleManager)})
	if err != nil {
		t.Fatalf("client creating manager: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, a, m.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client promoted to admin: %v", err)
	}
	// Other org is out of reach.
	n2 := c.next("c")
	if _, err := c.svc.CreateUser(c.ctx, a, c.b.ID, service.UserInput{GivenName: ptr("T"), Username: &n2, Email: ptr(n2 + "@example.com")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client in other org: %v", err)
	}
	// A client actor has no user id so it can neither mint nor list API tokens.
	if _, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "x", Scopes: []string{"api"}}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client minted token: %v", err)
	}
}

// Provisioning clients (SCIM client_credentials) never touch admins: no password reset, disable, delete or demote.
// A provisioning client never reaches administrators (their password, status, role, invitation or deletion), and never
// sets a password for anyone.
func TestProvisioningClientCannotTouchAdmins(t *testing.T) {
	c := newCast(t)
	_, a := newServiceAccount(t, c, c.a.ID, "scim")
	f := false
	role := model.RoleUser
	for name, in := range map[string]service.UserInput{
		"password": {Password: ptr("attacker-password-1")}, "disable": {Active: &f}, "demote": {Role: &role},
	} {
		if _, err := c.svc.UpdateUser(c.ctx, a, c.aAdmin.ID, in); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("%s admin: %v", name, err)
		}
	}
	if err := c.svc.DeleteUser(c.ctx, a, c.aAdmin.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("delete admin: %v", err)
	}
	// Plain users and managers remain manageable, but never get a password from the client: no setting it, and
	// no inviting or clearing the password of an admin.
	if _, err := c.svc.UpdateUser(c.ctx, a, c.aUser.ID, service.UserInput{Password: ptr("provisioned-pass-1")}); !errors.As(err, new(*service.FieldError)) {
		t.Errorf("plain user password: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, a, c.aUser.ID, service.UserInput{FamilyName: ptr("Renamed")}); err != nil {
		t.Errorf("plain user: %v", err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, a, c.aAdmin.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("invite admin: %v", err)
	}
	if err := c.svc.RemovePassword(c.ctx, a, c.aAdmin.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("remove admin password: %v", err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, a, c.aUser.ID); err != nil {
		t.Errorf("invite plain user: %v", err)
	}
}

// A provisioning client acts as an admin of its organization but never reaches administrators: not through group
// membership, nor through the tags (or deletion) of a group they belong to.
// A provisioning client never reaches administrators through groups either: not through membership, nor through the
// tags (or deletion) of a group they belong to.
func TestClientCannotManageAdminsThroughGroups(t *testing.T) {
	c := newCast(t)
	_, a := newServiceAccount(t, c, c.a.ID, "scim")
	g, err := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("staff")})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, c.aUser.ID, true); err != nil {
		t.Fatalf("client adds a user: %v", err)
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, c.aAdmin.ID, true); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("client adds an admin: %v", err)
	}
	// An admin puts themselves in the group: the client can neither remove them nor retag or delete the group.
	if err := c.svc.SetMembership(c.ctx, actor(c.aAdmin), g.ID, c.aAdmin.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.SetMembership(c.ctx, a, g.ID, c.aAdmin.ID, false); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("client removes an admin: %v", err)
	}
	if _, err := c.svc.UpdateGroup(c.ctx, a, g.ID, service.GroupInput{Tags: ptr([]string{"elevated"})}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("client tags an admin's group: %v", err)
	}
	if err := c.svc.DeleteGroup(c.ctx, a, g.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("client deletes an admin's group: %v", err)
	}
	// Renaming without touching tags is still fine, and so is everything for a group of plain users.
	if _, err := c.svc.UpdateGroup(c.ctx, a, g.ID, service.GroupInput{DisplayName: ptr("staff2")}); err != nil {
		t.Fatalf("client renames: %v", err)
	}
	plain, _ := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("plain")})
	_ = c.svc.SetMembership(c.ctx, a, plain.ID, c.aManager.ID, true)
	if _, err := c.svc.UpdateGroup(c.ctx, a, plain.ID, service.GroupInput{Tags: ptr([]string{"x"})}); err != nil {
		t.Fatalf("client tags a plain group: %v", err)
	}
	// An administrator is not limited.
	if err := c.svc.SetMembership(c.ctx, actor(c.aAdmin), plain.ID, c.aAdmin.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateGroup(c.ctx, actor(c.aAdmin), plain.ID, service.GroupInput{Tags: ptr([]string{"y"})}); err != nil {
		t.Fatalf("admin tags: %v", err)
	}
}
