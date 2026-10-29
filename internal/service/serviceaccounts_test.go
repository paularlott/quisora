package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// newServiceAccount creates a service account of orgID with scopes (made by a super admin) and returns it with the
// actor of a token carrying all of them.
func newServiceAccount(t *testing.T, c *cast, orgID string, scopes ...string) (*model.Client, *service.Actor) {
	t.Helper()
	sa, _, err := c.svc.CreateServiceAccount(c.ctx, actor(c.super), orgID, service.ServiceAccountInput{Name: ptr(c.next("sa")), Scopes: &scopes})
	if err != nil {
		t.Fatal(err)
	}
	return sa, service.ActorForServiceAccount(sa, scopes, "1.2.3.4")
}

// Who may give which scope: an org admin every scope of the organization but import; a super admin import too, and
// orgs:create and orgs:delete on the primary organization only; a service account only scopes it holds. Managers
// cannot touch service accounts at all.
func TestServiceAccountGrants(t *testing.T) {
	c := newCast(t)
	super, admin := actor(c.super), actor(c.aAdmin)
	in := func(scopes ...string) service.ServiceAccountInput {
		return service.ServiceAccountInput{Name: ptr(c.next("sa")), Scopes: &scopes}
	}
	sa, secret, err := c.svc.CreateServiceAccount(c.ctx, admin, c.a.ID, in("users", "admins", "groups", "providers", "tenants", "clients", "access", "scim", "service_accounts"))
	if err != nil || secret == "" || !sa.ServiceAccount || sa.TenantID != "" || len(sa.GrantTypes) != 1 || sa.GrantTypes[0] != "client_credentials" {
		t.Fatalf("org admin creates: %+v %v", sa, err)
	}
	for name, scopes := range map[string][]string{"import": {"import"}, "orgs:create": {"orgs:create"}, "unknown": {"backup"}, "none": {}} {
		if _, _, err := c.svc.CreateServiceAccount(c.ctx, admin, c.a.ID, in(scopes...)); fieldOf(err) != "scopes" {
			t.Errorf("org admin grants %s: %v", name, err)
		}
	}
	if _, _, err := c.svc.CreateServiceAccount(c.ctx, actor(c.aManager), c.a.ID, in("users")); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager creates: %v", err)
	}
	if _, _, err := c.svc.ListServiceAccounts(c.ctx, actor(c.aManager), c.a.ID, store.ListQuery{}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager lists: %v", err)
	}
	if _, _, err := c.svc.CreateServiceAccount(c.ctx, actor(c.bAdmin), c.a.ID, in("users")); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("another org's admin creates: %v", err)
	}
	// A super admin gives import anywhere, and orgs:* on the primary organization alone.
	if _, _, err := c.svc.CreateServiceAccount(c.ctx, super, c.a.ID, in("users", "import")); err != nil {
		t.Errorf("super grants import: %v", err)
	}
	if _, _, err := c.svc.CreateServiceAccount(c.ctx, super, c.a.ID, in("orgs:create")); fieldOf(err) != "scopes" {
		t.Errorf("orgs:create outside the primary org: %v", err)
	}
	if _, _, err := c.svc.CreateServiceAccount(c.ctx, super, c.primary.ID, in("orgs:create", "orgs:delete")); err != nil {
		t.Errorf("super grants orgs:* in the primary org: %v", err)
	}
	if _, _, err := c.svc.CreateServiceAccount(c.ctx, actor(c.pAdmin), c.primary.ID, in("orgs:create")); fieldOf(err) != "scopes" {
		t.Errorf("primary org admin grants orgs:create: %v", err)
	}
	// A service account gives no more than it holds, and leaves alone an account that holds more.
	_, sva := newServiceAccount(t, c, c.a.ID, "users", "service_accounts")
	if _, _, err := c.svc.CreateServiceAccount(c.ctx, sva, c.a.ID, in("users")); err != nil {
		t.Errorf("service account gives a scope it holds: %v", err)
	}
	if _, _, err := c.svc.CreateServiceAccount(c.ctx, sva, c.a.ID, in("users", "clients")); fieldOf(err) != "scopes" {
		t.Errorf("service account gives a scope it lacks: %v", err)
	}
	if _, err := c.svc.UpdateServiceAccount(c.ctx, sva, c.a.ID, sa.ID, service.ServiceAccountInput{Description: ptr("x")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("service account changes one holding more: %v", err)
	}
	if _, err := c.svc.RotateServiceAccountSecret(c.ctx, sva, c.a.ID, sa.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("service account rotates one holding more: %v", err)
	}
	// An org admin leaves alone an account with import (a super admin's grant), and may take scopes away.
	imp, _ := newServiceAccount(t, c, c.a.ID, "users", "import")
	if err := c.svc.DeleteServiceAccount(c.ctx, admin, c.a.ID, imp.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("org admin deletes an import account: %v", err)
	}
	if upd, err := c.svc.UpdateServiceAccount(c.ctx, admin, c.a.ID, sa.ID, service.ServiceAccountInput{Scopes: &[]string{"users"}}); err != nil || len(upd.Scopes) != 1 {
		t.Errorf("org admin narrows scopes: %v", err)
	}
}

// Service accounts are not applications: the client routes neither list nor reach them, and a client cannot become one.
func TestServiceAccountNotAClient(t *testing.T) {
	c := newCast(t)
	admin := actor(c.aAdmin)
	sa, _ := newServiceAccount(t, c, c.a.ID, "users")
	if _, err := c.svc.GetClient(c.ctx, admin, sa.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("get as a client: %v", err)
	}
	if _, err := c.svc.UpdateClient(c.ctx, admin, sa.ID, service.ClientInput{GrantTypes: ptr([]string{"authorization_code"})}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("update as a client: %v", err)
	}
	if err := c.svc.DeleteClient(c.ctx, admin, sa.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("delete as a client: %v", err)
	}
	l, _, err := c.svc.ListClients(c.ctx, admin, c.a.ID, store.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, cl := range l {
		if cl.ID == sa.ID {
			t.Error("a service account is listed among the clients")
		}
	}
	got, _, err := c.svc.ListServiceAccounts(c.ctx, admin, c.a.ID, store.ListQuery{})
	if err != nil || len(got) != 1 || got[0].ID != sa.ID {
		t.Errorf("service accounts: %v %v", got, err)
	}
	if _, err := c.svc.GetServiceAccount(c.ctx, actor(c.bAdmin), c.b.ID, sa.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("another org's service account: %v", err)
	}
}

// A token's scopes count only while the account still holds them.
func TestServiceAccountActorScopes(t *testing.T) {
	sa := &model.Client{Meta: model.Meta{ID: "c_x"}, OrgID: "o", Name: "deploy", Scopes: []string{"users"}}
	a := service.ActorForServiceAccount(sa, []string{"users", "clients"}, "")
	if !a.HasScope("users") || a.HasScope("clients") || a.HasScope(service.ScopeAdmin) || a.Role != model.RoleAdmin ||
		a.Name != "service:deploy" || a.ClientID != "c_x" || a.UserID != "" {
		t.Fatalf("actor %+v", a)
	}
}

// Without the admins scope a service account manages plain users and managers only; with it, administrators too, but
// never a super admin.
func TestServiceAccountRoles(t *testing.T) {
	c := newCast(t)
	_, users := newServiceAccount(t, c, c.a.ID, "users")
	_, admins := newServiceAccount(t, c, c.a.ID, "users", "admins")
	mk := func(a *service.Actor, role model.Role) error {
		n := c.next("u")
		_, err := c.svc.CreateUser(c.ctx, a, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: &n, Email: ptr(n + "@example.com"), Role: &role})
		return err
	}
	if err := mk(users, model.RoleManager); err != nil {
		t.Errorf("users: manager: %v", err)
	}
	if err := mk(users, model.RoleAdmin); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("users: admin: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, users, c.aAdmin.ID, service.UserInput{FamilyName: ptr("X")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("users: changes an admin: %v", err)
	}
	if err := mk(admins, model.RoleAdmin); err != nil {
		t.Errorf("admins: admin: %v", err)
	}
	if err := mk(admins, model.RoleSuperAdmin); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admins: super admin: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, admins, c.aAdmin.ID, service.UserInput{FamilyName: ptr("X")}); err != nil {
		t.Errorf("admins: changes an admin: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, admins, c.aManager.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err != nil {
		t.Errorf("admins: promotes: %v", err)
	}
}

// The import scope lets a service account bring authenticator secrets (and password hashes) into its organization.
func TestServiceAccountImport(t *testing.T) {
	c := newCast(t)
	_, plain := newServiceAccount(t, c, c.a.ID, "users")
	_, imp := newServiceAccount(t, c, c.a.ID, "users", "import")
	mk := func(a *service.Actor) error {
		n := c.next("u")
		_, err := c.svc.CreateUser(c.ctx, a, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: &n, Email: ptr(n + "@example.com"),
			TOTPSecret: ptr("JBSWY3DPEHPK3PXP")})
		return err
	}
	if err := mk(plain); fieldOf(err) != "totp_secret" {
		t.Errorf("without import: %v", err)
	}
	if err := mk(imp); err != nil {
		t.Errorf("with import: %v", err)
	}
}

// A primary-org service account with orgs:create creates an organization with its first service account, which may
// hold any of the organization's scopes (import too); with orgs:delete it deletes the organizations it created, and
// only those.
func TestServiceAccountOrgLifecycle(t *testing.T) {
	c := newCast(t)
	_, deploy := newServiceAccount(t, c, c.primary.ID, "orgs:create", "orgs:delete")
	_, other := newServiceAccount(t, c, c.primary.ID, "orgs:delete")
	first := &service.ServiceAccountInput{Name: ptr("setup"), Scopes: &[]string{"users", "admins", "import", "tenants", "clients", "providers", "service_accounts"}}
	o, sa, secret, err := c.svc.CreateOrgWithServiceAccount(c.ctx, deploy, service.OrgInput{Name: ptr("fortix-one"), ServiceAccount: first})
	if err != nil || sa == nil || secret == "" || sa.OrgID != o.ID || !sa.ServiceAccount || o.CreatedBy != deploy.ClientID {
		t.Fatalf("create: %+v %+v %v", o, sa, err)
	}
	// The new account works in the new organization: it creates an administrator there.
	setup := service.ActorForServiceAccount(sa, sa.Scopes, "")
	n := c.next("u")
	if _, err := c.svc.CreateUser(c.ctx, setup, o.ID, service.UserInput{GivenName: ptr("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleAdmin)}); err != nil {
		t.Errorf("first account creates an admin: %v", err)
	}
	// orgs:* never go to the first account, and a bad account leaves no organization behind.
	bad := &service.ServiceAccountInput{Name: ptr("x"), Scopes: &[]string{"orgs:create"}}
	if _, _, _, err := c.svc.CreateOrgWithServiceAccount(c.ctx, deploy, service.OrgInput{Name: ptr("fortix-two"), ServiceAccount: bad}); fieldOf(err) != "service_account.scopes" {
		t.Errorf("first account with orgs:create: %v", err)
	}
	if _, err := c.svc.OrgByName(c.ctx, "fortix-two"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("an organization was left behind: %v", err)
	}
	// Without orgs:create, no organization; the first account's import is the org creator's to give.
	if _, err := c.svc.CreateOrg(c.ctx, other, service.OrgInput{Name: ptr("fortix-three")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("create without orgs:create: %v", err)
	}
	// Deleting: only the creator's own organizations, never one a person made.
	if err := c.svc.DeleteOrg(c.ctx, other, o.ID, true); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("another service account deletes it: %v", err)
	}
	if err := c.svc.DeleteOrg(c.ctx, deploy, c.b.ID, true); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("deletes an org a person made: %v", err)
	}
	if err := c.svc.DeleteOrg(c.ctx, deploy, o.ID, true); err != nil {
		t.Errorf("creator deletes it: %v", err)
	}
}
