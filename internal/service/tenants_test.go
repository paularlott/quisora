package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestTenantsLifecycleAndRBAC(t *testing.T) {
	c := newCast(t)
	// Every org starts with a default tenant.
	def, err := c.svc.DefaultTenant(c.ctx, c.a.ID)
	if err != nil || def.Name != model.DefaultTenantName || !def.Settings.AllProviders {
		t.Fatalf("default tenant: %v %+v", err, def)
	}
	if n, _ := c.svc.Tenants.Count(c.ctx, c.a.ID); n != 1 {
		t.Fatalf("org-a tenants: %d", n)
	}
	// Admins of the org (and super admins) manage tenants; managers, users and other orgs cannot.
	for name, a := range map[string]*service.Actor{"manager": actor(c.aManager), "user": actor(c.aUser), "other org": actor(c.bAdmin)} {
		if _, err := c.svc.CreateTenant(c.ctx, a, c.a.ID, service.TenantInput{Name: ptr("x")}); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("%s created tenant: %v", name, err)
		}
		if _, err := c.svc.GetTenant(c.ctx, a, def.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s read tenant: %v", name, err)
		}
	}
	ten, err := c.svc.CreateTenant(c.ctx, actor(c.aAdmin), c.a.ID, service.TenantInput{Name: ptr("portal"), DisplayName: ptr("Portal")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.CreateTenant(c.ctx, actor(c.super), c.a.ID, service.TenantInput{Name: ptr("portal")}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate tenant name: %v", err)
	}
	if _, err := c.svc.CreateTenant(c.ctx, actor(c.aAdmin), c.a.ID, service.TenantInput{Name: ptr("Bad Name")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("invalid name: %v", err)
	}

	// Clients belong to a tenant of their own org; the default tenant when none is given.
	cl, _, err := c.svc.CreateClient(c.ctx, actor(c.aAdmin), c.a.ID, service.ClientInput{Name: ptr("app"),
		RedirectURIs: ptr([]string{"https://app.example/cb"})})
	if err != nil || cl.TenantID != def.ID {
		t.Fatalf("client default tenant: %v %s", err, cl.TenantID)
	}
	bTen, _ := c.svc.DefaultTenant(c.ctx, c.b.ID)
	if _, err := c.svc.UpdateClient(c.ctx, actor(c.aAdmin), cl.ID, service.ClientInput{TenantID: &bTen.ID}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("client moved to another org's tenant: %v", err)
	}
	if _, err := c.svc.UpdateClient(c.ctx, actor(c.aAdmin), cl.ID, service.ClientInput{TenantID: &ten.ID}); err != nil {
		t.Fatal(err)
	}
	// A tenant with clients cannot be deleted.
	if err := c.svc.DeleteTenant(c.ctx, actor(c.aAdmin), ten.ID); !errors.Is(err, service.ErrTenantInUse) {
		t.Errorf("deleted tenant in use: %v", err)
	}
	if _, err := c.svc.UpdateClient(c.ctx, actor(c.aAdmin), cl.ID, service.ClientInput{TenantID: &def.ID}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.DeleteTenant(c.ctx, actor(c.aAdmin), ten.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.GetTenant(c.ctx, nil, ten.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("deleted tenant: %v", err)
	}
	if len(c.audited(c.a.ID, "tenant.delete")) != 1 {
		t.Error("delete not audited")
	}
}

// Admins of the organization and super admins list and create its tenants; a tenant is open to its members only and
// named as given; another organization's administrator cannot see, change or delete it.
func TestTenantAdministrationAndDefaults(t *testing.T) {
	c := newCast(t)
	ten, err := c.svc.CreateTenant(c.ctx, actor(c.aAdmin), c.a.ID, service.TenantInput{Name: ptr("crm")})
	if err != nil {
		t.Fatal(err)
	}
	if !ten.Settings.MembersOnly || ten.DisplayName != "crm" {
		t.Errorf("new tenant defaults: %+v", ten)
	}
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{
		{"org admin", c.aAdmin, "ok"}, {"manager", c.aManager, "forbidden"}, {"user", c.aUser, "forbidden"},
		{"other org admin", c.bAdmin, "forbidden"}, {"super", c.super, "ok"},
	} {
		_, _, err := c.svc.ListTenants(c.ctx, actor(tc.u), c.a.ID, store.ListQuery{})
		c.check(t, tc.name+" list", err, tc.want)
	}
	if _, err := c.svc.UpdateTenant(c.ctx, actor(c.bAdmin), ten.ID, service.TenantInput{Description: ptr("x")}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("update: %v", err)
	}
	if err := c.svc.DeleteTenant(c.ctx, actor(c.bAdmin), ten.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("delete: %v", err)
	}
	if got, _ := c.svc.GetTenant(c.ctx, nil, ten.ID); got == nil || got.Description != "" {
		t.Error("tenant changed by a foreign admin")
	}
	if _, err := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{}); !isInvalid(err) {
		t.Errorf("nameless tenant: %v", err)
	}
}

func TestEffectiveSignIn(t *testing.T) {
	c := newCast(t)
	org, _ := c.svc.Orgs.Get(c.ctx, c.a.ID)
	mk := func(name string) *model.Provider {
		p, err := c.svc.CreateProvider(c.ctx, actor(c.aAdmin), c.a.ID, service.ProviderInput{Type: ptr("oidc"), Name: ptr(name),
			Issuer: ptr("https://" + name + ".example.com"), ClientID: ptr("id"), ClientSecret: ptr("secret")})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	google, okta := mk("google"), mk("okta")
	// Org level: everything enabled.
	m, err := c.svc.EffectiveSignIn(c.ctx, org, nil)
	if err != nil || !m.Password || !m.Passkey || len(m.Providers) != 2 || m.RequireMFA {
		t.Fatalf("org methods: %v %+v", err, m)
	}
	// A tenant narrows: passkey + okta only, and requires MFA.
	ten, err := c.svc.CreateTenant(c.ctx, actor(c.aAdmin), c.a.ID, service.TenantInput{Name: ptr("staff"),
		Settings: &model.TenantSettings{PasskeyLogin: true, Providers: []string{okta.ID}, RequireMFA: true}})
	if err != nil {
		t.Fatal(err)
	}
	m, _ = c.svc.EffectiveSignIn(c.ctx, org, ten)
	if m.Password || !m.Passkey || len(m.Providers) != 1 || !m.AllowsProvider(okta.ID) || m.AllowsProvider(google.ID) || !m.RequireMFA {
		t.Fatalf("tenant methods: %+v", m)
	}
	// The org switch wins: a tenant cannot enable what the org disabled.
	org.Settings.PasskeyLogin = false
	m, _ = c.svc.EffectiveSignIn(c.ctx, org, ten)
	if m.Passkey {
		t.Fatal("tenant re-enabled a method the org disabled")
	}
	// Disabled providers are never offered.
	if _, err := c.svc.UpdateProvider(c.ctx, actor(c.aAdmin), okta.ID, service.ProviderInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	m, _ = c.svc.EffectiveSignIn(c.ctx, org, ten)
	if len(m.Providers) != 0 {
		t.Fatal("disabled provider offered")
	}
	// Providers of another org cannot be referenced.
	bp, err := c.svc.CreateProvider(c.ctx, actor(c.bAdmin), c.b.ID, service.ProviderInput{Type: ptr("oidc"), Name: ptr("b"),
		Issuer: ptr("https://b.example.com"), ClientID: ptr("id"), ClientSecret: ptr("s")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateTenant(c.ctx, actor(c.aAdmin), ten.ID, service.TenantInput{Settings: &model.TenantSettings{Providers: []string{bp.ID}}}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("foreign provider accepted: %v", err)
	}
}

// A client's tenant that cannot be read is a failed read, not a missing tenant: the access decision made from it
// must not be made from its absence.
func TestClientTenantReportsReadFailure(t *testing.T) {
	e := newEnv(t)
	tn, err := e.svc.DefaultTenant(e.ctx, e.primary.ID)
	if err != nil {
		t.Fatal(err)
	}
	c := &model.Client{OrgID: e.primary.ID, TenantID: tn.ID}
	e.svc.Tenants.S = failingReads(e.svc.Tenants.S, model.KindTenant)
	if _, err := e.svc.ClientTenant(e.ctx, c); err == nil || errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unreadable tenant: %v, want a read failure", err)
	}
	if _, err := e.svc.TenantForResources(e.ctx, e.primary.ID, []string{"https://api.example"}); err == nil || errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unreadable tenant by resource: %v, want a read failure", err)
	}
}

func TestTenantInputValidation(t *testing.T) {
	c := newCast(t)
	sys := service.System
	prov, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, goodProvider("sso"))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := c.svc.CreateProvider(c.ctx, sys, c.b.ID, goodProvider("sso"))
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 1001)
	for name, in := range map[string]service.TenantInput{
		"bad name":         {Name: ptr("Not Valid")},
		"empty display":    {Name: ptr("x"), DisplayName: ptr("  ")},
		"long display":     {Name: ptr("x"), DisplayName: ptr(strings.Repeat("d", 201))},
		"long desc":        {Name: ptr("x"), Description: &long},
		"foreign provider": {Name: ptr("x"), Settings: &model.TenantSettings{Providers: []string{foreign.ID}}},
		"bad resource":     {Name: ptr("x"), Resources: &[]string{"not a uri"}},
		"http resource":    {Name: ptr("x"), Resources: &[]string{"http://api.example.com/"}},
		"query resource":   {Name: ptr("x"), Resources: &[]string{"https://api.example.com/?a=1"}},
		"dup resource":     {Name: ptr("x"), Resources: &[]string{"https://api.example.com/x", "https://API.example.com/x/"}},
	} {
		if _, err := c.svc.CreateTenant(c.ctx, sys, c.a.ID, in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok, err := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("good"), Resources: &[]string{"https://api.example.com/", "http://127.0.0.1:8080/mcp"},
		Settings: &model.TenantSettings{Providers: []string{prov.ID, prov.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ok.Settings.Providers) != 1 || len(ok.Resources) != 2 {
		t.Errorf("tenant %+v", ok)
	}
	// All providers clears the list.
	updates := len(c.audited(c.a.ID, "tenant.update"))
	ok, err = c.svc.UpdateTenant(c.ctx, sys, ok.ID, service.TenantInput{Settings: &model.TenantSettings{AllProviders: true, Providers: []string{prov.ID}}})
	if err != nil || ok.Settings.Providers != nil {
		t.Errorf("all providers: %v %+v", err, ok.Settings)
	}
	// A resource belongs to one tenant of an organization; another organization's tenant may own the same one (its
	// own address space has its own tokens), and a second tenant of the organization may not.
	if _, err = c.svc.CreateTenant(c.ctx, sys, c.b.ID, service.TenantInput{Name: ptr("same"), Resources: &[]string{"https://api.example.com/"}}); err != nil {
		t.Errorf("the same resource in another organization: %v", err)
	}
	_, err = c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("thief"), Resources: &[]string{"https://api.example.com/"}})
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("shared resource: %v", err)
	}
	_, err = c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("good")})
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
	other, err := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("other")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.svc.UpdateTenant(c.ctx, sys, other.ID, service.TenantInput{Resources: &[]string{"https://api.example.com/"}})
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("update onto another tenant's resource: %v", err)
	}
	_, err = c.svc.UpdateTenant(c.ctx, sys, other.ID, service.TenantInput{Name: ptr("good")})
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("update onto another tenant's name: %v", err)
	}
	if n := len(c.audited(c.a.ID, "tenant.update")); n != updates+1 {
		t.Errorf("%d updates audited after one successful update (%d before)", n, updates)
	}
}

func TestTenantForResources(t *testing.T) {
	c := newCast(t)
	sys := service.System
	open, _ := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("open"),
		Resources: &[]string{"https://one.example.com/", "https://two.example.com/"}, Settings: &model.TenantSettings{SelfRegistration: true}})
	if _, err := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("closed"), Resources: &[]string{"https://closed.example.com/"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("other"), Resources: &[]string{"https://three.example.com/"},
		Settings: &model.TenantSettings{SelfRegistration: true}}); err != nil {
		t.Fatal(err)
	}
	got, err := c.svc.TenantForResources(c.ctx, c.a.ID, []string{"https://one.example.com/", "https://two.example.com/"})
	if err != nil || got.ID != open.ID {
		t.Fatalf("one tenant's resources: %v %v", got, err)
	}
	for name, res := range map[string][]string{
		"none":     nil,
		"unknown":  {"https://nobody.example.com/"},
		"spanning": {"https://one.example.com/", "https://three.example.com/"},
		"not open": {"https://closed.example.com/"},
	} {
		if _, err := c.svc.TenantForResources(c.ctx, c.a.ID, res); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the organization's resources are its own: another organization finds no tenant for them, and its own tenant for
	// the same resource is its own
	if _, err := c.svc.TenantForResources(c.ctx, c.b.ID, []string{"https://one.example.com/"}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("another organization's resource: %v", err)
	}
	theirs, err := c.svc.CreateTenant(c.ctx, sys, c.b.ID, service.TenantInput{Name: ptr("theirs"), Resources: &[]string{"https://one.example.com/"},
		Settings: &model.TenantSettings{SelfRegistration: true}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.svc.TenantForResources(c.ctx, c.b.ID, []string{"https://one.example.com/"}); err != nil || got.ID != theirs.ID {
		t.Errorf("the same resource in another organization: %v %v", got, err)
	}
	if got, err := c.svc.TenantForResources(c.ctx, c.a.ID, []string{"https://one.example.com/"}); err != nil || got.ID != open.ID {
		t.Errorf("the resource in the first organization: %v %v", got, err)
	}
}
