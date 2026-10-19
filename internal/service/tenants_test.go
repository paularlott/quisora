package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
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
	// Cascade org deletion removes tenants.
	if err := c.svc.DeleteOrg(c.ctx, actor(c.super), c.b.ID, true); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.svc.Tenants.Count(c.ctx, c.b.ID); n != 0 {
		t.Fatalf("tenants left after cascade: %d", n)
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
