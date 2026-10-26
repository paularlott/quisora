package service_test

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestProviderValidationAndConflicts(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	if _, err := c.svc.CreateProvider(c.ctx, a, c.a.ID, goodProvider("okta")); err != nil {
		t.Fatal(err)
	}
	_, err := c.svc.CreateProvider(c.ctx, a, c.a.ID, goodProvider("OKTA"))
	var fe *service.FieldError
	if !errors.As(err, &fe) || fe.Field != "name" || !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate provider: %v", err)
	}
	// Same name in another org is fine.
	if _, err := c.svc.CreateProvider(c.ctx, actor(c.bAdmin), c.b.ID, goodProvider("okta")); err != nil {
		t.Errorf("provider in other org: %v", err)
	}
	bad := []service.ProviderInput{
		{Name: ptr("a"), Issuer: ptr("http://x.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s")},
		{Name: ptr("b"), Issuer: ptr("https://x.example.com"), ClientSecret: ptr("s")},
		{Name: ptr("c"), Issuer: ptr("https://x.example.com"), ClientID: ptr("c")},
		{Type: ptr("saml"), Name: ptr("d"), ClientID: ptr("c"), ClientSecret: ptr("s")},
	}
	for i, in := range bad {
		if _, err := c.svc.CreateProvider(c.ctx, a, c.a.ID, in); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("bad provider %d: %v", i, err)
		}
	}
	// The secret is sealed, never stored in clear.
	p, _ := c.svc.CreateProvider(c.ctx, a, c.a.ID, goodProvider("sealed"))
	if p.ClientSecret == "csecret" || p.ClientSecret == "" {
		t.Errorf("secret not sealed: %q", p.ClientSecret)
	}
}

func TestProviderAllowedDomains(t *testing.T) {
	c := newCast(t)
	in := func(d ...string) service.ProviderInput {
		return service.ProviderInput{Type: ptr(model.ProviderGitHub), Name: ptr("GH " + strings.Join(d, ",")), ClientID: ptr("cid"),
			ClientSecret: ptr("s"), AllowedDomains: &d}
	}
	p, err := c.svc.CreateProvider(c.ctx, actor(c.aAdmin), c.a.ID, in(" Example.COM ", "@corp.example.org", "example.com", ""))
	if err != nil || !slices.Equal(p.AllowedDomains, []string{"example.com", "corp.example.org"}) {
		t.Fatalf("normalised: %v %v", err, p)
	}
	if p, err := c.svc.CreateProvider(c.ctx, actor(c.aAdmin), c.a.ID, in()); err != nil || len(p.AllowedDomains) != 0 {
		t.Fatalf("none (any address): %v %v", err, p)
	}
	for _, bad := range []string{"not a domain", "localhost", "-x.example", "a..example", "http://example.com"} {
		_, err := c.svc.CreateProvider(c.ctx, actor(c.aAdmin), c.a.ID, in("ok.example", bad))
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "allowed_domains" || !strings.HasPrefix(fe.Msg, bad+" ") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestProviderTypes(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	mk := func(in service.ProviderInput) (*model.Provider, error) {
		in.ClientID, in.ClientSecret = ptr("cid"), ptr("sec")
		return c.svc.CreateProvider(c.ctx, a, c.a.ID, in)
	}
	// Presets: issuer and default button label per type.
	for _, tc := range []struct {
		typ, issuerIn, issuer, name string
	}{
		{model.ProviderGoogle, "", "https://accounts.google.com", "Google"},
		{model.ProviderGitLab, "", "https://gitlab.com", "GitLab"},
		{model.ProviderGitLab, "git.example.com/", "https://git.example.com", "GitLab"},
		{model.ProviderAuth0, "acme.eu.auth0.com", "https://acme.eu.auth0.com/", "Auth0"},
		{model.ProviderAuth0, "https://login.acme.example/", "https://login.acme.example/", "Auth0"},
	} {
		p, err := mk(service.ProviderInput{Type: ptr(tc.typ), Issuer: ptr(tc.issuerIn), Name: ptr("")})
		if err != nil || p.Issuer != tc.issuer || p.Name != tc.name || !slices.Equal(p.Scopes, []string{"openid", "profile", "email"}) {
			t.Errorf("%s %q: %v %+v", tc.typ, tc.issuerIn, err, p)
		}
		if p != nil {
			_ = c.svc.DeleteProvider(c.ctx, a, p.ID)
		}
	}
	if _, err := mk(service.ProviderInput{Type: ptr(model.ProviderAuth0)}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("auth0 without a domain: %v", err)
	}
	if _, err := mk(service.ProviderInput{Type: ptr(model.ProviderGitLab), Issuer: ptr("http://git.example.com")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("gitlab over http: %v", err)
	}

	// Microsoft: a tenant ID alone, or "organizations" with the allowed tenant IDs.
	tid := "72f988bf-86f1-41af-91ab-2d7cd011db47"
	p, err := mk(service.ProviderInput{Type: ptr(model.ProviderMicrosoft), Tenant: ptr(strings.ToUpper(tid)), AllowedTenants: &[]string{tid}})
	if err != nil || p.Tenant != tid || p.AllowedTenants != nil || p.Issuer != model.MicrosoftAuthority+"/"+tid+"/v2.0" || p.Name != "Microsoft" {
		t.Fatalf("single tenant: %v %+v", err, p)
	}
	_ = c.svc.DeleteProvider(c.ctx, a, p.ID)
	p, err = mk(service.ProviderInput{Type: ptr(model.ProviderMicrosoft), Tenant: ptr("organizations"), AllowedTenants: &[]string{tid, " " + tid}})
	if err != nil || !slices.Equal(p.AllowedTenants, []string{tid}) {
		t.Fatalf("organizations: %v %+v", err, p)
	}
	_ = c.svc.DeleteProvider(c.ctx, a, p.ID)
	for name, in := range map[string]service.ProviderInput{
		"no tenant":              {Type: ptr(model.ProviderMicrosoft)},
		"organizations, no list": {Type: ptr(model.ProviderMicrosoft), Tenant: ptr("organizations")},
		"common (personal)":      {Type: ptr(model.ProviderMicrosoft), Tenant: ptr("common")},
		"bad allowed tenant":     {Type: ptr(model.ProviderMicrosoft), Tenant: ptr("organizations"), AllowedTenants: &[]string{"contoso"}},
		"unknown type":           {Type: ptr("saml")},
	} {
		if _, err := mk(in); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Tenant fields belong to Microsoft only.
	p, err = mk(service.ProviderInput{Type: ptr(model.ProviderGoogle), Tenant: ptr(tid), AllowedTenants: &[]string{tid}})
	if err != nil || p.Tenant != "" || p.AllowedTenants != nil {
		t.Errorf("tenant on google: %v %+v", err, p)
	}
}

// A provider's scopes follow the client rule (RFC 6749 scope tokens): each goes into the upstream authorization
// request, so one with a space or a quote is refused rather than stored; blanks and repeats are dropped.
func TestProviderScopes(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	in := goodProvider("scopes")
	in.Scopes = &[]string{"openid", " email ", "openid", "", "api://app/access_as_user"}
	p, err := c.svc.CreateProvider(c.ctx, a, c.a.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Scopes, " ") != "openid email api://app/access_as_user" {
		t.Errorf("scopes %q", p.Scopes)
	}
	for i, bad := range badScopes {
		in := goodProvider("bad-" + strconv.Itoa(i))
		in.Scopes = &[]string{"openid", bad}
		var fe *service.FieldError
		if _, err := c.svc.CreateProvider(c.ctx, a, c.a.ID, in); !errors.As(err, &fe) || fe.Field != "scopes" {
			t.Errorf("scope %q: %v", bad, err)
		}
	}
}

// Only the organization's admins list, create, change and delete its providers; a manager or a foreign admin is told
// nothing of an existing one; trusting a provider's second factor is a super admin's decision.
func TestProviderAdministrationIsOrgAdminOnly(t *testing.T) {
	c := newCast(t)
	p, err := c.svc.CreateProvider(c.ctx, actor(c.aAdmin), c.a.ID, goodProvider("sso"))
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]*model.User{"manager": c.aManager, "foreign admin": c.bAdmin} {
		if _, err := c.svc.GetProvider(c.ctx, actor(a), p.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s get: %v", name, err)
		}
		if _, err := c.svc.UpdateProvider(c.ctx, actor(a), p.ID, service.ProviderInput{Name: ptr("x")}); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s update: %v", name, err)
		}
		if err := c.svc.DeleteProvider(c.ctx, actor(a), p.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s delete: %v", name, err)
		}
	}
	if got, _ := c.svc.GetProvider(c.ctx, nil, p.ID); got == nil || got.Name != "sso" {
		t.Error("provider changed or deleted by a foreign actor")
	}
	if _, err := c.svc.UpdateProvider(c.ctx, actor(c.aAdmin), p.ID, service.ProviderInput{TrustMFA: ptr(true)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin trusting MFA: %v", err)
	}
	if got, err := c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, service.ProviderInput{TrustMFA: ptr(true)}); err != nil || !got.TrustMFA {
		t.Errorf("super trusting MFA: %v", err)
	}
	if _, err := c.svc.UpdateProvider(c.ctx, actor(c.aAdmin), p.ID, service.ProviderInput{TrustMFA: ptr(true)}); err != nil {
		t.Errorf("unchanged TrustMFA by admin: %v", err)
	}
}

// A provider's id is a UUID that may be chosen once, its name is bounded, the Microsoft personal-accounts tenant is
// refused, and a GitHub provider needs no issuer; requests that are refused store nothing.
func TestProviderIdentityAndLimits(t *testing.T) {
	c := newCast(t)
	sys := service.System
	for name, in := range map[string]service.ProviderInput{
		"bad id":      {ID: ptr("NOT-A-UUID"), Name: ptr("x"), Issuer: ptr("https://i.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s")},
		"long name":   {Name: ptr(strings.Repeat("n", 101)), Issuer: ptr("https://i.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s")},
		"ms personal": {Type: ptr(model.ProviderMicrosoft), Name: ptr("x"), ClientID: ptr("c"), ClientSecret: ptr("s"), Tenant: ptr("consumers")},
	} {
		if _, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n, _ := c.svc.Providers.Count(c.ctx, c.a.ID); n != 0 {
		t.Errorf("%d providers stored by refused requests", n)
	}
	gh, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, service.ProviderInput{Type: ptr(model.ProviderGitHub), Name: ptr("gh"), ClientID: ptr("c"), ClientSecret: ptr("s")})
	if err != nil || gh.Issuer != "" || len(gh.Scopes) != 2 {
		t.Errorf("github %+v %v", gh, err)
	}
	id := "0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b"
	custom := goodProvider("custom")
	custom.ID = &id
	if p, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, custom); err != nil || p.ID != id {
		t.Fatalf("chosen id: %v", err)
	}
	dup := goodProvider("other")
	dup.ID = &id
	if _, err := c.svc.CreateProvider(c.ctx, sys, c.a.ID, dup); !errors.Is(err, service.ErrConflict) {
		t.Errorf("reused id: %v", err)
	}
	if _, err := c.svc.UpdateProvider(c.ctx, sys, gh.ID, service.ProviderInput{Name: ptr("custom")}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("rename onto another: %v", err)
	}
}

// Pointing a provider at another issuer makes its subjects mean other people: every link goes, a new secret is
// needed, and the audit event records it (without the secret).
func TestProviderAuthorityChangeUnlinksIdentities(t *testing.T) {
	c := newCast(t)
	sys := service.System
	p, _ := c.svc.CreateProvider(c.ctx, sys, c.a.ID, goodProvider("sso"))
	q, _ := c.svc.CreateProvider(c.ctx, sys, c.a.ID, goodProvider("other"))
	c.link(c.aUser, p, "s1")
	c.link(c.aManager, p, "s2")
	c.link(c.aAdmin, q, "s3")

	if _, err := c.svc.UpdateProvider(c.ctx, sys, p.ID, service.ProviderInput{Issuer: ptr("https://evil.example.com")}); !isInvalid(err) {
		t.Fatalf("new issuer without a new secret: %v", err)
	}
	if n, _ := c.svc.Identities.Count(c.ctx, c.aUser.ID); n != 1 {
		t.Fatal("links removed by a refused update")
	}
	got, err := c.svc.UpdateProvider(c.ctx, sys, p.ID, service.ProviderInput{Issuer: ptr("https://other-issuer.example.com"), ClientSecret: ptr("new-secret")})
	if err != nil || got.Issuer != "https://other-issuer.example.com" {
		t.Fatalf("update: %v", err)
	}
	for _, u := range []*model.User{c.aUser, c.aManager} {
		if n, _ := c.svc.Identities.Count(c.ctx, u.ID); n != 0 {
			t.Errorf("%s keeps a link to the repointed provider", u.Username)
		}
	}
	if n, _ := c.svc.Identities.Count(c.ctx, c.aAdmin.ID); n != 1 {
		t.Error("another provider's link removed")
	}
	ev := c.audited(c.a.ID, "provider.update")
	if len(ev) != 1 {
		t.Fatalf("audit events %d", len(ev))
	}
	if d := ev[0].Detail; d["identities_unlinked"] != "2" || d["client_secret"] != "replaced" {
		t.Errorf("audit detail %v", d)
	}
	for _, v := range ev[0].Detail {
		if strings.Contains(v, "new-secret") {
			t.Error("secret in audit detail")
		}
	}
	// a rename alone keeps the links
	if _, err := c.svc.UpdateProvider(c.ctx, sys, q.ID, service.ProviderInput{Name: ptr("renamed")}); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.svc.Identities.Count(c.ctx, c.aAdmin.ID); n != 1 {
		t.Error("link lost on rename")
	}
	if err := c.svc.DeleteProvider(c.ctx, actor(c.aAdmin), q.ID); err != nil {
		t.Fatal(err)
	}
	if len(c.audited(c.a.ID, "provider.delete")) != 1 {
		t.Error("delete not audited")
	}
	en, err := c.svc.EnabledProviders(c.ctx, c.a.ID)
	if err != nil || len(en) != 1 || en[0].ID != p.ID {
		t.Errorf("enabled providers %v %v", en, err)
	}
}
