package service_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func newClient(t *testing.T, c *cast, a *service.Actor, orgID string, in service.ClientInput) (*model.Client, string, error) {
	t.Helper()
	if in.Name == nil {
		in.Name = ptr(c.next("client"))
	}
	if in.RedirectURIs == nil {
		in.RedirectURIs = ptr([]string{"https://app.example.com/cb"})
	}
	return c.svc.CreateClient(c.ctx, a, orgID, in)
}

func TestClientSCIMFlag(t *testing.T) {
	c := newCast(t)
	super, admin := actor(c.super), actor(c.aAdmin)

	// SCIM: super admin only ...
	if _, _, err := newClient(t, c, admin, c.a.ID, service.ClientInput{SCIM: ptr(true)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin set scim on create: %v", err)
	}
	sc, _, err := newClient(t, c, super, c.a.ID, service.ClientInput{SCIM: ptr(true)})
	if err != nil || !sc.SCIM {
		t.Fatalf("super scim: %v", err)
	}
	if _, err := c.svc.UpdateClient(c.ctx, admin, sc.ID, service.ClientInput{SCIM: ptr(false)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin cleared scim: %v", err)
	}
	plain, _, _ := newClient(t, c, admin, c.a.ID, service.ClientInput{})
	if _, err := c.svc.UpdateClient(c.ctx, admin, plain.ID, service.ClientInput{SCIM: ptr(true)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin enabled scim: %v", err)
	}
	// ... and a provisioning client is managed by super admins only: any change, its secret, its deletion.
	for name, in := range map[string]service.ClientInput{
		"description": {Description: ptr("d")},
		"redirect":    {RedirectURIs: ptr([]string{"https://attacker.example/cb"})},
		"first party": {FirstParty: ptr(true)},
	} {
		if _, err := c.svc.UpdateClient(c.ctx, admin, sc.ID, in); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("org admin %s on a scim client: %v", name, err)
		}
	}
	if _, err := c.svc.RotateClientSecret(c.ctx, admin, sc.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("org admin rotated a scim client's secret: %v", err)
	}
	if err := c.svc.DeleteClient(c.ctx, admin, sc.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("org admin deleted a scim client: %v", err)
	}
	if _, err := c.svc.UpdateClient(c.ctx, super, sc.ID, service.ClientInput{Description: ptr("d")}); err != nil {
		t.Errorf("super admin edit: %v", err)
	}
}

func TestClientSecretLifecycle(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	cl, secret, err := newClient(t, c, a, c.a.ID, service.ClientInput{})
	if err != nil {
		t.Fatal(err)
	}
	if !service.VerifyClientSecret(cl, secret) || service.VerifyClientSecret(cl, secret+"x") || service.VerifyClientSecret(cl, "") {
		t.Error("secret verification")
	}
	if cl.SecretHash == secret {
		t.Error("secret stored in clear")
	}
	if !cl.Enabled || cl.AuthMethod != model.AuthMethodSecretPost {
		t.Errorf("defaults %+v", cl)
	}
	secret2, err := c.svc.RotateClientSecret(c.ctx, a, cl.ID)
	if err != nil || secret2 == secret {
		t.Fatal(err)
	}
	cl, _ = c.svc.Clients.Get(c.ctx, cl.ID)
	if service.VerifyClientSecret(cl, secret) || !service.VerifyClientSecret(cl, secret2) {
		t.Error("old secret still works after rotation")
	}
	// Other org's admin cannot see it.
	if _, err := c.svc.GetClient(c.ctx, actor(c.bAdmin), cl.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-org get: %v", err)
	}
}

func TestClientValidation(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	cases := []struct {
		name  string
		in    service.ClientInput
		field string
	}{
		{"no name", service.ClientInput{Name: nil, RedirectURIs: ptr([]string{"https://a.example.com"})}, "name"},
		{"http redirect", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"http://a.example.com/cb"})}, "redirect_uris"},
		{"fragment", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"https://a.example.com/cb#f"})}, "redirect_uris"},
		{"custom scheme", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"app://cb"})}, "redirect_uris"},
		{"no redirect", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{})}, "redirect_uris"},
		{"grant", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"https://a.example.com/cb"}), GrantTypes: ptr([]string{"implicit"})}, "grant_types"},
		{"auth method", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"https://a.example.com/cb"}), AuthMethod: ptr("client_secret_jwt")}, "token_endpoint_auth_method"},
		{"alg", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"https://a.example.com/cb"}), SigningAlg: ptr("HS256")}, "id_token_signed_response_alg"},
		{"private jwt without keys", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"https://a.example.com/cb"}), AuthMethod: ptr("private_key_jwt")}, "jwks"},
		{"jwks_uri http", service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"https://a.example.com/cb"}), JWKSURI: ptr("http://a.example.com/jwks")}, "jwks_uri"},
	}
	for _, tc := range cases {
		_, _, err := c.svc.CreateClient(c.ctx, a, c.a.ID, tc.in)
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("%s: want field %s, got %v", tc.name, tc.field, err)
		}
	}
	// http loopback is allowed; a client_credentials-only client needs no redirect.
	if _, _, err := c.svc.CreateClient(c.ctx, a, c.a.ID, service.ClientInput{Name: ptr("dev"),
		RedirectURIs: ptr([]string{"http://localhost:3000/cb", "http://127.0.0.1/cb"})}); err != nil {
		t.Errorf("loopback: %v", err)
	}
	if _, _, err := c.svc.CreateClient(c.ctx, a, c.a.ID, service.ClientInput{Name: ptr("m2m"),
		GrantTypes: ptr([]string{"client_credentials"}), RedirectURIs: ptr([]string{})}); err != nil {
		t.Errorf("m2m: %v", err)
	}
}

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

func TestPublicClients(t *testing.T) {
	c := newCast(t)
	admin, super := actor(c.aAdmin), actor(c.super)
	none := ptr("none")
	fieldOf := func(err error) string {
		var fe *service.FieldError
		if errors.As(err, &fe) {
			return fe.Field
		}
		return ""
	}
	cl, secret, err := newClient(t, c, admin, c.a.ID, service.ClientInput{AuthMethod: none})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || cl.SecretHash != "" || !cl.Public() || !cl.RotateRefresh {
		t.Errorf("public client: secret=%q hash=%q public=%v rotate=%v", secret, cl.SecretHash, cl.Public(), cl.RotateRefresh)
	}
	// Rotation cannot be switched off.
	cl, err = c.svc.UpdateClient(c.ctx, admin, cl.ID, service.ClientInput{RotateRefresh: ptr(false)})
	if err != nil || !cl.RotateRefresh {
		t.Errorf("rotate must stay on: %v", err)
	}
	if service.VerifyClientSecret(cl, "") || service.VerifyClientSecret(cl, "qsrs_anything") {
		t.Error("secret check passed for public client")
	}
	if _, err := c.svc.RotateClientSecret(c.ctx, admin, cl.ID); fieldOf(err) != "token_endpoint_auth_method" {
		t.Errorf("rotate secret on public client: %v", err)
	}
	// Forbidden combinations.
	if _, _, err := newClient(t, c, admin, c.a.ID, service.ClientInput{AuthMethod: none,
		GrantTypes: ptr([]string{"client_credentials"})}); fieldOf(err) != "grant_types" {
		t.Errorf("none + client_credentials: %v", err)
	}
	if _, _, err := newClient(t, c, super, c.a.ID, service.ClientInput{AuthMethod: none, SCIM: ptr(true)}); fieldOf(err) != "scim" {
		t.Errorf("none + scim: %v", err)
	}
	// Switching an existing confidential client to public is validated too.
	conf, _, _ := newClient(t, c, admin, c.a.ID, service.ClientInput{GrantTypes: ptr([]string{"client_credentials"})})
	if _, err := c.svc.UpdateClient(c.ctx, admin, conf.ID, service.ClientInput{AuthMethod: none}); fieldOf(err) != "grant_types" {
		t.Errorf("switch to public with client_credentials: %v", err)
	}
	// Redirect URI rules.
	for uri, ok := range map[string]bool{
		"com.example.app:/callback":  true,
		"myapp:/cb":                  false,
		"http://localhost:8123/cb":   true,
		"http://127.0.0.1:9/cb":      true,
		"http://app.example.com/cb":  false,
		"https://app.example.com/cb": true,
	} {
		_, _, err := newClient(t, c, admin, c.a.ID, service.ClientInput{AuthMethod: none, RedirectURIs: ptr([]string{uri})})
		if ok && err != nil {
			t.Errorf("redirect %q rejected: %v", uri, err)
		}
		if !ok && fieldOf(err) != "redirect_uris" {
			t.Errorf("redirect %q should be rejected: %v", uri, err)
		}
	}
}

func TestClientScopeValidation(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	bad := []string{"has space", "quo\"te", "back\\slash", "caf\u00e9", "tab\there", strings.Repeat("x", 101)}
	for _, sc := range bad {
		_, _, err := newClient(t, c, a, c.a.ID, service.ClientInput{Scopes: ptr([]string{"openid", sc})})
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "scopes" {
			t.Errorf("scope %q: want scopes error, got %v", sc, err)
		}
	}
	many := make([]string, 51)
	for i := range many {
		many[i] = "s" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if _, _, err := newClient(t, c, a, c.a.ID, service.ClientInput{Scopes: ptr(many)}); err == nil {
		t.Error("51 scopes accepted")
	}
	// custom scopes are kept in order, trimmed, without blanks or duplicates
	cl, _, err := newClient(t, c, a, c.a.ID, service.ClientInput{Scopes: ptr([]string{"openid", " orders:read ", "", "orders:read", "https://api.example/scope.v1", "profile"})})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(cl.Scopes, ","), "openid,orders:read,https://api.example/scope.v1,profile"; got != want {
		t.Errorf("scopes = %s, want %s", got, want)
	}
	// an empty list clears the scopes
	cl, err = c.svc.UpdateClient(c.ctx, a, cl.ID, service.ClientInput{Scopes: ptr([]string{})})
	if err != nil || len(cl.Scopes) != 0 {
		t.Errorf("clear: %v %v", cl, err)
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
