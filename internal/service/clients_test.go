package service_test

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
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

// first_party skips consent, so its redirect URIs receive any user's code from a link they open: an org admin who
// could set it, or edit such a client, could act as a peer administrator. Like SCIM, it is super admins' alone.
func TestClientFirstPartyFlag(t *testing.T) {
	c := newCast(t)
	super, admin := actor(c.super), actor(c.aAdmin)

	if _, _, err := newClient(t, c, admin, c.a.ID, service.ClientInput{FirstParty: ptr(true)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin set first_party on create: %v", err)
	}
	plain, _, err := newClient(t, c, admin, c.a.ID, service.ClientInput{FirstParty: ptr(false)})
	if err != nil {
		t.Fatalf("admin creates a client, first_party false: %v", err)
	}
	if _, err := c.svc.UpdateClient(c.ctx, admin, plain.ID, service.ClientInput{FirstParty: ptr(true)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin enabled first_party: %v", err)
	}
	if _, err := c.svc.UpdateClient(c.ctx, admin, plain.ID, service.ClientInput{FirstParty: ptr(false), Description: ptr("d")}); err != nil {
		t.Errorf("admin edits an ordinary client, first_party unchanged: %v", err)
	}
	fp, _, err := newClient(t, c, super, c.a.ID, service.ClientInput{FirstParty: ptr(true)})
	if err != nil || !fp.FirstParty {
		t.Fatalf("super first_party: %v", err)
	}
	for name, in := range map[string]service.ClientInput{
		"clear":       {FirstParty: ptr(false)},
		"description": {Description: ptr("d")},
		"redirect":    {RedirectURIs: ptr([]string{"https://attacker.example/cb"})},
	} {
		if _, err := c.svc.UpdateClient(c.ctx, admin, fp.ID, in); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("org admin %s on a first-party client: %v", name, err)
		}
	}
	if _, err := c.svc.RotateClientSecret(c.ctx, admin, fp.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("org admin rotated a first-party client's secret: %v", err)
	}
	if err := c.svc.DeleteClient(c.ctx, admin, fp.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("org admin deleted a first-party client: %v", err)
	}
	if got, _ := c.svc.Clients.Get(c.ctx, fp.ID); got == nil || !got.FirstParty || slices.Contains(got.RedirectURIs, "https://attacker.example/cb") {
		t.Errorf("first-party client changed: %+v", got)
	}
	if _, err := c.svc.UpdateClient(c.ctx, super, fp.ID, service.ClientInput{FirstParty: ptr(false)}); err != nil {
		t.Errorf("super admin clears first_party: %v", err)
	}
	if err := c.svc.DeleteClient(c.ctx, admin, fp.ID); err != nil {
		t.Errorf("org admin deletes the client once it is ordinary: %v", err)
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
	foreignTenant, err := c.svc.CreateTenant(c.ctx, service.System, c.b.ID, service.TenantInput{Name: ptr("theirs")})
	if err != nil {
		t.Fatal(err)
	}
	jwks := `{"keys":[]}`
	// fapi is a client of the FAPI profile with private-key authentication and ES256, to which mod adds one fault
	fapi := func(mod func(*service.ClientInput)) service.ClientInput {
		in := service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"https://a.example.com/cb"}),
			AuthMethod: ptr(model.AuthMethodPrivateJWT), FAPI: ptr(true), JWKS: &jwks, SigningAlg: ptr("ES256")}
		mod(&in)
		return in
	}
	// with adds one fault to an otherwise good client
	with := func(mod func(*service.ClientInput)) service.ClientInput {
		in := service.ClientInput{Name: ptr("x"), RedirectURIs: ptr([]string{"https://a.example.com/cb"})}
		mod(&in)
		return in
	}
	var tooManyResources []string
	for i := range 21 {
		tooManyResources = append(tooManyResources, "https://r"+strconv.Itoa(i)+".example.com/")
	}
	cases := []struct {
		name  string
		in    service.ClientInput
		field string
	}{
		{"no name", service.ClientInput{Name: nil, RedirectURIs: ptr([]string{"https://a.example.com"})}, "name"},
		{"blank name", with(func(in *service.ClientInput) { in.Name = ptr(" ") }), "name"},
		{"long name", with(func(in *service.ClientInput) { in.Name = ptr(strings.Repeat("n", 201)) }), "name"},
		{"foreign tenant", with(func(in *service.ClientInput) { in.TenantID = &foreignTenant.ID }), "tenant_id"},
		{"unknown tenant", with(func(in *service.ClientInput) { in.TenantID = ptr("nope") }), "tenant_id"},
		{"post logout uri", with(func(in *service.ClientInput) { in.PostLogoutURIs = ptr([]string{"javascript:alert(1)"}) }), "post_logout_redirect_uris"},
		{"http backchannel", with(func(in *service.ClientInput) { in.BackchannelURI = ptr("http://a.example.com/bc") }), "backchannel_logout_uri"},
		{"resource not absolute", with(func(in *service.ClientInput) { in.Resources = ptr([]string{"not absolute"}) }), "resources"},
		{"too many resources", with(func(in *service.ClientInput) { in.Resources = &tooManyResources }), "resources"},
		{"public without PKCE", with(func(in *service.ClientInput) {
			in.AuthMethod, in.RequirePKCE = ptr(model.AuthMethodNone), ptr(false)
		}), "require_pkce"},
		{"public token exchange", with(func(in *service.ClientInput) {
			in.AuthMethod, in.GrantTypes = ptr(model.AuthMethodNone), ptr([]string{service.GrantTokenExchange})
		}), "grant_types"},
		{"fapi without private key", with(func(in *service.ClientInput) { in.FAPI = ptr(true) }), "token_endpoint_auth_method"},
		{"fapi with RS256", fapi(func(in *service.ClientInput) { in.SigningAlg = ptr("RS256") }), "id_token_signed_response_alg"},
		{"fapi with device code", fapi(func(in *service.ClientInput) {
			in.GrantTypes = ptr([]string{"authorization_code", service.GrantDeviceCode})
		}), "grant_types"},
		{"fapi without PKCE", fapi(func(in *service.ClientInput) { in.RequirePKCE = ptr(false) }), "require_pkce"},
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
	// an app scheme is accepted, and a blank redirect entry is dropped
	if got, _, err := c.svc.CreateClient(c.ctx, a, c.a.ID, service.ClientInput{Name: ptr("app"),
		RedirectURIs: ptr([]string{"com.example.app:/callback", " "})}); err != nil || len(got.RedirectURIs) != 1 {
		t.Errorf("app scheme redirect: %v", err)
	}
	// the FAPI profile brings its requirements with it: PAR, DPoP and no refresh rotation
	cl, _, err := c.svc.CreateClient(c.ctx, a, c.a.ID, fapi(func(in *service.ClientInput) { in.Name = ptr("fapi") }))
	if err != nil || !cl.RequirePAR || !cl.DPoPBound || cl.RotateRefresh {
		t.Fatalf("fapi client: %v %+v", err, cl)
	}
	// a public client always rotates refresh tokens and cannot introspect
	pub, _, err := c.svc.CreateClient(c.ctx, a, c.a.ID, with(func(in *service.ClientInput) {
		in.Name = ptr("public")
		in.AuthMethod, in.IntrospectOrg, in.RotateRefresh = ptr(model.AuthMethodNone), ptr(true), ptr(false)
	}))
	if err != nil || !pub.RotateRefresh || pub.IntrospectOrg {
		t.Errorf("public client: %v %+v", err, pub)
	}
	// the refused requests stored nothing
	if l, _, _ := c.svc.ListClients(c.ctx, a, c.a.ID, store.ListQuery{}); len(l) != 5 {
		t.Errorf("%d clients stored, want the 5 accepted", len(l))
	}
}

// Only the organization's admins list, create, change and delete its clients; a manager or a foreign admin is told
// nothing of an existing one, and a denied caller changes nothing. Resource indicators are absolute, short URIs.
func TestClientAdministrationIsOrgAdminOnly(t *testing.T) {
	c := newCast(t)
	cl, _, err := c.svc.CreateClient(c.ctx, actor(c.aAdmin), c.a.ID, service.ClientInput{Name: ptr("app"), RedirectURIs: ptr([]string{"https://app.example.com/cb"})})
	if err != nil {
		t.Fatal(err)
	}
	for name, u := range map[string]*model.User{"manager": c.aManager, "foreign admin": c.bAdmin} {
		if _, err := c.svc.GetClient(c.ctx, actor(u), cl.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s get: %v", name, err)
		}
		if _, err := c.svc.UpdateClient(c.ctx, actor(u), cl.ID, service.ClientInput{Name: ptr("x")}); err == nil {
			t.Errorf("%s update allowed", name)
		}
		if err := c.svc.DeleteClient(c.ctx, actor(u), cl.ID); err == nil {
			t.Errorf("%s delete allowed", name)
		}
		if _, err := c.svc.RotateClientSecret(c.ctx, actor(u), cl.ID); err == nil {
			t.Errorf("%s secret rotation allowed", name)
		}
	}
	if got, err := c.svc.GetClient(c.ctx, actor(c.super), cl.ID); err != nil || got.Name != "app" {
		t.Errorf("client changed by denied callers: %v", err)
	}
	for v, want := range map[string]bool{"https://api.example.com/": true, "urn:example:api": true, "api.example.com": false, "https://a/#f": false,
		" https://a.example.com/": false, "https://": false, "https://" + strings.Repeat("a", 520) + ".com/": false} {
		if service.ValidResource(v) != want {
			t.Errorf("ValidResource(%q) != %v", v, want)
		}
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
	for _, sc := range badScopes {
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
