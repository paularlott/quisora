package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestOrgAdministrationAuthorization(t *testing.T) {
	c := newCast(t)
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{
		{"super", c.super, "ok"}, {"primary admin", c.pAdmin, "forbidden"}, {"org admin", c.aAdmin, "forbidden"}, {"user", c.aUser, "forbidden"},
	} {
		_, err := c.svc.CreateOrg(c.ctx, actor(tc.u), service.OrgInput{Name: ptr(strings.ToLower(c.next("org")))})
		c.check(t, tc.name+" create", err, tc.want)
		_, err = c.svc.UpdateOrg(c.ctx, actor(tc.u), c.b.ID, service.OrgInput{DisplayName: ptr("B " + tc.name)})
		c.check(t, tc.name+" update", err, tc.want)
	}
	// non-super callers see only their own organization
	l, n, err := c.svc.ListOrgs(c.ctx, actor(c.aAdmin), store.ListQuery{})
	if err != nil || n != 1 || l[0].ID != c.a.ID {
		t.Errorf("admin list: %v %d", err, n)
	}
	if _, n, _ := c.svc.ListOrgs(c.ctx, actor(c.super), store.ListQuery{}); n < 3 {
		t.Errorf("super list: %d", n)
	}
	if _, err := c.svc.GetOrg(c.ctx, actor(c.aAdmin), c.b.ID); err == nil {
		t.Error("an admin read another organization")
	}
	if _, err := c.svc.GetOrg(c.ctx, actor(c.aUser), c.a.ID); err != nil {
		t.Errorf("own org: %v", err)
	}
	if _, _, err := c.svc.ListOrgs(c.ctx, &service.Actor{OrgID: "gone", Role: model.RoleAdmin}, store.ListQuery{}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("list for a missing org: %v", err)
	}
	if got, _ := c.svc.OrgByName(c.ctx, "org-b"); got == nil || got.ID != c.b.ID {
		t.Error("org by name")
	}
	if _, err := c.svc.OrgByName(c.ctx, "nope"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("org by unknown name: %v", err)
	}
}

func TestOrgInputValidation(t *testing.T) {
	c := newCast(t)
	sys := service.System
	for name, in := range map[string]service.OrgInput{
		"no name": {}, "upper": {Name: ptr("Org")}, "hyphen edge": {Name: ptr("-x")}, "long": {Name: ptr(strings.Repeat("a", 64))},
		"negative ttl":             {Name: ptr("ok1"), Settings: &model.OrgSettings{SessionTTL: -1}},
		"negative idle":            {Name: ptr("ok2"), Settings: &model.OrgSettings{SessionIdle: -1}},
		"ttl above server":         {Name: ptr("ok3"), Settings: &model.OrgSettings{SessionTTL: c.svc.Cfg.Session.TTL + 1}},
		"email codes without mail": {Name: ptr("ok4"), Settings: &model.OrgSettings{EmailCodes: true}},
	} {
		if _, err := c.svc.CreateOrg(c.ctx, sys, in); !isInvalid(err) {
			t.Errorf("create %s: %v", name, err)
		}
	}
	if _, err := c.svc.CreateOrg(c.ctx, sys, service.OrgInput{Name: ptr("org-a")}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
	o, err := c.svc.CreateOrg(c.ctx, sys, service.OrgInput{Name: ptr(" Fine ")})
	if err == nil {
		t.Errorf("untrimmed uppercase accepted: %v", o)
	}
	o, err = c.svc.CreateOrg(c.ctx, sys, service.OrgInput{Name: ptr(" fine "), DisplayName: ptr("  Fine Org ")})
	if err != nil || o.Name != "fine" || o.DisplayName != "Fine Org" {
		t.Fatalf("create: %v %+v", err, o)
	}
	if d, err := c.svc.DefaultTenant(c.ctx, o.ID); err != nil || d.Name != "default" {
		t.Errorf("new org's default tenant: %v", err)
	}
	for name, in := range map[string]service.OrgInput{
		"bad name": {Name: ptr("Bad Name")}, "empty display": {DisplayName: ptr(" ")},
		"negative": {Settings: &model.OrgSettings{SessionTTL: -5}},
		"too long": {Settings: &model.OrgSettings{SessionTTL: c.svc.Cfg.Session.TTL + 1}},
	} {
		if _, err := c.svc.UpdateOrg(c.ctx, sys, o.ID, in); !isInvalid(err) {
			t.Errorf("update %s: %v", name, err)
		}
	}
	if _, err := c.svc.UpdateOrg(c.ctx, sys, o.ID, service.OrgInput{Name: ptr("org-a")}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("rename onto another: %v", err)
	}
	if _, err := c.svc.UpdateOrg(c.ctx, sys, "missing", service.OrgInput{}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown org: %v", err)
	}
	got, err := c.svc.UpdateOrg(c.ctx, sys, o.ID, service.OrgInput{Name: ptr("renamed"), DisplayName: ptr("R"), Settings: &model.OrgSettings{RequireMFA: true, SessionTTL: 60}})
	if err != nil || got.Name != "renamed" || !got.Settings.RequireMFA {
		t.Fatalf("update: %v", err)
	}
	// a lifetime saved before the server's limit does not block saving other settings
	got.Settings.SessionTTL = c.svc.Cfg.Session.TTL + 100
	if err := c.svc.Orgs.Update(c.ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateOrg(c.ctx, sys, o.ID, service.OrgInput{Settings: &model.OrgSettings{SessionTTL: got.Settings.SessionTTL, RequireMFA: false}}); err != nil {
		t.Errorf("unchanged old lifetime refused: %v", err)
	}
	if len(c.audited(o.ID, "org.update")) != 2 {
		t.Error("updates not audited")
	}
}

func TestSetPrimaryOrgRefusalsAndCounters(t *testing.T) {
	c := newCast(t)
	if _, _, err := c.svc.SetPrimaryOrg(c.ctx, "missing", c.aAdmin.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown org: %v", err)
	}
	if _, _, err := c.svc.SetPrimaryOrg(c.ctx, c.primary.ID, c.pAdmin.ID); !isInvalid(err) {
		t.Errorf("already primary: %v", err)
	}
	if _, _, err := c.svc.SetPrimaryOrg(c.ctx, c.a.ID, c.bAdmin.ID); !isInvalid(err) {
		t.Errorf("an admin of another org as the super admin: %v", err)
	}
	if _, _, err := c.svc.SetPrimaryOrg(c.ctx, c.a.ID, "nobody"); !isInvalid(err) {
		t.Errorf("unknown super admin: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.aManager.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.SetPrimaryOrg(c.ctx, c.a.ID, c.aManager.ID); !isInvalid(err) {
		t.Errorf("disabled super admin: %v", err)
	}
	if p, _ := c.svc.PrimaryOrg(c.ctx); p.ID != c.primary.ID {
		t.Fatal("primary moved by refused calls")
	}
	// A server-wide sign-out before the move: its counters move with the primary role.
	if _, err := c.svc.SignOutServer(c.ctx, actor(c.super), service.SignOutOptions{Reason: "x", APITokens: true}); err != nil {
		t.Fatal(err)
	}
	old, demoted, err := c.svc.SetPrimaryOrg(c.ctx, c.a.ID, c.aAdmin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.ID != c.primary.ID || old.Primary || len(demoted) != 1 || demoted[0].ID != c.super.ID || demoted[0].Role != model.RoleAdmin {
		t.Errorf("old %+v demoted %+v", old, demoted)
	}
	if p, _ := c.svc.PrimaryOrg(c.ctx); p.ID != c.a.ID || p.ServerSignOut.Sessions == 0 || p.ServerSignOut.APITokens == 0 || p.LastServerSignOut == nil {
		t.Errorf("new primary %+v", p)
	}
	if got := c.fresh(c.aAdmin); got.Role != model.RoleSuperAdmin {
		t.Errorf("new super admin role %v", got.Role)
	}
	// the demoted super admin no longer acts as one
	if c.svc.CanAdminOrg(actor(c.fresh(c.super)), c.b.ID) {
		t.Error("demoted super admin still administers other organizations")
	}
	if !c.svc.CanAdminOrg(actor(c.fresh(c.aAdmin)), c.b.ID) {
		t.Error("new super admin cannot administer other organizations")
	}
}

func TestClientValidationBranches(t *testing.T) {
	c := newCast(t)
	sys := service.System
	base := func() service.ClientInput {
		return service.ClientInput{Name: ptr(c.next("cl")), RedirectURIs: ptr([]string{"https://app.example.com/cb"})}
	}
	foreignTenant, _ := c.svc.CreateTenant(c.ctx, sys, c.b.ID, service.TenantInput{Name: ptr("theirs")})
	for name, mod := range map[string]func(*service.ClientInput){
		"foreign tenant":         func(in *service.ClientInput) { in.TenantID = &foreignTenant.ID },
		"unknown tenant":         func(in *service.ClientInput) { in.TenantID = ptr("nope") },
		"empty name":             func(in *service.ClientInput) { in.Name = ptr(" ") },
		"long name":              func(in *service.ClientInput) { in.Name = ptr(strings.Repeat("n", 201)) },
		"http redirect":          func(in *service.ClientInput) { in.RedirectURIs = ptr([]string{"http://evil.example.com/cb"}) },
		"fragment redirect":      func(in *service.ClientInput) { in.RedirectURIs = ptr([]string{"https://a.example.com/cb#x"}) },
		"bad post logout":        func(in *service.ClientInput) { in.PostLogoutURIs = ptr([]string{"javascript:alert(1)"}) },
		"http backchannel":       func(in *service.ClientInput) { in.BackchannelURI = ptr("http://a.example.com/bc") },
		"unknown grant":          func(in *service.ClientInput) { in.GrantTypes = ptr([]string{"password"}) },
		"bad scope":              func(in *service.ClientInput) { in.Scopes = ptr([]string{"a b"}) },
		"bad resource":           func(in *service.ClientInput) { in.Resources = ptr([]string{"not absolute"}) },
		"bad auth method":        func(in *service.ClientInput) { in.AuthMethod = ptr("password") },
		"bad alg":                func(in *service.ClientInput) { in.SigningAlg = ptr("none") },
		"http jwks uri":          func(in *service.ClientInput) { in.JWKSURI = ptr("http://a.example.com/jwks") },
		"private key no keys":    func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodPrivateJWT) },
		"fapi needs private key": func(in *service.ClientInput) { in.FAPI = ptr(true) },
		"public with pkce off": func(in *service.ClientInput) {
			in.AuthMethod, in.RequirePKCE = ptr(model.AuthMethodNone), ptr(false)
		},
		"public token exchange": func(in *service.ClientInput) {
			in.AuthMethod, in.GrantTypes = ptr(model.AuthMethodNone), ptr([]string{service.GrantTokenExchange})
		},
		"auth code without redirect": func(in *service.ClientInput) { in.RedirectURIs = ptr([]string{}) },
		"too many resources": func(in *service.ClientInput) {
			var r []string
			for i := 0; i < 21; i++ {
				r = append(r, "https://r"+itoa(i)+".example.com/")
			}
			in.Resources = &r
		},
	} {
		in := base()
		mod(&in)
		if _, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n, _, _ := c.svc.ListClients(c.ctx, sys, c.a.ID, store.ListQuery{}); len(n) != 0 {
		t.Errorf("%d clients stored by refused requests", len(n))
	}
	// FAPI with its requirements: PAR, DPoP and no refresh rotation follow from the profile
	jwks := `{"keys":[]}`
	in := base()
	in.AuthMethod, in.FAPI, in.JWKS, in.SigningAlg = ptr(model.AuthMethodPrivateJWT), ptr(true), &jwks, ptr("ES256")
	cl, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, in)
	if err != nil || !cl.RequirePAR || !cl.DPoPBound || cl.RotateRefresh {
		t.Fatalf("fapi client: %v %+v", err, cl)
	}
	rs := base()
	rs.AuthMethod, rs.FAPI, rs.JWKS, rs.SigningAlg = ptr(model.AuthMethodPrivateJWT), ptr(true), &jwks, ptr("RS256")
	if _, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, rs); !isInvalid(err) {
		t.Errorf("fapi with RS256: %v", err)
	}
	dc := base()
	dc.AuthMethod, dc.FAPI, dc.JWKS, dc.GrantTypes = ptr(model.AuthMethodPrivateJWT), ptr(true), &jwks, ptr([]string{"authorization_code", service.GrantDeviceCode})
	if _, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, dc); !isInvalid(err) {
		t.Errorf("fapi with device code: %v", err)
	}
	pk := base()
	pk.AuthMethod, pk.FAPI, pk.JWKS, pk.RequirePKCE = ptr(model.AuthMethodPrivateJWT), ptr(true), &jwks, ptr(false)
	if _, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, pk); !isInvalid(err) {
		t.Errorf("fapi without PKCE: %v", err)
	}
	// a public client always rotates refresh tokens and cannot introspect
	pub := base()
	pub.AuthMethod, pub.IntrospectOrg, pub.RotateRefresh = ptr(model.AuthMethodNone), ptr(true), ptr(false)
	p, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, pub)
	if err != nil || !p.RotateRefresh || p.IntrospectOrg {
		t.Errorf("public client: %v %+v", err, p)
	}
	// loopback http redirects and app schemes are accepted
	ok := base()
	ok.RedirectURIs = ptr([]string{"http://localhost:8080/cb", "http://127.0.0.1/cb", "com.example.app:/callback", " "})
	if got, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, ok); err != nil || len(got.RedirectURIs) != 3 {
		t.Errorf("loopback and app scheme redirects: %v", err)
	}
}

func TestClientAdministrationAuthorization(t *testing.T) {
	c := newCast(t)
	cl, _, err := c.svc.CreateClient(c.ctx, actor(c.aAdmin), c.a.ID, service.ClientInput{Name: ptr("app"), RedirectURIs: ptr([]string{"https://app.example.com/cb"})})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{{"manager", c.aManager, "forbidden"}, {"user", c.aUser, "forbidden"}, {"foreign admin", c.bAdmin, "forbidden"}, {"admin", c.aAdmin, "ok"}} {
		_, _, err := c.svc.ListClients(c.ctx, actor(tc.u), c.a.ID, store.ListQuery{})
		c.check(t, tc.name+" list", err, tc.want)
		_, _, err = c.svc.CreateClient(c.ctx, actor(tc.u), c.a.ID, service.ClientInput{Name: ptr(c.next("x")), RedirectURIs: ptr([]string{"https://app.example.com/cb"})})
		c.check(t, tc.name+" create", err, tc.want)
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
	// resource indicators
	for v, want := range map[string]bool{"https://api.example.com/": true, "urn:example:api": true, "api.example.com": false, "https://a/#f": false,
		" https://a.example.com/": false, "https://": false, "https://" + strings.Repeat("a", 520) + ".com/": false} {
		if service.ValidResource(v) != want {
			t.Errorf("ValidResource(%q) != %v", v, want)
		}
	}
	// FirstParty and SCIM are super admin flags
	for _, in := range []service.ClientInput{{FirstParty: ptr(true)}, {SCIM: ptr(true)}} {
		if _, err := c.svc.UpdateClient(c.ctx, actor(c.aAdmin), cl.ID, in); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("admin setting a super-only flag: %v", err)
		}
	}
	if got, _ := c.svc.GetClient(c.ctx, service.System, cl.ID); got.FirstParty || got.SCIM {
		t.Error("super-only flag set by an admin")
	}
}
