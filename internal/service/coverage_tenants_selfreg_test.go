package service_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestTenantAdministrationAuthorization(t *testing.T) {
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
		_, err = c.svc.CreateTenant(c.ctx, actor(tc.u), c.a.ID, service.TenantInput{Name: ptr(c.next("tn"))})
		c.check(t, tc.name+" create", err, tc.want)
	}
	// another org's administrator cannot see, change or delete it: it does not exist for them
	if _, err := c.svc.GetTenant(c.ctx, actor(c.bAdmin), ten.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("get: %v", err)
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
		"empty display":    {Name: ptr("ok1"), DisplayName: ptr("  ")},
		"long display":     {Name: ptr("ok2"), DisplayName: ptr(strings.Repeat("d", 201))},
		"long desc":        {Name: ptr("ok3"), Description: &long},
		"foreign provider": {Name: ptr("ok4"), Settings: &model.TenantSettings{Providers: []string{foreign.ID}}},
		"bad resource":     {Name: ptr("ok5"), Resources: &[]string{"not a uri"}},
		"http resource":    {Name: ptr("ok6"), Resources: &[]string{"http://api.example.com/"}},
		"query resource":   {Name: ptr("ok7"), Resources: &[]string{"https://api.example.com/?a=1"}},
		"dup resource":     {Name: ptr("ok8"), Resources: &[]string{"https://api.example.com/x", "https://API.example.com/x/"}},
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
	ok, err = c.svc.UpdateTenant(c.ctx, sys, ok.ID, service.TenantInput{Settings: &model.TenantSettings{AllProviders: true, Providers: []string{prov.ID}}})
	if err != nil || ok.Settings.Providers != nil {
		t.Errorf("all providers: %v %+v", err, ok.Settings)
	}
	// A resource belongs to one tenant, server-wide.
	_, err = c.svc.CreateTenant(c.ctx, sys, c.b.ID, service.TenantInput{Name: ptr("thief"), Resources: &[]string{"https://api.example.com/"}})
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
	if len(c.audited(c.a.ID, "tenant.update")) != 1 {
		t.Error("update not audited exactly once")
	}
}

func TestDeleteTenantInUse(t *testing.T) {
	c := newCast(t)
	ten, _ := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{Name: ptr("busy")})
	if _, _, err := c.svc.CreateClient(c.ctx, service.System, c.a.ID, service.ClientInput{Name: ptr("app"), TenantID: &ten.ID,
		RedirectURIs: ptr([]string{"https://app.example.com/cb"})}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.DeleteTenant(c.ctx, actor(c.aAdmin), ten.ID); !errors.Is(err, service.ErrTenantInUse) {
		t.Fatalf("delete with clients: %v", err)
	}
	empty, _ := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{Name: ptr("idle")})
	if err := c.svc.DeleteTenant(c.ctx, actor(c.aAdmin), empty.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.GetTenant(c.ctx, nil, empty.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("deleted tenant: %v", err)
	}
	if len(c.audited(c.a.ID, "tenant.delete")) != 1 {
		t.Error("delete not audited")
	}
}

func TestTenantForResources(t *testing.T) {
	c := newCast(t)
	sys := service.System
	open, _ := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("open"),
		Resources: &[]string{"https://one.example.com/", "https://two.example.com/"}, Settings: &model.TenantSettings{SelfRegistration: true}})
	closed, _ := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("closed"), Resources: &[]string{"https://closed.example.com/"}})
	other, _ := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("other"), Resources: &[]string{"https://three.example.com/"},
		Settings: &model.TenantSettings{SelfRegistration: true}})
	_ = closed
	got, err := c.svc.TenantForResources(c.ctx, []string{"https://one.example.com/", "https://two.example.com/"})
	if err != nil || got.ID != open.ID {
		t.Fatalf("one tenant's resources: %v %v", got, err)
	}
	for name, res := range map[string][]string{
		"none":     nil,
		"unknown":  {"https://nobody.example.com/"},
		"spanning": {"https://one.example.com/", "https://three.example.com/"},
		"not open": {"https://closed.example.com/"},
	} {
		if _, err := c.svc.TenantForResources(c.ctx, res); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_ = other
}

func TestSelfRegistrationMetadataAndRedirects(t *testing.T) {
	c := newCast(t)
	bad := map[string]service.RegistrationInput{
		"confidential":  {AuthMethod: "client_secret_basic", RedirectURIs: []string{"https://a.example.com/cb"}},
		"grant":         {GrantTypes: []string{"client_credentials"}, RedirectURIs: []string{"https://a.example.com/cb"}},
		"response type": {ResponseTypes: []string{"token"}, RedirectURIs: []string{"https://a.example.com/cb"}},
		"no redirects":  {},
		"too many":      {RedirectURIs: []string{"https://1/", "https://2/", "https://3/", "https://4/", "https://5/", "https://6/", "https://7/", "https://8/", "https://9/", "https://10/", "https://11/"}},
		"http remote":   {RedirectURIs: []string{"http://evil.example.com/cb"}},
		"javascript":    {RedirectURIs: []string{"javascript:alert(1)"}},
		"fragment":      {RedirectURIs: []string{"https://a.example.com/cb#x"}},
		"credentials":   {RedirectURIs: []string{"https://user:pw@a.example.com/cb"}},
		"no dot scheme": {RedirectURIs: []string{"myapp:/cb"}},
		"https no host": {RedirectURIs: []string{"https:///cb"}},
		"too long":      {RedirectURIs: []string{"https://a.example.com/" + strings.Repeat("a", 2000)}},
	}
	for name, in := range bad {
		_, err := c.svc.RegisterClient(c.ctx, in)
		var re *service.RegistrationError
		if !errors.As(err, &re) || (re.Code != "invalid_redirect_uri" && re.Code != "invalid_client_metadata") {
			t.Errorf("%s: %v", name, err)
		}
	}
	cl, err := c.svc.RegisterClient(c.ctx, service.RegistrationInput{ClientName: "  ", Scope: "email bogus profile",
		RedirectURIs: []string{"https://a.example.com/cb", "https://a.example.com/cb", "http://localhost:3000/cb", "com.example.app:/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	if cl.Name != "Unnamed application" || len(cl.RedirectURIs) != 3 || !cl.Public() || !cl.SelfRegistered || !strings.HasPrefix(cl.ID, "dyn-") {
		t.Errorf("client %+v", cl)
	}
	if cl.Scopes[0] != "openid" {
		t.Errorf("openid first: %v", cl.Scopes)
	}
	for _, sc := range cl.Scopes {
		if sc == "bogus" {
			t.Error("unknown scope kept")
		}
	}
	if len(c.audited("", "client.self_register")) != 1 {
		t.Error("registration not audited")
	}

	// metadata documents
	id := "https://app.example.com/client.json"
	doc := `{"client_id":"` + id + `","client_name":"Doc App","redirect_uris":["https://app.example.com/cb"]}`
	app, err := service.ParseMetadata(id, []byte(doc))
	if err != nil || app.ID != id || app.MetadataFetched.IsZero() || !app.IsMetadataClient() {
		t.Fatalf("metadata: %v %+v", err, app)
	}
	for name, d := range map[string]string{"not json": "{", "wrong id": `{"client_id":"https://evil/","redirect_uris":["https://a.example.com/"]}`,
		"bad redirect": `{"client_id":"` + id + `","redirect_uris":["http://evil/"]}`} {
		var re *service.RegistrationError
		if _, err := service.ParseMetadata(id, []byte(d)); !errors.As(err, &re) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSelfRegisteredLifecycle(t *testing.T) {
	c := newCast(t)
	sys := service.System
	ten, _ := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("mcp"), Resources: &[]string{"https://mcp.example.com/"},
		Settings: &model.TenantSettings{SelfRegistration: true}})
	app, err := c.svc.RegisterClient(c.ctx, service.RegistrationInput{ClientName: "Zed", RedirectURIs: []string{"https://z.example.com/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	view := service.InTenant(app, ten)
	if view.OrgID != c.a.ID || view.TenantID != ten.ID || len(view.Resources) != 1 || view.FirstParty || view.SCIM || view.IntrospectOrg {
		t.Errorf("InTenant %+v", view)
	}
	if app.OrgID != "" || app.TenantID != "" {
		t.Error("InTenant mutated the stored client")
	}
	// not listed until used
	if l, _ := c.svc.SelfRegisteredApps(c.ctx, actor(c.aAdmin), ten.ID); len(l) != 0 {
		t.Errorf("unused app listed: %v", l)
	}
	c.svc.NoteSelfRegisteredUse(c.ctx, app, ten)
	grant := &model.Grant{UserID: c.aUser.ID, OrgID: c.a.ID, ClientID: app.ID}
	if err := c.svc.Grants.Create(c.ctx, grant); err != nil {
		t.Fatal(err)
	}
	// a metadata document application is stored on its first authorization
	mid := "https://meta.example.com/c.json"
	meta, _ := service.ParseMetadata(mid, []byte(`{"client_id":"`+mid+`","client_name":"alpha meta","redirect_uris":["https://meta.example.com/cb"]}`))
	c.svc.NoteSelfRegisteredUse(c.ctx, meta, ten)
	// an administrator's client of an unknown id is never stored by this
	c.svc.NoteSelfRegisteredUse(c.ctx, &model.Client{Meta: model.Meta{ID: "ghost"}, Name: "ghost"}, ten)
	if _, err := c.svc.Clients.Get(c.ctx, "ghost"); err == nil {
		t.Error("unknown client stored")
	}
	l, err := c.svc.SelfRegisteredApps(c.ctx, actor(c.aAdmin), ten.ID)
	if err != nil || len(l) != 2 || l[0].Name != "alpha meta" || !l[0].Metadata || l[1].Users != 1 {
		t.Fatalf("listing %+v %v", l, err)
	}
	// A repeat use within the hour changes nothing.
	before, _ := c.svc.Clients.Get(c.ctx, app.ID)
	c.svc.NoteSelfRegisteredUse(c.ctx, app, ten)
	after, _ := c.svc.Clients.Get(c.ctx, app.ID)
	if !after.LastUsed.Equal(before.LastUsed) {
		t.Error("use rewritten within the hour")
	}

	// authorization
	if _, err := c.svc.SelfRegisteredApps(c.ctx, actor(c.bAdmin), ten.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("foreign list: %v", err)
	}
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.bAdmin), ten.ID, app.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("foreign revoke: %v", err)
	}
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.aAdmin), ten.ID, "nope"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown app: %v", err)
	}
	admins, _, _ := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("own"), RedirectURIs: ptr([]string{"https://o.example.com/cb"})})
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.aAdmin), ten.ID, admins.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("revoking a registered (not self-registered) client: %v", err)
	}
	if n, _ := c.svc.Grants.Count(c.ctx, c.aUser.ID); n != 1 {
		t.Fatal("grant lost to denied revocations")
	}
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.aAdmin), ten.ID, app.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.svc.Grants.Count(c.ctx, c.aUser.ID); n != 0 {
		t.Errorf("grants after revoke: %d", n)
	}
}

func TestRefreshMetadataClientAndPurge(t *testing.T) {
	c := newCast(t)
	ten, _ := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{Name: ptr("mcp")})
	mid := "https://meta.example.com/c.json"
	doc := func(name string) *model.Client {
		m, err := service.ParseMetadata(mid, []byte(`{"client_id":"`+mid+`","client_name":"`+name+`","redirect_uris":["https://meta.example.com/cb"]}`))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if _, err := c.svc.RefreshMetadataClient(c.ctx, doc("v1")); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("refreshing an unstored client: %v", err)
	}
	c.svc.NoteSelfRegisteredUse(c.ctx, doc("v1"), ten)
	got, err := c.svc.RefreshMetadataClient(c.ctx, doc("v2"))
	if err != nil || got.Name != "v2" || len(got.UsedIn) != 1 || got.LastUsed.IsZero() {
		t.Fatalf("refresh %+v %v", got, err)
	}
	// An administrator's client with the same id is never replaced by a document.
	own, _, _ := c.svc.CreateClient(c.ctx, service.System, c.a.ID, service.ClientInput{Name: ptr("own"), RedirectURIs: ptr([]string{"https://o.example.com/cb"})})
	fake := doc("hijack")
	fake.ID = own.ID
	if _, err := c.svc.RefreshMetadataClient(c.ctx, fake); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("refreshing an admin's client: %v", err)
	}
	if cur, _ := c.svc.Clients.Get(c.ctx, own.ID); cur.Name != "own" {
		t.Error("admin client overwritten")
	}

	// Purge removes unused registrations older than a day, keeps used and fresh ones.
	old, _ := c.svc.RegisterClient(c.ctx, service.RegistrationInput{ClientName: "stale", RedirectURIs: []string{"https://s.example.com/cb"}})
	if n := c.svc.PurgeSelfRegistered(c.ctx, time.Now()); n != 0 {
		t.Errorf("fresh registration purged: %d", n)
	}
	if n := c.svc.PurgeSelfRegistered(c.ctx, time.Now().Add(48*time.Hour)); n != 1 {
		t.Errorf("purged %d, want 1 (the used one stays)", n)
	}
	if _, err := c.svc.Clients.Get(c.ctx, old.ID); err == nil {
		t.Error("stale registration kept")
	}
	if _, err := c.svc.Clients.Get(c.ctx, mid); err != nil {
		t.Error("used application purged")
	}
}

func TestUseOnce(t *testing.T) {
	e := newEnv(t)
	exp := time.Now().Add(time.Minute)
	if ok, err := e.svc.UseOnce(e.ctx, "ns:value", exp); err != nil || !ok {
		t.Fatalf("first use: %v %v", ok, err)
	}
	if ok, err := e.svc.UseOnce(e.ctx, "ns:value", exp); err != nil || ok {
		t.Fatalf("replay: %v %v", ok, err)
	}
	if ok, err := e.svc.UseOnce(e.ctx, "ns:other", exp); err != nil || !ok {
		t.Fatalf("other key: %v %v", ok, err)
	}
}

func TestOrgPredicatesExported(t *testing.T) {
	c := newCast(t)
	for _, tc := range []struct {
		name                 string
		u                    *model.User
		admin, users, manage bool // admin/manage users of org a; manage c.aUser
	}{
		{"super", c.super, true, true, true},
		{"a-admin", c.aAdmin, true, true, true},
		{"a-manager", c.aManager, false, true, true},
		{"a-user", c.aUser, false, false, false},
		{"b-admin", c.bAdmin, false, false, false},
		{"primary-admin", c.pAdmin, false, false, false},
	} {
		a := actor(tc.u)
		if got := c.svc.CanAdminOrg(a, c.a.ID); got != tc.admin {
			t.Errorf("%s CanAdminOrg %v", tc.name, got)
		}
		if got := c.svc.CanManageUsers(a, c.a.ID); got != tc.users {
			t.Errorf("%s CanManageUsers %v", tc.name, got)
		}
		if got := c.svc.CanManageUser(a, c.aUser); got != tc.manage {
			t.Errorf("%s CanManageUser %v", tc.name, got)
		}
	}
	// managers manage plain users only, admins everyone but super admins; provisioning clients stop at managers
	if c.svc.CanManageUser(actor(c.aManager), c.aAdmin) || c.svc.CanManageUser(actor(c.aManager), c.aManager) {
		t.Error("manager manages a manager or admin")
	}
	if !c.svc.CanManageUser(actor(c.aAdmin), c.aManager) {
		t.Error("admin cannot manage a manager")
	}
	cl := &model.Client{Meta: model.Meta{ID: "scim"}, OrgID: c.a.ID}
	ca := service.ActorForClient(cl, "")
	if c.svc.CanManageUser(ca, c.aAdmin) || !c.svc.CanManageUser(ca, c.aManager) || !c.svc.CanManageUser(ca, c.aUser) {
		t.Error("provisioning client rank limits")
	}
}

func isInvalid(err error) bool { return errors.Is(err, service.ErrInvalid) }
