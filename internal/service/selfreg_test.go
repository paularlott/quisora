package service_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A dynamically registered application is a public client with at least one redirect URI of the kinds selfRegRedirect
// allows; nothing else about the request may widen that. The same rules apply to a client metadata document.
func TestSelfRegistrationMetadata(t *testing.T) {
	c := newCast(t)
	bad := map[string]service.RegistrationInput{
		"confidential":  {AuthMethod: "client_secret_basic", RedirectURIs: []string{"https://a.example.com/cb"}},
		"grant":         {GrantTypes: []string{"client_credentials"}, RedirectURIs: []string{"https://a.example.com/cb"}},
		"response type": {ResponseTypes: []string{"token"}, RedirectURIs: []string{"https://a.example.com/cb"}},
		"no redirects":  {},
		"too many":      {RedirectURIs: []string{"https://1/", "https://2/", "https://3/", "https://4/", "https://5/", "https://6/", "https://7/", "https://8/", "https://9/", "https://10/", "https://11/"}},
		"http remote":   {RedirectURIs: []string{"http://evil.example.com/cb"}}, // the rest of the redirect rules: TestSelfRegRedirect
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

// A self-registered application's redirect URIs: https, http on the loopback interface, or a private-use scheme
// named after a domain; never a fragment, credentials or an opaque URI.
func TestSelfRegRedirect(t *testing.T) {
	for ru, want := range map[string]bool{
		"https://app.example/cb":           true,
		"http://127.0.0.1:33418/callback":  true,
		"http://[::1]/callback":            true,
		"http://localhost:8080/cb":         true,
		"com.example.app:/oauth/callback":  true,
		"com.example.app://callback":       true,
		"http://app.example/cb":            false,
		"http://localhost.evil.example/cb": false,
		"https://app.example/cb#x":         false,
		"https://user:pw@app.example/cb":   false,
		"https:///cb":                      false,
		"myapp:/cb":                        false,
		"com.example.app:cb":               false,
		"com.example.app:/cb#x":            false,
		"javascript:alert(1)":              false,
		"data:text/html,x":                 false,
		"file:///etc/passwd":               false,
		"":                                 false,
	} {
		if got := service.SelfRegRedirect(ru); got != want {
			t.Errorf("%q: %v, want %v", ru, got, want)
		}
	}
}
