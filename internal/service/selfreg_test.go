package service_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// A dynamically registered application is a public client with at least one redirect URI of the kinds selfRegRedirect
// allows; nothing else about the request may widen that. The same rules apply to a client metadata document.
func TestSelfRegistrationMetadata(t *testing.T) {
	c := newCast(t)
	c.acceptSelfRegistered(c.a.ID)
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
		_, err := c.svc.RegisterClient(c.ctx, c.a.ID, in)
		var re *service.RegistrationError
		if !errors.As(err, &re) || (re.Code != "invalid_redirect_uri" && re.Code != "invalid_client_metadata") {
			t.Errorf("%s: %v", name, err)
		}
	}
	cl, err := c.svc.RegisterClient(c.ctx, c.a.ID, service.RegistrationInput{ClientName: "  ", Scope: "email bogus profile",
		RedirectURIs: []string{"https://a.example.com/cb", "https://a.example.com/cb", "http://localhost:3000/cb", "com.example.app:/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	if cl.Name != "Unnamed application" || len(cl.RedirectURIs) != 3 || !cl.Public() || !cl.SelfRegistered || cl.OrgID != c.a.ID || cl.TenantID != "" || !strings.HasPrefix(cl.ID, "dyn-") {
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
	if len(c.audited(c.a.ID, "client.self_register")) != 1 {
		t.Error("registration not audited")
	}

	// metadata documents
	id := "https://app.example.com/client.json"
	doc := `{"client_id":"` + id + `","client_name":"Doc App","redirect_uris":["https://app.example.com/cb"]}`
	app, err := service.ParseMetadata(c.a.ID, id, []byte(doc))
	if err != nil || app.ID != model.ClientRecordID(c.a.ID, id) || app.ClientID() != id || app.OrgID != c.a.ID ||
		app.MetadataFetched.IsZero() || !app.IsMetadataClient() {
		t.Fatalf("metadata: %v %+v", err, app)
	}
	for name, d := range map[string]string{"not json": "{", "wrong id": `{"client_id":"https://evil/","redirect_uris":["https://a.example.com/"]}`,
		"bad redirect": `{"client_id":"` + id + `","redirect_uris":["http://evil/"]}`} {
		var re *service.RegistrationError
		if _, err := service.ParseMetadata(c.a.ID, id, []byte(d)); !errors.As(err, &re) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSelfRegisteredLifecycle(t *testing.T) {
	c := newCast(t)
	sys := service.System
	ten, _ := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("mcp"), Resources: &[]string{"https://mcp.example.com/"},
		Settings: &model.TenantSettings{SelfRegistration: true}})
	app, err := c.svc.RegisterClient(c.ctx, c.a.ID, service.RegistrationInput{ClientName: "Zed", RedirectURIs: []string{"https://z.example.com/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	view := service.InTenant(app, ten)
	if view.OrgID != c.a.ID || view.TenantID != ten.ID || len(view.Resources) != 1 || view.FirstParty || view.IntrospectOrg {
		t.Errorf("InTenant %+v", view)
	}
	if app.TenantID != "" || len(app.Resources) != 0 {
		t.Error("InTenant mutated the stored client")
	}
	// the organization's applications, used or not
	if l, _, _ := c.svc.SelfRegisteredApps(c.ctx, actor(c.aAdmin), c.a.ID, store.ListQuery{}); len(l) != 1 || l[0].Users != 0 {
		t.Errorf("registered app not listed: %v", l)
	}
	c.svc.NoteSelfRegisteredUse(c.ctx, app, ten)
	grant := &model.Grant{UserID: c.aUser.ID, OrgID: c.a.ID, ClientID: app.ID}
	if err := c.svc.Grants.Create(c.ctx, grant); err != nil {
		t.Fatal(err)
	}
	// a metadata document application is stored on its first authorization, in the organization
	mid := "https://meta.example.com/c.json"
	meta, _ := service.ParseMetadata(c.a.ID, mid, []byte(`{"client_id":"`+mid+`","client_name":"alpha meta","redirect_uris":["https://meta.example.com/cb"]}`))
	c.svc.NoteSelfRegisteredUse(c.ctx, meta, ten)
	// an administrator's client of an unknown id is never stored by this
	c.svc.NoteSelfRegisteredUse(c.ctx, &model.Client{Meta: model.Meta{ID: "ghost"}, Name: "ghost"}, ten)
	if _, err := c.svc.Clients.Get(c.ctx, "ghost"); err == nil {
		t.Error("unknown client stored")
	}
	l, _, err := c.svc.SelfRegisteredApps(c.ctx, actor(c.aAdmin), c.a.ID, store.ListQuery{})
	if err != nil || len(l) != 2 || l[0].Name != "alpha meta" || !l[0].Metadata || l[0].ClientID != mid || l[1].Users != 1 {
		t.Fatalf("listing %+v %v", l, err)
	}
	// they are not among the clients an administrator sets up, and are not edited as such
	if cs, _, _ := c.svc.ListClients(c.ctx, actor(c.aAdmin), c.a.ID, store.ListQuery{}); len(cs) != 0 {
		t.Errorf("self-registered applications among the clients: %d", len(cs))
	}
	if _, err := c.svc.GetClient(c.ctx, actor(c.aAdmin), app.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("an administrator reading a self-registered client: %v", err)
	}
	// A repeat use within the hour changes nothing.
	before, _ := c.svc.Clients.Get(c.ctx, app.ID)
	c.svc.NoteSelfRegisteredUse(c.ctx, app, ten)
	after, _ := c.svc.Clients.Get(c.ctx, app.ID)
	if !after.LastUsed.Equal(before.LastUsed) {
		t.Error("use rewritten within the hour")
	}

	// authorization: another organization's administrator sees and ends nothing here
	if _, _, err := c.svc.SelfRegisteredApps(c.ctx, actor(c.bAdmin), c.a.ID, store.ListQuery{}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("foreign list: %v", err)
	}
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.bAdmin), c.a.ID, app.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("foreign revoke: %v", err)
	}
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.bAdmin), c.b.ID, app.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("revoking another organization's application as one's own: %v", err)
	}
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.aAdmin), c.a.ID, "nope"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown app: %v", err)
	}
	admins, _, _ := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("own"), RedirectURIs: ptr([]string{"https://o.example.com/cb"})})
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.aAdmin), c.a.ID, admins.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("revoking a registered (not self-registered) client: %v", err)
	}
	if n, _ := c.svc.Grants.Count(c.ctx, c.aUser.ID); n != 1 {
		t.Fatal("grant lost to denied revocations")
	}
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.aAdmin), c.a.ID, app.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.svc.Grants.Count(c.ctx, c.aUser.ID); n != 0 {
		t.Errorf("grants after revoke: %d", n)
	}
	if _, err := c.svc.Clients.Get(c.ctx, app.ID); err == nil {
		t.Error("revoked application kept")
	}
}

// The same metadata document is a different application in each organization that lets it in: one record each, in its
// own organization, ended and listed there only.
func TestMetadataApplicationPerOrganization(t *testing.T) {
	c := newCast(t)
	sys := service.System
	tenA, _ := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("mcp"), Resources: &[]string{"https://mcp.example.com/"},
		Settings: &model.TenantSettings{SelfRegistration: true}})
	tenB, _ := c.svc.CreateTenant(c.ctx, sys, c.b.ID, service.TenantInput{Name: ptr("mcp"), Resources: &[]string{"https://mcp.example.com/"},
		Settings: &model.TenantSettings{SelfRegistration: true}})
	mid := "https://meta.example.com/c.json"
	doc := []byte(`{"client_id":"` + mid + `","client_name":"Shared","redirect_uris":["https://meta.example.com/cb"]}`)
	inA, err := service.ParseMetadata(c.a.ID, mid, doc)
	if err != nil {
		t.Fatal(err)
	}
	inB, _ := service.ParseMetadata(c.b.ID, mid, doc)
	if inA.ID == inB.ID || inA.ClientID() != mid || inB.ClientID() != mid {
		t.Fatalf("one record for two organizations: %q %q", inA.ID, inB.ID)
	}
	c.svc.NoteSelfRegisteredUse(c.ctx, service.InTenant(inA, tenA), tenA)
	c.svc.NoteSelfRegisteredUse(c.ctx, service.InTenant(inB, tenB), tenB)
	for _, x := range []struct {
		org *model.Org
		rec string
	}{{c.a, inA.ID}, {c.b, inB.ID}} {
		got, err := c.svc.Clients.Get(c.ctx, x.rec)
		if err != nil || got.OrgID != x.org.ID || got.TenantID != "" || got.MetadataURL != mid {
			t.Fatalf("record of %s: %+v %v", x.org.Name, got, err)
		}
	}
	if l, _, _ := c.svc.SelfRegisteredApps(c.ctx, actor(c.aAdmin), c.a.ID, store.ListQuery{}); len(l) != 1 || l[0].ClientID != mid {
		t.Errorf("organization a's list: %+v", l)
	}
	// ending it in a leaves b's
	if err := c.svc.RevokeSelfRegisteredApp(c.ctx, actor(c.aAdmin), c.a.ID, mid); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.Clients.Get(c.ctx, inA.ID); err == nil {
		t.Error("a's record kept")
	}
	if _, err := c.svc.Clients.Get(c.ctx, inB.ID); err != nil {
		t.Errorf("b's record lost with a's: %v", err)
	}
}

func TestRefreshMetadataClientAndPurge(t *testing.T) {
	c := newCast(t)
	ten, _ := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{Name: ptr("mcp")})
	mid := "https://meta.example.com/c.json"
	rec := model.ClientRecordID(c.a.ID, mid)
	doc := func(name string) *model.Client {
		m, err := service.ParseMetadata(c.a.ID, mid, []byte(`{"client_id":"`+mid+`","client_name":"`+name+`","redirect_uris":["https://meta.example.com/cb"]}`))
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
	if err != nil || got.Name != "v2" || got.ID != rec || got.LastUsed.IsZero() {
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
	c.acceptSelfRegistered(c.a.ID)
	old, _ := c.svc.RegisterClient(c.ctx, c.a.ID, service.RegistrationInput{ClientName: "stale", RedirectURIs: []string{"https://s.example.com/cb"}})
	if n := c.svc.PurgeSelfRegistered(c.ctx, time.Now()); n != 0 {
		t.Errorf("fresh registration purged: %d", n)
	}
	if n := c.svc.PurgeSelfRegistered(c.ctx, time.Now().Add(48*time.Hour)); n != 1 {
		t.Errorf("purged %d, want 1 (the used one stays)", n)
	}
	if _, err := c.svc.Clients.Get(c.ctx, old.ID); err == nil {
		t.Error("stale registration kept")
	}
	if _, err := c.svc.Clients.Get(c.ctx, rec); err != nil {
		t.Error("used application purged")
	}
	// A used one goes once it has not been used for 90 days (the refresh token lifetime is shorter): no grant of it
	// still works by then.
	c.svc.PurgeSelfRegistered(c.ctx, time.Now().Add(60*24*time.Hour))
	if _, err := c.svc.Clients.Get(c.ctx, rec); err != nil {
		t.Error("an application used 60 days ago was purged")
	}
	c.svc.PurgeSelfRegistered(c.ctx, time.Now().Add(91*24*time.Hour))
	if _, err := c.svc.Clients.Get(c.ctx, rec); err == nil {
		t.Error("an application unused for 91 days was kept")
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

// The cap on applications nobody has used is each organization's own, and at it a registration makes room by
// removing one unused application rather than being refused: the count stays at the cap, an application in use is
// never removed, and another organization is untouched. The purge removes every organization's, however many there
// are (it reads them a page at a time).
func TestSelfRegistrationCapIsPerOrganizationAndPurgePages(t *testing.T) {
	c := newCast(t)
	c.acceptSelfRegistered(c.a.ID)
	c.acceptSelfRegistered(c.b.ID)
	in := service.RegistrationInput{RedirectURIs: []string{"https://a.example.com/cb"}}
	for i := range service.MaxSelfRegistered {
		cl := &model.Client{Meta: model.Meta{ID: fmt.Sprintf("dyn-fill-%d", i)}, OrgID: c.a.ID, Name: "fill", SelfRegistered: true,
			AuthMethod: model.AuthMethodNone, Enabled: true}
		if err := c.svc.Clients.Create(c.ctx, cl); err != nil {
			t.Fatal(err)
		}
	}
	// one of them in use: never the one removed
	used, err := c.svc.Clients.Get(c.ctx, "dyn-fill-0")
	if err != nil {
		t.Fatal(err)
	}
	used.LastUsed = time.Now()
	if err := c.svc.Clients.Update(c.ctx, used); err != nil {
		t.Fatal(err)
	}
	unused := func(orgID string) int {
		_, n, err := c.svc.Clients.IDs(c.ctx, store.ListQuery{Scope: orgID, Limit: 1,
			Filters: []store.Filter{{Field: "unused_self_registered", Value: true}}})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := c.svc.Clients.Create(c.ctx, &model.Client{Meta: model.Meta{ID: "dyn-fill-x"}, OrgID: c.a.ID,
		Name: "fill", SelfRegistered: true, AuthMethod: model.AuthMethodNone, Enabled: true}); err != nil {
		t.Fatal(err)
	} // back at the cap of unused ones
	for range 3 {
		if _, err := c.svc.RegisterClient(c.ctx, c.a.ID, in); err != nil {
			t.Fatalf("registering at the cap: %v", err)
		}
		if n := unused(c.a.ID); n != service.MaxSelfRegistered {
			t.Fatalf("unused after registering at the cap: %d, want %d", n, service.MaxSelfRegistered)
		}
	}
	if _, err := c.svc.Clients.Get(c.ctx, "dyn-fill-0"); err != nil {
		t.Errorf("the application in use was removed: %v", err)
	}
	if len(c.audited(c.a.ID, "client.self_registered.evict")) != 3 {
		t.Error("the removals were not audited")
	}
	if _, err := c.svc.RegisterClient(c.ctx, c.b.ID, in); err != nil {
		t.Fatalf("another organization's registration: %v", err)
	}
	if n := c.svc.PurgeSelfRegistered(c.ctx, time.Now().Add(48*time.Hour)); n != service.MaxSelfRegistered+1 {
		t.Errorf("purged %d, want %d", n, service.MaxSelfRegistered+1)
	}
	if _, err := c.svc.RegisterClient(c.ctx, c.a.ID, in); err != nil {
		t.Errorf("registering after the purge: %v", err)
	}
}

// acceptSelfRegistered gives organization orgID a tenant that accepts self-registered applications, without which
// the organization refuses registrations.
func (e *env) acceptSelfRegistered(orgID string) *model.Tenant {
	e.t.Helper()
	t, err := e.svc.CreateTenant(e.ctx, service.System, orgID, service.TenantInput{Name: ptr("selfreg"),
		Resources: &[]string{"https://selfreg.example.com/"}, Settings: &model.TenantSettings{SelfRegistration: true}})
	if err != nil {
		e.t.Fatal(err)
	}
	return t
}

// Registration is open only at an organization with a tenant that lets self-registered applications sign in for a
// resource it owns: anywhere else a registration could never be used, and anyone may ask for one.
func TestRegistrationNeedsATenantThatAcceptsIt(t *testing.T) {
	c := newCast(t)
	in := service.RegistrationInput{RedirectURIs: []string{"https://a.example.com/cb"}}
	if _, err := c.svc.RegisterClient(c.ctx, c.a.ID, in); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("an organization without tenants: %v", err)
	}
	// a tenant with the switch on but no resource accepts nothing; one with resources but the switch off neither
	if _, err := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{Name: ptr("nores"),
		Settings: &model.TenantSettings{SelfRegistration: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{Name: ptr("off"),
		Resources: &[]string{"https://off.example.com/"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.RegisterClient(c.ctx, c.a.ID, in); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("no tenant accepts self-registered applications: %v", err)
	}
	if l, _, _ := c.svc.Clients.List(c.ctx, store.ListQuery{Scope: c.a.ID, Filters: []store.Filter{{Field: "self_registered", Value: true}}}); len(l) != 0 {
		t.Errorf("a refused registration stored %d applications", len(l))
	}
	c.acceptSelfRegistered(c.a.ID)
	if _, err := c.svc.RegisterClient(c.ctx, c.a.ID, in); err != nil {
		t.Fatalf("with a tenant that accepts them: %v", err)
	}
	if _, err := c.svc.RegisterClient(c.ctx, c.b.ID, in); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("another organization's tenant opened this one: %v", err)
	}
}

// The administrators' list of self-registered applications is read a page at a time, by name, with the total: an
// organization may hold thousands nobody has used, and only the page's grants are counted.
func TestSelfRegisteredAppsArePaged(t *testing.T) {
	c := newCast(t)
	for i, name := range []string{"Charlie", "Alpha", "Bravo"} {
		if err := c.svc.Clients.Create(c.ctx, &model.Client{Meta: model.Meta{ID: fmt.Sprintf("dyn-page-%d", i)}, OrgID: c.a.ID,
			Name: name, SelfRegistered: true, AuthMethod: model.AuthMethodNone, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	names := func(l []service.SelfRegApp) (out []string) {
		for _, a := range l {
			out = append(out, a.Name)
		}
		return out
	}
	l, n, err := c.svc.SelfRegisteredApps(c.ctx, actor(c.aAdmin), c.a.ID, store.ListQuery{Limit: 2})
	if err != nil || n != 3 || strings.Join(names(l), ",") != "Alpha,Bravo" {
		t.Fatalf("first page: %v %d %v", names(l), n, err)
	}
	l, n, err = c.svc.SelfRegisteredApps(c.ctx, actor(c.aAdmin), c.a.ID, store.ListQuery{Limit: 2, Offset: 2})
	if err != nil || n != 3 || strings.Join(names(l), ",") != "Charlie" {
		t.Fatalf("second page: %v %d %v", names(l), n, err)
	}
}
