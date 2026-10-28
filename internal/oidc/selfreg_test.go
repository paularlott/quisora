package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Dynamic client registration accepts public clients only, with https, loopback or private-use scheme redirect URIs
// (selfRegRedirect), answers in RFC 7591 form, and is limited per address.
// A registration body that is not a JSON object is refused.
func TestRegistrationBodyMustBeAnObject(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	if r := h.postJSON(h.orgBase+"/oauth/register", "not an object"); r.status != 400 || r.str("error") != "invalid_client_metadata" {
		t.Fatalf("%d %v", r.status, r.m)
	}
}

func TestDynamicRegistration(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	r := h.postJSON(h.orgBase+"/oauth/register", map[string]any{"client_name": "Claude Code", "redirect_uris": []string{"http://127.0.0.1:33418/callback", "http://localhost:33418/callback", "com.example.claude:/callback"},
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "none", "scope": "openid profile admin"})
	if r.status != 201 || r.str("client_name") != "Claude Code" || r.str("token_endpoint_auth_method") != "none" ||
		r.str("scope") != "openid profile" || r.m["client_id_issued_at"] == nil {
		t.Fatalf("register: %d %v", r.status, r.m)
	}
	c, err := h.env.Svc.Clients.Get(context.Background(), r.str("client_id"))
	if err != nil || !c.SelfRegistered || c.OrgID != h.env.Primary.ID || c.TenantID != "" || !c.Public() || !c.RequirePKCE() || len(c.RedirectURIs) != 3 {
		t.Fatalf("stored %+v %v", c, err)
	}
	metadata, redirect := "invalid_client_metadata", "invalid_redirect_uri"
	for name, tc := range map[string]struct {
		body any
		code string
	}{
		"confidential":       {map[string]any{"redirect_uris": []string{"https://app.example/cb"}, "token_endpoint_auth_method": "client_secret_basic"}, metadata},
		"client credentials": {map[string]any{"redirect_uris": []string{"https://app.example/cb"}, "grant_types": []string{"client_credentials"}}, metadata},
		"implicit":           {map[string]any{"redirect_uris": []string{"https://app.example/cb"}, "response_types": []string{"token"}}, metadata},
		"plain http":         {map[string]any{"redirect_uris": []string{"http://app.example/cb"}}, redirect},
		"scheme without dot": {map[string]any{"redirect_uris": []string{"myapp:/cb"}}, redirect},
		"fragment":           {map[string]any{"redirect_uris": []string{"https://app.example/cb#x"}}, redirect},
		"no redirect":        {map[string]any{"client_name": "x"}, redirect},
		"opaque scheme":      {map[string]any{"redirect_uris": []string{"com.example.app:cb"}}, redirect},
		"too many redirects": {map[string]any{"redirect_uris": []string{"https://a/1", "https://a/2", "https://a/3", "https://a/4", "https://a/5", "https://a/6", "https://a/7", "https://a/8", "https://a/9", "https://a/10", "https://a/11"}}, redirect},
	} {
		if r := h.postJSON(h.orgBase+"/oauth/register", tc.body); r.status != 400 || r.str("error") != tc.code {
			t.Errorf("%s: %d %v, want 400 %s", name, r.status, r.m, tc.code)
		}
	}
	// per address
	limited := false
	for range registerPerIPMin + 2 {
		if r := h.postJSON(h.orgBase+"/oauth/register", map[string]any{"redirect_uris": []string{"https://app.example/cb"}}); r.status == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("registration is not limited per address")
	}
}

// A self-registered application signs in only for a resource whose tenant allows self-registered applications; it
// is then that tenant's client: consent warns that it is not verified, tokens are for the resource, and turning the
// tenant's switch off (or revoking the app) ends its refresh tokens.
func TestSelfRegisteredSignIn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.mcpTenant("mcp", false)
	cl := h.register("http://127.0.0.1:44001/callback")
	c, _ := h.session(h.user)
	_, ch := pkce()

	// no resource, an unknown one, and the tenant's switch off: invalid_target back to the app
	for name, extra := range map[string]url.Values{
		"no resource":      nil,
		"unknown resource": {"resource": {"https://other.example/mcp"}},
		"switch off":       {"resource": {mcpResource}},
	} {
		u := h.authorize(c, authzQuery(cl, ch, extra))
		if u.Query().Get("error") != "invalid_target" {
			t.Errorf("%s: %s", name, u)
		}
	}

	on := tn.Settings
	on.SelfRegistration = true
	if _, err := h.env.Svc.UpdateTenant(ctx, h.admin, tn.ID, service.TenantInput{Settings: &on}); err != nil {
		t.Fatal(err)
	}
	page, _ := h.consentPage(c, cl, ch, url.Values{"resource": {mcpResource}})
	if !strings.Contains(page, "Not verified by your organization") || !strings.Contains(page, "127.0.0.1:44001") || !strings.Contains(page, mcpResource) {
		t.Errorf("consent page lacks the warning: %.600s", page)
	}

	r, _ := h.publicLogin(cl, url.Values{"resource": {mcpResource}})
	if r.status != 200 {
		t.Fatalf("token: %d %v", r.status, r.m)
	}
	at := claimsOf(t, r.str("access_token"))
	aud := strsOf(at["aud"])
	if at["aud"] == mcpResource {
		aud = []string{mcpResource}
	}
	if !slices.Contains(aud, mcpResource) || at["client_id"] != cl.ID || at["sub"] != h.user.ID {
		t.Errorf("access token %v", at)
	}
	stored, _ := h.env.Svc.Clients.Get(ctx, cl.ID)
	if stored.LastUsed.IsZero() || stored.OrgID != h.env.Primary.ID || stored.TenantID != "" {
		t.Errorf("use not recorded / client misplaced: %+v", stored)
	}
	rt := r.str("refresh_token")
	r2 := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {cl.ID}}, "", "")
	if r2.status != 200 {
		t.Fatalf("refresh: %d %v", r2.status, r2.m)
	}
	rt = r2.str("refresh_token")

	// the organization's administrators see it, with one user
	apps, err := h.env.Svc.SelfRegisteredApps(ctx, h.admin, h.env.Primary.ID)
	if err != nil || len(apps) != 1 || apps[0].ClientID != cl.ID || apps[0].Users != 1 || apps[0].Name != "Claude" {
		t.Fatalf("apps %+v %v", apps, err)
	}

	// the MCP server introspects the token as a client of the tenant's organization allowed to see all its tokens
	rs, rsSecret := h.newClient(func(in *service.ClientInput) {
		in.GrantTypes, in.IntrospectOrg, in.RedirectURIs = ptr([]string{"client_credentials"}), ptr(true), ptr([]string{})
	})
	if got := h.introspect(rs, rsSecret, r2.str("access_token")); got["active"] != true || got["client_id"] != cl.ID {
		t.Fatalf("resource server introspection: %v", got)
	}

	// switch off: the access token is inactive at once, the refresh token stops working, and so does a new
	// authorization
	if _, err := h.env.Svc.UpdateTenant(ctx, h.admin, tn.ID, service.TenantInput{Settings: &tn.Settings}); err != nil {
		t.Fatal(err)
	}
	if got := h.introspect(rs, rsSecret, r2.str("access_token")); got["active"] != false {
		t.Errorf("access token still active with the switch off: %v", got)
	}
	if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {cl.ID}}, "", ""); r.status != 400 {
		t.Errorf("refresh with the switch off: %d %v", r.status, r.m)
	}
	if u := h.authorize(c, authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); u.Query().Get("error") != "invalid_target" {
		t.Errorf("authorize with the switch off: %s", u)
	}

	// back on; revoking the app ends every user's access and takes it off the list
	if _, err := h.env.Svc.UpdateTenant(ctx, h.admin, tn.ID, service.TenantInput{Settings: &on}); err != nil {
		t.Fatal(err)
	}
	r3, _ := h.publicLogin(cl, url.Values{"resource": {mcpResource}})
	if err := h.env.Svc.RevokeSelfRegisteredApp(ctx, h.admin, h.env.Primary.ID, cl.ID); err != nil {
		t.Fatal(err)
	}
	if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r3.str("refresh_token")}, "client_id": {cl.ID}}, "", ""); r.status != 400 {
		t.Errorf("refresh after revoke: %d", r.status)
	}
	if apps, _ := h.env.Svc.SelfRegisteredApps(ctx, h.admin, h.env.Primary.ID); len(apps) != 0 {
		t.Errorf("revoked app still listed: %+v", apps)
	}
}

// In a members-only tenant a self-registered application, like any of its clients, serves only users with access.
func TestSelfRegisteredMembersOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.mcpTenant("mcp", true)
	set := tn.Settings
	set.MembersOnly = true
	if _, err := h.env.Svc.UpdateTenant(ctx, h.admin, tn.ID, service.TenantInput{Settings: &set}); err != nil {
		t.Fatal(err)
	}
	cl := h.register("http://127.0.0.1:44002/callback")
	c, _ := h.session(h.user)
	_, ch := pkce()
	if code, st, text := h.tryCode(c, cl, ch, url.Values{"resource": {mcpResource}}); code != "" || st != http.StatusForbidden || !strings.Contains(text, "do not have access") {
		t.Fatalf("no access: %d %q", st, text)
	}
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{Roles: &[]string{"mcp-user"}})
	r, _ := h.publicLogin(cl, url.Values{"resource": {mcpResource}, "scope": {"openid profile"}})
	if r.status != 200 {
		t.Fatalf("token with access: %d %v", r.status, r.m)
	}
}

// A resource belongs to one tenant of an organization: another claiming it is refused.
func TestTenantResourcesUnique(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("one", true)
	set := model.DefaultTenantSettings()
	_, err := h.env.Svc.CreateTenant(context.Background(), h.admin, h.env.Primary.ID,
		service.TenantInput{Name: ptr("two"), Settings: &set, Resources: &[]string{mcpResource}})
	var fe *service.FieldError
	if !errors.As(err, &fe) || fe.Field != "resources" {
		t.Fatalf("second tenant with the same resource: %v", err)
	}
	if _, err := h.env.Svc.CreateTenant(context.Background(), h.admin, h.env.Primary.ID,
		service.TenantInput{Name: ptr("three"), Settings: &set, Resources: &[]string{"not a uri"}}); !errors.As(err, &fe) || fe.Field != "resources" {
		t.Fatalf("bad resource: %v", err)
	}
}

// A client_id that is the https URL of a Client ID Metadata Document is read on first use and signs in like a
// registered one; a document that does not name itself, or a URL that cannot be read, is not an application.
func TestMetadataDocumentClient(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	docs := map[string]string{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(d))
	}))
	defer ts.Close()
	h.p.HTTP = ts.Client() // trusts the test server's certificate (and reaches loopback, as the guard would not)
	id := ts.URL + "/clients/desktop.json"
	redirect := "http://127.0.0.1:44003/callback"
	docs["/clients/desktop.json"] = `{"client_id":"` + id + `","client_name":"Desktop AI","redirect_uris":["` + redirect + `"],
		"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
	cl := &model.Client{Meta: model.Meta{ID: id}, RedirectURIs: []string{redirect}}
	r, _ := h.publicLogin(cl, url.Values{"resource": {mcpResource}})
	if r.status != 200 {
		t.Fatalf("token: %d %v", r.status, r.m)
	}
	stored, err := h.env.Svc.Clients.Get(context.Background(), model.ClientRecordID(h.env.Primary.ID, id))
	if err != nil || !stored.SelfRegistered || !stored.IsMetadataClient() || stored.ClientID() != id || stored.Name != "Desktop AI" || stored.MetadataFetched.IsZero() {
		t.Fatalf("stored %+v %v", stored, err)
	}

	c, _ := h.session(h.user)
	_, ch := pkce()
	bad := ts.URL + "/clients/other.json"
	docs["/clients/other.json"] = `{"client_id":"https://elsewhere.example/c.json","redirect_uris":["` + redirect + `"]}`
	for name, tc := range map[string]struct{ id, resource string }{
		"names another url":       {bad, mcpResource},
		"not found":               {ts.URL + "/clients/missing.json", mcpResource},
		"no resource":             {id, ""},
		"resource no tenant owns": {id, "https://nobody.example"},
	} {
		q := authzQuery(&model.Client{Meta: model.Meta{ID: tc.id}, RedirectURIs: []string{redirect}}, ch, url.Values{"resource": {tc.resource}})
		resp := h.get(c, h.orgBase+"/oauth/authorize?"+q.Encode())
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body(resp), "not recognised") {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
}

// Registrations never used to sign anyone in go after a day; used ones stay.
func TestPurgeSelfRegistered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	unused := h.register("http://127.0.0.1:44004/callback")
	used := h.register("http://127.0.0.1:44005/callback")
	if r, _ := h.publicLogin(used, url.Values{"resource": {mcpResource}}); r.status != 200 {
		t.Fatalf("login: %d", r.status)
	}
	if n := h.env.Svc.PurgeSelfRegistered(ctx, time.Now()); n != 0 {
		t.Errorf("purged fresh registrations: %d", n)
	}
	if n := h.env.Svc.PurgeSelfRegistered(ctx, time.Now().Add(25*time.Hour)); n != 1 {
		t.Errorf("purged %d, want 1", n)
	}
	if _, err := h.env.Svc.Clients.Get(ctx, unused.ID); err == nil {
		t.Error("unused registration kept")
	}
	if _, err := h.env.Svc.Clients.Get(ctx, used.ID); err != nil {
		t.Error("used registration purged")
	}
}

// Metadata documents cost nothing until a user lets the application in: a request for a resource nobody accepts is
// refused without reading the document; one for an accepting resource reads it but stores no client before consent;
// and new documents read per address are limited.
func TestMetadataDocumentsUnstoredUntilConsent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	hits := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		id := "https://" + r.Host + r.URL.Path
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Gen","redirect_uris":["http://127.0.0.1:44010/callback"]}`))
	}))
	defer ts.Close()
	h.p.HTTP = ts.Client()
	c, _ := h.session(h.user)
	_, ch := pkce()
	req := func(id, resource string) *http.Response {
		q := authzQuery(&model.Client{Meta: model.Meta{ID: id}, RedirectURIs: []string{"http://127.0.0.1:44010/callback"}}, ch,
			url.Values{"resource": {resource}})
		return h.get(c, h.orgBase+"/oauth/authorize?"+q.Encode())
	}
	// a resource nobody accepts: refused, nothing read
	if resp := req(ts.URL+"/gen/0", "https://nobody.example/mcp"); resp.StatusCode != http.StatusBadRequest || hits != 0 {
		t.Fatalf("unaccepted resource: %d, %d documents read", resp.StatusCode, hits)
	}
	// an accepting resource: read once, consent asked, nothing stored
	resp := req(ts.URL+"/gen/1", mcpResource)
	body(resp)
	if resp.StatusCode != http.StatusFound || hits != 1 {
		t.Fatalf("accepted resource: %d, %d documents read", resp.StatusCode, hits)
	}
	if _, err := h.env.Svc.Clients.Get(ctx, model.ClientRecordID(h.env.Primary.ID, ts.URL+"/gen/1")); err == nil {
		t.Fatal("a metadata-document client was stored before anyone consented")
	}
	// many made-up documents from one address: only metadataPerIPMin are read
	for i := 2; i < metadataPerIPMin+10; i++ {
		body(req(ts.URL+"/gen/"+strconv.Itoa(i), mcpResource))
	}
	if hits > metadataPerIPMin {
		t.Errorf("%d documents read for one address within a minute (limit %d)", hits, metadataPerIPMin)
	}
	if l, _, _ := h.env.Svc.Clients.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "self_registered", Value: true}}}); len(l) != 0 {
		t.Errorf("%d self-registered clients stored without consent", len(l))
	}
}

// Tenants claim resources by their canonical form: a variant (letter case, trailing slash, default port) of
// another tenant's resource is refused, as is plain http (except loopback), a query, or a duplicate.
func TestTenantResourceVariants(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("one", true)
	set := model.DefaultTenantSettings()
	var fe *service.FieldError
	for name, res := range map[string][]string{
		"upper case host": {"https://MCP.example.com/mcp"},
		"trailing slash":  {"https://mcp.example.com/mcp/"},
		"default port":    {"https://mcp.example.com:443/mcp"},
		"plain http":      {"http://api.example.com/mcp"},
		"query":           {"https://api.example.com/mcp?x=1"},
		"credentials":     {"https://u:p@api.example.com/mcp"},
		"duplicate":       {"https://api.example.com/a", "https://API.example.com/a/"},
	} {
		_, err := h.env.Svc.CreateTenant(context.Background(), h.admin, h.env.Primary.ID,
			service.TenantInput{Name: ptr("t-" + strings.ReplaceAll(name, " ", "-")), Settings: &set, Resources: &res})
		if !errors.As(err, &fe) || fe.Field != "resources" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.env.Svc.CreateTenant(context.Background(), h.admin, h.env.Primary.ID,
		service.TenantInput{Name: ptr("loop"), Settings: &set, Resources: &[]string{"http://127.0.0.1:8080/mcp"}}); err != nil {
		t.Errorf("loopback http resource: %v", err)
	}
	// registration: no credentials in redirect URIs
	if r := h.postJSON(h.orgBase+"/oauth/register", map[string]any{"redirect_uris": []string{"https://u:p@app.example/cb"}}); r.status != 400 {
		t.Errorf("redirect with credentials: %d %v", r.status, r.m)
	}
}

// A desktop app on a private-use scheme: consent names the scheme as where the result goes.
func TestSelfRegisteredPrivateScheme(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	cl := h.register("com.example.claude:/callback")
	c, _ := h.session(h.user)
	_, ch := pkce()
	page, _ := h.consentPage(c, cl, ch, url.Values{"resource": {mcpResource}})
	if !strings.Contains(page, "Not verified by your organization") || !strings.Contains(page, "com.example.claude:") {
		t.Fatalf("consent for a private-use scheme:\n%s", page)
	}
}
