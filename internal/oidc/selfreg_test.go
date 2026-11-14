package oidc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
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
	h.mcpTenant("mcp", true)
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

// An organization with no tenant that accepts self-registered applications takes no registrations: none could ever
// sign anyone in, and anyone may ask for one.
func TestRegistrationNeedsATenantThatAcceptsIt(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	reg := map[string]any{"redirect_uris": []string{"https://app.example/cb"}}
	if r := h.postJSON(h.orgBase+"/oauth/register", reg); r.status != 403 || r.str("error") != "access_denied" {
		t.Fatalf("registration with no tenant accepting it: %d %v", r.status, r.m)
	}
	h.mcpTenant("mcp", false) // owns a resource, but does not let self-registered applications in
	if r := h.postJSON(h.orgBase+"/oauth/register", reg); r.status != 403 {
		t.Fatalf("registration with the tenant's switch off: %d %v", r.status, r.m)
	}
	h.mcpTenantOf("open", "https://open.example.com/mcp", true)
	if r := h.postJSON(h.orgBase+"/oauth/register", reg); r.status != 201 {
		t.Fatalf("registration with a tenant accepting it: %d %v", r.status, r.m)
	}
}

// Besides its own minute's allowance, an address has a day's at each organization (it cannot fill the organization's
// cap of unused registrations alone), and an organization a minute's from every address together.
func TestRegistrationLimitsPerOrganization(t *testing.T) {
	t.Parallel()
	reg := map[string]any{"redirect_uris": []string{"https://app.example/cb"}}
	for _, l := range []struct {
		key   string // after the organization's id
		limit int64
		why   string
	}{
		{"register-day|%s|127.0.0.1", registerPerIPDay, "from this address"},
		{"register-org|%s", registerPerOrgMin, "at this organization"},
	} {
		h := setup(t, nil)
		h.mcpTenant("mcp", true)
		// the allowance spent but for one (as other requests would have): one more registration, then refused
		key := fmt.Sprintf(l.key, h.env.Primary.ID)
		if _, err := h.p.s.Eph.Incr(context.Background(), nsRateOIDC, key, l.limit-1, time.Hour); err != nil {
			t.Fatal(err)
		}
		if r := h.postJSON(h.orgBase+"/oauth/register", reg); r.status != 201 {
			t.Fatalf("%s: the last registration of the allowance: %d %v", l.why, r.status, r.m)
		}
		r := h.postJSON(h.orgBase+"/oauth/register", reg)
		if r.status != 429 || r.str("error") != "slow_down" || !strings.Contains(r.str("error_description"), l.why) || r.hdr.Get("Retry-After") == "" {
			t.Fatalf("%s: past the allowance: %d %v", l.why, r.status, r.m)
		}
	}
}

// A refused registration does not spend the organization's minute, which every address shares: only one made counts,
// so a few addresses sending requests that are refused (no tenant accepts them, bad metadata) cannot block everyone's.
func TestRefusedRegistrationsDoNotSpendTheOrganizationsMinute(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	key := "register-org|" + h.env.Primary.ID
	spent := func() int64 {
		t.Helper()
		n, err := h.p.s.Eph.Incr(context.Background(), nsRateOIDC, key, 0, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	reg := map[string]any{"redirect_uris": []string{"https://app.example/cb"}}
	if r := h.postJSON(h.orgBase+"/oauth/register", reg); r.status != 403 {
		t.Fatalf("registration with no tenant accepting it: %d %v", r.status, r.m)
	}
	h.mcpTenant("mcp", true)
	if r := h.postJSON(h.orgBase+"/oauth/register", map[string]any{"redirect_uris": []string{"ftp://app.example/cb"}}); r.status != 400 {
		t.Fatalf("registration with bad metadata: %d %v", r.status, r.m)
	}
	if n := spent(); n != 0 {
		t.Fatalf("refused registrations spent %d of the organization's minute", n)
	}
	if r := h.postJSON(h.orgBase+"/oauth/register", reg); r.status != 201 {
		t.Fatalf("registration: %d %v", r.status, r.m)
	}
	if n := spent(); n != 1 {
		t.Fatalf("a registration made counted %d", n)
	}
}

// The last registerOrgReserve of the organization's minute are for addresses that have not registered there today: a
// few addresses that keep registering cannot spend it all.
func TestRegistrationReserveIsForNewAddresses(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	ctx := context.Background()
	if _, err := h.p.s.Eph.Incr(ctx, nsRateOIDC, "register-org|"+h.env.Primary.ID, registerPerOrgMin-registerOrgReserve, time.Minute); err != nil {
		t.Fatal(err)
	}
	reg := map[string]any{"redirect_uris": []string{"https://app.example/cb"}}
	if r := h.postJSON(h.orgBase+"/oauth/register", reg); r.status != 201 {
		t.Fatalf("an address new to the organization, from the reserve: %d %v", r.status, r.m)
	}
	r := h.postJSON(h.orgBase+"/oauth/register", reg)
	if r.status != 429 || !strings.Contains(r.str("error_description"), "at this organization") {
		t.Fatalf("an address that registered today, from the reserve: %d %v", r.status, r.m)
	}
}

// An IPv6 address is new to the organization only when its /48 is too, and the /48 has its own share of the minute:
// sixty /64s of one /48, each registering once, used to be sixty new addresses and spend the organization's minute,
// reserve included, after which an application registering from an address that never had was refused.
func TestRegistrationReserveCountsTheSlash48(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	reg := func(ip string) int {
		req := httptest.NewRequest(http.MethodPost, h.orgBase+"/oauth/register",
			bytes.NewReader([]byte(`{"redirect_uris":["https://app.example/cb"]}`)))
		req.Header.Set("Content-Type", "application/json")
		return h.serveFrom(ip, req).Code
	}
	made := 0
	for i := range registerPerOrgMin {
		switch code := reg(fmt.Sprintf("2001:db8:1:%x::1", i+1)); code {
		case http.StatusCreated:
			made++
		case http.StatusTooManyRequests:
		default:
			t.Fatalf("registration %d from one /48: %d", i, code)
		}
	}
	if made != registerPerOrgMin-registerOrgReserve {
		t.Fatalf("one /48's /64s made %d registrations in the minute, want %d (the reserve is for new addresses)",
			made, registerPerOrgMin-registerOrgReserve)
	}
	for _, ip := range []string{"198.51.100.200", "2001:db8:2::1"} {
		if code := reg(ip); code != http.StatusCreated {
			t.Fatalf("a first registration from %s after one /48's flood: %d", ip, code)
		}
	}
	// the /48's minute: past it, a /64 of it that has not registered is refused at once
	h2 := setup(t, nil)
	h2.mcpTenant("mcp", true)
	if _, err := h2.p.s.Eph.Incr(context.Background(), nsRateOIDC, "register-net|2001:db8:3::/48", registerPerNetMin, time.Minute); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, h2.orgBase+"/oauth/register", bytes.NewReader([]byte(`{"redirect_uris":["https://app.example/cb"]}`)))
	req.Header.Set("Content-Type", "application/json")
	if rec := h2.serveFrom("2001:db8:3:99::1", req); rec.Code != http.StatusTooManyRequests ||
		!strings.Contains(rec.Body.String(), "from this address") {
		t.Fatalf("a /64 of a /48 past its minute: %d %s", rec.Code, rec.Body)
	}
}

// A registration request that makes nothing leaves no counter that lasts a day: an organization that takes no
// registrations, or metadata refused. Only a registration made counts toward the address's day.
func TestRefusedRegistrationsMakeNoDayCounter(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	key := "register-day|" + h.env.Primary.ID + "|127.0.0.1"
	day := func() int64 {
		t.Helper()
		n, err := h.p.s.Eph.Incr(context.Background(), nsRateOIDC, key, 0, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if r := h.postJSON(h.orgBase+"/oauth/register", map[string]any{"redirect_uris": []string{"https://app.example/cb"}}); r.status != 403 {
		t.Fatalf("registration with no tenant accepting it: %d %v", r.status, r.m)
	}
	if n := day(); n != 0 {
		t.Fatalf("a registration refused by an organization that takes none counted %d toward the day", n)
	}
	h.mcpTenant("mcp", true)
	if r := h.postJSON(h.orgBase+"/oauth/register", map[string]any{"redirect_uris": []string{"ftp://app.example/cb"}}); r.status != 400 {
		t.Fatalf("registration with bad metadata: %d %v", r.status, r.m)
	}
	if n := day(); n != 0 {
		t.Fatalf("a registration with bad metadata counted %d toward the day", n)
	}
	h.register("https://app.example/cb")
	if n := day(); n != 1 {
		t.Fatalf("a registration made counted %d toward the day", n)
	}
}

// A self-registered application signs in only for a resource whose tenant allows self-registered applications; it
// is then that tenant's client: consent warns that it is not verified, tokens are for the resource, and turning the
// tenant's switch off (or revoking the app) ends its refresh tokens.
func TestSelfRegisteredSignIn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.mcpTenant("mcp", true)
	cl := h.register("http://127.0.0.1:44001/callback")
	on, off := tn.Settings, tn.Settings
	off.SelfRegistration = false
	if _, err := h.env.Svc.UpdateTenant(ctx, h.admin, tn.ID, service.TenantInput{Settings: &off}); err != nil {
		t.Fatal(err)
	}
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
	apps, _, err := h.env.Svc.SelfRegisteredApps(ctx, h.admin, h.env.Primary.ID, store.ListQuery{})
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
	if _, err := h.env.Svc.UpdateTenant(ctx, h.admin, tn.ID, service.TenantInput{Settings: &off}); err != nil {
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
	if apps, _, _ := h.env.Svc.SelfRegisteredApps(ctx, h.admin, h.env.Primary.ID, store.ListQuery{}); len(apps) != 0 {
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
	// an address over its own limit does not spend another document's one read a minute: once that address's minute
	// is over (or for anyone else), the document is still read
	victim, before := ts.URL+"/gen/victim", hits
	body(req(victim, mcpResource))
	if hits != before {
		t.Fatalf("a document was read for an address over its limit")
	}
	if err := h.p.s.Eph.Delete(ctx, nsRateOIDC, "cimd-ip|127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	body(req(victim, mcpResource))
	if hits != before+1 {
		t.Fatalf("the document's read was spent by a caller over its own limit (%d reads)", hits-before)
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

// A resource this process serves (Quisora's MCP server) accepts a user's token only when it names that resource, and
// only while the user may still use the application: the resource's tenant still accepts it.
func TestVerifyResourceToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.mcpTenant("mcp", true)
	cl := h.register("http://127.0.0.1:44001/callback")
	r, _ := h.publicLogin(cl, url.Values{"resource": {mcpResource}})
	tok := r.str("access_token")
	verify := func(resource string) (*model.User, error) {
		req := httptest.NewRequest(http.MethodPost, mcpResource, nil)
		_, u, err := h.p.VerifyResourceToken(req, "Bearer", tok, resource)
		return u, err
	}
	if u, err := verify(mcpResource); err != nil || u.ID != h.user.ID {
		t.Fatalf("the token for the resource: %v %v", u, err)
	}
	if _, err := verify("https://MCP.example.com/mcp/"); err != nil {
		t.Errorf("the same resource written differently: %v", err)
	}
	if _, err := verify("https://other.example/mcp"); err == nil {
		t.Error("accepted for another resource")
	}
	off := tn.Settings
	off.SelfRegistration = false
	if _, err := h.env.Svc.UpdateTenant(ctx, h.admin, tn.ID, service.TenantInput{Settings: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(mcpResource); err == nil {
		t.Error("accepted after the tenant stopped accepting self-registered apps")
	}
}

// An application an administrator set up may use a resource it lists; taking the resource off it stops its tokens at
// once, not when they expire. A client's own token (client_credentials) is never a user's.
func TestVerifyResourceTokenAdminApp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.Resources = &[]string{mcpResource, "https://api.example"}
	})
	verify := func(tok string) error {
		_, _, err := h.p.VerifyResourceToken(httptest.NewRequest(http.MethodPost, mcpResource, nil), "Bearer", tok, mcpResource)
		return err
	}
	forAddress := func(m map[string]any) { m["aud"] = []string{cl.ID, mcpResource} }
	if err := verify(h.forgeAccess(cl, forAddress)); err != nil {
		t.Fatalf("an administrator's application listing the resource: %v", err)
	}
	if err := verify(h.forgeAccess(cl, func(m map[string]any) { forAddress(m); m["sub"] = cl.ID })); err == nil {
		t.Error("accepted a client_credentials token")
	}
	live := h.forgeAccess(cl, forAddress)
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{Resources: &[]string{"https://api.example"}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID) // the cluster does this in a server, on every change to the record
	if err := verify(live); err == nil {
		t.Error("a live token was accepted after the resource was taken off the application")
	}
}

// A metadata document's URL is read at most once a minute, for every caller: a requester that hangs up while it is
// being read does not end the read, and what was read is kept for the sign-in that comes next.
func TestMetadataReadOutlivesItsRequester(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx, hangUp := context.WithCancel(context.Background())
	var id string
	srv, hits := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		hangUp() // while the document is on its way
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Doc App","redirect_uris":["https://app.example/cb"]}`))
	})
	h.p.HTTP = srv.Client()
	id = srv.URL + "/client.json"
	org := h.env.Primary.ID
	_, _, _ = h.p.readMetadata(ctx, nil, org, id, true)
	ce, _, err := h.p.appClient(context.Background(), nil, org, id, nil)
	if err != nil || ce.c.Name != "Doc App" || hits.Load() != 1 {
		t.Fatalf("after the requester hung up: %+v %v, %d reads", ce, err, hits.Load())
	}
}

// metadataDocServer serves, at any path, a valid metadata document naming that URL, padded with pad bytes, with
// redirect as its one redirect URI; before, when set, runs first.
func metadataDocServer(t *testing.T, redirect string, pad int, before func()) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	return newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if before != nil {
			before()
		}
		id := "https://" + r.Host + r.URL.Path
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Gen","redirect_uris":["` + redirect +
			`"],"padding":"` + strings.Repeat("x", pad) + `"}`))
	})
}

// A metadata document read for a request that never becomes a sign-in (here: its redirect URI is not the document's,
// so no flow starts) keeps nothing in the sign-in state: what is shared of it is held in the node's caches, under
// their own cap. Requests nobody has admitted cannot fill the room flows and codes need.
func TestMetadataDocumentsKeepOutOfSignInState(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	srv, hits := metadataDocServer(t, "http://127.0.0.1:44020/callback", 4500, nil)
	h.p.HTTP = srv.Client()
	local, ok := h.env.Server.Eph.(*ephemeral.Local)
	if !ok {
		t.Fatalf("the test server's ephemeral store is %T", h.env.Server.Eph)
	}
	_, ch := pkce()
	before := local.Used()
	const n = 15 // within the address's metadataPerIPMin
	for i := range n {
		cl := &model.Client{Meta: model.Meta{ID: srv.URL + "/flood/" + strconv.Itoa(i)}, RedirectURIs: []string{"http://127.0.0.1:44020/elsewhere"}}
		rec := h.startFrom("198.51.100.40", authzQuery(cl, ch, url.Values{"resource": {mcpResource}}))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "redirect") {
			t.Fatalf("request %d: %d %.200s", i, rec.Code, rec.Body)
		}
	}
	if hits.Load() != n {
		t.Fatalf("%d documents read, want %d", hits.Load(), n)
	}
	if grew := local.Used() - before; grew > 4<<10 {
		t.Errorf("%d documents read for requests that started no sign-in took %d bytes of the sign-in state", n, grew)
	}
	if local.Cached() < n*4500 {
		t.Errorf("the documents read are not shared from the caches: %d bytes there", local.Cached())
	}
}

// The document a sign-in read when it began is kept in its flow: resume and consent do not need the copy every
// caller shares, which a node keeps only while its caches have room (and only for a minute). With that copy never
// kept, the sign-in still completes, its document read once.
func TestMetadataSignInKeepsItsOwnDocument(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44021/callback"
	srv, hits := metadataDocServer(t, redirect, 0, nil)
	h.p.HTTP = srv.Client()
	h.useEph(func(op, ns string) error {
		if op == "set" && ns == nsCIMD {
			return ephemeral.ErrFull // the caches are full: nothing is shared
		}
		return nil
	})
	cl := &model.Client{Meta: model.Meta{ID: srv.URL + "/app.json"}, RedirectURIs: []string{redirect}}
	if r, _ := h.publicLogin(cl, url.Values{"resource": {mcpResource}}); r.status != http.StatusOK {
		t.Fatalf("sign-in with nothing shared: %d %v", r.status, r.m)
	}
	if hits.Load() != 1 {
		t.Errorf("the document was read %d times for one sign-in", hits.Load())
	}
}

// Concurrent first requests for one document share one read: none of them is told the application is unknown because
// another spent the URL's read a minute.
func TestConcurrentFirstMetadataReadsShareOne(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44022/callback"
	g := newGate(t)
	srv, hits := metadataDocServer(t, redirect, 0, g.hold)
	h.p.HTTP = srv.Client()
	cl := &model.Client{Meta: model.Meta{ID: srv.URL + "/shared.json"}, RedirectURIs: []string{redirect}}
	_, ch := pkce()
	const n = 5
	codes := make(chan int, n)
	start := func(i int) {
		rec := h.startFrom("198.51.100."+strconv.Itoa(50+i), authzQuery(cl, ch, url.Values{"resource": {mcpResource}}))
		codes <- rec.Code
	}
	go start(0)
	g.waitHeld(t) // the first read is under way
	for i := 1; i < n; i++ {
		go start(i)
	}
	time.Sleep(200 * time.Millisecond) // the others arrive while it is
	g.open()
	for range n {
		if code := <-codes; code != http.StatusFound {
			t.Errorf("a concurrent first request: %d, want a sign-in started (302)", code)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("the document was read %d times", hits.Load())
	}
}

// A URL's read a minute is each organization's own: requests naming one organization (anyone may send them, every
// minute) cannot keep another organization's application from being read, even when nothing read is shared.
func TestMetadataReadLimitIsPerOrganization(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	srv, hits := metadataDocServer(t, "https://app.example/cb", 0, nil)
	h.p.HTTP = srv.Client()
	h.useEph(func(op, ns string) error {
		if op == "set" && ns == nsCIMD {
			return ephemeral.ErrFull
		}
		return nil
	})
	ctx, id := context.Background(), srv.URL+"/client.json"
	if c, _, err := h.p.readMetadata(ctx, nil, "org-attacker", id, true); c == nil || err != nil {
		t.Fatalf("first read: %v", err)
	}
	if c, _, err := h.p.readMetadata(ctx, nil, "org-victim", id, true); c == nil || err != nil || c.OrgID != "org-victim" {
		t.Fatalf("another organization's read in the same minute: %+v %v", c, err)
	}
	if hits.Load() != 2 {
		t.Fatalf("%d reads, want one per organization", hits.Load())
	}
	// Nothing was shared (the caches could not keep it): the minute's read is over, so a caller reads again rather
	// than wait for a copy that is not coming, a few times a minute at most, and is refused at once past them.
	for i := range metadataRereadsPerMin {
		if c, _, _ := h.p.readMetadata(ctx, nil, "org-victim", id, true); c == nil || hits.Load() != int32(3+i) {
			t.Fatalf("read again %d, nothing shared: %v, %d reads", i+1, c != nil, hits.Load())
		}
	}
	start := time.Now()
	if c, _, _ := h.p.readMetadata(ctx, nil, "org-victim", id, true); c != nil || hits.Load() != 2+metadataRereadsPerMin ||
		time.Since(start) > 3*time.Second {
		t.Errorf("a read for one organization past the minute's reads again: %v, %d reads, after %v", c != nil, hits.Load(), time.Since(start))
	}
}

// A self-registered application's first use is on record before its code is issued: when it cannot be recorded, no
// code is issued (the flow is kept, and works once the store does), for an application never used is one the cap on
// unused registrations may remove, its users' grants with it.
func TestSelfRegisteredFirstUseRecordedBeforeCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	cl := h.register("http://127.0.0.1:44023/callback")
	c, csrf := h.session(h.user)
	_, ch := pkce()
	to := h.authorize(c, authzQuery(cl, ch, url.Values{"resource": {mcpResource}}))
	_, resume := h.decideConsent(c, csrf, to.Query().Get("flow"), true)
	if resume == "" {
		t.Fatalf("consent not accepted: %s", to)
	}
	good := h.env.Svc.Clients.S
	h.env.Svc.Clients.S = failCAS(good, model.KindClient, func() error { return store.ErrUnavailable })
	resp := h.get(c, resume)
	text := body(resp)
	h.env.Svc.Clients.S = good
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Location") != "" {
		t.Fatalf("a code with the use unrecorded: %d %s %.200s", resp.StatusCode, resp.Header.Get("Location"), text)
	}
	if stored, _ := h.env.Svc.Clients.Get(ctx, cl.ID); !stored.LastUsed.IsZero() {
		t.Fatal("use recorded through a failing store")
	}
	if code := loc(t, h.get(c, resume)).Query().Get("code"); code == "" {
		t.Fatal("no code once the use could be recorded")
	}
	if stored, _ := h.env.Svc.Clients.Get(ctx, cl.ID); stored.LastUsed.IsZero() {
		t.Error("use not recorded")
	}
}
