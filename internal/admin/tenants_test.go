package admin_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

func TestTenants(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	T := A + "/tenants"

	// every org starts with its default tenant
	r := ad.get(T)
	want(t, r, 200)
	if r.total() != 1 || r.items()[0].(map[string]any)["name"] != "default" {
		t.Fatalf("default tenant: %s", r.Raw)
	}
	defID := r.items()[0].(map[string]any)["id"].(string)

	// create with settings
	prov := ad.post(A+"/providers", map[string]any{"type": "oidc", "name": "SSO", "issuer": "https://sso.example", "client_id": "c", "client_secret": "s"})
	want(t, prov, 201)
	r = ad.post(T, map[string]any{"name": "staff", "display_name": "Staff", "description": "Internal", "settings": map[string]any{
		"password_login": false, "passkey_login": true, "all_providers": false, "providers": []string{prov.str("id")}, "require_mfa": true}})
	want(t, r, 201)
	id := r.str("id")
	set, _ := r.JSON["settings"].(map[string]any)
	if r.str("name") != "staff" || set["password_login"] != false || set["require_mfa"] != true || r.JSON["clients"] != float64(0) {
		t.Fatalf("create: %s", r.Raw)
	}
	// defaults: everything the org allows
	r = ad.post(T, map[string]any{"name": "plain", "display_name": "Plain"})
	want(t, r, 201)
	set, _ = r.JSON["settings"].(map[string]any)
	if set["password_login"] != true || set["all_providers"] != true {
		t.Fatalf("default settings: %s", r.Raw)
	}
	wantField(t, ad.post(T, map[string]any{"name": "staff", "display_name": "Dup"}), 409, "name")
	wantField(t, ad.post(T, map[string]any{"name": "Bad Name", "display_name": "x"}), 422, "name")
	wantField(t, ad.post(T, map[string]any{"display_name": "x"}), 422, "name")
	wantField(t, ad.post(T, map[string]any{"name": "nodisplay", "display_name": " "}), 422, "display_name")
	wantField(t, ad.post(T, map[string]any{"name": "x1", "display_name": "x", "settings": map[string]any{"providers": []string{"nope"}}}), 422, "settings")

	// a provider of another organization cannot be allowed
	gp := w.as("other").post(G+"/providers", map[string]any{"type": "oidc", "name": "Theirs", "issuer": "https://t.example", "client_id": "c", "client_secret": "s"})
	want(t, gp, 201)
	wantField(t, ad.post(T, map[string]any{"name": "x2", "display_name": "x", "settings": map[string]any{"providers": []string{gp.str("id")}}}), 422, "settings")

	// get, list, search, sort, paging
	r = ad.get(T + "/" + id)
	want(t, r, 200)
	if r.str("display_name") != "Staff" {
		t.Fatal(string(r.Raw))
	}
	if ad.get(T).total() != 3 || ad.get(T+"?q=staf").total() != 1 || ad.get(T+"?q=zzz").total() != 0 {
		t.Fatal("list / search")
	}
	if ad.get(T + "?sort=name&desc=1").items()[0].(map[string]any)["name"] != "staff" {
		t.Fatal("sort")
	}
	if r = ad.get(T + "?limit=1&offset=1"); len(r.items()) != 1 || r.total() != 3 {
		t.Fatal("paging")
	}

	// patch
	r = ad.patch(T+"/"+id, map[string]any{"display_name": "Staff tools", "settings": map[string]any{"password_login": true, "passkey_login": true, "all_providers": true}})
	want(t, r, 200)
	set, _ = r.JSON["settings"].(map[string]any)
	if r.str("display_name") != "Staff tools" || set["all_providers"] != true || r.str("name") != "staff" {
		t.Fatal(string(r.Raw))
	}
	wantField(t, ad.patch(T+"/"+id, map[string]any{"name": "plain"}), 409, "name")
	want(t, ad.patch(T+"/"+id, map[string]any{"bogus": 1}), 400)

	// clients: tenant_id is accepted, returned, validated and filterable
	r = ad.post(A+"/clients", map[string]any{"name": "Portal", "tenant_id": id, "redirect_uris": []string{"https://p.example/cb"}})
	want(t, r, 201)
	cid := r.str("id")
	if r.str("tenant_id") != id {
		t.Fatalf("client tenant: %s", r.Raw)
	}
	r = ad.post(A+"/clients", map[string]any{"name": "Untenanted", "redirect_uris": []string{"https://u.example/cb"}})
	want(t, r, 201)
	if r.str("tenant_id") != defID {
		t.Fatalf("client without tenant gets the default tenant: %s", r.Raw)
	}
	wantField(t, ad.post(A+"/clients", map[string]any{"name": "Bad", "tenant_id": "nope", "redirect_uris": []string{"https://b.example/cb"}}), 422, "tenant_id")
	ot := w.as("other").post(G+"/tenants", map[string]any{"name": "theirs", "display_name": "Theirs"})
	want(t, ot, 201)
	wantField(t, ad.post(A+"/clients", map[string]any{"name": "Bad", "tenant_id": ot.str("id"), "redirect_uris": []string{"https://b.example/cb"}}), 422, "tenant_id")
	wantField(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": ot.str("id")}), 422, "tenant_id")
	if r = ad.get(A + "/clients?tenant=" + id); r.total() != 1 || r.items()[0].(map[string]any)["id"] != cid {
		t.Fatalf("tenant filter: %s", r.Raw)
	}
	if ad.get(A+"/clients?tenant="+defID).total() != 1 || ad.get(A+"/clients").total() != 2 || ad.get(A+"/clients?tenant=nope").total() != 0 {
		t.Fatal("tenant filter counts")
	}
	want(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": defID}), 200)
	if ad.get(A+"/clients?tenant="+defID).total() != 2 {
		t.Fatal("moving a client between tenants")
	}
	want(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": id}), 200)

	// clients count; delete in use -> 409
	r = ad.get(T + "/" + id)
	if r.JSON["clients"] != float64(1) {
		t.Fatalf("clients count: %s", r.Raw)
	}
	for _, it := range ad.get(T + "?q=staff").items() {
		if it.(map[string]any)["clients"] != float64(1) {
			t.Fatal("list clients count")
		}
	}
	r = ad.delete(T + "/" + id)
	want(t, r, 409)
	if !strings.Contains(r.str("error"), "clients") {
		t.Fatal(string(r.Raw))
	}
	want(t, ad.delete(A+"/clients/"+cid), 200)
	want(t, ad.delete(T+"/"+id), 200)
	want(t, ad.get(T+"/"+id), 404)
	want(t, ad.delete(T+"/"+id), 404)

	// tenants of another organization are invisible
	want(t, ad.get(T+"/"+ot.str("id")), 404)
	want(t, ad.patch(T+"/"+ot.str("id"), map[string]any{"display_name": "x"}), 404)
	want(t, ad.delete(T+"/"+ot.str("id")), 404)
	want(t, w.as("other").get(T+"/"+defID), 404)
}

func TestTenantPermissions(t *testing.T) {
	w := newWorld(t)
	T := A + "/tenants"
	made := w.as("admin").post(T, map[string]any{"name": "t1", "display_name": "T1"})
	want(t, made, 201)
	id := made.str("id")

	// admins and super admins: full access; super may act in any org
	su := w.as("super")
	want(t, su.get(T), 200)
	want(t, su.post(T, map[string]any{"name": "bysuper", "display_name": "By super"}), 201)
	want(t, su.patch(T+"/"+id, map[string]any{"description": "d"}), 200)
	want(t, su.get(G+"/tenants"), 200)

	// managers and users: forbidden everywhere
	for _, who := range []string{"manager", "user"} {
		c := w.as(who)
		want(t, c.get(T), 403)
		want(t, c.post(T, map[string]any{"name": "x", "display_name": "x"}), 403)
		// a single tenant is invisible to those who may not administer the org
		want(t, c.get(T+"/"+id), 404)
		want(t, c.patch(T+"/"+id, map[string]any{"description": "x"}), 404)
		want(t, c.delete(T+"/"+id), 404)
	}

	// another organization's admin: acme does not exist for them
	ot := w.as("other")
	want(t, ot.get(T), 404)
	want(t, ot.post(T, map[string]any{"name": "x", "display_name": "x"}), 404)
	want(t, ot.get(T+"/"+id), 404)
	want(t, ot.patch(T+"/"+id, map[string]any{"description": "x"}), 404)
	want(t, ot.delete(T+"/"+id), 404)
	want(t, ot.get(G+"/tenants"), 200)

	// anonymous
	want(t, w.anon().get(T), 401)

	// bearer tokens: the role still limits the call; the admin scope is required
	at := w.withBearer("admin", service.ScopeAdmin)
	want(t, at.get(T), 200)
	want(t, at.post(T, map[string]any{"name": "viatoken", "display_name": "Via token"}), 201)
	want(t, at.get(T+"/"+id), 200)
	want(t, at.patch(T+"/"+id, map[string]any{"description": "tok"}), 200)
	want(t, at.get(G+"/tenants"), 404)
	mt := w.withBearer("manager", service.ScopeAdmin)
	want(t, mt.get(T), 403)
	want(t, mt.post(T, map[string]any{"name": "x", "display_name": "x"}), 403)
	api := w.withBearer("admin", service.ScopeAPI)
	want(t, api.get(T), 403)
	want(t, at.delete(T+"/"+id), 200)
}

// The tenant page: same RBAC as the tenants list, 404 for unknown tenants and tenants of other organizations.
func TestTenantPage(t *testing.T) {
	w := newWorld(t)
	ad, su, mg, us := w.as("admin"), w.as("super"), w.as("manager"), w.as("user")
	get := func(c *caller, path string) (int, string, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", w.env.URL+path, nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b), res.Header.Get("Location")
	}
	st := ad.post("/api/orgs/acme/tenants", map[string]any{"name": "staff", "display_name": "Staff tools"})
	want(t, st, 201)
	want(t, su.post("/api/orgs/globex/tenants", map[string]any{"name": "theirs", "display_name": "Theirs"}), 201)

	code, body, _ := get(ad, "/admin/orgs/acme/tenants/staff")
	if code != 200 {
		t.Fatalf("tenant page: %d", code)
	}
	for _, s := range []string{`x-data="adminTenant"`, `aria-label="Breadcrumb"`, `aria-current="page"`, "Tenant: Staff tools", `data-tenant="` + st.str("id") + `"`,
		`/api/orgs/acme`, `href="/admin/orgs/acme/tenants"`} {
		if !strings.Contains(body, s) {
			t.Errorf("tenant page missing %q", s)
		}
	}
	if strings.Contains(body, `href="/admin/orgs/acme/clients"`) {
		t.Error("the navigation must not link to a top-level Clients page")
	}
	if code, _, _ = get(ad, "/admin/orgs/acme/tenants/default"); code != 200 {
		t.Errorf("default tenant page: %d", code)
	}
	// the tenant's clients and SSH certificates have pages of their own, under the tenant's: same rules, own title and
	// component, the breadcrumb back to the tenant
	for _, sub := range []struct{ path, comp, title, crumb string }{
		{"clients", "adminTenantClients", "Clients: Staff tools", `<span aria-current="page">Clients</span>`},
		{"ssh", "adminTenantSSH", "SSH certificates: Staff tools", `<span aria-current="page">SSH certificates</span>`},
	} {
		code, body, _ := get(ad, "/admin/orgs/acme/tenants/staff/"+sub.path)
		if code != 200 {
			t.Fatalf("%s page: %d", sub.path, code)
		}
		for _, s := range []string{`x-data="` + sub.comp + `"`, `aria-label="Breadcrumb"`, sub.crumb, sub.title, `data-tenant="` + st.str("id") + `"`,
			`data-slug="staff"`, `/api/orgs/acme`, `href="/admin/orgs/acme/tenants"`} {
			if !strings.Contains(body, s) {
				t.Errorf("%s page missing %q", sub.path, s)
			}
		}
		if code, _, _ = get(ad, "/admin/orgs/acme/tenants/default/"+sub.path); code != 200 {
			t.Errorf("default tenant's %s page: %d", sub.path, code)
		}
		if code, _, _ = get(su, "/admin/orgs/globex/tenants/theirs/"+sub.path); code != 200 {
			t.Errorf("super admin, other org, %s: %d", sub.path, code)
		}
		for _, p := range []string{"/admin/orgs/acme/tenants/nope/", "/admin/orgs/acme/tenants/theirs/", "/admin/orgs/globex/tenants/staff/", "/admin/orgs/nope/tenants/staff/"} {
			if code, _, _ = get(su, p+sub.path); code != 404 {
				t.Errorf("%s%s (super): %d want 404", p, sub.path, code)
			}
		}
		if code, _, _ = get(ad, "/admin/orgs/globex/tenants/theirs/"+sub.path); code != 404 {
			t.Errorf("admin of another org, %s: %d want 404", sub.path, code)
		}
		for _, c := range []*caller{mg, us} {
			if code, _, _ = get(c, "/admin/orgs/acme/tenants/staff/"+sub.path); code != 403 {
				t.Errorf("non-admin, %s: %d want 403", sub.path, code)
			}
		}
		if code, _, l := get(w.anon(), "/admin/orgs/acme/tenants/staff/"+sub.path); code != 303 || !strings.HasPrefix(l, "/o/acme/login?next=") {
			t.Errorf("anonymous, %s: %d %q", sub.path, code, l)
		}
	}
	// the tenant page itself leads to them, and no longer holds the clients table or the SSH card
	if _, body, _ := get(ad, "/admin/orgs/acme/tenants/staff"); strings.Contains(body, `aria-label="Clients table"`) || strings.Contains(body, `x-data="tenantSSH"`) ||
		!strings.Contains(body, `Manage clients`) || !strings.Contains(body, `Manage SSH certificates`) {
		t.Error("the tenant page does not lead to its clients and SSH pages")
	}
	if code, _, _ = get(su, "/admin/orgs/acme/tenants/staff"); code != 200 {
		t.Errorf("super admin: %d", code)
	}
	if code, _, _ = get(su, "/admin/orgs/globex/tenants/theirs"); code != 200 {
		t.Errorf("super admin, other org: %d", code)
	}
	// unknown tenant, tenant of another organization, unknown organization
	for _, p := range []string{"/admin/orgs/acme/tenants/nope", "/admin/orgs/acme/tenants/theirs", "/admin/orgs/globex/tenants/staff", "/admin/orgs/nope/tenants/staff"} {
		if code, _, _ = get(su, p); code != 404 {
			t.Errorf("%s (super): %d want 404", p, code)
		}
	}
	if code, _, _ = get(ad, "/admin/orgs/globex/tenants/theirs"); code != 404 {
		t.Errorf("admin of another org: %d want 404", code)
	}
	// RBAC as the tenants list: managers and users are refused, anonymous visitors go to sign-in
	for _, c := range []*caller{mg, us} {
		if code, _, _ = get(c, "/admin/orgs/acme/tenants/staff"); code != 403 {
			t.Errorf("non-admin: %d want 403", code)
		}
	}
	if code, _, l := get(w.anon(), "/admin/orgs/acme/tenants/staff"); code != 303 || !strings.HasPrefix(l, "/o/acme/login?next=") {
		t.Errorf("anonymous: %d %q", code, l)
	}
	// old clients URL redirects (302) for everyone who can sign in; anonymous users are sent to sign-in first
	if code, _, l := get(ad, "/admin/orgs/acme/clients"); code != 302 || l != "/admin/orgs/acme/tenants" {
		t.Errorf("clients redirect: %d %q", code, l)
	}
}

func TestTenantAccessAPI(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	made := ad.post(A+"/tenants", map[string]any{"name": "staff", "display_name": "Staff"})
	want(t, made, 201)
	if set, _ := made.JSON["settings"].(map[string]any); set["members_only"] != true {
		t.Fatalf("a new tenant is members-only: %s", made.Raw)
	}
	T := A + "/tenants/" + made.str("id") + "/access"
	cl := ad.post(A+"/clients", map[string]any{"name": "app", "tenant_id": made.str("id"), "redirect_uris": []string{"https://app.example/cb"}})
	want(t, cl, 201)
	alan := w.users["user"]

	r := ad.post(T, map[string]any{"subject_type": "user", "subject_id": alan.ID, "roles": []string{"editor"}, "tags": []string{"t1"},
		"all_clients": false, "clients": []string{cl.str("id")}, "expires": "2099-01-01"})
	want(t, r, 201)
	if r.str("name") == "" || r.str("detail") != alan.Email || r.JSON["all_clients"] != false || r.JSON["expired"] != false ||
		!strings.HasPrefix(r.str("expires"), "2099-01-01T00:00:00") {
		t.Fatalf("add: %s", r.Raw)
	}
	aid := r.str("id")
	want(t, ad.post(T, map[string]any{"subject_type": "user", "subject_id": alan.ID}), 409)
	want(t, ad.post(T, map[string]any{"subject_type": "user", "subject_id": w.users["other"].ID}), 422)

	r = ad.get(T + "?q=" + url.QueryEscape(alan.Email))
	want(t, r, 200)
	if r.total() != 1 {
		t.Fatalf("search: %s", r.Raw)
	}
	r = ad.patch(T+"/"+aid, map[string]any{"all_clients": true, "expires": ""})
	want(t, r, 200)
	if r.JSON["all_clients"] != true || r.JSON["expires"] != nil {
		t.Fatalf("update: %s", r.Raw)
	}
	want(t, ad.get(T+"/"+aid), 200)

	// malformed bodies, unknown subjects and unknown ids; the organization's self-registered apps are listed alongside
	SR := A + "/self-registered"
	for _, c := range []struct {
		method, path string
		body         any
		status       int
	}{
		{"POST", T, "not json", 400},
		{"POST", T, map[string]any{"subject_type": "user", "subject_id": "ghost"}, 422},
		{"PATCH", T + "/" + aid, "not json", 400},
		{"GET", T + "/nope", nil, 404},
		{"PATCH", T + "/nope", map[string]any{"tags": []string{"x"}}, 404},
		{"DELETE", T + "/nope", nil, 404},
		{"GET", SR, nil, 200},
		{"DELETE", SR + "/ghost", nil, 404},
	} {
		if r := ad.do(c.method, c.path, c.body); r.Status != c.status {
			t.Errorf("%s %s: %d, want %d: %s", c.method, c.path, r.Status, c.status, r.Raw)
		}
	}

	// managers, users and other organizations cannot see or change access
	for _, who := range []string{"manager", "user"} {
		want(t, w.as(who).get(T), 404)
		want(t, w.as(who).post(T, map[string]any{"subject_type": "user", "subject_id": alan.ID}), 404)
	}
	for _, p := range []string{T, T + "/" + aid, SR} {
		want(t, w.as("other").get(p), 404)
	}

	want(t, ad.delete(T+"/"+aid), 200)
	want(t, ad.get(T+"/"+aid), 404)
	if r := ad.get(T); r.total() != 0 {
		t.Fatalf("after delete: %s", r.Raw)
	}
}

// A tenant is addressed by its id or by its name (the console shows and links by name); another organization's
// tenant name never resolves.
func TestTenantByName(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	T := A + "/tenants"
	r := ad.post(T, map[string]any{"name": "mcp", "display_name": "MCP", "resources": []string{"https://mcp.example.com/mcp"},
		"settings": map[string]any{"password_login": true, "passkey_login": true, "all_providers": true, "self_registration": true}})
	want(t, r, 201)
	id := r.str("id")
	byName := ad.get(T + "/mcp")
	want(t, byName, 200)
	if byName.str("id") != id {
		t.Fatalf("by name: %s", byName.Raw)
	}
	want(t, ad.patch(T+"/mcp", map[string]any{"display_name": "MCP servers"}), 200)
	want(t, ad.get(T+"/no-such-tenant"), 404)
	want(t, w.as("other").get(G+"/tenants/mcp"), 404) // globex has no tenant named mcp
	want(t, w.as("other").get(A+"/tenants/mcp"), 404) // and acme's is not theirs
}
