package admin_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPages(t *testing.T) {
	w := newWorld(t)
	ad, su, mg := w.as("admin"), w.as("super"), w.as("manager")
	html := func(c *caller, path string, status int) string {
		t.Helper()
		req, _ := http.NewRequest("GET", w.env.URL+path, nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != status {
			t.Fatalf("%s: status %d want %d\n%s", path, res.StatusCode, status, b)
		}
		return string(b)
	}
	for _, p := range []struct{ path, comp string }{
		{"/admin/orgs/acme/users", "adminUsers"}, {"/admin/orgs/acme/groups", "adminGroups"},
		{"/admin/orgs/acme/tenants", "adminTenants"}, {"/admin/orgs/acme/providers", "adminProviders"}, {"/admin/orgs/acme/audit", "adminAudit"},
		{"/admin/orgs/acme/service-accounts", "adminServiceAccounts"},
		{"/admin/orgs/acme/users/" + w.users["user"].ID, "adminUser"},
	} {
		body := html(ad, p.path, 200)
		for _, s := range []string{`x-data="` + p.comp + `"`, `<meta name="csrf-token" content="`, `aria-label="Primary"`, `class="skip-link"`,
			`<h1 `, `/api/orgs/acme`, `theme-boot-`, `lang="en"`} {
			if !strings.Contains(body, s) {
				t.Errorf("%s missing %q", p.path, s)
			}
		}
		if strings.Contains(body, "<script>") || strings.Contains(body, " onclick=") {
			t.Errorf("%s: inline script", p.path)
		}
	}
	if b := html(su, "/admin/orgs", 200); !strings.Contains(b, `x-data="adminOrgs"`) || !strings.Contains(b, `href="/admin/orgs" aria-current="page"`) {
		t.Error("orgs page")
	}
	// the organization block: for administrators the link to its overview (current on that page); for managers a
	// label; the organizations list is a System link, for super admins only
	if b := html(ad, "/admin/orgs/acme", 200); !strings.Contains(b, `class="nav-link nav-org-link" href="/admin/orgs/acme" aria-current="page"`) ||
		strings.Contains(b, `href="/admin/orgs"`) {
		t.Error("admin: organization block")
	}
	if b := html(mg, "/admin/orgs/acme/users", 200); strings.Contains(b, "nav-org-link") || !strings.Contains(b, `class="nav-org"`) {
		t.Error("manager: organization block")
	}
	if b := html(su, "/admin/orgs/acme/users", 200); !strings.Contains(b, `href="/admin/orgs"`) || !strings.Contains(b, `href="/admin/audit"`) {
		t.Error("super admin: System links")
	}
	// the audit log of every organization is reached from the menu, not from an organization's audit log
	if b := html(su, "/admin/orgs/acme/audit", 200); strings.Count(b, `href="/admin/audit"`) != 1 {
		t.Error("an organization's audit log links to every organization's besides the menu")
	}
	// current-page marker in the navigation
	if b := html(ad, "/admin/orgs/acme/groups", 200); !strings.Contains(b, `href="/admin/orgs/acme/groups" aria-current="page"`) {
		t.Error("aria-current")
	}
	// super admin administering another org: the nav shows that org
	if b := html(su, "/admin/orgs/globex/users", 200); !strings.Contains(b, "Globex") || !strings.Contains(b, `/api/orgs/globex`) {
		t.Error("super admin on another org")
	}

	// the system overview (the server as a whole: cluster, signing keys, emergency sign-out): super admins only, in the
	// menu's System group, which keeps the organization last administered
	if b := html(su, "/admin/system", 200); !strings.Contains(b, `x-data="adminSystem"`) ||
		!strings.Contains(b, `href="/admin/system" aria-current="page"`) || !strings.Contains(b, `id="signout-dialog"`) ||
		!strings.Contains(b, `id="rotate-keys"`) || !strings.Contains(b, `aria-label="Cluster nodes table"`) {
		t.Error("system overview")
	}
	if b := html(su, "/admin/orgs/acme/users", 200); !strings.Contains(b, `href="/admin/system"`) {
		t.Error("no system link for a super admin")
	}
	if b := html(su, "/admin/system", 200); !strings.Contains(b, `href="/admin/orgs/acme/users"`) {
		t.Error("the system overview does not keep the organization last administered")
	}
	html(su, "/admin/orgs/globex/users", 200)
	if b := html(su, "/admin/system", 200); !strings.Contains(b, `href="/admin/orgs/globex/users"`) {
		t.Error("the system overview does not follow the organization last administered")
	}
	for _, path := range []string{"/admin/system", "/admin/system/master-key"} {
		html(ad, path, 404)
		html(mg, path, 404)
	}
	if b := html(ad, "/admin/orgs/acme/users", 200); strings.Contains(b, "/admin/system") {
		t.Error("system link for an organization admin")
	}
	w.env.Server.Site.Clustered = true
	html(su, "/admin/orgs/primary/settings", 404) // organization settings are edited from the organizations list
	w.env.Server.Site.Clustered = false

	// permissions
	html(ad, "/admin/orgs", 403)
	html(su, "/admin/audit", 200) // every organization's audit log
	html(ad, "/admin/audit", 403)
	html(mg, "/admin/orgs/acme/users", 200)
	// managers reach the groups page for its members dialog only
	if b := html(mg, "/admin/orgs/acme/groups", 200); !strings.Contains(b, `href="/admin/orgs/acme/groups" aria-current="page"`) ||
		strings.Contains(b, "data-admin") || strings.Contains(b, "openCreate") || strings.Contains(b, `@click="edit"`) || strings.Contains(b, `@click="remove"`) ||
		!strings.Contains(b, `@click="openMembers"`) {
		t.Error("manager: groups page")
	}
	if b := html(ad, "/admin/orgs/acme/groups", 200); !strings.Contains(b, "data-admin") || !strings.Contains(b, "openCreate") {
		t.Error("admin: groups page")
	}
	html(mg, "/admin/orgs/acme/service-accounts", 403)
	if b := html(mg, "/admin/orgs/acme/users", 200); strings.Contains(b, "/service-accounts") {
		t.Error("manager: service accounts link")
	}
	if b := html(ad, "/admin/orgs/acme/users", 200); !strings.Contains(b, `href="/admin/orgs/acme/service-accounts"`) {
		t.Error("admin: no service accounts link")
	}
	b := html(mg, "/admin/orgs/acme/tenants", 403)
	if !strings.Contains(b, "Not allowed") || !strings.Contains(b, "<h1") {
		t.Error("403 page")
	}
	html(w.as("user"), "/admin/orgs/acme/users", 403)
	html(ad, "/admin/orgs/globex/users", 404)
	html(ad, "/admin/orgs/nope/users", 404)
	html(ad, "/admin/orgs/acme/users/not-a-user", 200) // the page loads; the API reports the missing user
	// an organization's overview, with its emergency sign-out: its administrators and super admins; managers go to users
	if b := html(ad, "/admin/orgs/acme", 200); !strings.Contains(b, `x-data="adminOrg"`) ||
		!strings.Contains(b, `href="/admin/orgs/acme" aria-current="page"`) || !strings.Contains(b, `id="signout-dialog"`) {
		t.Error("organization overview")
	}
	html(su, "/admin/orgs/globex", 200)
	html(ad, "/admin/orgs/globex", 404)
	html(mg, "/admin/orgs/acme", 303)
	if b := html(mg, "/admin/orgs/acme/users", 200); strings.Contains(b, `href="/admin/orgs/acme" `) {
		t.Error("overview link for a manager")
	}

	// redirects
	loc := func(c *caller, path string) string {
		req, _ := http.NewRequest("GET", w.env.URL+path, nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.Header.Get("Location")
	}
	// signed out: an organization's pages go to its sign-in page (and back); the rest to the primary organization's
	if l := loc(w.anon(), "/admin/orgs"); l != "/o/"+w.env.Primary.ID+"/login?next="+url.QueryEscape("/admin/orgs") {
		t.Errorf("anonymous redirect %q", l)
	}
	if l := loc(w.anon(), "/admin/orgs/acme/users?q=x"); l != "/o/acme/login?next="+url.QueryEscape("/admin/orgs/acme/users?q=x") {
		t.Errorf("anonymous redirect from an organization's page %q", l)
	}
	if l := loc(su, "/admin"); l != "/admin/system" {
		t.Errorf("super /admin -> %q", l)
	}
	if l := loc(ad, "/admin"); l != "/admin/orgs/acme" {
		t.Errorf("admin /admin -> %q", l)
	}
	if l := loc(mg, "/admin"); l != "/admin/orgs/acme/users" {
		t.Errorf("manager /admin -> %q", l)
	}
	if l := loc(mg, "/admin/orgs/acme"); l != "/admin/orgs/acme/users" {
		t.Errorf("org home for a manager -> %q", l)
	}
	html(w.as("user"), "/admin", 403)
	// clients live under tenants: the old page redirects to the tenants list
	if l := loc(ad, "/admin/orgs/acme/clients"); l != "/admin/orgs/acme/tenants" {
		t.Errorf("clients -> %q", l)
	}
}

func TestNotFound(t *testing.T) {
	w := newWorld(t)
	anon := w.anon()
	res, err := anon.c.Get(w.env.URL + "/no/such/page")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	// signed out: how to sign in, as a 404
	if res.StatusCode != 404 || !strings.Contains(string(b), "Sign in through your application") || !strings.Contains(string(b), "does not exist") ||
		!strings.Contains(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("html 404 signed out: %d %s", res.StatusCode, b)
	}
	// signed in: the ordinary not-found page
	in, err := w.as("admin").c.Get(w.env.URL + "/no/such/page")
	if err != nil {
		t.Fatal(err)
	}
	ib, _ := io.ReadAll(in.Body)
	in.Body.Close()
	if in.StatusCode != 404 || !strings.Contains(string(ib), "Page not found") {
		t.Fatalf("html 404 signed in: %d %.300s", in.StatusCode, ib)
	}
	r := anon.get("/api/nothing")
	want(t, r, 404)
	if r.str("error") == "" {
		t.Fatal("json 404 body")
	}
}

func TestErrorPageTemplates(t *testing.T) {
	// every status the error page is used for renders
	w := newWorld(t)
	for p, status := range map[string]int{"/admin/orgs": 403, "/admin/nope": 404} {
		res, err := w.as("admin").c.Get(w.env.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != status || !strings.Contains(string(b), "Error ") {
			t.Fatalf("%s: %d, want %d", p, res.StatusCode, status)
		}
	}
}

// The users list's role filter offers the viewer's own role and lower: super admin only to super admins on the primary
// organization.
func TestRoleFilterOptions(t *testing.T) {
	w := newWorld(t)
	page := func(c *caller, path string) string {
		r := c.do("GET", path, nil)
		want(t, r, 200)
		b := string(r.Raw)
		start := strings.Index(b, `id="filter-role"`)
		return b[start : start+strings.Index(b[start:], "</select>")]
	}
	for _, c := range []struct {
		who, path string
		want      []string
		not       []string
	}{
		{"manager", "/admin/orgs/acme/users", []string{`"user"`, `"manager"`}, []string{`"admin"`, `"super_admin"`}},
		{"admin", "/admin/orgs/acme/users", []string{`"user"`, `"manager"`, `"admin"`}, []string{`"super_admin"`}},
		{"super", "/admin/orgs/acme/users", []string{`"admin"`}, []string{`"super_admin"`}},
		{"super", "/admin/orgs/primary/users", []string{`"admin"`, `"super_admin"`}, nil},
	} {
		sel := page(w.as(c.who), c.path)
		for _, v := range c.want {
			if !strings.Contains(sel, `value=`+v) {
				t.Errorf("%s on %s: no %s option", c.who, c.path, v)
			}
		}
		for _, v := range c.not {
			if strings.Contains(sel, `value=`+v) {
				t.Errorf("%s on %s: %s offered", c.who, c.path, v)
			}
		}
	}
}
