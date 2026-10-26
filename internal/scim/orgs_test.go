package scim_test

import (
	"slices"
	"testing"
)

func TestOrganizationsResource(t *testing.T) {
	e := newEnv(t)
	// Super admins only.
	for _, tok := range []string{e.admA, e.mgrA, e.admB} {
		if r := e.do("GET", "/scim/v2/Organizations", tok, nil); r.Status != 403 {
			t.Errorf("non-super list: %d", r.Status)
		}
		if r := e.do("POST", "/scim/v2/Organizations", tok, map[string]any{"name": "sneaky"}); r.Status != 403 {
			t.Errorf("non-super create: %d", r.Status)
		}
		if r := e.do("DELETE", "/scim/v2/Organizations/"+e.orgB.ID, tok, nil); r.Status != 403 {
			t.Errorf("non-super delete: %d", r.Status)
		}
	}
	if r := e.do("GET", "/scim/v2/Organizations", "", nil); r.Status != 401 {
		t.Errorf("anonymous: %d", r.Status)
	}
	// List, filter, sort.
	r := e.do("GET", "/scim/v2/Organizations?sortBy=name", e.super, nil)
	if r.Status != 200 || r.total() != 3 || !slices.Equal(r.names("name"), []string{"acme", "globex", "primary"}) {
		t.Errorf("list: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/Organizations?filter="+qs(`name eq "GLOBEX"`), e.super, nil); r.total() != 1 {
		t.Errorf("filter eq: %s", r.Raw)
	}
	if r := e.do("GET", "/scim/v2/Organizations?filter="+qs(`primary eq true`), e.super, nil); r.total() != 1 || r.names("name")[0] != "primary" {
		t.Errorf("filter primary: %s", r.Raw)
	}
	if r := e.do("GET", "/scim/v2/Organizations?count=1&startIndex=2&sortBy=name", e.super, nil); r.total() != 3 || r.names("name")[0] != "globex" {
		t.Errorf("paging: %s", r.Raw)
	}
	// Create.
	c := e.do("POST", "/scim/v2/Organizations", e.super, map[string]any{"schemas": []string{schemaOrgURN}, "name": "initech", "displayName": "Initech",
		"settings": map[string]any{"requireMfa": true, "sessionTtl": 3600}})
	if c.Status != 201 || c.str("name") != "initech" || c.str("meta", "resourceType") != "Organization" || c.Header.Get("ETag") == "" ||
		c.Header.Get("Location") != e.URL+"/scim/v2/Organizations/"+c.str("id") {
		t.Fatalf("create: %d %v %s", c.Status, c.Header, c.Raw)
	}
	st := c.Body["settings"].(map[string]any)
	if st["requireMfa"] != true || st["sessionTtl"].(float64) != 3600 || st["passwordLogin"] != true {
		t.Errorf("settings: %v", st)
	}
	id := c.str("id")
	o, err := e.Svc.OrgByName(e.ctx, "initech")
	if err != nil || o.ID != id || !o.Settings.RequireMFA {
		t.Errorf("stored org: %v", err)
	}
	// Errors.
	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		typ    string
	}{
		"duplicate":  {map[string]any{"name": "acme"}, 409, "uniqueness"},
		"reserved":   {map[string]any{"name": "admin"}, 400, "invalidValue"},
		"bad name":   {map[string]any{"name": "Has Space"}, 400, "invalidValue"},
		"no name":    {map[string]any{"displayName": "x"}, 400, "invalidValue"},
		"bad ttl":    {map[string]any{"name": "ttl", "settings": map[string]any{"sessionTtl": -5}}, 400, "invalidValue"},
		"ttl string": {map[string]any{"name": "ttl2", "settings": map[string]any{"sessionTtl": "soon"}}, 400, "invalidValue"},
	} {
		if r := e.do("POST", "/scim/v2/Organizations", e.super, tc.body); r.Status != tc.status || r.str("scimType") != tc.typ {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	// GET, PATCH, PUT.
	if g := e.do("GET", "/scim/v2/Organizations/"+id, e.super, nil); g.Status != 200 || g.str("displayName") != "Initech" {
		t.Errorf("get: %s", g.Raw)
	}
	if e.do("GET", "/scim/v2/Organizations/nope", e.super, nil).Status != 404 {
		t.Error("unknown org")
	}
	p := e.do("PATCH", "/scim/v2/Organizations/"+id, e.super, patchBody(op("replace", "displayName", "Initech Inc"), op("replace", "settings.passkeyLogin", false),
		op("replace", "primary", true), op("replace", "settings.sessionIdle", 120)))
	if p.Status != 200 || p.str("displayName") != "Initech Inc" || p.Body["primary"] != false ||
		p.Body["settings"].(map[string]any)["passkeyLogin"] != false || p.Body["settings"].(map[string]any)["sessionIdle"].(float64) != 120 {
		t.Errorf("patch: %d %s", p.Status, p.Raw)
	}
	if p := e.do("PATCH", "/scim/v2/Organizations/"+id, e.super, patchBody(op("replace", "name", "admin"))); p.Status != 400 {
		t.Errorf("patch reserved: %d", p.Status)
	}
	if p := e.do("PATCH", "/scim/v2/Organizations/"+id, e.super, patchBody(op("replace", "name", "acme"))); p.Status != 409 {
		t.Errorf("patch clash: %d", p.Status)
	}
	put := e.do("PUT", "/scim/v2/Organizations/"+id, e.super, map[string]any{"name": "initech-2", "displayName": "Initech 2"})
	if put.Status != 200 || put.str("name") != "initech-2" || put.Body["settings"].(map[string]any)["passkeyLogin"] != false {
		t.Errorf("put: %d %s", put.Status, put.Raw)
	}
	// The renamed org's SCIM endpoint follows the name.
	if r := e.do("GET", "/scim/v2/initech-2/Users", e.super, nil); r.Status != 200 {
		t.Errorf("renamed org endpoint: %d", r.Status)
	}
	// Deleting an organization takes a super admin's re-authentication in the admin console, as in the management
	// API: a token cannot, empty or not, cascading or not (deletion itself is tested in the service).
	for _, q := range []string{"", "?cascade=true"} {
		if r := e.do("DELETE", "/scim/v2/Organizations/"+e.orgA.ID+q, e.super, nil); r.Status != 403 {
			t.Errorf("delete%s: %d %s", q, r.Status, r.Raw)
		}
	}
	if r := e.do("DELETE", "/scim/v2/Organizations/"+id, e.super, nil); r.Status != 403 {
		t.Errorf("delete empty: %d", r.Status)
	}
	if _, err := e.Svc.Orgs.Get(e.ctx, e.orgA.ID); err != nil {
		t.Errorf("organization deleted through SCIM: %v", err)
	}
	if r := e.do("PUT", "/scim/v2/Organizations", e.super, nil); r.Status != 405 {
		t.Errorf("PUT collection: %d", r.Status)
	}
}

// Requests the Organizations resource refuses or answers in a particular way, beside those of
// TestOrganizationsResource.
func TestOrganizationRequests(t *testing.T) {
	e := newEnv(t)
	base := "/scim/v2/Organizations"
	// A boolean setting is accepted as the string a provisioning client may send.
	r := e.do("POST", base, e.super, map[string]any{"name": "initech", "displayName": "Initech", "settings": map[string]any{
		"passwordLogin": true, "passwordReset": true, "passkeyLogin": false, "requireMfa": "false", "sessionTtl": 3600, "sessionIdle": 600}})
	if r.Status != 201 || r.Body["settings"].(map[string]any)["requireMfa"] != false {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	item := base + "/" + id
	for _, tc := range []struct {
		name, method, path string
		body               any
		status             int
		typ                string
	}{
		{"POST to an organization", "POST", base + "/x", map[string]any{}, 405, ""},
		{"extra path segment", "GET", base + "/a/b", nil, 404, ""},
		{"create bad JSON", "POST", base, "{", 400, "invalidSyntax"},
		{"create name not string", "POST", base, map[string]any{"name": []any{}}, 400, "invalidValue"},
		{"create displayName not string", "POST", base, map[string]any{"name": "o1", "displayName": []any{}}, 400, "invalidValue"},
		{"settings not an object", "POST", base, map[string]any{"name": "o1", "settings": "x"}, 400, "invalidValue"},
		{"boolean setting not a bool", "POST", base, map[string]any{"name": "o1", "settings": map[string]any{"passwordLogin": []any{}}}, 400, "invalidValue"},
		{"duration not whole", "POST", base, map[string]any{"name": "o1", "settings": map[string]any{"sessionTtl": 1.5}}, 400, "invalidValue"},
		{"duration not a number", "POST", base, map[string]any{"name": "o1", "settings": map[string]any{"sessionIdle": "x"}}, 400, "invalidValue"},
		{"bad filter", "GET", base + "?filter=" + qs("name eq"), nil, 400, "invalidFilter"},
		{"PUT bad JSON", "PUT", item, "{", 400, "invalidSyntax"},
		{"PUT name not string", "PUT", item, map[string]any{"name": []any{}}, 400, "invalidValue"},
		{"PUT unknown", "PUT", base + "/nope", map[string]any{"name": "x"}, 404, ""},
		{"PATCH bad JSON", "PATCH", item, "{", 400, "invalidSyntax"},
		{"PATCH without operations", "PATCH", item, map[string]any{}, 400, "invalidSyntax"},
		{"PATCH bad value", "PATCH", item, patchBody(op("replace", "settings.sessionTtl", "x")), 400, "invalidValue"},
		{"PATCH unknown", "PATCH", base + "/nope", patchBody(op("replace", "name", "y")), 404, ""},
		// The primary organization's sign-in settings need a console session.
		{"primary sign-in settings", "PATCH", base + "/" + e.Primary.ID, patchBody(op("replace", "settings.requireMfa", true)), 403, ""},
	} {
		r := e.do(tc.method, tc.path, e.super, tc.body)
		if r.Status != tc.status || r.str("scimType") != tc.typ {
			t.Errorf("%s: %d %s", tc.name, r.Status, r.Raw)
		}
	}
	if r := e.do("GET", base+"?filter="+qs(`displayName sw "Init"`)+"&sortBy=name", e.super, nil); r.total() != 1 || r.names("name")[0] != "initech" {
		t.Errorf("sw filter: %s", r.Raw)
	}
	r = e.do("GET", item+"?attributes=name", e.super, nil)
	if r.Status != 200 || r.str("name") != "initech" || r.str("displayName") != "" {
		t.Errorf("get attributes: %s", r.Raw)
	}
	// Conditional PUT: stale, matching, and unchanged (which keeps the version).
	etag := r.Header.Get("ETag")
	wantStatus(t, "PUT stale", e.do("PUT", item, e.super, map[string]any{"name": "initech"}, "If-Match", `W/"1"`), 412)
	r = e.do("PUT", item, e.super, map[string]any{"name": "initech", "displayName": "Initech 2"}, "If-Match", etag)
	if r.Status != 200 || r.str("displayName") != "Initech 2" {
		t.Errorf("PUT match: %d %s", r.Status, r.Raw)
	}
	if u := e.do("PUT", item, e.super, map[string]any{"name": "initech", "displayName": "Initech 2"}); u.Status != 200 || u.Header.Get("ETag") != r.Header.Get("ETag") {
		t.Errorf("PUT unchanged: %d %s", u.Status, u.Raw)
	}
}
