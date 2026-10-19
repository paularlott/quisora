package scim_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

func (e *env) mk(name string, extra map[string]any) string {
	body := map[string]any{"userName": name, "emails": []any{map[string]any{"value": name + "@acme.test", "type": "work", "primary": true}}}
	for k, v := range extra {
		body[k] = v
	}
	r := e.createUser("acme", e.admA, body)
	if r.Status != 201 {
		e.t.Fatalf("create %s: %d %s", name, r.Status, r.Raw)
	}
	return r.str("id")
}

func (e *env) patch(id string, ops ...map[string]any) resp {
	return e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, patchBody(ops...))
}

func TestPatchEntraUser(t *testing.T) {
	e := newEnv(t)
	// Entra and Okta send title, phoneNumbers and the enterprise extension by default: the title and the extension
	// are kept (a manager this organization does not have is left out), phone numbers are ignored.
	id := e.mk("mike", map[string]any{"displayName": "Mike M", "title": "Dev",
		"name":         map[string]any{"givenName": "Mike", "familyName": "M"},
		"phoneNumbers": []any{map[string]any{"value": "111", "type": "work"}},
		entURN:         map[string]any{"department": "Ops", "manager": map[string]any{"value": "x"}}})
	if g := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil); g.Status != 200 || g.str("title") != "Dev" || g.Body["phoneNumbers"] != nil ||
		g.str(entURN, "department") != "Ops" || strings.Contains(string(g.Raw), "manager") {
		t.Fatalf("work details: %s", g.Raw)
	}
	// The operations Microsoft Entra ID sends for attribute changes (capitalised ops, string booleans, filtered paths).
	r := e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, `{
	  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	  "Operations": [
	    {"op": "Replace", "path": "displayName", "value": "ignored"},
	    {"op": "Replace", "path": "name.familyName", "value": "Mann"},
	    {"op": "Replace", "path": "name.givenName", "value": "Michael"},
	    {"op": "Replace", "path": "emails[type eq \"work\"].value", "value": "michael@acme.test"},
	    {"op": "Replace", "path": "phoneNumbers[type eq \"work\"].value", "value": "222"},
	    {"op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Sales"},
	    {"op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", "value": "99"},
	    {"op": "Replace", "path": "title", "value": "VP"},
	    {"op": "Replace", "path": "active", "value": "False"}
	  ]}`)
	if r.Status != 200 {
		t.Fatalf("entra patch: %d %s", r.Status, r.Raw)
	}
	if r.str("displayName") != "Michael Mann" || r.str("name", "givenName") != "Michael" || r.str("name", "familyName") != "Mann" ||
		r.Body["active"] != false || r.str("title") != "VP" || r.Body["phoneNumbers"] != nil ||
		r.str(entURN, "department") != "Sales" || r.str(entURN, "employeeNumber") != "99" {
		t.Errorf("entra result: %s", r.Raw)
	}
	if r.list("emails")[0].(map[string]any)["value"] != "michael@acme.test" {
		t.Errorf("filtered paths: %s", r.Raw)
	}
	// Reactivate; removes clear stored attributes and are no-ops on ignored ones.
	r = e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
	    {"op":"Replace","path":"active","value":"True"},
	    {"op":"Remove","path":"phoneNumbers[type eq \"work\"].value","value":"222"},
	    {"op":"Remove","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"Sales"},
	    {"op":"Remove","path":"title"}]}`)
	if r.Status != 200 || r.Body["active"] != true || r.Body["title"] != nil || r.str(entURN, "department") != "" ||
		r.str(entURN, "employeeNumber") != "99" || r.Body["phoneNumbers"] != nil {
		t.Errorf("entra remove: %d %s", r.Status, r.Raw)
	}
	// Add without a path and with a value object holding attribute paths (seen with Entra "Add" of several attributes).
	r = e.patch(id, op("Add", "", map[string]any{
		"title": "CTO", "name.familyName": "Mann", entURN + ":costCenter": "CC1",
		"emails[type eq \"work\"].value": "mm@acme.test",
	}))
	if r.Status != 200 || r.str("title") != "CTO" || r.str("name", "familyName") != "Mann" || r.str(entURN, "costCenter") != "CC1" ||
		r.list("emails")[0].(map[string]any)["value"] != "mm@acme.test" {
		t.Errorf("pathless add: %d %s", r.Status, r.Raw)
	}
	// Ext object as the value: its sub-attributes are set, the others kept (RFC 7644 §3.5.2.3).
	r = e.patch(id, op("Replace", "", map[string]any{entURN: map[string]any{"division": "EMEA"}}))
	if r.Status != 200 || r.str(entURN, "division") != "EMEA" || r.str(entURN, "costCenter") != "CC1" {
		t.Errorf("ext object: %d %s", r.Status, r.Raw)
	}
	// A filtered path on an ignored attribute is a no-op too.
	r = e.patch(id, op("Add", `phoneNumbers[type eq "mobile"].value`, "555"))
	if r.Status != 200 || r.Body["phoneNumbers"] != nil {
		t.Errorf("seeded element: %d %s", r.Status, r.Raw)
	}
}

func TestPatchOktaUser(t *testing.T) {
	e := newEnv(t)
	id := e.mk("olga", map[string]any{"displayName": "Olga"})
	// Okta deactivates with a pathless replace and a value object.
	r := e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	  "Operations":[{"op":"replace","value":{"active":false}}]}`)
	if r.Status != 200 || r.Body["active"] != false {
		t.Fatalf("okta deactivate: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("replace", "", map[string]any{"active": true, "displayName": "Olga O", "name": map[string]any{"givenName": "Olga", "familyName": "O"}}))
	if r.Status != 200 || r.Body["active"] != true || r.str("displayName") != "Olga O" || r.str("name", "familyName") != "O" {
		t.Errorf("okta reactivate: %d %s", r.Status, r.Raw)
	}
	// Okta profile push uses PUT with the whole user, including read-only members that must be ignored.
	cur := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	body := cur.Body
	body["name"].(map[string]any)["familyName"] = "Pushed"
	body["groups"] = []any{map[string]any{"value": "ghost"}}
	body["id"] = "ignored"
	put := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, body)
	if put.Status != 200 || put.str("displayName") != "Olga Pushed" || put.str("id") != id || len(put.list("groups")) != 0 {
		t.Errorf("okta put: %d %s", put.Status, put.Raw)
	}
}

func TestPatchSemantics(t *testing.T) {
	e := newEnv(t)
	id := e.mk("pat", map[string]any{"externalId": "e1"})

	// Case-insensitive op, attribute names and booleans as strings.
	if r := e.patch(id, op("REPLACE", "Name.FamilyName", "P"), op("remove", "externalId", nil)); r.Status != 200 ||
		r.str("displayName") != "pat P" || r.Body["externalId"] != nil {
		t.Errorf("case-insensitive: %d %s", r.Status, r.Raw)
	}
	// Adding a second, non-primary email leaves the primary alone; making it primary switches the user's email.
	r := e.patch(id, op("add", "emails", []any{map[string]any{"value": "second@acme.test", "type": "home"}}))
	if r.Status != 200 || r.list("emails")[0].(map[string]any)["value"] != "pat@acme.test" {
		t.Errorf("add email: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("add", "emails", []any{map[string]any{"value": "second@acme.test", "type": "home", "primary": "True"}}))
	if r.Status != 200 || r.list("emails")[0].(map[string]any)["value"] != "second@acme.test" {
		t.Errorf("primary switch: %d %s", r.Status, r.Raw)
	}
	// replace whole emails
	r = e.patch(id, op("replace", "emails", []any{map[string]any{"value": "only@acme.test", "primary": true}}))
	if r.Status != 200 || r.list("emails")[0].(map[string]any)["value"] != "only@acme.test" {
		t.Errorf("replace emails: %d %s", r.Status, r.Raw)
	}
	// the email is required: removing it is refused and the address stays
	r = e.patch(id, op("remove", `emails[value eq "only@acme.test"]`, nil))
	if r.Status != 400 || r.str("scimType") != "invalidValue" {
		t.Errorf("remove by filter: %d %s", r.Status, r.Raw)
	}
	u, _ := e.Svc.Users.Get(e.ctx, id)
	if u.Email != "only@acme.test" {
		t.Errorf("email must be kept: %q", u.Email)
	}
	// Complex attribute: replace whole name object, then add merges.
	r = e.patch(id, op("replace", "name", map[string]any{"givenName": "Pat", "familyName": "Q"}))
	if r.str("name", "familyName") != "Q" {
		t.Errorf("replace name: %s", r.Raw)
	}
	r = e.patch(id, op("add", "name", map[string]any{"givenName": "Patricia"}))
	if r.str("name", "givenName") != "Patricia" || r.str("name", "familyName") != "Q" {
		t.Errorf("add name merges: %s", r.Raw)
	}
	r = e.patch(id, op("replace", "name", map[string]any{"givenName": "Solo"}))
	if r.str("name", "givenName") != "Solo" || r.str("name", "familyName") != "" {
		t.Errorf("replace name replaces: %s", r.Raw)
	}
	// Read-only attributes are ignored.
	r = e.patch(id, op("replace", "id", "hacked"), op("replace", "meta.version", "x"), op("add", "groups", []any{map[string]any{"value": "g"}}))
	if r.Status != 200 || r.str("id") != id {
		t.Errorf("read-only: %d %s", r.Status, r.Raw)
	}
	// Passwords cannot be provisioned: PATCH is refused with scimType mutability.
	r = e.patch(id, op("replace", "password", "patched-password-1"))
	if r.Status != 400 || r.str("scimType") != "mutability" || strings.Contains(string(r.Raw), "patched-password") {
		t.Errorf("password patch: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("add", "", map[string]any{"password": "patched-password-1"}))
	if r.Status != 400 || r.str("scimType") != "mutability" {
		t.Errorf("password patch (no path): %d %s", r.Status, r.Raw)
	}
	u, _ = e.Svc.Users.Get(e.ctx, id)
	if u.PasswordHash != "" {
		t.Error("password set through SCIM")
	}
	// Role via the quisora extension.
	r = e.patch(id, op("replace", quisoraURN+":role", "manager"))
	if r.Status != 200 || r.str(quisoraURN, "role") != "manager" {
		t.Errorf("role patch: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("replace", "", map[string]any{quisoraURN: map[string]any{"role": "admin"}}))
	if r.Status != 200 || r.str(quisoraURN, "role") != "admin" {
		t.Errorf("role via ext object: %d %s", r.Status, r.Raw)
	}
	// Rename into an existing userName.
	e.mk("other-pat", nil)
	if r := e.patch(id, op("replace", "userName", "other-pat")); r.Status != 409 || r.str("scimType") != "uniqueness" {
		t.Errorf("rename clash: %d %s", r.Status, r.Raw)
	}
	if r := e.patch(id, op("replace", "userName", "renamed-pat")); r.Status != 200 || r.str("userName") != "renamed-pat" {
		t.Errorf("rename: %d %s", r.Status, r.Raw)
	}
	// An error rolls the whole request back.
	before := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	if r := e.patch(id, op("replace", "displayName", "will not stick"), op("replace", "active", "perhaps")); r.Status != 400 {
		t.Errorf("bad bool: %d %s", r.Status, r.Raw)
	}
	if after := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil); after.Header.Get("ETag") != before.Header.Get("ETag") {
		t.Error("partial patch applied")
	}

	// Malformed requests.
	bad := []struct {
		name string
		body any
		typ  string
	}{
		{"no Operations", map[string]any{"schemas": []string{"x"}}, "invalidSyntax"},
		{"empty Operations", patchBody(), "invalidSyntax"},
		{"unknown op", patchBody(op("move", "displayName", "x")), "invalidSyntax"},
		{"op not object", map[string]any{"Operations": []any{"x"}}, "invalidSyntax"},
		{"missing value", map[string]any{"Operations": []any{map[string]any{"op": "replace", "path": "displayName"}}}, "invalidSyntax"},
		{"remove without path", patchBody(op("remove", "", nil)), "noTarget"},
		{"bad path", patchBody(op("replace", "emails[", "x")), "invalidPath"},
		{"bad path 2", patchBody(op("replace", "a b", "x")), "invalidPath"},
		{"unknown schema in path", patchBody(op("replace", "urn:example:nope:2.0:User:thing", "x")), "invalidPath"},
		{"pathless non-object", patchBody(op("add", "", "x")), "invalidValue"},
		{"not json", "nope", "invalidSyntax"},
	}
	for _, tc := range bad {
		r := e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, tc.body)
		if r.Status != 400 || r.str("scimType") != tc.typ {
			t.Errorf("%s: %d %s", tc.name, r.Status, r.Raw)
		}
	}
	if r := e.do("PATCH", "/scim/v2/acme/Users/nope", e.admA, patchBody(op("replace", "displayName", "x"))); r.Status != 404 {
		t.Errorf("patch unknown: %d", r.Status)
	}
}

func TestETagAndIfMatch(t *testing.T) {
	e := newEnv(t)
	id := e.mk("etag", nil)
	url := "/scim/v2/acme/Users/" + id
	g := e.do("GET", url, e.admA, nil)
	tag := g.Header.Get("ETag")
	if tag == "" || tag != g.str("meta", "version") {
		t.Fatalf("etag %q meta %q", tag, g.str("meta", "version"))
	}
	body := map[string]any{"userName": "etag", "displayName": "v2", "emails": []any{map[string]any{"value": "etag@acme.test"}}}

	// Stale If-Match: every write is refused with 412 and nothing changes.
	stale := `W/"1"`
	if r := e.do("PUT", url, e.admA, body, "If-Match", stale); r.Status != 412 || r.str("status") != "412" {
		t.Errorf("PUT stale: %d %s", r.Status, r.Raw)
	}
	if r := e.do("PATCH", url, e.admA, patchBody(op("replace", "displayName", "x")), "If-Match", stale); r.Status != 412 {
		t.Errorf("PATCH stale: %d", r.Status)
	}
	if r := e.do("DELETE", url, e.admA, nil, "If-Match", stale); r.Status != 412 {
		t.Errorf("DELETE stale: %d", r.Status)
	}
	if now := e.do("GET", url, e.admA, nil); now.Header.Get("ETag") != tag {
		t.Error("a refused write changed the resource")
	}
	// Matching, in weak and strong spelling, in lists, and *.
	r := e.do("PUT", url, e.admA, body, "If-Match", tag)
	if r.Status != 200 || r.Header.Get("ETag") == tag {
		t.Fatalf("PUT match: %d", r.Status)
	}
	tag2 := r.Header.Get("ETag")
	if r := e.do("PATCH", url, e.admA, patchBody(op("replace", "displayName", "x")), "If-Match", strings.TrimPrefix(tag2, "W/")); r.Status != 200 {
		t.Errorf("PATCH strong spelling: %d %s", r.Status, r.Raw)
	}
	cur := e.do("GET", url, e.admA, nil).Header.Get("ETag")
	if r := e.do("PATCH", url, e.admA, patchBody(op("replace", "name.familyName", "y")), "If-Match", `W/"1", `+cur); r.Status != 200 {
		t.Errorf("PATCH list: %d", r.Status)
	}
	if r := e.do("PATCH", url, e.admA, patchBody(op("replace", "name.familyName", "z")), "If-Match", "*"); r.Status != 200 {
		t.Errorf("PATCH *: %d", r.Status)
	}
	// The old tag no longer matches after a change.
	if r := e.do("PUT", url, e.admA, body, "If-Match", tag2); r.Status != 412 {
		t.Errorf("old tag: %d", r.Status)
	}
	// Delete with the current tag.
	cur = e.do("GET", url, e.admA, nil).Header.Get("ETag")
	if r := e.do("DELETE", url, e.admA, nil, "If-Match", cur); r.Status != 204 {
		t.Errorf("DELETE match: %d", r.Status)
	}
	// Groups and organizations carry ETags too.
	gr := e.do("POST", "/scim/v2/acme/Groups", e.admA, map[string]any{"displayName": "etag-group"})
	if gr.Header.Get("ETag") == "" {
		t.Error("group etag")
	}
	if r := e.do("PUT", "/scim/v2/acme/Groups/"+gr.str("id"), e.admA, map[string]any{"displayName": "x"}, "If-Match", stale); r.Status != 412 {
		t.Errorf("group stale: %d", r.Status)
	}
	org := e.do("GET", "/scim/v2/Organizations/"+e.orgA.ID, e.super, nil)
	if r := e.do("PATCH", "/scim/v2/Organizations/"+e.orgA.ID, e.super, patchBody(op("replace", "displayName", "X")), "If-Match", stale); r.Status != 412 {
		t.Errorf("org stale: %d", r.Status)
	}
	if r := e.do("PATCH", "/scim/v2/Organizations/"+e.orgA.ID, e.super, patchBody(op("replace", "displayName", "X")), "If-Match", org.Header.Get("ETag")); r.Status != 200 {
		t.Errorf("org match: %d", r.Status)
	}
}

func TestConcurrentPatches(t *testing.T) {
	e := newEnv(t)
	id := e.mk("busy", nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	attrs := []string{"displayName"}
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.patch(id, op("replace", attrs[i%len(attrs)], strings.Repeat("v", i+1)))
			mu.Lock()
			codes[r.Status]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	for c := range codes {
		if c != 200 && c != 409 {
			t.Errorf("unexpected status %d", c)
		}
	}
	if codes[200] == 0 {
		t.Error("no patch succeeded")
	}
	// Writers with different If-Match values never both win.
	tag := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil).Header.Get("ETag")
	wins := 0
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, patchBody(op("replace", "name.familyName", "race")), "If-Match", tag)
			mu.Lock()
			if r.Status == 200 {
				wins++
			} else if r.Status != 412 {
				t.Errorf("status %d", r.Status)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Errorf("%d concurrent writers won with the same If-Match", wins)
	}
	_ = model.RoleUser
}
