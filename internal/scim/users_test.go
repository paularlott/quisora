package scim_test

import (
	"fmt"
	"strings"
	"testing"
)

func TestUserCRUD(t *testing.T) {
	e := newEnv(t)
	body := map[string]any{
		"userName": "Jane.Doe", "externalId": "ext-42", "displayName": "Jane Doe",
		"name":         map[string]any{"givenName": "Jane", "familyName": "Doe"},
		"emails":       []any{map[string]any{"value": "jane@acme.example", "type": "work", "primary": true}},
		"phoneNumbers": []any{map[string]any{"value": "+44 1234", "type": "work"}},
		"title":        "Engineer", "locale": "en-GB", "active": true,
		entURN: map[string]any{"employeeNumber": "701984", "department": "Tech", "manager": map[string]any{"value": "mgr-1"}},
	}
	r := e.createUser("acme", e.admA, body)
	if r.Status != 201 {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	loc := e.URL + "/scim/v2/acme/Users/" + id
	if r.Header.Get("Location") != loc || r.str("meta", "location") != loc || r.str("meta", "resourceType") != "User" ||
		r.Header.Get("ETag") == "" || r.Header.Get("ETag") != r.str("meta", "version") || !strings.HasPrefix(r.Header.Get("ETag"), `W/"`) {
		t.Errorf("create headers/meta: %v %s", r.Header, r.Raw)
	}
	if _, has := r.Body["password"]; has || strings.Contains(string(r.Raw), "super-secret") {
		t.Error("password leaked")
	}
	if r.str("name", "formatted") != "Jane Doe" || r.str("userName") != "Jane.Doe" ||
		r.str("title") != "Engineer" || r.Body["phoneNumbers"] != nil || r.str(quisoraURN, "role") != "user" || r.str("meta", "created") == "" ||
		r.str("locale") != "en-GB" || r.str("preferredLanguage") != "en-GB" {
		t.Errorf("create body: %s", r.Raw)
	}
	// the enterprise extension is kept (an unknown manager left out); phone numbers are accepted and ignored
	if r.str(entURN, "employeeNumber") != "701984" || r.str(entURN, "department") != "Tech" || strings.Contains(string(r.Raw), "+44 1234") ||
		strings.Contains(string(r.Raw), "mgr-1") || !strings.Contains(fmt.Sprint(r.list("schemas")), "enterprise") {
		t.Errorf("enterprise extension: %s", r.Raw)
	}
	schemas := fmt.Sprint(r.list("schemas"))
	for _, s := range []string{"core:2.0:User", quisoraURN} {
		if !strings.Contains(schemas, s) {
			t.Errorf("schemas %s missing %s", schemas, s)
		}
	}
	em := r.list("emails")[0].(map[string]any)
	if em["value"] != "jane@acme.example" || em["primary"] != true || em["type"] != "work" {
		t.Errorf("emails: %v", em)
	}
	// Service view agrees; no password was provisioned.
	u, err := e.Svc.Users.Get(e.ctx, id)
	if err != nil || u.Email != "jane@acme.example" {
		t.Fatalf("stored user: %v %+v", err, u)
	}
	if u.PasswordHash != "" {
		t.Error("a password appeared")
	}
	if u.OrgID != e.orgA.ID {
		t.Error("wrong org")
	}

	// GET.
	g := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	if g.Status != 200 || g.str("id") != id || g.Header.Get("ETag") != r.Header.Get("ETag") {
		t.Fatalf("get: %d %s", g.Status, g.Raw)
	}
	// Conditional GET.
	if c := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil, "If-None-Match", g.Header.Get("ETag")); c.Status != 304 {
		t.Errorf("If-None-Match: %d", c.Status)
	}
	if e.do("GET", "/scim/v2/acme/Users/nope", e.admA, nil).Status != 404 {
		t.Error("unknown id")
	}

	// PUT replaces: omitted attributes are cleared.
	put := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "Jane.Doe", "displayName": "J. Doe", "active": true,
		"emails": []any{map[string]any{"value": "jd@acme.example", "primary": true}},
	})
	if put.Status != 200 {
		t.Fatalf("put: %d %s", put.Status, put.Raw)
	}
	if put.str("displayName") != "J. Doe" || put.str("title") != "" || put.str("name", "familyName") != "" || put.Body["externalId"] != nil ||
		put.Body[entURN] != nil || put.Body["phoneNumbers"] != nil || put.str("emails") != "" {
		t.Errorf("put body: %s", put.Raw)
	}
	if put.list("emails")[0].(map[string]any)["value"] != "jd@acme.example" {
		t.Errorf("put email: %s", put.Raw)
	}
	if put.Header.Get("ETag") == r.Header.Get("ETag") {
		t.Error("etag did not change")
	}
	// PUT with a password is refused (mutability) and changes nothing.
	pw := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{"userName": "Jane.Doe", "password": "another-secret-1"})
	if pw.Status != 400 || pw.str("scimType") != "mutability" || !strings.Contains(pw.str("detail"), "invitation") {
		t.Errorf("PUT password: %d %s", pw.Status, pw.Raw)
	}
	u, _ = e.Svc.Users.Get(e.ctx, id)
	if u.PasswordHash != "" || u.FullName() != "J. Doe" {
		t.Errorf("refused PUT changed the user: %+v", u)
	}

	// No-op PUT does not change the version.
	cur := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	noop := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, cur.Body)
	if noop.Status != 200 || noop.Header.Get("ETag") != cur.Header.Get("ETag") {
		t.Errorf("noop put: %d etag %s vs %s", noop.Status, noop.Header.Get("ETag"), cur.Header.Get("ETag"))
	}

	// DELETE.
	if d := e.do("DELETE", "/scim/v2/acme/Users/"+id, e.admA, nil); d.Status != 204 || len(d.Raw) != 0 {
		t.Errorf("delete: %d %s", d.Status, d.Raw)
	}
	if e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil).Status != 404 {
		t.Error("deleted user still there")
	}
	if e.do("DELETE", "/scim/v2/acme/Users/"+id, e.admA, nil).Status != 404 {
		t.Error("second delete")
	}
}

func TestUserCreateErrors(t *testing.T) {
	e := newEnv(t)
	e.createUser("acme", e.admA, map[string]any{"userName": "taken", "externalId": "x1",
		"emails": []any{map[string]any{"value": "taken@example.org"}}})
	cases := []struct {
		name   string
		body   any
		status int
		typ    string
	}{
		{"missing userName", map[string]any{"displayName": "x", "emails": mail("x@acme.test")}, 400, "invalidValue"},
		{"duplicate userName", map[string]any{"userName": "TAKEN", "emails": mail("other@acme.test")}, 409, "uniqueness"},
		{"duplicate email", map[string]any{"userName": "u2", "emails": []any{map[string]any{"value": "Taken@example.org"}}}, 409, "uniqueness"},
		{"duplicate externalId", map[string]any{"userName": "u3", "externalId": "x1", "emails": mail("u3@acme.test")}, 409, "uniqueness"},
		{"bad userName", map[string]any{"userName": "has space", "emails": mail("hs@acme.test")}, 400, "invalidValue"},
		{"bad email", map[string]any{"userName": "u4", "emails": []any{map[string]any{"value": "nope"}}}, 400, "invalidValue"},
		{"password", map[string]any{"userName": "u5", "emails": mail("u5@acme.test"), "password": "long-enough-password"}, 400, "mutability"},
		{"short password", map[string]any{"userName": "u5b", "emails": mail("u5b@acme.test"), "password": "short"}, 400, "mutability"},
		{"bad role", map[string]any{"userName": "u6", "emails": mail("u6@acme.test"), quisoraURN: map[string]any{"role": "emperor"}}, 400, "invalidValue"},
		{"userName not string", map[string]any{"userName": []any{"a"}}, 400, "invalidValue"},
		{"active nonsense", map[string]any{"userName": "u7", "emails": mail("u7@acme.test"), "active": "maybe"}, 400, "invalidValue"},
		{"name not object", map[string]any{"userName": "u8", "emails": mail("u8@acme.test"), "name": "Jane"}, 400, "invalidValue"},
		{"emails not objects", map[string]any{"userName": "u9", "emails": []any{1}}, 400, "invalidValue"},
		{"no email, userName not an address", map[string]any{"userName": "u10"}, 400, "invalidValue"},
		{"empty emails, userName not an address", map[string]any{"userName": "u11", "emails": []any{}}, 400, "invalidValue"},
		{"blank email value", map[string]any{"userName": "u12", "emails": []any{map[string]any{"value": ""}}}, 400, "invalidValue"},
		{"externalId not string", map[string]any{"userName": "w1", "emails": mail("w1@acme.test"), "externalId": []any{}}, 400, "invalidValue"},
		{"displayName not string", map[string]any{"userName": "w2", "emails": mail("w2@acme.test"), "displayName": []any{}}, 400, "invalidValue"},
		{"givenName not string", map[string]any{"userName": "w3", "emails": mail("w3@acme.test"), "name": map[string]any{"givenName": []any{}}}, 400, "invalidValue"},
		{"familyName not string", map[string]any{"userName": "w4", "emails": mail("w4@acme.test"), "name": map[string]any{"familyName": []any{}}}, 400, "invalidValue"},
		{"email value not string", map[string]any{"userName": "w5", "emails": []any{map[string]any{"value": []any{}}}}, 400, "invalidValue"},
		{"phoneNumbers not objects", map[string]any{"userName": "w6", "emails": mail("w6@acme.test"), "phoneNumbers": []any{5}}, 400, "invalidValue"},
		{"password not string", map[string]any{"userName": "w7", "emails": mail("w7@acme.test"), "password": []any{}}, 400, "invalidValue"},
		{"role not string", map[string]any{"userName": "w8", "emails": mail("w8@acme.test"), quisoraURN: map[string]any{"role": []any{}}}, 400, "invalidValue"},
		{"tags not a list", map[string]any{"userName": "w9", "emails": mail("w9@acme.test"), quisoraURN: map[string]any{"tags": "x"}}, 400, "invalidValue"},
		{"tag not string", map[string]any{"userName": "w10", "emails": mail("w10@acme.test"), quisoraURN: map[string]any{"tags": []any{1}}}, 400, "invalidValue"},
		{"validUntil not string", map[string]any{"userName": "w11", "emails": mail("w11@acme.test"), quisoraURN: map[string]any{"validUntil": []any{}}}, 400, "invalidValue"},
		{"timezone not string", map[string]any{"userName": "w12", "emails": mail("w12@acme.test"), "timezone": []any{}}, 400, "invalidValue"},
		{"locale not string", map[string]any{"userName": "w13", "emails": mail("w13@acme.test"), "locale": []any{}}, 400, "invalidValue"},
		{"preferredLanguage not string", map[string]any{"userName": "w14", "emails": mail("w14@acme.test"), "preferredLanguage": []any{}}, 400, "invalidValue"},
		{"title not string", map[string]any{"userName": "w15", "emails": mail("w15@acme.test"), "title": []any{}}, 400, "invalidValue"},
		{"enterprise not object", map[string]any{"userName": "w16", "emails": mail("w16@acme.test"), entURN: "x"}, 400, "invalidValue"},
		{"enterprise attribute not string", map[string]any{"userName": "w17", "emails": mail("w17@acme.test"), entURN: map[string]any{"department": []any{}}}, 400, "invalidValue"},
		{"manager not object or id", map[string]any{"userName": "w18", "emails": mail("w18@acme.test"), entURN: map[string]any{"manager": 5}}, 400, "invalidValue"},
		{"manager value not string", map[string]any{"userName": "w19", "emails": mail("w19@acme.test"), entURN: map[string]any{"manager": map[string]any{"value": []any{}}}}, 400, "invalidValue"},
		{"not json", "{nope", 400, "invalidSyntax"},
		{"json array", "[1]", 400, "invalidSyntax"},
		{"null body", "null", 400, "invalidSyntax"},
	}
	for _, tc := range cases {
		r := e.do("POST", "/scim/v2/acme/Users", e.admA, tc.body)
		if r.Status != tc.status || r.str("scimType") != tc.typ || r.str("status") != fmt.Sprint(tc.status) || r.str("detail") == "" {
			t.Errorf("%s: %d %s", tc.name, r.Status, r.Raw)
		}
	}
	// Active accepted as the string Entra sends.
	if r := e.createUser("acme", e.admA, map[string]any{"userName": "inactive", "active": "False"}); r.Status != 201 || r.Body["active"] != false {
		t.Errorf("active string: %d %s", r.Status, r.Raw)
	}
	// The email is required: its message says so, and nothing was created.
	if r := e.do("POST", "/scim/v2/acme/Users", e.admA, map[string]any{"userName": "u10"}); !strings.HasPrefix(r.str("detail"), "an email address is required") {
		t.Errorf("detail: %s", r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/Users?filter="+qs(`userName eq "u10"`), e.admA, nil); r.total() != 0 {
		t.Errorf("rejected user exists: %s", r.Raw)
	}
	// Oversized body.
	big := `{"userName":"big","title":"` + strings.Repeat("x", 2<<20) + `"}`
	if r := e.do("POST", "/scim/v2/acme/Users", e.admA, big); r.Status != 413 {
		t.Errorf("big body: %d", r.Status)
	}
	if r := e.do("PATCH", "/scim/v2/acme/Users", e.admA, map[string]any{}); r.Status != 405 {
		t.Errorf("PATCH collection: %d", r.Status)
	}
	if r := e.do("POST", "/scim/v2/acme/Users/x", e.admA, map[string]any{}); r.Status != 405 {
		t.Errorf("POST to a user: %d", r.Status)
	}
	if r := e.do("PUT", "/scim/v2/acme/Users/nope", e.admA, map[string]any{"userName": "nope", "emails": mail("nope@acme.test")}); r.Status != 404 {
		t.Errorf("PUT unknown: %d", r.Status)
	}
	if r := e.do("GET", "/scim/v2/acme/Widgets", e.admA, nil); r.Status != 404 {
		t.Errorf("unknown resource: %d", r.Status)
	}
	if r := e.do("GET", "/scim/v2/acme/Users/a/b", e.admA, nil); r.Status != 404 {
		t.Errorf("too deep: %d", r.Status)
	}
}

// Entra and Okta usually send the UPN / email as userName: it becomes the email when none is sent; the username
// attribute keeps the userName.
func TestUserNameAsEmail(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct{ name, userName string }{{"entra", "Ada.Lovelace@Acme.Example"}, {"okta", "grace@acme.example"}} {
		r := e.do("POST", "/scim/v2/acme/Users", e.admA, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": tc.userName, "displayName": tc.name})
		if r.Status != 201 || r.str("userName") != tc.userName {
			t.Fatalf("%s: %d %s", tc.name, r.Status, r.Raw)
		}
		em := r.list("emails")
		if len(em) != 1 || em[0].(map[string]any)["value"] != tc.userName {
			t.Errorf("%s: emails %s", tc.name, r.Raw)
		}
		// Signing in is by that address, any case.
		u, err := e.Svc.FindUserByEmail(e.ctx, e.orgA.ID, strings.ToUpper(tc.userName))
		if err != nil || u.Username != tc.userName {
			t.Errorf("%s: %v %+v", tc.name, err, u)
		}
	}
	// A real address wins over a userName that is also an address, and the userName stays the username.
	r := e.do("POST", "/scim/v2/acme/Users", e.admA, map[string]any{"userName": "bob@corp.example", "emails": mail("bob@acme.example")})
	if r.Status != 201 || r.str("userName") != "bob@corp.example" || r.list("emails")[0].(map[string]any)["value"] != "bob@acme.example" {
		t.Errorf("explicit email: %d %s", r.Status, r.Raw)
	}
	// PUT without emails keeps working when userName is an address.
	id := r.str("id")
	if r := e.do("PUT", "/scim/v2/acme/Users/"+id, e.admA, map[string]any{"userName": "bob@corp.example"}); r.Status != 200 ||
		r.list("emails")[0].(map[string]any)["value"] != "bob@corp.example" {
		t.Errorf("PUT: %d %s", r.Status, r.Raw)
	}
}
