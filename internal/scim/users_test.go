package scim_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

const (
	entURN     = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	quisoraURN = "urn:paularlott:quisora:scim:schemas:2.0:User"
)

// mail is an emails attribute with one primary address.
func mail(addr string) []any {
	return []any{map[string]any{"value": addr, "type": "work", "primary": true}}
}

// createUser POSTs a user. Most fixtures only care about userName, so an address (<userName>@acme.test) is added when
// the body has none; tests of the missing-email rules post with e.do instead.
func (e *env) createUser(org, token string, body map[string]any) resp {
	if un, ok := body["userName"].(string); ok && body["emails"] == nil {
		body["emails"] = mail(un + "@acme.test")
	}
	if body["schemas"] == nil {
		body["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}
	}
	return e.do("POST", "/scim/v2/"+org+"/Users", token, body)
}

func TestDiscovery(t *testing.T) {
	e := newEnv(t)
	for _, base := range []string{"/scim/v2", "/scim/v2/acme"} {
		r := e.do("GET", base+"/ServiceProviderConfig", "", nil)
		if r.Status != 200 || r.Header.Get("Content-Type") != "application/scim+json; charset=utf-8" {
			t.Fatalf("%s SPC: %d %s", base, r.Status, r.Header.Get("Content-Type"))
		}
		bulk := r.Body["bulk"].(map[string]any)
		patch := r.Body["patch"].(map[string]any)
		if bulk["supported"] != false || patch["supported"] != true || r.Body["etag"].(map[string]any)["supported"] != true ||
			r.Body["filter"].(map[string]any)["maxResults"].(float64) != 1000 {
			t.Errorf("SPC body: %s", r.Raw)
		}
		if r.Body["changePassword"].(map[string]any)["supported"] != false {
			t.Errorf("SCIM must not advertise password changes: %s", r.Raw)
		}
		rt := e.do("GET", base+"/ResourceTypes", "", nil)
		want := 3
		if base != "/scim/v2" {
			want = 2
		}
		if rt.Status != 200 || rt.total() != want {
			t.Errorf("%s ResourceTypes: %d %s", base, rt.Status, rt.Raw)
		}
		if one := e.do("GET", base+"/ResourceTypes/User", "", nil); one.Status != 200 || one.str("endpoint") != "/Users" {
			t.Errorf("ResourceType User: %s", one.Raw)
		}
		if e.do("GET", base+"/ResourceTypes/Nope", "", nil).Status != 404 {
			t.Error("unknown resource type")
		}
		sc := e.do("GET", base+"/Schemas", "", nil)
		if sc.Status != 200 || sc.total() < 4 {
			t.Errorf("%s Schemas: %d %s", base, sc.Status, sc.Raw)
		}
		if one := e.do("GET", base+"/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "", nil); one.Status != 200 || one.str("name") != "User" {
			t.Errorf("Schema User: %d %s", one.Status, one.Raw)
		}
	}
	if r := e.do("GET", "/scim/v2/Schemas/"+schemaOrgURN, "", nil); r.Status != 200 {
		t.Errorf("org schema: %s", r.Raw)
	}
	if r := e.do("POST", "/scim/v2/ServiceProviderConfig", "", nil); r.Status != 405 || r.Header.Get("Allow") != "GET" {
		t.Errorf("POST SPC: %d", r.Status)
	}
	if r := e.do("GET", "/scim/v2/", "", nil); r.Status != 404 {
		t.Errorf("root: %d", r.Status)
	}
}

const schemaOrgURN = "urn:paularlott:quisora:scim:schemas:2.0:Organization"

func TestAuthentication(t *testing.T) {
	e := newEnv(t)
	plain := e.mkUser(e.orgA, "plain", model.RoleUser)
	cases := []struct {
		name  string
		token string
		hdr   []string
		want  int
	}{
		{"no token", "", nil, 401},
		{"garbage", "nope", nil, 401},
		{"unknown api token", "qsr_abc_def", nil, 401},
		{"valid", e.admA, nil, 200},
		{"wrong scheme", "", []string{"Authorization", "Basic " + e.admA}, 401},
		{"lowercase scheme", "", []string{"Authorization", "bearer " + e.admA}, 200},
	}
	for _, tc := range cases {
		r := e.do("GET", "/scim/v2/acme/Users", tc.token, nil, tc.hdr...)
		if r.Status != tc.want {
			t.Errorf("%s: %d %s", tc.name, r.Status, r.Raw)
		}
		if tc.want == 401 {
			if r.Header.Get("WWW-Authenticate") == "" || r.str("status") != "401" ||
				r.list("schemas")[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
				t.Errorf("%s: 401 shape %s %v", tc.name, r.Raw, r.Header)
			}
		}
	}
	// Scope: tokens without scim are refused, and roles that cannot use SCIM cannot even hold the scope.
	apiOnly := e.token(e.users["adm-a"], "api")
	if r := e.do("GET", "/scim/v2/acme/Users", apiOnly, nil); r.Status != 403 {
		t.Errorf("token without scim scope: %d", r.Status)
	}
	if _, _, err := e.Svc.CreateAPIToken(e.ctx, service.ActorForUser(plain, ""), service.APITokenInput{Name: "x", Scopes: []string{"scim"}}); err == nil {
		t.Fatal("plain user got scim scope")
	}
	// An owner demoted after minting loses access.
	mgr := e.mkUser(e.orgA, "will-demote", model.RoleManager)
	tok := e.token(mgr, "scim")
	if r := e.do("GET", "/scim/v2/acme/Users", tok, nil); r.Status != 200 {
		t.Fatal(r.Status)
	}
	if _, err := e.Svc.UpdateUser(e.ctx, service.System, mgr.ID, service.UserInput{Role: ptr(model.RoleUser)}); err != nil {
		t.Fatal(err)
	}
	// A token whose scopes now exceed its owner's role is no longer valid at all.
	if r := e.do("GET", "/scim/v2/acme/Users", tok, nil); r.Status != 401 {
		t.Errorf("demoted owner: %d", r.Status)
	}
	// Disabled owner.
	if _, err := e.Svc.UpdateUser(e.ctx, service.ActorForUser(e.users["adm-a"], ""), mgr.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if r := e.do("GET", "/scim/v2/acme/Users", tok, nil); r.Status != 401 {
		t.Errorf("disabled owner: %d", r.Status)
	}
}

func TestClientCredentialsVerifier(t *testing.T) {
	e := newEnv(t)
	cl, _, err := e.Svc.CreateClient(e.ctx, service.ActorForUser(e.Admin, ""), e.orgA.ID, service.ClientInput{Name: ptr("entra"),
		SCIM: ptr(true), GrantTypes: ptr([]string{"client_credentials"}), RedirectURIs: ptr([]string{})})
	if err != nil {
		t.Fatal(err)
	}
	e.verify = func(_ context.Context, b string) (*service.Actor, error) {
		if b == "jwt-for-entra" {
			return service.ActorForClient(cl, ""), nil
		}
		if b == "jwt-no-scope" {
			a := service.ActorForClient(cl, "")
			a.Scopes = []string{"openid"}
			return a, nil
		}
		return nil, service.ErrBadToken
	}
	r := e.createUser("acme", "jwt-for-entra", map[string]any{"userName": "from-entra"})
	if r.Status != 201 {
		t.Fatalf("create via client: %d %s", r.Status, r.Raw)
	}
	// The client is bound to its own org.
	if r := e.do("GET", "/scim/v2/globex/Users", "jwt-for-entra", nil); r.Status != 404 {
		t.Errorf("client in other org: %d", r.Status)
	}
	// It may create managers but never admins.
	r = e.createUser("acme", "jwt-for-entra", map[string]any{"userName": "mgr", quisoraURN: map[string]any{"role": "manager"}})
	if r.Status != 201 {
		t.Errorf("client creating manager: %d %s", r.Status, r.Raw)
	}
	r = e.createUser("acme", "jwt-for-entra", map[string]any{"userName": "boss", quisoraURN: map[string]any{"role": "admin"}})
	if r.Status != 403 {
		t.Errorf("client creating admin: %d %s", r.Status, r.Raw)
	}
	// Groups work (it acts as an org admin).
	if r := e.do("POST", "/scim/v2/acme/Groups", "jwt-for-entra", map[string]any{"displayName": "Entra group"}); r.Status != 201 {
		t.Errorf("client creating group: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/Users", "jwt-no-scope", nil); r.Status != 403 {
		t.Errorf("verifier actor without scim scope: %d", r.Status)
	}
	if r := e.do("GET", "/scim/v2/acme/Users", "jwt-bogus", nil); r.Status != 401 {
		t.Errorf("rejected bearer: %d", r.Status)
	}
	// One form only: without the organization in the path there is no Users resource.
	if r := e.do("GET", "/scim/v2/Users?filter="+qs(`userName eq "from-entra"`), "jwt-for-entra", nil); r.Status != 404 {
		t.Errorf("org-less path: %d %s", r.Status, r.Raw)
	}
}

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
	if r := e.do("POST", "/scim/v2/acme/Users", e.admA, map[string]any{"userName": "u10"}); r.str("detail") != "an email address is required" {
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
	if r := e.do("GET", "/scim/v2/acme/Widgets", e.admA, nil); r.Status != 404 {
		t.Errorf("unknown resource: %d", r.Status)
	}
	if r := e.do("GET", "/scim/v2/acme/Users/a/b", e.admA, nil); r.Status != 404 {
		t.Errorf("too deep: %d", r.Status)
	}
}

func TestSuperAdminRoleThroughSCIM(t *testing.T) {
	e := newEnv(t)
	// An administrator role is granted in the admin console after a re-authentication, never with a token (as the
	// management API): not by creating a user, nor by changing one's role.
	for _, role := range []string{"admin", "super_admin"} {
		if r := e.createUser("primary", e.super, map[string]any{"userName": "new-" + role, quisoraURN: map[string]any{"role": role}}); r.Status != 403 {
			t.Errorf("%s through SCIM: %d %s", role, r.Status, r.Raw)
		}
	}
	r := e.createUser("primary", e.super, map[string]any{"userName": "plain"})
	if p := e.do("PATCH", "/scim/v2/primary/Users/"+r.str("id"), e.super, patchBody(op("replace", quisoraURN+":role", "admin"))); p.Status != 403 {
		t.Errorf("promotion to admin through SCIM: %d %s", p.Status, p.Raw)
	}
	// Role changes downwards go through the service guards.
	id := e.mkUser(e.primary(), "sa2", model.RoleSuperAdmin).ID
	if p := e.do("PATCH", "/scim/v2/primary/Users/"+id, e.admA, patchBody(op("replace", quisoraURN+":role", "user"))); p.Status != 404 {
		t.Errorf("other org's admin patching primary: %d", p.Status)
	}
	if p := e.do("PATCH", "/scim/v2/primary/Users/"+id, e.super, patchBody(op("replace", quisoraURN+":role", "user"))); p.Status != 200 || p.str(quisoraURN, "role") != "user" {
		t.Errorf("demote: %d %s", p.Status, p.Raw)
	}
	// Last super admin: the bootstrap admin cannot be demoted by a (hypothetical) peer, but a second super may.
	sid := e.Admin.ID
	if p := e.do("PATCH", "/scim/v2/primary/Users/"+sid, e.super, patchBody(op("replace", "active", false))); p.Status != 422 && p.Status != 400 {
		t.Errorf("self-disable: %d %s", p.Status, p.Raw)
	}
	_ = service.ScopeSCIM
	_ = http.StatusOK
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
