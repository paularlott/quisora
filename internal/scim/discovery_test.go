package scim_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/scim"
	"github.com/paularlott/quisora/internal/service"
)

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

// The discovery endpoints answer only the paths and methods they serve, resource types are found by name in any
// case, and an organization-scoped listing has no Organization type.
func TestDiscoveryEdges(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/scim/v2/ServiceProviderConfig/x", "", 404},
		{"GET", "/scim/v2/acme/ServiceProviderConfig/x", "", 404},
		{"GET", "/scim/v2/Schemas/a/b", "", 404},
		{"GET", "/scim/v2/ResourceTypes/a/b", "", 404},
		{"DELETE", "/scim/v2/acme/ResourceTypes", "", 405},
		{"PUT", "/scim/v2/Schemas", "", 405},
		{"GET", "/scim/v2/Schemas/urn:nope", "", 404},
		{"GET", "/scim/v2/acme/ResourceTypes/Organization", "", 404},
		{"GET", "/scim/v2/acme/Bogus", e.admA, 404},
		{"GET", "/scim/v2/acme", e.admA, 404},
		{"GET", "/scim/v2/ac%6De/Users", e.admA, 200}, // an escaped organization name
	} {
		var body any
		if tc.method == "PUT" {
			body = map[string]any{}
		}
		wantStatus(t, tc.method+" "+tc.path, e.do(tc.method, tc.path, tc.token, body), tc.want)
	}
	if r := e.do("GET", "/scim/v2/ResourceTypes/organization", "", nil); r.Status != 200 || r.str("id") != "Organization" {
		t.Errorf("type by name: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/Schemas", "", nil); r.Status != 200 || r.total() != 5 {
		t.Errorf("scoped schemas: %d %s", r.Status, r.Raw)
	}
}

// Every operation scim.Routes documents (in the OpenAPI document) is one the handler serves: never "Resource not
// found" (no such path) or 405 (no such method).
func TestRoutesAreServed(t *testing.T) {
	e := newEnv(t)
	// real ids: a missing one answers the same "not found" as a missing path
	ids := map[string]string{"User": e.mkUser(e.orgA, "routes", model.RoleUser).ID, "Organization": e.org("initech").ID}
	g, err := e.Svc.CreateGroup(e.ctx, service.System, e.orgA.ID, service.GroupInput{DisplayName: ptr("routes")})
	if err != nil {
		t.Fatal(err)
	}
	ids["Group"] = g.ID
	for _, rt := range scim.Routes {
		path := strings.NewReplacer("{org}", "acme", "{id}", ids[rt.Resource]).Replace(rt.Path)
		token := e.super
		if rt.Public {
			token = ""
		}
		var body any
		switch rt.Method {
		case "POST", "PUT":
			body = map[string]any{}
		case "PATCH":
			body = map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": []any{}}
		}
		r := e.do(rt.Method, path, token, body)
		if r.Status == 405 || strings.Contains(string(r.Raw), "Resource not found") {
			t.Errorf("%s %s: %d %s", rt.Method, rt.Path, r.Status, r.Raw)
		}
	}
	// and the org-less spelling of Users and Groups is not one of them
	if r := e.do("GET", "/scim/v2/Users", e.super, nil); r.Status != 404 {
		t.Errorf("org-less Users: %d", r.Status)
	}
}

// displayName is derived from the name, so the Schemas endpoint says it is read-only (TestPatchEntraUser shows a
// PATCH of it changes nothing).
func TestDisplayNameIsReadOnlyInSchema(t *testing.T) {
	e := newEnv(t)
	s := e.do("GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "", nil)
	attrs, _ := s.Body["attributes"].([]any)
	for _, a := range attrs {
		if m, _ := a.(map[string]any); m["name"] == "displayName" {
			if m["mutability"] != "readOnly" {
				t.Fatalf("displayName mutability %v", m["mutability"])
			}
			return
		}
	}
	t.Fatal("displayName not in the User schema")
}
