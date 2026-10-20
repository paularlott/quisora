package scim_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/scim"
	"github.com/paularlott/quisora/internal/service"
)

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
