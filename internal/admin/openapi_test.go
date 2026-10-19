package admin_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/admin"
)

// Every registered /api/v1 route must be described in the OpenAPI document, and the document must not describe
// routes that do not exist.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	w := newWorld(t)
	r := w.anon().get("/api/openapi.json")
	want(t, r, 200)
	var doc struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
		Comps   struct {
			Schemas         map[string]json.RawMessage `json:"schemas"`
			SecuritySchemes map[string]struct {
				Type   string `json:"type"`
				Scheme string `json:"scheme"`
				In     string `json:"in"`
			} `json:"securitySchemes"`
			Parameters map[string]struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
		} `json:"components"`
	}
	if err := json.Unmarshal(r.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("openapi version %q", doc.OpenAPI)
	}
	if ss := doc.Comps.SecuritySchemes; ss["bearer"].Scheme != "bearer" || ss["session"].In != "cookie" {
		t.Errorf("security schemes: %+v", ss)
	}
	if p := doc.Comps.Parameters["ApiVersion"]; p.Name != "Api-Version" || p.In != "header" {
		t.Errorf("Api-Version parameter: %+v", p)
	}

	registered := map[string]bool{}
	for _, rt := range w.mod.Routes() {
		if !strings.HasPrefix(rt.Path, "/api/v1/") {
			t.Errorf("route outside /api/v1: %s", rt.Path)
		}
		key := rt.Method + " " + rt.Path
		registered[key] = true
		ops, ok := doc.Paths[rt.Path]
		if !ok {
			t.Errorf("route %s is missing from the OpenAPI document", key)
			continue
		}
		if _, ok := ops[strings.ToLower(rt.Method)]; !ok {
			t.Errorf("route %s: method missing from the OpenAPI document", key)
		}
	}
	var extra []string
	for path, ops := range doc.Paths {
		for m := range ops {
			if !registered[strings.ToUpper(m)+" "+path] {
				extra = append(extra, strings.ToUpper(m)+" "+path)
			}
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("the OpenAPI document describes routes that are not registered: %v", extra)
	}
	// every $ref resolves
	for _, ref := range strings.Split(string(r.Raw), `"$ref": "#/components/schemas/`)[1:] {
		name := ref[:strings.Index(ref, `"`)]
		if _, ok := doc.Comps.Schemas[name]; !ok {
			t.Errorf("unresolved schema reference %s", name)
		}
	}
	_ = admin.New
}

// Tags are documented on users and groups (read and write) and the user list takes ?tag=.
func TestOpenAPITags(t *testing.T) {
	w := newWorld(t)
	r := w.anon().get("/api/openapi.json")
	want(t, r, 200)
	var doc struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
		} `json:"paths"`
		Comps struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type     string `json:"type"`
					MaxItems int    `json:"maxItems"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(r.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"User", "UserInput", "UserCreate", "UserCreated", "Group", "GroupInput"} {
		p, ok := doc.Comps.Schemas[name].Properties["tags"]
		if !ok || p.Type != "array" || p.MaxItems != 50 {
			t.Errorf("schema %s: tags property %+v", name, p)
		}
	}
	found := false
	for _, p := range doc.Paths["/api/v1/orgs/{org}/users"]["get"].Parameters {
		if p.Name == "tag" && p.In == "query" {
			found = true
		}
	}
	if !found {
		t.Error("GET users does not document the tag query parameter")
	}
}
