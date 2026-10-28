package admin_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/scim"
	"github.com/paularlott/quisora/internal/web"
	"go.yaml.in/yaml/v3"
)

// openAPISpec returns the OpenAPI description as JSON, read from its source: the server serves the copy the web
// build bundles (dist/openapi.json), which go test does not need.
func openAPISpec(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../web/openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("openapi.yaml: %v", err)
	}
	raw, err := json.MarshalIndent(stringKeys(doc), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// stringKeys turns mappings with non-string keys (an unquoted 200: response code decodes as an int) into
// map[string]any, which JSON can encode.
func stringKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = stringKeys(x)
		}
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = stringKeys(x)
		}
		return m
	case []any:
		for i, x := range t {
			t[i] = stringKeys(x)
		}
	}
	return v
}

// openAPIMethods are the keys of a path item that are operations (the others: parameters, summary, description).
var openAPIMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "patch": true,
	"head": true, "options": true, "trace": true}

// openAPIOp decodes the operation method of path from the OpenAPI document raw into v.
func openAPIOp(t *testing.T, raw []byte, path, method string, v any) {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	op, ok := doc.Paths[path][method]
	if !ok {
		t.Fatalf("no %s %s in the OpenAPI document", method, path)
	}
	if err := json.Unmarshal(op, v); err != nil {
		t.Fatal(err)
	}
}

type openAPIParam struct {
	Ref    string `json:"$ref"`
	Name   string `json:"name"`
	In     string `json:"in"`
	Schema struct {
		Pattern string `json:"pattern"`
	} `json:"schema"`
}

// Every registered /api route must be described in the OpenAPI document, and the document must not describe
// routes that do not exist. The document is written by hand (web/openapi/openapi.yaml), so this also checks what a
// generator would have guaranteed: every path parameter is declared and every reference resolves.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	w := newWorld(t)
	raw := openAPISpec(t)
	var doc struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Version string `json:"version"`
		} `json:"info"`
		Paths map[string]map[string]json.RawMessage `json:"paths"`
		Comps map[string]map[string]json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("openapi version %q", doc.OpenAPI)
	}
	var schemes map[string]struct {
		Type   string `json:"type"`
		Scheme string `json:"scheme"`
		In     string `json:"in"`
	}
	if err := json.Unmarshal(mustJSON(t, doc.Comps["securitySchemes"]), &schemes); err != nil {
		t.Fatal(err)
	}
	if schemes["bearer"].Scheme != "bearer" || schemes["session"].In != "cookie" {
		t.Errorf("security schemes: %+v", schemes)
	}
	params := map[string]openAPIParam{}
	for name, raw := range doc.Comps["parameters"] {
		var p openAPIParam
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		params[name] = p
	}
	if p := params["ApiVersion"]; p.Name != "Api-Version" || p.In != "header" {
		t.Errorf("Api-Version parameter: %+v", p)
	}
	var version struct {
		Schema struct {
			Enum []string `json:"enum"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(doc.Comps["parameters"]["ApiVersion"], &version); err != nil {
		t.Fatal(err)
	}
	if strings.Join(version.Schema.Enum, ",") != strings.Join(web.APIVersions, ",") {
		t.Errorf("Api-Version enum %v, supported versions %v", version.Schema.Enum, web.APIVersions)
	}
	if doc.Info.Version != web.APIVersionLatest {
		t.Errorf("info.version %q, latest API version %q", doc.Info.Version, web.APIVersionLatest)
	}
	resolve := func(p openAPIParam) openAPIParam {
		if name, ok := strings.CutPrefix(p.Ref, "#/components/parameters/"); ok {
			return params[name]
		}
		return p
	}

	registered := map[string]bool{}
	for _, rt := range w.mod.Routes() {
		if !strings.HasPrefix(rt.Path, "/api/") {
			t.Errorf("route outside /api: %s", rt.Path)
		}
		path := strings.ReplaceAll(rt.Path, "...}", "}") // (a {name...} wildcard is one parameter to OpenAPI)
		key := rt.Method + " " + path
		registered[key] = true
		ops, ok := doc.Paths[path]
		if !ok {
			t.Errorf("route %s is missing from the OpenAPI document", key)
			continue
		}
		if _, ok := ops[strings.ToLower(rt.Method)]; !ok {
			t.Errorf("route %s: method missing from the OpenAPI document", key)
		}
	}
	// SCIM is described from scim.Routes, which the scim package tests against its handler.
	for _, rt := range scim.Routes {
		registered[rt.Method+" "+rt.Path] = true
		if _, ok := doc.Paths[rt.Path][strings.ToLower(rt.Method)]; !ok {
			t.Errorf("SCIM route %s %s is missing from the OpenAPI document", rt.Method, rt.Path)
		}
	}
	pathParam := regexp.MustCompile(`\{([^}]+)\}`)
	var extra []string
	for path, item := range doc.Paths {
		var shared []openAPIParam
		if raw, ok := item["parameters"]; ok {
			if err := json.Unmarshal(raw, &shared); err != nil {
				t.Fatalf("%s parameters: %v", path, err)
			}
		}
		for m, raw := range item {
			if !openAPIMethods[m] {
				continue
			}
			if !registered[strings.ToUpper(m)+" "+path] {
				extra = append(extra, strings.ToUpper(m)+" "+path)
			}
			var op struct {
				Parameters []openAPIParam `json:"parameters"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatalf("%s %s: %v", m, path, err)
			}
			declared := map[string]bool{}
			for _, p := range append(append([]openAPIParam{}, shared...), op.Parameters...) {
				if p = resolve(p); p.In == "path" {
					declared[p.Name] = true
				}
			}
			for _, sub := range pathParam.FindAllStringSubmatch(path, -1) {
				if !declared[sub[1]] {
					t.Errorf("%s %s: path parameter %s is not declared", strings.ToUpper(m), path, sub[1])
				}
				delete(declared, sub[1])
			}
			for name := range declared {
				t.Errorf("%s %s: declares path parameter %s, which the path does not have", strings.ToUpper(m), path, name)
			}
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("the OpenAPI document describes routes that are not registered: %v", extra)
	}
	// every local $ref resolves
	for _, m := range regexp.MustCompile(`"\$ref": "#/components/([^/"]+)/([^"]+)"`).FindAllStringSubmatch(string(raw), -1) {
		if _, ok := doc.Comps[m[1]][m[2]]; !ok {
			t.Errorf("unresolved reference #/components/%s/%s", m[1], m[2])
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Tags are documented on users and groups (read and write) and the user list takes ?tag=.
func TestOpenAPITags(t *testing.T) {
	raw := openAPISpec(t)
	var doc struct {
		Comps struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type     string `json:"type"`
					MaxItems int    `json:"maxItems"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"User", "UserInput", "UserCreate", "UserCreated", "Group", "GroupInput"} {
		p, ok := doc.Comps.Schemas[name].Properties["tags"]
		if !ok || p.Type != "array" || p.MaxItems != 50 {
			t.Errorf("schema %s: tags property %+v", name, p)
		}
	}
	var op struct {
		Parameters []openAPIParam `json:"parameters"`
	}
	openAPIOp(t, raw, "/api/orgs/{org}/users", "get", &op)
	found := false
	for _, p := range op.Parameters {
		if p.Name == "tag" && p.In == "query" {
			found = true
		}
	}
	if !found {
		t.Error("GET users does not document the tag query parameter")
	}
}

// The values the document lists by hand match the code: provider types and the organization name pattern.
func TestOpenAPIMatchesModel(t *testing.T) {
	raw := openAPISpec(t)
	var doc struct {
		Comps struct {
			Parameters map[string]openAPIParam `json:"parameters"`
			Schemas    map[string]struct {
				Properties map[string]struct {
					Enum    []string `json:"enum"`
					Pattern string   `json:"pattern"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Provider", "ProviderInput"} {
		if got := doc.Comps.Schemas[name].Properties["type"].Enum; strings.Join(got, ",") != strings.Join(model.ProviderTypes, ",") {
			t.Errorf("schema %s: type enum %v, model.ProviderTypes %v", name, got, model.ProviderTypes)
		}
	}
	re, err := regexp.Compile(doc.Comps.Parameters["Org"].Schema.Pattern)
	if err != nil || doc.Comps.Parameters["Org"].Schema.Pattern == "" {
		t.Fatalf("Org parameter pattern %q: %v", doc.Comps.Parameters["Org"].Schema.Pattern, err)
	}
	// reserved names match the pattern but are refused, so the samples avoid them
	for _, name := range []string{"acme", "a", "acme-corp", "a1", "Acme", "-acme", "acme-", "acme_corp", "Organizations",
		strings.Repeat("a", 63), strings.Repeat("a", 64), "", "x.y"} {
		if re.MatchString(name) != model.ValidOrgName(name) {
			t.Errorf("organization name %q: pattern says %v, model.ValidOrgName %v", name, re.MatchString(name), model.ValidOrgName(name))
		}
	}
	// A provider's chosen id: the pattern accepts what model.IsID does, but for the values above 2^128-1 that start
	// with 7 (a regular expression comparing with the largest id would be unreadable; the server refuses them).
	pat := doc.Comps.Schemas["ProviderInput"].Properties["id"].Pattern
	idRe, err := regexp.Compile(pat)
	if err != nil || pat == "" {
		t.Fatalf("ProviderInput id pattern %q: %v", pat, err)
	}
	id := model.NewID()
	for _, s := range []string{id, "0000000000000000000000", "7n42DGM5Tflk9n8mt7Fhc7", "8000000000000000000000",
		"zzzzzzzzzzzzzzzzzzzzzz", id[:21], id + "0", id[:10] + "-" + id[11:], id[:10] + "_" + id[11:], id[:10] + "." + id[11:], "acme", ""} {
		if idRe.MatchString(s) != model.IsID(s) {
			t.Errorf("id %q: pattern says %v, model.IsID %v", s, idRe.MatchString(s), model.IsID(s))
		}
	}
}

// The OpenAPI document matches what the handlers do: the rotate response (TestKeyRotationHooks), the member schema,
// the backup scope and the 503 answers.
func TestOpenAPISecurityResponsesAndSchemas(t *testing.T) {
	raw := openAPISpec(t)
	var doc struct {
		Comps struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	type op struct {
		Security   []map[string][]string      `json:"security"`
		Responses  map[string]json.RawMessage `json:"responses"`
		Parameters []struct {
			Name string `json:"name"`
			In   string `json:"in"`
		} `json:"parameters"`
	}
	var backup, createUser op
	openAPIOp(t, raw, "/api/backup", "get", &backup)
	openAPIOp(t, raw, "/api/orgs/{org}/users", "post", &createUser)
	if b := backup; len(b.Security) != 2 || b.Security[1]["bearer"][0] != "backup" {
		t.Errorf("backup security: %+v", b.Security)
	}
	in := map[string]string{}
	for _, p := range backup.Parameters {
		in[p.Name] = p.In
	}
	if in["plain"] != "query" || in["X-Backup-Password"] != "header" {
		t.Errorf("backup parameters: %v", in)
	}
	if _, ok := createUser.Responses["503"]; !ok {
		t.Error("no 503 response")
	}
	if p := doc.Comps.Schemas["Member"].Properties; p["name"] == nil || p["display_name"] != nil {
		t.Errorf("Member schema: %v", p)
	}
	if !strings.Contains(string(raw), `"#/components/schemas/KeyRotated"`) || doc.Comps.Schemas["KeyRotated"].Properties["rotated"] == nil {
		t.Error("rotate response schema")
	}
}
