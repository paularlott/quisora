package scim_test

import (
	"slices"
	"strings"
	"testing"
)

const (
	extUser  = "urn:paularlott:quisora:scim:schemas:2.0:User"
	extGroup = "urn:paularlott:quisora:scim:schemas:2.0:Group"
)

func tagsOf(r resp, urn string) []string {
	ext, _ := r.Body[urn].(map[string]any)
	l, ok := ext["tags"].([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, v := range l {
		out = append(out, v.(string))
	}
	return out
}

func TestUserTagsSCIM(t *testing.T) {
	e := newEnv(t)
	r := e.createUser("acme", e.admA, map[string]any{"userName": "tagged",
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User", extUser},
		extUser:   map[string]any{"tags": []string{"dept:finance", "vip", "vip"}}})
	if r.Status != 201 || !slices.Equal(tagsOf(r, extUser), []string{"dept:finance", "vip"}) {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	url := "/scim/v2/acme/Users/" + id
	// a user without tags renders an empty list
	plain := e.mk("plain", nil)
	if g := e.do("GET", "/scim/v2/acme/Users/"+plain, e.admA, nil); g.Status != 200 || tagsOf(g, extUser) == nil || len(tagsOf(g, extUser)) != 0 {
		t.Fatalf("empty tags: %s", g.Raw)
	}
	patch := func(ops ...map[string]any) resp { return e.do("PATCH", url, e.admA, patchBody(ops...)) }

	// add (with the full URN path), replace, remove one value, remove all
	if r := patch(op("add", extUser+":tags", []any{"team:blue", "vip"})); r.Status != 200 ||
		!slices.Equal(tagsOf(r, extUser), []string{"dept:finance", "team:blue", "vip"}) {
		t.Fatalf("add: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("remove", extUser+":tags", []any{"vip"})); r.Status != 200 ||
		!slices.Equal(tagsOf(r, extUser), []string{"dept:finance", "team:blue"}) {
		t.Fatalf("remove value: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("replace", extUser+":tags", []any{"b", "a"})); r.Status != 200 ||
		!slices.Equal(tagsOf(r, extUser), []string{"a", "b"}) {
		t.Fatalf("replace: %d %s", r.Status, r.Raw)
	}
	// pathless add with the extension object
	if r := patch(op("add", "", map[string]any{extUser: map[string]any{"tags": []any{"c"}}})); r.Status != 200 ||
		!slices.Equal(tagsOf(r, extUser), []string{"a", "b", "c"}) {
		t.Fatalf("pathless add: %d %s", r.Status, r.Raw)
	}
	// other attributes keep the tags
	if r := patch(op("replace", "displayName", "Boss")); r.Status != 200 || len(tagsOf(r, extUser)) != 3 {
		t.Fatalf("unrelated patch: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("remove", extUser+":tags", nil)); r.Status != 200 || len(tagsOf(r, extUser)) != 0 {
		t.Fatalf("remove all: %d %s", r.Status, r.Raw)
	}
	// invalid values are rejected
	if r := patch(op("add", extUser+":tags", []any{"not valid"})); r.Status != 400 && r.Status != 422 {
		t.Fatalf("invalid tag: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("add", extUser+":tags", []any{1})); r.Status != 400 {
		t.Fatalf("non-string tag: %d %s", r.Status, r.Raw)
	}
	// PUT: tags given are applied, tags not mentioned are kept
	put := func(body map[string]any) resp {
		body["userName"], body["emails"] = "tagged", mail("tagged@acme.test")
		return e.do("PUT", url, e.admA, body)
	}
	if r := put(map[string]any{extUser: map[string]any{"tags": []string{"p"}}}); r.Status != 200 || !slices.Equal(tagsOf(r, extUser), []string{"p"}) {
		t.Fatalf("put with tags: %d %s", r.Status, r.Raw)
	}
	if r := put(map[string]any{}); r.Status != 200 || !slices.Equal(tagsOf(r, extUser), []string{"p"}) {
		t.Fatalf("put without tags: %d %s", r.Status, r.Raw)
	}
	if r := put(map[string]any{extUser: map[string]any{"tags": []string{}}}); r.Status != 200 || len(tagsOf(r, extUser)) != 0 {
		t.Fatalf("put empty tags: %d %s", r.Status, r.Raw)
	}
	// a manager may tag plain users; filtering by tag works in memory
	if r := e.do("PATCH", url, e.mgrA, patchBody(op("add", extUser+":tags", []any{"mgr"}))); r.Status != 200 {
		t.Fatalf("manager: %d %s", r.Status, r.Raw)
	}
	f := e.do("GET", "/scim/v2/acme/Users?filter="+qs(`urn:paularlott:quisora:scim:schemas:2.0:User:tags eq "mgr"`), e.admA, nil)
	if f.Status != 200 || f.total() != 1 {
		t.Fatalf("filter by tag: %d %s", f.Status, f.Raw)
	}
}

func TestGroupTagsSCIM(t *testing.T) {
	e := newEnv(t)
	r := e.do("POST", "/scim/v2/acme/Groups", e.admA, map[string]any{"displayName": "Tagged",
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group", extGroup},
		extGroup:  map[string]any{"tags": []string{"team:b", "team:a"}}})
	if r.Status != 201 || !slices.Equal(tagsOf(r, extGroup), []string{"team:a", "team:b"}) {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	url := "/scim/v2/acme/Groups/" + r.str("id")
	patch := func(ops ...map[string]any) resp { return e.do("PATCH", url, e.admA, patchBody(ops...)) }
	if r := patch(op("add", extGroup+":tags", []any{"x"})); r.Status != 200 || !slices.Equal(tagsOf(r, extGroup), []string{"team:a", "team:b", "x"}) {
		t.Fatalf("add: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("remove", extGroup+":tags", []any{"team:a"})); r.Status != 200 || !slices.Equal(tagsOf(r, extGroup), []string{"team:b", "x"}) {
		t.Fatalf("remove value: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("replace", extGroup+":tags", []any{"only"})); r.Status != 200 || !slices.Equal(tagsOf(r, extGroup), []string{"only"}) {
		t.Fatalf("replace: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("replace", "displayName", "Renamed")); r.Status != 200 || r.str("displayName") != "Renamed" || len(tagsOf(r, extGroup)) != 1 {
		t.Fatalf("rename keeps tags: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("add", extGroup+":tags", []any{"bad tag"})); r.Status != 400 && r.Status != 422 {
		t.Fatalf("invalid: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("remove", extGroup+":tags", nil)); r.Status != 200 || len(tagsOf(r, extGroup)) != 0 {
		t.Fatalf("remove all: %d %s", r.Status, r.Raw)
	}
	// PUT without tags keeps them, with tags sets them
	put := func(body map[string]any) resp { body["displayName"] = "Renamed"; return e.do("PUT", url, e.admA, body) }
	if r := put(map[string]any{extGroup: map[string]any{"tags": []string{"q"}}}); r.Status != 200 || !slices.Equal(tagsOf(r, extGroup), []string{"q"}) {
		t.Fatalf("put: %d %s", r.Status, r.Raw)
	}
	if r := put(map[string]any{}); r.Status != 200 || !slices.Equal(tagsOf(r, extGroup), []string{"q"}) {
		t.Fatalf("put without: %d %s", r.Status, r.Raw)
	}
}

func TestTagsDiscovery(t *testing.T) {
	e := newEnv(t)
	for _, base := range []string{"/scim/v2", "/scim/v2/acme"} {
		for _, urn := range []string{extUser, extGroup} {
			r := e.do("GET", base+"/Schemas/"+urn, "", nil)
			attrs, _ := r.Body["attributes"].([]any)
			found := false
			for _, a := range attrs {
				m := a.(map[string]any)
				if m["name"] == "tags" && m["multiValued"] == true && m["type"] == "string" {
					found = true
				}
			}
			if r.Status != 200 || !found {
				t.Errorf("%s schema %s lacks multi-valued tags: %d %s", base, urn, r.Status, r.Raw)
			}
		}
		// the enterprise extension is advertised with its attributes (work details are stored)
		if r := e.do("GET", base+"/Schemas", "", nil); !strings.Contains(string(r.Raw), "extension:enterprise:2.0:User") ||
			!strings.Contains(string(r.Raw), "costCenter") {
			t.Errorf("%s Schemas lack the enterprise extension", base)
		}
		if r := e.do("GET", base+"/ResourceTypes/User", "", nil); !strings.Contains(string(r.Raw), "extension:enterprise:2.0:User") {
			t.Errorf("%s User resource type lacks the enterprise extension: %s", base, r.Raw)
		}
		g := e.do("GET", base+"/ResourceTypes/Group", "", nil)
		exts, _ := g.Body["schemaExtensions"].([]any)
		if g.Status != 200 || len(exts) != 1 || exts[0].(map[string]any)["schema"] != extGroup {
			t.Errorf("%s Group resource type: %s", base, g.Raw)
		}
	}
}
