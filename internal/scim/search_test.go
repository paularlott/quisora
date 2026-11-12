package scim_test

import (
	"slices"
	"strings"
	"testing"
)

const searchURN = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"

func searchBody(m map[string]any) map[string]any {
	m["schemas"] = []string{searchURN}
	return m
}

// POST .search answers as the GET listing does: the same filter, sort, paging and projection.
func TestSCIMPostSearchMatchesGetListing(t *testing.T) {
	e := newEnv(t)
	seedOrg(e)
	e.group("Ops")

	get := e.do("GET", "/scim/v2/acme/Users?filter="+qs(`userName sw "a" or userName sw "b"`)+"&sortBy=userName&sortOrder=descending&startIndex=1&count=2&attributes=userName", e.admA, nil)
	post := e.do("POST", "/scim/v2/acme/Users/.search", e.admA, searchBody(map[string]any{
		"filter": `userName sw "a" or userName sw "b"`, "sortBy": "userName", "sortOrder": "descending",
		"startIndex": 1, "count": 2, "attributes": []string{"userName"}}))
	if post.Status != 200 || !slices.Equal(post.names("userName"), get.names("userName")) || post.total() != get.total() || len(post.names("userName")) != 2 {
		t.Fatalf("users: post %d %s\nget %s", post.Status, post.Raw, get.Raw)
	}
	if _, ok := post.list("Resources")[0].(map[string]any)["emails"]; ok {
		t.Errorf("attributes ignored: %s", post.Raw)
	}

	g := e.do("POST", "/scim/v2/acme/Groups/.search", e.admA, searchBody(map[string]any{"filter": `displayName eq "Ops"`, "excludedAttributes": []string{"members"}}))
	if g.Status != 200 || g.total() != 1 || g.names("displayName")[0] != "Ops" {
		t.Errorf("groups: %d %s", g.Status, g.Raw)
	}

	// The count of zero is the listing's: only the total.
	if r := e.do("POST", "/scim/v2/acme/Users/.search", e.admA, searchBody(map[string]any{"count": 0})); r.Status != 200 || len(r.list("Resources")) != 0 || r.total() < 5 {
		t.Errorf("count 0: %d %s", r.Status, r.Raw)
	}
}

func TestSCIMPostSearchRefusals(t *testing.T) {
	e := newEnv(t)
	seedOrg(e)
	for _, tc := range []struct {
		name string
		body any
		want int
		typ  string
	}{
		{"not json", "{nope", 400, "invalidSyntax"},
		{"array", "[1]", 400, "invalidSyntax"},
		{"no schemas", map[string]any{"count": 1}, 400, "invalidSyntax"},
		{"count a string", searchBody(map[string]any{"count": "1"}), 400, "invalidSyntax"},
		{"count a fraction", `{"schemas":["` + searchURN + `"],"count":1.5}`, 400, "invalidValue"},
		{"startIndex out of range", `{"schemas":["` + searchURN + `"],"startIndex":1e30}`, 400, "invalidValue"},
		{"attribute with a comma", searchBody(map[string]any{"attributes": []string{"userName,emails"}}), 400, "invalidValue"},
		{"excluded attribute empty", searchBody(map[string]any{"excludedAttributes": []string{""}}), 400, "invalidValue"},
		{"attributes a string", searchBody(map[string]any{"attributes": "userName"}), 400, "invalidSyntax"},
		{"bad filter", searchBody(map[string]any{"filter": "userName eq"}), 400, "invalidFilter"},
		{"bad sortOrder", searchBody(map[string]any{"sortOrder": "sideways"}), 400, "invalidValue"},
		{"too large", `{"filter":"` + strings.Repeat("x", 2<<20) + `"}`, 413, ""},
	} {
		if r := e.do("POST", "/scim/v2/acme/Users/.search", e.admA, tc.body); r.Status != tc.want || r.str("scimType") != tc.typ {
			t.Errorf("%s: %d %s", tc.name, r.Status, r.Raw)
		}
	}
	if r := e.do("GET", "/scim/v2/acme/Users/.search", e.admA, nil); r.Status != 405 {
		t.Errorf("GET .search: %d", r.Status)
	}
	// Authorization is the listing's.
	b := searchBody(map[string]any{})
	if r := e.do("POST", "/scim/v2/acme/Users/.search", "", b); r.Status != 401 {
		t.Errorf("no token: %d", r.Status)
	}
	if r := e.do("POST", "/scim/v2/acme/Users/.search", e.admB, b); r.Status != 404 {
		t.Errorf("other org: %d", r.Status)
	}
}

// Removing every email is refused: the primary email is the sign-in name.
func TestSCIMPatchRemovingAllEmailsIsRefused(t *testing.T) {
	e := newEnv(t)
	id := e.mk("keeper", nil)
	for _, o := range []map[string]any{op("remove", "emails", nil), op("replace", "emails", []any{})} {
		r := e.patch(id, o)
		if r.Status != 400 || r.str("scimType") != "invalidValue" || !strings.Contains(r.str("detail"), "primary email cannot be removed") {
			t.Errorf("%v: %d %s", o, r.Status, r.Raw)
		}
	}
	if r := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil); !strings.Contains(string(r.Raw), "keeper@acme.test") {
		t.Errorf("email lost: %s", r.Raw)
	}
}
