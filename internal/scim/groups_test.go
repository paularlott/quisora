package scim_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

func memberValues(r resp) []string {
	var out []string
	for _, m := range r.list("members") {
		out = append(out, m.(map[string]any)["value"].(string))
	}
	slices.Sort(out)
	return out
}

func (e *env) group(name string, members ...string) string {
	body := map[string]any{"displayName": name}
	if len(members) > 0 {
		ms := make([]any, len(members))
		for i, m := range members {
			ms[i] = map[string]any{"value": m}
		}
		body["members"] = ms
	}
	r := e.do("POST", "/scim/v2/acme/Groups", e.admA, body)
	if r.Status != 201 {
		e.t.Fatalf("group %s: %d %s", name, r.Status, r.Raw)
	}
	return r.str("id")
}

func sorted(s ...string) []string { slices.Sort(s); return s }

func TestGroupCRUD(t *testing.T) {
	e := newEnv(t)
	u1, u2, u3 := e.mk("g1", nil), e.mk("g2", nil), e.mk("g3", nil)
	r := e.do("POST", "/scim/v2/acme/Groups", e.admA, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Platform", "externalId": "grp-1",
		"members": []any{map[string]any{"value": u1}, map[string]any{"value": u2, "display": "ignored"}, map[string]any{"value": u1}},
	})
	if r.Status != 201 {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	if r.str("meta", "resourceType") != "Group" || r.Header.Get("Location") != e.URL+"/scim/v2/acme/Groups/"+id || r.Header.Get("ETag") == "" ||
		r.str("externalId") != "grp-1" {
		t.Errorf("create meta: %v %s", r.Header, r.Raw)
	}
	if got := memberValues(r); !slices.Equal(got, sorted(u1, u2)) { // duplicate collapsed
		t.Errorf("members %v", got)
	}
	m0 := r.list("members")[0].(map[string]any)
	if m0["display"] == nil || m0["type"] != "User" || !strings.Contains(m0["$ref"].(string), "/scim/v2/acme/Users/"+m0["value"].(string)) {
		t.Errorf("member shape %v", m0)
	}
	// GET and the user's groups attribute.
	g := e.do("GET", "/scim/v2/acme/Groups/"+id, e.admA, nil)
	if g.Status != 200 || len(g.list("members")) != 2 {
		t.Errorf("get: %s", g.Raw)
	}
	ug := e.do("GET", "/scim/v2/acme/Users/"+u1, e.admA, nil)
	if gs := ug.list("groups"); len(gs) != 1 || gs[0].(map[string]any)["display"] != "Platform" {
		t.Errorf("user groups: %s", ug.Raw)
	}
	// PUT without members keeps them, with members replaces them, with [] clears.
	if p := e.do("PUT", "/scim/v2/acme/Groups/"+id, e.admA, map[string]any{"displayName": "Platform 2"}); p.Status != 200 ||
		p.str("displayName") != "Platform 2" || len(p.list("members")) != 2 || p.Body["externalId"] != nil {
		t.Errorf("put no members: %d %s", p.Status, p.Raw)
	}
	p := e.do("PUT", "/scim/v2/acme/Groups/"+id, e.admA, map[string]any{"displayName": "Platform 2",
		"members": []any{map[string]any{"value": u2}, map[string]any{"value": u3}}})
	if got := memberValues(p); !slices.Equal(got, sorted(u2, u3)) {
		t.Errorf("put members %v", got)
	}
	if ug := e.do("GET", "/scim/v2/acme/Users/"+u1, e.admA, nil); len(ug.list("groups")) != 0 {
		t.Error("removed member still lists the group")
	}
	if p := e.do("PUT", "/scim/v2/acme/Groups/"+id, e.admA, map[string]any{"displayName": "Platform 2", "members": []any{}}); len(p.list("members")) != 0 {
		t.Errorf("put empty: %s", p.Raw)
	}
	// Errors.
	for name, tc := range map[string]struct {
		body   any
		status int
		typ    string
	}{
		"no name":       {map[string]any{"externalId": "x"}, 400, "invalidValue"},
		"blank name":    {map[string]any{"displayName": "  "}, 400, "invalidValue"},
		"duplicate":     {map[string]any{"displayName": "platform 2"}, 409, "uniqueness"},
		"dup external":  {map[string]any{"displayName": "other", "externalId": "grp-1"}, 409, "uniqueness"},
		"unknown user":  {map[string]any{"displayName": "z1", "members": []any{map[string]any{"value": "ghost"}}}, 400, "invalidValue"},
		"member no val": {map[string]any{"displayName": "z2", "members": []any{map[string]any{"display": "x"}}}, 400, "invalidValue"},
		"members type":  {map[string]any{"displayName": "z3", "members": "x"}, 400, "invalidValue"},
	} {
		if name == "dup external" {
			e.do("PUT", "/scim/v2/acme/Groups/"+id, e.admA, map[string]any{"displayName": "Platform 2", "externalId": "grp-1"})
		}
		r := e.do("POST", "/scim/v2/acme/Groups", e.admA, tc.body)
		if r.Status != tc.status || r.str("scimType") != tc.typ {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	// A failed create with a bad member leaves no group behind.
	if r := e.do("GET", "/scim/v2/acme/Groups?filter="+qs(`displayName eq "z1"`), e.admA, nil); r.total() != 0 {
		t.Error("group left behind after failed create")
	}
	// Delete removes memberships.
	e.do("PUT", "/scim/v2/acme/Groups/"+id, e.admA, map[string]any{"displayName": "Platform 2", "members": []any{map[string]any{"value": u1}}})
	if d := e.do("DELETE", "/scim/v2/acme/Groups/"+id, e.admA, nil); d.Status != 204 {
		t.Errorf("delete: %d", d.Status)
	}
	if e.do("GET", "/scim/v2/acme/Groups/"+id, e.admA, nil).Status != 404 {
		t.Error("deleted group")
	}
	if ug := e.do("GET", "/scim/v2/acme/Users/"+u1, e.admA, nil); len(ug.list("groups")) != 0 {
		t.Error("user still in deleted group")
	}
}

func TestGroupPatch(t *testing.T) {
	e := newEnv(t)
	u1, u2, u3 := e.mk("p1", nil), e.mk("p2", nil), e.mk("p3", nil)
	id := e.group("Patched", u1)
	url := "/scim/v2/acme/Groups/" + id
	patch := func(ops ...map[string]any) resp { return e.do("PATCH", url, e.admA, patchBody(ops...)) }

	// Entra: add members (value list), remove members (value list), rename.
	r := e.do("PATCH", url, e.admA, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
	  {"op":"Add","path":"members","value":[{"value":"`+u2+`"},{"value":"`+u3+`"}]},
	  {"op":"Replace","path":"displayName","value":"Patched 2"}]}`)
	if r.Status != 200 || r.str("displayName") != "Patched 2" || !slices.Equal(memberValues(r), sorted(u1, u2, u3)) {
		t.Fatalf("entra add: %d %s", r.Status, r.Raw)
	}
	r = e.do("PATCH", url, e.admA, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
	  {"op":"Remove","path":"members","value":[{"value":"`+u3+`"}]}]}`)
	if r.Status != 200 || !slices.Equal(memberValues(r), sorted(u1, u2)) {
		t.Errorf("entra remove: %d %s", r.Status, r.Raw)
	}
	// Okta: remove with a filter path, add with display.
	r = patch(op("remove", `members[value eq "`+u2+`"]`, nil))
	if r.Status != 200 || !slices.Equal(memberValues(r), sorted(u1)) {
		t.Errorf("okta remove: %d %s", r.Status, r.Raw)
	}
	r = patch(op("add", "members", []any{map[string]any{"value": u2, "display": "p2"}}))
	if r.Status != 200 || !slices.Equal(memberValues(r), sorted(u1, u2)) {
		t.Errorf("okta add: %d %s", r.Status, r.Raw)
	}
	// Adding an existing member is idempotent; removing a non-member too.
	if r := patch(op("add", "members", []any{map[string]any{"value": u2}})); r.Status != 200 || len(r.list("members")) != 2 {
		t.Errorf("add existing: %s", r.Raw)
	}
	if r := patch(op("remove", `members[value eq "`+u3+`"]`, nil)); r.Status != 200 || len(r.list("members")) != 2 {
		t.Errorf("remove non-member: %d %s", r.Status, r.Raw)
	}
	// Replace the member list; pathless replace; remove all.
	if r := patch(op("replace", "members", []any{map[string]any{"value": u3}})); !slices.Equal(memberValues(r), sorted(u3)) {
		t.Errorf("replace members: %s", r.Raw)
	}
	if r := patch(op("replace", "", map[string]any{"displayName": "Pathless", "externalId": "pl"})); r.Status != 200 ||
		r.str("displayName") != "Pathless" || r.str("externalId") != "pl" || len(r.list("members")) != 1 {
		t.Errorf("pathless: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("remove", "members", nil)); r.Status != 200 || len(r.list("members")) != 0 {
		t.Errorf("remove all: %s", r.Raw)
	}
	if r := patch(op("remove", "externalId", nil)); r.Status != 200 || r.Body["externalId"] != nil {
		t.Errorf("remove externalId: %s", r.Raw)
	}
	// Errors: unknown user, bad paths, empty name, clash.
	if r := patch(op("add", "members", []any{map[string]any{"value": "ghost"}})); r.Status != 400 || r.str("scimType") != "invalidValue" {
		t.Errorf("unknown member: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("replace", "displayName", "")); r.Status != 400 {
		t.Errorf("empty name: %d", r.Status)
	}
	e.group("Taken")
	if r := patch(op("replace", "displayName", "taken")); r.Status != 409 || r.str("scimType") != "uniqueness" {
		t.Errorf("name clash: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("replace", "members[", "x")); r.Status != 400 || r.str("scimType") != "invalidPath" {
		t.Errorf("bad path: %d %s", r.Status, r.Raw)
	}
	// A cross-org user cannot be added.
	other := e.mkUser(e.orgB, "outsider", model.RoleUser)
	if r := patch(op("add", "members", []any{map[string]any{"value": other.ID}})); r.Status != 400 {
		t.Errorf("cross-org member: %d %s", r.Status, r.Raw)
	}
}

func TestGroupListAndFilters(t *testing.T) {
	e := newEnv(t)
	u1, u2 := e.mk("l1", nil), e.mk("l2", nil)
	a := e.group("Alpha", u1, u2)
	b := e.group("Beta", u2)
	e.group("Gamma")
	e.do("PUT", "/scim/v2/acme/Groups/"+b, e.admA, map[string]any{"displayName": "Beta", "externalId": "ext-beta"})
	list := func(q string) []string {
		r := e.do("GET", "/scim/v2/acme/Groups?sortBy=displayName&filter="+qs(q), e.admA, nil)
		if r.Status != 200 {
			t.Fatalf("%s: %d %s", q, r.Status, r.Raw)
		}
		return r.names("displayName")
	}
	for q, want := range map[string][]string{
		`displayName eq "alpha"`:                {"Alpha"},
		`displayName co "a"`:                    {"Alpha", "Beta", "Gamma"},
		`displayName sw "G"`:                    {"Gamma"},
		`displayName ew "ta"`:                   {"Beta"},
		`externalId eq "ext-beta"`:              {"Beta"},
		`externalId pr`:                         {"Beta"},
		`members.value eq "` + u2 + `"`:         {"Alpha", "Beta"},
		`members[value eq "` + u1 + `"]`:        {"Alpha"},
		`not (members pr)`:                      {"Gamma"},
		`displayName ne "Alpha" and members pr`: {"Beta"},
		`id eq "` + a + `"`:                     {"Alpha"},
		`displayName eq "nope"`:                 nil,
	} {
		if got := list(q); !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("%s: got %v want %v", q, got, want)
		}
	}
	all := e.do("GET", "/scim/v2/acme/Groups?sortBy=displayName&sortOrder=descending&count=2", e.admA, nil)
	if all.total() != 3 || !slices.Equal(all.names("displayName"), []string{"Gamma", "Beta"}) {
		t.Errorf("sorted page: %s", all.Raw)
	}
	// members default in lists, excluded on request
	r := e.do("GET", "/scim/v2/acme/Groups?filter="+qs(`displayName eq "Alpha"`), e.admA, nil)
	if len(r.list("Resources")[0].(map[string]any)["members"].([]any)) != 2 {
		t.Errorf("members in list: %s", r.Raw)
	}
	r = e.do("GET", "/scim/v2/acme/Groups?excludedAttributes=members&filter="+qs(`displayName eq "Alpha"`), e.admA, nil)
	if r.list("Resources")[0].(map[string]any)["members"] != nil {
		t.Errorf("members not excluded: %s", r.Raw)
	}
	r = e.do("GET", "/scim/v2/acme/Groups?attributes=displayName&filter="+qs(`displayName eq "Alpha"`), e.admA, nil)
	if res := r.list("Resources")[0].(map[string]any); res["members"] != nil || res["displayName"] != "Alpha" {
		t.Errorf("attributes: %s", r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/Groups?filter="+qs(`displayName eq`), e.admA, nil); r.Status != 400 || r.str("scimType") != "invalidFilter" {
		t.Errorf("bad filter: %d", r.Status)
	}
	// A large group still renders with display names.
	for i := range 30 {
		e.mk("bulk"+strings.Repeat("x", i%3)+string(rune('a'+i%26))+string(rune('a'+i/26)), nil)
	}
	users := e.do("GET", "/scim/v2/acme/Users?count=1000&filter="+qs(`userName sw "bulk"`), e.admA, nil)
	var ids []string
	for _, it := range users.list("Resources") {
		ids = append(ids, it.(map[string]any)["id"].(string))
	}
	big := e.group("Big", ids...)
	g := e.do("GET", "/scim/v2/acme/Groups/"+big, e.admA, nil)
	if len(g.list("members")) != 30 || g.list("members")[0].(map[string]any)["display"] == nil {
		t.Errorf("big group: %d members", len(g.list("members")))
	}
}
