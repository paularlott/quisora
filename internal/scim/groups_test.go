package scim_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

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
	patch(op("add", "members", []any{map[string]any{"value": u1}}))
	if r := patch(op("remove", "members", []any{map[string]any{"value": u1}})); r.Status != 200 || len(r.list("members")) != 0 {
		t.Errorf("remove the last member by value: %s", r.Raw)
	}
	if r := patch(op("remove", "externalId", nil)); r.Status != 200 || r.Body["externalId"] != nil {
		t.Errorf("remove externalId: %s", r.Raw)
	}
	// Two attributes in two operations; replacing the members with an empty list clears them.
	if r := patch(op("replace", "externalId", "ext-9"), op("replace", "displayName", "Patched 3")); r.Status != 200 ||
		r.str("externalId") != "ext-9" || r.str("displayName") != "Patched 3" {
		t.Errorf("two attributes: %d %s", r.Status, r.Raw)
	}
	patch(op("add", "members", []any{map[string]any{"value": u1}}))
	if r := patch(op("replace", "members", []any{})); r.Status != 200 || len(r.list("members")) != 0 {
		t.Errorf("replace members with []: %d %s", r.Status, r.Raw)
	}
	// An attribute a group does not have is ignored.
	if r := patch(op("replace", "unknownAttr", "x")); r.Status != 200 || r.Body["unknownAttr"] != nil {
		t.Errorf("unknown attribute: %d %s", r.Status, r.Raw)
	}
	// Errors: unknown user, bad paths, empty name, clash.
	if r := patch(op("add", "members", []any{map[string]any{"value": "ghost"}})); r.Status != 400 || r.str("scimType") != "invalidValue" {
		t.Errorf("unknown member: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("replace", "displayName", "")); r.Status != 400 || r.str("scimType") != "invalidValue" {
		t.Errorf("empty name: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("remove", "displayName", nil)); r.Status != 400 || r.str("scimType") != "invalidValue" {
		t.Errorf("remove the name: %d %s", r.Status, r.Raw)
	}
	if r := patch(op("add", "members", "u")); r.Status != 400 || r.str("scimType") != "invalidValue" {
		t.Errorf("members not a list: %d %s", r.Status, r.Raw)
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
	if r := e.do("GET", "/scim/v2/acme/Groups?sortBy=members&attributes=members", e.admA, nil); r.Status != 200 || r.total() != 3 {
		t.Errorf("sort by members: %d %s", r.Status, r.Raw)
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

// Requests a group resource refuses, beside those of TestGroupCRUD and TestGroupPatch.
func TestGroupRequestRefusals(t *testing.T) {
	e := newEnv(t)
	gid := e.group("Refusals", e.mk("gr1", nil))
	other := e.do("POST", "/scim/v2/globex/Groups", e.admB, map[string]any{"displayName": "G"})
	wantStatus(t, "globex create", other, 201)
	base := "/scim/v2/acme/Groups"
	item := base + "/" + gid
	bad := `{"displayName":`
	for _, tc := range []struct {
		name, method, path string
		body               any
		status             int
		typ                string
	}{
		{"create bad JSON", "POST", base, bad, 400, "invalidSyntax"},
		{"create name not string", "POST", base, map[string]any{"displayName": []any{}}, 400, "invalidValue"},
		{"create externalId not string", "POST", base, map[string]any{"displayName": "x", "externalId": []any{}}, 400, "invalidValue"},
		{"create tags not a list", "POST", base, map[string]any{"displayName": "x", groupURN: map[string]any{"tags": "nope"}}, 400, "invalidValue"},
		{"members not objects", "POST", base, map[string]any{"displayName": "x", "members": []any{"u"}}, 400, "invalidValue"},
		{"member value not string", "POST", base, map[string]any{"displayName": "x", "members": []any{map[string]any{"value": true}}}, 400, "invalidValue"},
		{"DELETE the collection", "DELETE", base, nil, 405, ""},
		{"POST to a group", "POST", item, map[string]any{}, 405, ""},
		{"PUT unknown", "PUT", base + "/nope", map[string]any{"displayName": "x"}, 404, ""},
		{"PUT bad JSON", "PUT", item, bad, 400, "invalidSyntax"},
		{"PUT without a name", "PUT", item, map[string]any{"members": []any{}}, 400, "invalidValue"},
		{"PATCH unknown", "PATCH", base + "/nope", patchBody(op("replace", "displayName", "x")), 404, ""},
		{"PATCH bad JSON", "PATCH", item, bad, 400, "invalidSyntax"},
		{"PATCH without operations", "PATCH", item, map[string]any{"Operations": []any{}}, 400, "invalidSyntax"},
		{"PATCH bad path", "PATCH", item, patchBody(op("replace", "a[", "x")), 400, "invalidPath"},
		{"DELETE unknown", "DELETE", base + "/nope", nil, 404, ""},
		// another organization's group addressed through this organization's URL
		{"GET foreign group", "GET", base + "/" + other.str("id"), nil, 404, ""},
		{"DELETE foreign group", "DELETE", base + "/" + other.str("id"), nil, 404, ""},
	} {
		r := e.do(tc.method, tc.path, e.admA, tc.body)
		if r.Status != tc.status || r.str("scimType") != tc.typ {
			t.Errorf("%s: %d %s", tc.name, r.Status, r.Raw)
		}
	}
	if g := e.do("GET", item, e.admA, nil); g.Status != 200 || g.str("displayName") != "Refusals" || len(g.list("members")) != 1 {
		t.Errorf("refused requests changed the group: %s", g.Raw)
	}
}

// A PATCH is applied whole or not at all: a refused member undoes the rename in the same request.
func TestGroupPatchIsAtomic(t *testing.T) {
	e := newEnv(t)
	uid := e.mk("atomic-u", nil)
	id := e.group("Original")
	path := "/scim/v2/acme/Groups/" + id
	r := e.do("PATCH", path, e.admA, patchBody(op("replace", "displayName", "Changed"), op("add", "members", []any{map[string]any{"value": uid}, map[string]any{"value": "ghost"}})))
	if r.Status != 400 {
		t.Fatalf("expected failed patch: %d %s", r.Status, r.Raw)
	}
	got := e.do("GET", path, e.admA, nil)
	if got.str("displayName") != "Original" || len(got.list("members")) != 0 {
		t.Fatalf("failed PATCH persisted partial changes: %s", got.Raw)
	}
}

// A membership change is a change of the group: its ETag changes, so a conditional GET with the old one is answered
// in full.
func TestGroupMembershipChangeChangesETag(t *testing.T) {
	e := newEnv(t)
	uid := e.mk("etag-v", nil)
	id := e.group("ETag")
	path := "/scim/v2/acme/Groups/" + id
	tag := e.do("GET", path, e.admA, nil).Header.Get("ETag")
	r := e.do("PATCH", path, e.admA, patchBody(op("add", "members", []any{map[string]any{"value": uid}})))
	if r.Status != 200 {
		t.Fatalf("patch: %d %s", r.Status, r.Raw)
	}
	if r.Header.Get("ETag") == tag {
		t.Errorf("membership change kept the ETag %s", tag)
	}
	after := e.do("GET", path, e.admA, nil, "If-None-Match", tag)
	if after.Status != 200 {
		t.Fatalf("changed resource with old ETag returns %d; original tag %s patch tag %s", after.Status, tag, r.Header.Get("ETag"))
	}
}

// failRecord fails every compare-and-swap of records whose id ends in suffix.
type failRecord struct {
	store.Store
	suffix string
}

func (s failRecord) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if strings.HasSuffix(r.ID, s.suffix) {
		return errors.New("membership storage failure")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A group created with members is one commit: a POST whose membership write fails still created the group with
// every member (seen whole through the record), and one whose member is refused creates nothing, with nothing to
// delete afterwards.
func TestGroupCreateWithMembersIsOneCommit(t *testing.T) {
	e := newEnv(t)
	u1, u2 := e.mk("c1", nil), e.mk("c2", nil)
	inner := e.Svc.Members.S
	e.Svc.Members.S = failRecord{Store: inner, suffix: u2}
	r := e.do("POST", "/scim/v2/acme/Groups", e.admA, map[string]any{"displayName": "Committed",
		"members": []any{map[string]any{"value": u1}, map[string]any{"value": u2}}})
	if r.Status != 201 || len(r.list("members")) != 2 {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	if g := e.do("GET", "/scim/v2/acme/Groups/"+id, e.admA, nil); len(g.list("members")) != 2 {
		t.Fatalf("members seen: %s", g.Raw)
	}
	if ug := e.do("GET", "/scim/v2/acme/Users/"+u2, e.admA, nil); len(ug.list("groups")) != 1 {
		t.Fatalf("user's groups: %s", ug.Raw)
	}
	e.Svc.Members.S = inner
	if n, err := e.Svc.FinishGroupChanges(e.ctx, 0); err != nil || n != 1 {
		t.Fatalf("housekeeping: %d %v", n, err)
	}
	if m, err := e.Svc.Members.Get(e.ctx, model.MemberID(id, u2)); err != nil || !m.Active() {
		t.Fatalf("membership not materialized: %v", err)
	}
	// Refused: no group, no memberships, nothing written.
	r = e.do("POST", "/scim/v2/acme/Groups", e.admA, map[string]any{"displayName": "Refused",
		"members": []any{map[string]any{"value": u1}, map[string]any{"value": "ghost"}}})
	if r.Status != 400 {
		t.Fatalf("refused create: %d %s", r.Status, r.Raw)
	}
	if l := e.do("GET", "/scim/v2/acme/Groups?filter="+qs(`displayName eq "Refused"`), e.admA, nil); l.total() != 0 {
		t.Fatalf("group left behind: %s", l.Raw)
	}
	if ug := e.do("GET", "/scim/v2/acme/Users/"+u1, e.admA, nil); len(ug.list("groups")) != 1 {
		t.Fatalf("user's groups after the refused create: %s", ug.Raw)
	}
}

// A PATCH or PUT changing more than service.MaxMembersPerChange memberships is refused with 413 (RFC 7644 §3.12).
func TestGroupChangeTooLarge(t *testing.T) {
	e := newEnv(t)
	id := e.group("Big")
	members := make([]any, service.MaxMembersPerChange+1)
	for i := range members {
		members[i] = map[string]any{"value": fmt.Sprintf("user-%d", i)}
	}
	r := e.do("PATCH", "/scim/v2/acme/Groups/"+id, e.admA, patchBody(op("add", "members", members)))
	if r.Status != 413 {
		t.Fatalf("too large PATCH: %d %s", r.Status, r.Raw)
	}
	r = e.do("PUT", "/scim/v2/acme/Groups/"+id, e.admA, map[string]any{"displayName": "Big", "members": members})
	if r.Status != 413 {
		t.Fatalf("too large PUT: %d %s", r.Status, r.Raw)
	}
	if g := e.do("GET", "/scim/v2/acme/Groups/"+id, e.admA, nil); len(g.list("members")) != 0 {
		t.Fatalf("members after refused changes: %s", g.Raw)
	}
}

// groupWriteGate pauses the first write of a group's record: the commit of the request's change, before which
// nothing is written.
type groupWriteGate struct {
	store.Store
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (s *groupWriteGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindGroup && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.resume
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A conditional PATCH that loses a race with another node's change (412) must not undo that change's membership.
func TestFailedConditionalGroupPatchKeepsConcurrentChange(t *testing.T) {
	e := newEnv(t)
	uid := e.mk("racing-member", nil)
	id := e.group("Original")
	path := "/scim/v2/acme/Groups/" + id
	tag := e.do("GET", path, e.admA, nil).Header.Get("ETag")
	gate := &groupWriteGate{Store: e.Svc.Groups.S, entered: make(chan struct{}), resume: make(chan struct{})}
	e.Svc.Groups.S = gate
	gate.armed.Store(true)
	done := make(chan resp, 1)
	go func() {
		done <- e.do("PATCH", path, e.admA, patchBody(op("add", "members", []any{map[string]any{"value": uid}})), "If-Match", tag)
	}()
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the PATCH never wrote the group")
	}
	g, err := e.Svc.Groups.Get(e.ctx, id)
	if err != nil {
		close(gate.resume)
		<-done
		t.Fatal(err)
	}
	// Another node has its own SCIM lock; call the same service operation directly to model its concurrent PATCH.
	name := "Concurrent success"
	_, err = e.Svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{DisplayName: &name}, []string{uid}, nil)
	close(gate.resume)
	first := <-done
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != 412 {
		t.Fatalf("first conditional request: %d %s", first.Status, first.Raw)
	}
	got := e.do("GET", path, e.admA, nil)
	if len(got.list("members")) != 1 {
		t.Fatalf("concurrent successful change lost member after failed conditional PATCH: %s", got.Raw)
	}
}
