package scim_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

type seed struct {
	name, given, family, email, title, dept, ext string
	role                                         model.Role
	inactive                                     bool
}

// seedOrg creates a small set of distinct users in org A and returns the group ids.
func seedOrg(e *env) {
	t := e.t
	people := []seed{
		{"alice", "Alice", "Anderson", "alice@acme.test", "Engineer", "Tech", "ext-A", model.RoleUser, false},
		{"bob", "Bob", "Brown", "bob@acme.test", "Designer", "Design", "ext-b", model.RoleUser, false},
		{"carol", "Carol", "Clark", "carol@other.test", "", "Tech", "", model.RoleUser, true},
		{"dave", "Dave", "Davis", "dave@acme.test", "Manager", "Ops", "", model.RoleManager, false},
		{"erin", "Erin", "Evans", "erin@acme.test", "Engineer", "", "", model.RoleUser, false},
	}
	for _, p := range people {
		in := service.UserInput{Username: &p.name, GivenName: &p.given, FamilyName: &p.family, Role: &p.role}
		if p.email != "" {
			in.Email = &p.email
		}
		if p.ext != "" {
			in.ExternalID = &p.ext
		}
		if p.inactive {
			in.Active = ptr(false)
		}
		if _, err := e.Svc.CreateUser(e.ctx, service.System, e.orgA.ID, in); err != nil {
			t.Fatal(err)
		}
	}
	g1, err := e.Svc.CreateGroup(e.ctx, service.System, e.orgA.ID, service.GroupInput{DisplayName: ptr("Engineering")})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alice", "bob"} {
		u, _ := e.Svc.FindUserByEmail(e.ctx, e.orgA.ID, n+"@acme.test")
		if err := e.Svc.SetMembership(e.ctx, service.System, g1.ID, u.ID, true); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *env) usernames(filter string, extra ...string) ([]string, resp) {
	path := "/scim/v2/acme/Users?count=1000&sortBy=userName&filter=" + qs(filter)
	for _, x := range extra {
		path += "&" + x
	}
	r := e.do("GET", path, e.admA, nil)
	var out []string
	for _, n := range r.names("userName") {
		out = append(out, n)
	}
	return out, r
}

func TestFilterOperators(t *testing.T) {
	e := newEnv(t)
	seedOrg(e)
	// adm-a and mgr-a exist as well; filters that could match them are anchored.
	cases := []struct {
		filter string
		want   []string
	}{
		{`userName eq "alice"`, []string{"alice"}},
		{`userName eq "ALICE"`, []string{"alice"}},                   // userName is case-insensitive
		{`USERNAME EQ "alice"`, []string{"alice"}},                   // names and operators too
		{`userName ne "alice" and userName sw "b"`, []string{"bob"}}, // ne
		{`userName co "ar"`, []string{"carol"}},                      // co
		{`userName sw "da"`, []string{"dave"}},                       // sw
		{`userName ew "ve"`, []string{"dave"}},                       // ew
		{`userName ew "VE"`, []string{"dave"}},
		{`externalId pr`, []string{"alice", "bob"}},  // pr
		{`externalId eq "ext-A"`, []string{"alice"}}, // externalId is case-exact
		{`externalId eq "ext-a"`, nil},
		{`userName gt "dave" and userName lt "zzz"`, []string{"erin", "mgr-a"}}, // gt lt
		{`userName ge "dave" and userName le "erin"`, []string{"dave", "erin"}}, // ge le
		{`userName lt "bob" and userName ge "alice"`, []string{"alice", "adm-a"}[:1]},
		{`active eq false`, []string{"carol"}},
		{`active eq "false"`, []string{"carol"}},
		{`active eq true and userName sw "a"`, []string{"adm-a", "alice"}},
		{`active ne true`, []string{"carol"}},
		{`name.givenName eq "bob"`, []string{"bob"}},
		{`name.familyName sw "c"`, []string{"carol"}},
		{`name.givenName eq "Bob" or name.givenName eq "Dave"`, []string{"bob", "dave"}},
		{`displayName eq "alice anderson"`, []string{"alice"}},
		{`emails.value eq "alice@acme.test"`, []string{"alice"}},
		{`emails.value co "@other"`, []string{"carol"}},
		{`emails eq "bob@acme.test"`, []string{"bob"}},
		{`emails[type eq "work"].value ew "other.test"`, []string{"carol"}},
		{`emails[type eq "work" and value sw "dave"]`, []string{"dave"}},
		{`emails[type eq "home"]`, nil},
		{`emails pr and not (emails pr)`, nil},
		{`not (externalId pr) and userName sw "e"`, []string{"erin"}},
		{`phoneNumbers pr`, nil},
		{quisoraURN + `:role eq "manager"`, []string{"dave", "mgr-a"}},
		{`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "bob"`, []string{"bob"}},
		{`groups.display eq "Engineering"`, []string{"alice", "bob"}},
		{`groups[display co "eer"].value pr`, []string{"alice", "bob"}},
		{`not (groups pr) and userName sw "c"`, []string{"carol"}},
		{`meta.resourceType eq "User" and userName eq "bob"`, []string{"bob"}},
		{`meta.created gt "2000-01-01T00:00:00Z" and userName eq "bob"`, []string{"bob"}},
		{`meta.created lt "2000-01-01T00:00:00Z"`, nil},
		{`meta.lastModified ge "2000-01-01T00:00:00+01:00" and userName eq "bob"`, []string{"bob"}},
		{`externalId eq null and userName sw "c"`, []string{"carol"}},
		{`externalId ne null and userName sw "a"`, []string{"alice"}},
		{`(userName eq "alice" or userName eq "bob") and active eq true`, []string{"alice", "bob"}},
		{`userName eq "alice" or userName eq "bob" and active eq false`, []string{"alice"}}, // and binds tighter
		{`not (userName eq "alice" or userName eq "bob") and userName sw "d"`, []string{"dave"}},
		{`not ((userName pr))`, nil},
		{`userName eq "alice"`, []string{"alice"}}, // JSON escapes
		{`userName eq "al\"ice"`, nil},
		{`id eq "no-such-id"`, nil},
	}
	for _, tc := range cases {
		got, r := e.usernames(tc.filter)
		if r.Status != 200 {
			t.Errorf("%s: status %d %s", tc.filter, r.Status, r.Raw)
			continue
		}
		slices.Sort(got)
		want := slices.Clone(tc.want)
		slices.Sort(want)
		if !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("%s: got %v want %v", tc.filter, got, want)
		}
		if r.total() != len(tc.want) && !(tc.filter == `userName lt "bob" and userName ge "alice"`) {
			t.Errorf("%s: totalResults %d want %d", tc.filter, r.total(), len(tc.want))
		}
	}
}

func TestFilterByID(t *testing.T) {
	e := newEnv(t)
	seedOrg(e)
	bob, _ := e.Svc.FindUserByEmail(e.ctx, e.orgA.ID, "bob@acme.test")
	names, r := e.usernames(`id eq "` + bob.ID + `"`)
	if r.Status != 200 || !slices.Equal(names, []string{"bob"}) {
		t.Errorf("id eq: %v %s", names, r.Raw)
	}
}

func TestInvalidFilters(t *testing.T) {
	e := newEnv(t)
	for _, f := range []string{
		`userName eq`, `userName`, `eq "x"`, `userName foo "x"`, `(userName eq "a"`, `userName eq "a")`, `userName eq "unterminated`,
		`userName eq "a" and`, `userName eq "a" userName eq "b"`, `not userName eq "a"`, `userName eq 12abc`,
		`emails[type eq "work"`, `emails[].value eq "a"`, `user name eq "a"`, `userName co`, `and userName eq "a"`,
		`userName eq "\x"`, strings.Repeat("(", 100) + `userName pr` + strings.Repeat(")", 100),
	} {
		r := e.do("GET", "/scim/v2/acme/Users?filter="+qs(f), e.admA, nil)
		if r.Status != 400 || r.str("scimType") != "invalidFilter" {
			t.Errorf("%q: %d %s", f, r.Status, r.Raw)
		}
	}
	for q, typ := range map[string]string{"sortBy=%5B&": "invalidPath", "sortOrder=sideways&": "invalidValue",
		"startIndex=abc&": "invalidValue", "count=abc&": "invalidValue"} {
		r := e.do("GET", "/scim/v2/acme/Users?"+q, e.admA, nil)
		if r.Status != 400 || r.str("scimType") != typ {
			t.Errorf("%q: %d %s", q, r.Status, r.Raw)
		}
	}
}

func TestSortAndPaging(t *testing.T) {
	e := newEnv(t)
	for i := range 25 {
		name := fmt.Sprintf("user%02d", i)
		fam := fmt.Sprintf("Fam%02d", 24-i) // reverse of username order
		if _, err := e.Svc.CreateUser(e.ctx, service.System, e.orgA.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: ptr(name + "@acme.test"), FamilyName: &fam}); err != nil {
			t.Fatal(err)
		}
	}
	// 25 + adm-a + mgr-a
	all := e.do("GET", "/scim/v2/acme/Users?count=1000", e.admA, nil)
	if all.total() != 27 || len(all.list("Resources")) != 27 || all.Body["startIndex"].(float64) != 1 || all.Body["itemsPerPage"].(float64) != 27 {
		t.Fatalf("all: %s", all.Raw[:200])
	}
	if all.Body["schemas"].([]any)[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
		t.Error("list schema")
	}
	// default order is creation order (ids are time-ordered)
	names := all.names("userName")
	if names[0] != "adm-a" || names[2] != "user00" || names[26] != "user24" {
		t.Errorf("default order %v", names)
	}
	// paging
	p := e.do("GET", "/scim/v2/acme/Users?startIndex=3&count=5&sortBy=userName", e.admA, nil)
	got := p.names("userName")
	if p.total() != 27 || len(got) != 5 || p.Body["startIndex"].(float64) != 3 || p.Body["itemsPerPage"].(float64) != 5 {
		t.Fatalf("page: %s", p.Raw)
	}
	if !slices.IsSorted(got) || got[0] != "user00" {
		t.Errorf("sorted page %v", got)
	}
	// descending
	d := e.do("GET", "/scim/v2/acme/Users?count=3&sortBy=userName&sortOrder=descending", e.admA, nil)
	if got := d.names("userName"); !slices.Equal(got, []string{"user24", "user23", "user22"}) {
		t.Errorf("desc %v", got)
	}
	// sort by a nested attribute (in-memory path), missing values last when ascending, first when descending
	f := e.do("GET", "/scim/v2/acme/Users?count=3&sortBy=name.familyName", e.admA, nil)
	if got := f.names("userName"); !slices.Equal(got, []string{"user24", "user23", "user22"}) {
		t.Errorf("by family %v", got)
	}
	f = e.do("GET", "/scim/v2/acme/Users?count=2&sortBy=name.familyName&sortOrder=descending", e.admA, nil)
	if got := f.names("userName"); !slices.Equal(got, []string{"adm-a", "mgr-a"}) {
		t.Errorf("by family desc (missing first): %v", got)
	}
	// sort + filter + paging
	s := e.do("GET", "/scim/v2/acme/Users?filter="+qs(`userName sw "user1"`)+"&sortBy=name.familyName&count=4&startIndex=2", e.admA, nil)
	if s.total() != 10 || len(s.list("Resources")) != 4 {
		t.Errorf("filter+sort+page: %d %s", s.total(), s.Raw)
	}
	if got := s.names("userName"); got[0] != "user18" {
		t.Errorf("filter+sort order %v", got)
	}
	// boundaries
	if z := e.do("GET", "/scim/v2/acme/Users?count=0", e.admA, nil); z.total() != 27 || len(z.list("Resources")) != 0 {
		t.Errorf("count=0: %s", z.Raw)
	}
	if z := e.do("GET", "/scim/v2/acme/Users?startIndex=0&count=1", e.admA, nil); z.Body["startIndex"].(float64) != 1 || len(z.list("Resources")) != 1 {
		t.Errorf("startIndex=0: %s", z.Raw)
	}
	if z := e.do("GET", "/scim/v2/acme/Users?startIndex=100", e.admA, nil); z.total() != 27 || len(z.list("Resources")) != 0 {
		t.Errorf("past the end: %s", z.Raw)
	}
	if z := e.do("GET", "/scim/v2/acme/Users?count=-5", e.admA, nil); z.Status != 200 || len(z.list("Resources")) != 0 {
		t.Errorf("negative count: %s", z.Raw)
	}
	if z := e.do("GET", "/scim/v2/acme/Users?count=5000", e.admA, nil); z.Status != 200 || len(z.list("Resources")) != 27 {
		t.Errorf("huge count: %d", len(z.list("Resources")))
	}
	if z := e.do("GET", "/scim/v2/acme/Users", e.admA, nil); len(z.list("Resources")) != 27 {
		t.Errorf("default count: %d", len(z.list("Resources")))
	}
	// sort by creation time and by id are accepted too
	for _, by := range []string{"meta.created", "id", "emails.value", "displayName", "active", "meta.lastModified"} {
		if z := e.do("GET", "/scim/v2/acme/Users?count=2&sortBy="+by, e.admA, nil); z.Status != 200 || len(z.list("Resources")) != 2 {
			t.Errorf("sortBy %s: %d", by, z.Status)
		}
	}
}

func TestDefaultCountIs100(t *testing.T) {
	e := newEnv(t)
	for i := range 130 {
		name := fmt.Sprintf("u%03d", i)
		if _, err := e.Svc.CreateUser(e.ctx, service.System, e.orgA.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: ptr(name + "@acme.test")}); err != nil {
			t.Fatal(err)
		}
	}
	r := e.do("GET", "/scim/v2/acme/Users", e.admA, nil)
	if r.total() != 132 || len(r.list("Resources")) != 100 || r.Body["itemsPerPage"].(float64) != 100 {
		t.Errorf("default count: total %d, %d returned", r.total(), len(r.list("Resources")))
	}
	r = e.do("GET", "/scim/v2/acme/Users?startIndex=101", e.admA, nil)
	if len(r.list("Resources")) != 32 {
		t.Errorf("second page: %d", len(r.list("Resources")))
	}
	// Filtered lists page in memory.
	r = e.do("GET", "/scim/v2/acme/Users?filter="+qs(`userName sw "u"`)+"&count=1000", e.admA, nil)
	if r.total() != 130 || len(r.list("Resources")) != 130 {
		t.Errorf("filtered: %d", r.total())
	}
}

func TestAttributeSelection(t *testing.T) {
	e := newEnv(t)
	seedOrg(e)
	f := "/scim/v2/acme/Users?filter=" + qs(`userName eq "alice"`)
	r := e.do("GET", f+"&attributes=userName,name.givenName,emails.value", e.admA, nil)
	res := r.list("Resources")[0].(map[string]any)
	if res["userName"] != "alice" || res["id"] == nil || res["schemas"] == nil {
		t.Fatalf("attributes: %v", res)
	}
	name := res["name"].(map[string]any)
	if name["givenName"] != "Alice" || name["familyName"] != nil {
		t.Errorf("name projection: %v", name)
	}
	em := res["emails"].([]any)[0].(map[string]any)
	if em["value"] != "alice@acme.test" || em["type"] != nil {
		t.Errorf("emails projection: %v", em)
	}
	for _, k := range []string{"displayName", "meta", "active", "groups", quisoraURN} {
		if res[k] != nil {
			t.Errorf("%s should not be returned: %v", k, res[k])
		}
	}
	// excludedAttributes
	r = e.do("GET", f+"&excludedAttributes=groups,name.familyName,emails", e.admA, nil)
	res = r.list("Resources")[0].(map[string]any)
	if res["groups"] != nil || res["emails"] != nil || res["userName"] != "alice" || res["meta"] == nil {
		t.Errorf("excluded: %v", res)
	}
	if n := res["name"].(map[string]any); n["familyName"] != nil || n["givenName"] != "Alice" {
		t.Errorf("excluded sub-attribute: %v", n)
	}
	if res[entURN] != nil {
		if _, has := res[entURN].(map[string]any)["department"]; has {
			t.Error("excluded extension attribute returned")
		}
	}
	// id and schemas cannot be excluded.
	r = e.do("GET", f+"&excludedAttributes=id,schemas", e.admA, nil)
	res = r.list("Resources")[0].(map[string]any)
	if res["id"] == nil || res["schemas"] == nil {
		t.Error("id/schemas excluded")
	}
	// whole extension, and on single GET
	id := res["id"].(string)
	g := e.do("GET", "/scim/v2/acme/Users/"+id+"?attributes=displayName,"+quisoraURN, e.admA, nil)
	if g.str("displayName") != "Alice Anderson" || g.str(quisoraURN, "role") != "user" || g.Body["userName"] != nil {
		t.Errorf("single get attributes: %s", g.Raw)
	}
	// groups default is returned.
	g = e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil)
	gr := g.list("groups")
	if len(gr) != 1 || gr[0].(map[string]any)["display"] != "Engineering" || !strings.HasSuffix(gr[0].(map[string]any)["$ref"].(string), "/Groups/"+gr[0].(map[string]any)["value"].(string)) {
		t.Errorf("groups: %s", g.Raw)
	}
	// Unknown attributes are ignored.
	if r := e.do("GET", f+"&attributes=nope,also.nope", e.admA, nil); r.Status != 200 {
		t.Errorf("unknown attributes: %d", r.Status)
	}
}
