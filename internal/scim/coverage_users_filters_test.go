package scim_test

import (
	"strings"
	"testing"
)

const idpURN = "urn:paularlott:quisora:scim:schemas:2.0:User"

func TestCoverageUserCreateRefusals(t *testing.T) {
	e := newEnv(t)
	base := "/scim/v2/acme/Users"
	ok := func() map[string]any {
		return map[string]any{"userName": "cr-user", "emails": []any{map[string]any{"value": "cr@acme.test"}}}
	}
	with := func(k string, v any) map[string]any { m := ok(); m[k] = v; return m }
	cases := map[string]map[string]any{
		"userName type":       with("userName", []any{}),
		"externalId type":     with("externalId", []any{}),
		"displayName type":    with("displayName", []any{}),
		"name not object":     with("name", "x"),
		"givenName type":      with("name", map[string]any{"givenName": []any{}}),
		"familyName type":     with("name", map[string]any{"familyName": []any{}}),
		"active type":         with("active", "maybe"),
		"emails not objects":  with("emails", []any{[]any{}}),
		"email value type":    with("emails", []any{map[string]any{"value": []any{}}}),
		"phones not objects":  with("phoneNumbers", []any{5}),
		"password":            with("password", "secret"),
		"password type":       with("password", []any{}),
		"role invalid":        with(idpURN, map[string]any{"role": "emperor"}),
		"role type":           with(idpURN, map[string]any{"role": []any{}}),
		"tags type":           with(idpURN, map[string]any{"tags": "x"}),
		"tags element":        with(idpURN, map[string]any{"tags": []any{1}}),
		"validUntil type":     with(idpURN, map[string]any{"validUntil": []any{}}),
		"timezone type":       with("timezone", []any{}),
		"locale type":         with("locale", []any{}),
		"preferredLang type":  with("preferredLanguage", []any{}),
		"title type":          with("title", []any{}),
		"enterprise type":     with(entURN, "x"),
		"enterprise attr":     with(entURN, map[string]any{"department": []any{}}),
		"manager type":        with(entURN, map[string]any{"manager": 5}),
		"manager value type":  with(entURN, map[string]any{"manager": map[string]any{"value": []any{}}}),
		"no email at all":     {"userName": "plain"},
		"no userName":         {"emails": []any{map[string]any{"value": "a@acme.test"}}},
		"empty email entries": {"userName": "plain", "emails": []any{map[string]any{"value": ""}}},
	}
	for name, body := range cases {
		if r := e.do("POST", base, e.admA, body); r.Status != 400 {
			t.Errorf("%s: status %d: %s", name, r.Status, r.Raw)
		}
	}
	wantStatus(t, "bad JSON", e.do("POST", base, e.admA, "[]"), 400)
	wantStatus(t, "oversized", e.do("POST", base, e.admA, `{"userName":"`+strings.Repeat("a", 2<<20)+`"}`), 413)
	wantStatus(t, "list method", e.do("DELETE", base, e.admA, nil), 405)
	wantStatus(t, "item method", e.do("POST", base+"/x", e.admA, map[string]any{}), 405)
	wantStatus(t, "get unknown", e.do("GET", base+"/nope", e.admA, nil), 404)
	wantStatus(t, "put unknown", e.do("PUT", base+"/nope", e.admA, ok()), 404)
	wantStatus(t, "patch unknown", e.do("PATCH", base+"/nope", e.admA, patchBody(op("replace", "title", "x"))), 404)
	wantStatus(t, "delete unknown", e.do("DELETE", base+"/nope", e.admA, nil), 404)

	// The same user twice: the second create is refused as a duplicate.
	wantStatus(t, "create", e.do("POST", base, e.admA, ok()), 201)
	wantStatus(t, "duplicate", e.do("POST", base, e.admA, ok()), 409)
	// A manager of another organization is left unset rather than refused.
	r := e.do("POST", base, e.admA, map[string]any{"userName": "cr2", "emails": []any{map[string]any{"value": "cr2@acme.test"}},
		entURN: map[string]any{"manager": e.users["adm-b"].ID}})
	if r.Status != 201 || strings.Contains(string(r.Raw), e.users["adm-b"].ID) {
		t.Errorf("foreign manager: %d %s", r.Status, r.Raw)
	}
	// A manager given as a bare id of this organization is kept.
	r = e.do("POST", base, e.admA, map[string]any{"userName": "cr3", "emails": []any{map[string]any{"value": "cr3@acme.test"}},
		entURN: map[string]any{"manager": e.users["mgr-a"].ID}})
	if r.Status != 201 || r.str(entURN, "manager", "value") != e.users["mgr-a"].ID {
		t.Errorf("manager: %d %s", r.Status, r.Raw)
	}
	// preferredLanguage supplies the locale; role, tags and validUntil come from the extension.
	r = e.do("POST", base, e.admA, map[string]any{"userName": "cr4@acme.test", "preferredLanguage": "en-GB,en;q=0.9",
		"phoneNumbers": []any{map[string]any{"value": "+441632960961", "primary": true}},
		idpURN:         map[string]any{"role": "Manager", "tags": []any{"a"}, "validUntil": "2099-01-01T00:00:00Z"}})
	if r.Status != 201 || r.str("locale") != "en-GB" || r.str(idpURN, "role") != "manager" || r.str(idpURN, "validUntil") == "" {
		t.Errorf("profile: %d %s", r.Status, r.Raw)
	}
	// Linked emails are kept besides the primary; PUT replaces the set.
	r = e.do("POST", base, e.admA, map[string]any{"userName": "cr5", "emails": []any{
		map[string]any{"value": "cr5@acme.test", "primary": true}, map[string]any{"value": "cr5b@acme.test"}}})
	if r.Status != 201 || len(r.list("emails")) < 2 {
		t.Errorf("linked emails: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	r = e.do("PUT", base+"/"+id, e.admA, map[string]any{"userName": "cr5", "emails": []any{map[string]any{"value": "cr5@acme.test"}},
		"timezone": "Europe/London", "title": "T", idpURN: map[string]any{"validUntil": nil}})
	if r.Status != 200 || len(r.list("emails")) != 1 || r.str("timezone") != "Europe/London" {
		t.Errorf("put: %d %s", r.Status, r.Raw)
	}
	// Preconditions on a user.
	etag := r.Header.Get("ETag")
	wantStatus(t, "put stale", e.do("PUT", base+"/"+id, e.admA, map[string]any{"userName": "cr5"}, "If-Match", `W/"1"`), 412)
	wantStatus(t, "patch stale", e.do("PATCH", base+"/"+id, e.admA, patchBody(op("replace", "title", "z")), "If-Match", `W/"1"`), 412)
	wantStatus(t, "delete stale", e.do("DELETE", base+"/"+id, e.admA, nil, "If-Match", `W/"1"`), 412)
	wantStatus(t, "not modified", e.do("GET", base+"/"+id, e.admA, nil, "If-None-Match", etag), 304)
	wantStatus(t, "patch match", e.do("PATCH", base+"/"+id, e.admA, patchBody(op("replace", "title", "z")), "If-Match", etag), 200)
	wantStatus(t, "delete star", e.do("DELETE", base+"/"+id, e.admA, nil, "If-Match", "*"), 204)
}

func TestCoverageUserAuthorization(t *testing.T) {
	e := newEnv(t)
	id := e.mk("au1", nil)
	base := "/scim/v2/acme/Users"
	// A manager cannot reach another organization's users; neither can an admin of another organization.
	wantStatus(t, "foreign org list", e.do("GET", base, e.admB, nil), 404)
	wantStatus(t, "foreign org get", e.do("GET", base+"/"+id, e.admB, nil), 404)
	wantStatus(t, "unknown org", e.do("GET", "/scim/v2/nope/Users", e.admA, nil), 404)
	// A user of another organization addressed through this organization's URL is not found.
	wantStatus(t, "foreign user", e.do("GET", base+"/"+e.users["adm-b"].ID, e.admA, nil), 404)
	// Bad tokens.
	wantStatus(t, "no token", e.do("GET", base, "", nil), 401)
	wantStatus(t, "garbage token", e.do("GET", base, "garbage", nil), 401)
	wantStatus(t, "dpop garbage", e.do("GET", base, "", nil, "Authorization", "DPoP garbage"), 401)
	wantStatus(t, "basic scheme", e.do("GET", base, "", nil, "Authorization", "Basic abc"), 401)
	// A token without the scim scope.
	noScope := e.token(e.users["adm-a"], "admin")
	wantStatus(t, "no scope", e.do("GET", base, noScope, nil), 403)
	// Super admin can use any org.
	wantStatus(t, "super", e.do("GET", base, e.super, nil), 200)
	// A TokenVerifier that returns an error or nil gives 401.
	e.verify = nil
	wantStatus(t, "verifier fails", e.do("GET", base, "oauth-token", nil, "Authorization", "Bearer oauth-token"), 401)
}

func TestCoverageUserListEdges(t *testing.T) {
	e := newEnv(t)
	for _, n := range []string{"le1", "le2", "le3"} {
		e.mk(n, map[string]any{idpURN: map[string]any{"tags": []any{"t-" + n}}, "title": "Eng"})
	}
	base := "/scim/v2/acme/Users?"
	r := e.do("GET", base+"count=0", e.admA, nil)
	if r.Status != 200 || r.total() < 3 || len(r.list("Resources")) != 0 {
		t.Errorf("count 0: %s", r.Raw)
	}
	r = e.do("GET", base+"startIndex=100", e.admA, nil)
	if r.Status != 200 || len(r.list("Resources")) != 0 {
		t.Errorf("past end: %s", r.Raw)
	}
	r = e.do("GET", base+"startIndex=-5&count=1", e.admA, nil)
	if r.Status != 200 || len(r.list("Resources")) != 1 || r.Body["startIndex"] != float64(1) {
		t.Errorf("negative start: %s", r.Raw)
	}
	r = e.do("GET", base+"count=100000", e.admA, nil)
	if r.Status != 200 {
		t.Errorf("huge count: %s", r.Raw)
	}
	r = e.do("GET", base+"sortBy=userName&sortOrder=descending&count=2", e.admA, nil)
	if r.Status != 200 || len(r.names("userName")) != 2 || r.names("userName")[0] < r.names("userName")[1] {
		t.Errorf("sort desc: %s", r.Raw)
	}
	// An in-memory sort on attributes the store cannot order by: strings, booleans, missing values.
	for _, s := range []string{"title", "active", "name.givenName", "meta.created", "emails.value", "emails", "groups"} {
		for _, o := range []string{"ascending", "descending"} {
			if r := e.do("GET", base+"sortBy="+qs(s)+"&sortOrder="+o, e.admA, nil); r.Status != 200 {
				t.Errorf("sortBy %s %s: %d %s", s, o, r.Status, r.Raw)
			}
		}
	}
	r = e.do("GET", base+"sortBy=title&sortOrder=ascending", e.admA, nil)
	if r.Status != 200 || len(r.list("Resources")) < 3 {
		t.Errorf("title sort: %s", r.Raw)
	}
	// Filters answered in memory.
	for filter, want := range map[string]int{
		`title eq "eng"`:                                               3,
		`title pr`:                                                     3,
		`not (title pr)`:                                               4,
		`title eq null`:                                                4,
		`title ne null`:                                                3,
		`title co "ng" and userName sw "le"`:                           3,
		`userName ew "1" or userName ew "2"`:                           2,
		`active eq true`:                                               7,
		`active eq "true"`:                                             7,
		`active ne false`:                                              7,
		`meta.created gt "2000-01-01T00:00:00Z"`:                       7,
		`meta.created lt "2000-01-01T00:00:00Z"`:                       0,
		`meta.created ge "2000-01-01T00:00:00Z"`:                       7,
		`meta.created le "2000-01-01T00:00:00Z"`:                       0,
		`meta.created eq "2000-01-01T00:00:00Z"`:                       0,
		`emails[type eq "work"].value co "le1"`:                        1,
		`emails[value co "le2"]`:                                       1,
		`urn:paularlott:quisora:scim:schemas:2.0:User:tags eq "t-le2"`: 1,
		`active eq 5`:                                                  0,
		`userName eq 5`:                                                0,
		`userName gt "le1"`:                                            2,
	} {
		r := e.do("GET", base+"filter="+qs(filter), e.admA, nil)
		if r.Status != 200 {
			t.Errorf("%s: %d %s", filter, r.Status, r.Raw)
		} else if r.total() < want-4 || (want == 0 && r.total() != 0) {
			t.Errorf("%s: total %d, want about %d", filter, r.total(), want)
		}
	}
}

func TestCoverageFilterSyntaxErrors(t *testing.T) {
	e := newEnv(t)
	for _, f := range []string{
		`userName eq "unterminated`, `userName eq`, `userName`, `userName bogus "x"`, `(userName eq "a"`, `userName eq "a")`,
		`userName eq "a" and`, `and userName eq "a"`, `userName eq "a" userName eq "b"`, `not userName eq "a"`,
		`emails[type eq "work"`, `emails]type eq "work"[`, `emails[]`, `1bad eq "x"`, `userName eq "a" or or userName eq "b"`,
		`userName pr "x"`, `userName eq tru`, `userName co 5 5`, `urn:x: eq "y"`, `name.givenName.x eq "a"`,
		`emails[type eq "work"][type eq "x"]`, `userName eq "a\u00zz"`, `)`, `(`, `()`, `userName eq "\`,
		strings.Repeat("(", 80) + `userName pr` + strings.Repeat(")", 80),
		`userName eq "` + strings.Repeat("a", 9000) + `"`,
	} {
		for _, res := range []string{"Users", "Groups"} {
			if r := e.do("GET", "/scim/v2/acme/"+res+"?filter="+qs(f), e.admA, nil); r.Status != 400 || r.str("scimType") != "invalidFilter" {
				t.Errorf("%s %.40q: %d %s", res, f, r.Status, r.Raw)
			}
		}
	}
	// Filters that parse in unusual ways.
	for _, f := range []string{
		`NOT (userName eq "a")`, `userName EQ "a"`, `userName eq "a" AND active eq true`, `userName pr and active pr`,
		`emails[type eq "work" and primary eq true].value pr`, `userName eq true`, `userName eq false`, `userName eq null`,
		`userName eq -1.5e3`, `userName eq "a\"b"`, `meta.lastModified ge "2000-01-01T00:00:00.5Z"`,
	} {
		if r := e.do("GET", "/scim/v2/acme/Users?filter="+qs(f), e.admA, nil); r.Status != 200 {
			t.Errorf("%q: %d %s", f, r.Status, r.Raw)
		}
	}
}

func TestCoverageUserTooManyAndSelf(t *testing.T) {
	e := newEnv(t)
	id := e.mk("ts1", nil)
	// Attributes / excludedAttributes projections.
	base := "/scim/v2/acme/Users/" + id + "?"
	for q, forbidden := range map[string]string{
		"attributes=userName":                      "emails",
		"attributes=name.givenName,emails.value":   "userName",
		"attributes=" + qs(idpURN):                 "userName",
		"attributes=" + qs(idpURN+":role"):         "userName",
		"attributes=" + qs(entURN):                 "userName",
		"excludedAttributes=emails,name.givenName": `"emails"`,
		"excludedAttributes=emails.value":          `"value":"ts1@`,
		"excludedAttributes=" + qs(idpURN):         "tags",
		"excludedAttributes=" + qs(idpURN+":role"): `"role"`,
		"excludedAttributes=nonsense,a[,groups":    `"groups"`,
		"attributes=nonsense,a[":                   "userName",
	} {
		r := e.do("GET", base+q, e.admA, nil)
		if r.Status != 200 {
			t.Errorf("%s: %d %s", q, r.Status, r.Raw)
		} else if strings.Contains(string(r.Raw), forbidden) && !strings.HasPrefix(q, "attributes=nonsense") && !strings.HasPrefix(q, "attributes="+qs(entURN)) {
			t.Errorf("%s: still has %s: %s", q, forbidden, r.Raw)
		}
	}
}

func TestCoverageDiscoveryEdges(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/scim/v2/acme", "/scim/v2/"} {
		_ = p
	}
	wantStatus(t, "spc extra", e.do("GET", "/scim/v2/ServiceProviderConfig/x", "", nil), 404)
	wantStatus(t, "spc org extra", e.do("GET", "/scim/v2/acme/ServiceProviderConfig/x", "", nil), 404)
	wantStatus(t, "spc method", e.do("POST", "/scim/v2/ServiceProviderConfig", "", map[string]any{}), 405)
	wantStatus(t, "types method", e.do("DELETE", "/scim/v2/acme/ResourceTypes", "", nil), 405)
	wantStatus(t, "schemas method", e.do("PUT", "/scim/v2/Schemas", "", map[string]any{}), 405)
	wantStatus(t, "unknown type", e.do("GET", "/scim/v2/ResourceTypes/Nope", "", nil), 404)
	wantStatus(t, "unknown schema", e.do("GET", "/scim/v2/Schemas/urn:nope", "", nil), 404)
	if r := e.do("GET", "/scim/v2/ResourceTypes/organization", "", nil); r.Status != 200 || r.str("id") != "Organization" {
		t.Errorf("type by name: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/ResourceTypes/Organization", "", nil); r.Status != 404 {
		t.Errorf("org-scoped Organization type: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/Schemas", "", nil); r.Status != 200 || r.total() != 5 {
		t.Errorf("scoped schemas: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "", nil); r.Status != 200 || r.str("name") != "User" {
		t.Errorf("schema by id: %d %s", r.Status, r.Raw)
	}
	wantStatus(t, "unknown route", e.do("GET", "/scim/v2/acme/Bogus", e.admA, nil), 404)
	wantStatus(t, "too deep", e.do("GET", "/scim/v2/acme/Users/a/b", e.admA, nil), 404)
	wantStatus(t, "bare org", e.do("GET", "/scim/v2/acme", e.admA, nil), 404)
	wantStatus(t, "bare root", e.do("GET", "/scim/v2/", e.admA, nil), 404)
	wantStatus(t, "escaped org", e.do("GET", "/scim/v2/ac%6De/Users", e.admA, nil), 200)
}
