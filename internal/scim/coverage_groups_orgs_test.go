package scim_test

import (
	"strings"
	"testing"
)

func wantStatus(t *testing.T, what string, r resp, status int) {
	t.Helper()
	if r.Status != status {
		t.Errorf("%s: status %d, want %d: %s", what, r.Status, status, r.Raw)
	}
}

func TestCoverageGroupRefusals(t *testing.T) {
	e := newEnv(t)
	u := e.mk("gr1", nil)
	gid := e.group("Refusals", u)
	base := "/scim/v2/acme/Groups"
	jsonBad := `{"displayName":`

	wantStatus(t, "create no body", e.do("POST", base, e.admA, jsonBad), 400)
	wantStatus(t, "create no name", e.do("POST", base, e.admA, map[string]any{"displayName": " "}), 400)
	wantStatus(t, "create name type", e.do("POST", base, e.admA, map[string]any{"displayName": []any{}}), 400)
	wantStatus(t, "create externalId type", e.do("POST", base, e.admA, map[string]any{"displayName": "x", "externalId": []any{}}), 400)
	wantStatus(t, "create tags type", e.do("POST", base, e.admA, map[string]any{"displayName": "x",
		"urn:paularlott:quisora:scim:schemas:2.0:Group": map[string]any{"tags": "nope"}}), 400)
	wantStatus(t, "members not list", e.do("POST", base, e.admA, map[string]any{"displayName": "x", "members": "u"}), 400)
	wantStatus(t, "members not objects", e.do("POST", base, e.admA, map[string]any{"displayName": "x", "members": []any{"u"}}), 400)
	wantStatus(t, "member no value", e.do("POST", base, e.admA, map[string]any{"displayName": "x", "members": []any{map[string]any{}}}), 400)
	wantStatus(t, "member value type", e.do("POST", base, e.admA, map[string]any{"displayName": "x", "members": []any{map[string]any{"value": true}}}), 400)
	if r := e.do("POST", base, e.admA, map[string]any{"displayName": "x", "members": []any{map[string]any{"value": "ghost"}}}); r.Status < 400 {
		t.Errorf("unknown member accepted: %d %s", r.Status, r.Raw)
	}
	wantStatus(t, "duplicate name", e.do("POST", base, e.admA, map[string]any{"displayName": "Refusals"}), 409)

	wantStatus(t, "list method", e.do("DELETE", base, e.admA, nil), 405)
	wantStatus(t, "item method", e.do("POST", base+"/"+gid, e.admA, map[string]any{}), 405)
	wantStatus(t, "get unknown", e.do("GET", base+"/nope", e.admA, nil), 404)
	wantStatus(t, "put unknown", e.do("PUT", base+"/nope", e.admA, map[string]any{"displayName": "x"}), 404)
	wantStatus(t, "put bad body", e.do("PUT", base+"/"+gid, e.admA, jsonBad), 400)
	wantStatus(t, "put no name", e.do("PUT", base+"/"+gid, e.admA, map[string]any{"members": []any{}}), 400)
	wantStatus(t, "patch unknown", e.do("PATCH", base+"/nope", e.admA, patchBody(op("replace", "displayName", "x"))), 404)
	wantStatus(t, "patch bad body", e.do("PATCH", base+"/"+gid, e.admA, jsonBad), 400)
	wantStatus(t, "patch no ops", e.do("PATCH", base+"/"+gid, e.admA, map[string]any{"Operations": []any{}}), 400)
	wantStatus(t, "patch bad path", e.do("PATCH", base+"/"+gid, e.admA, patchBody(op("replace", "a[", "x"))), 400)
	wantStatus(t, "delete unknown", e.do("DELETE", base+"/nope", e.admA, nil), 404)

	// Cross-org: an admin of another organization reaches neither the group nor the collection.
	wantStatus(t, "other org get", e.do("GET", base+"/"+gid, e.admB, nil), 404)
	wantStatus(t, "other org list", e.do("GET", base, e.admB, nil), 404)
	// A group of another org addressed through this org's URL is not found.
	other := e.do("POST", "/scim/v2/globex/Groups", e.admB, map[string]any{"displayName": "G"})
	wantStatus(t, "globex create", other, 201)
	wantStatus(t, "foreign group get", e.do("GET", base+"/"+other.str("id"), e.admA, nil), 404)
	wantStatus(t, "foreign group delete", e.do("DELETE", base+"/"+other.str("id"), e.admA, nil), 404)

	// Preconditions.
	wantStatus(t, "put stale", e.do("PUT", base+"/"+gid, e.admA, map[string]any{"displayName": "R2"}, "If-Match", `W/"1"`), 412)
	wantStatus(t, "patch stale", e.do("PATCH", base+"/"+gid, e.admA, patchBody(op("replace", "displayName", "R2")), "If-Match", `W/"1"`), 412)
	wantStatus(t, "delete stale", e.do("DELETE", base+"/"+gid, e.admA, nil, "If-Match", `W/"1"`), 412)
	g := e.do("GET", base+"/"+gid, e.admA, nil)
	etag := g.Header.Get("ETag")
	wantStatus(t, "not modified", e.do("GET", base+"/"+gid, e.admA, nil, "If-None-Match", etag), 304)
	wantStatus(t, "put match", e.do("PUT", base+"/"+gid, e.admA, map[string]any{"displayName": "R3"}, "If-Match", etag), 200)
	wantStatus(t, "delete star", e.do("DELETE", base+"/"+gid, e.admA, nil, "If-Match", "*"), 204)
}

func TestCoverageGroupListing(t *testing.T) {
	e := newEnv(t)
	u := e.mk("gl1", nil)
	e.group("Alpha", u)
	e.group("Beta")
	e.group("Alphabet")
	base := "/scim/v2/acme/Groups?"
	r := e.do("GET", base+"filter="+qs(`displayName sw "Alph"`), e.admA, nil)
	if r.total() != 2 {
		t.Errorf("sw: %s", r.Raw)
	}
	r = e.do("GET", base+"filter="+qs(`displayName eq "Beta"`), e.admA, nil)
	if r.total() != 1 {
		t.Errorf("eq: %s", r.Raw)
	}
	r = e.do("GET", base+"filter="+qs(`displayName eq "Nope"`), e.admA, nil)
	if r.total() != 0 {
		t.Errorf("eq none: %s", r.Raw)
	}
	r = e.do("GET", base+"filter="+qs(`externalId eq "zz"`), e.admA, nil)
	if r.Status != 200 || r.total() != 0 {
		t.Errorf("externalId: %s", r.Raw)
	}
	r = e.do("GET", base+"filter="+qs(`members.value eq "`+u+`"`), e.admA, nil)
	if r.Status != 200 || r.total() != 1 {
		t.Errorf("members filter: %d %s", r.Status, r.Raw)
	}
	r = e.do("GET", base+"sortBy=members&attributes=members", e.admA, nil)
	if r.Status != 200 || r.total() != 3 {
		t.Errorf("members sort: %d %s", r.Status, r.Raw)
	}
	r = e.do("GET", base+"attributes=displayName,members&sortBy=displayName&sortOrder=descending&count=2", e.admA, nil)
	if r.Status != 200 || strings.Join(r.names("displayName"), ",") != "Beta,Alphabet" {
		t.Errorf("members page: %d %s", r.Status, r.Raw)
	}
	r = e.do("GET", base+"excludedAttributes=members", e.admA, nil)
	if r.Status != 200 || strings.Contains(string(r.Raw), `"members"`) {
		t.Errorf("excluded: %s", r.Raw)
	}
	for _, q := range []string{"filter=" + qs("displayName eq"), "sortOrder=sideways", "startIndex=x", "count=x", "sortBy=a["} {
		wantStatus(t, q, e.do("GET", base+q, e.admA, nil), 400)
	}
	// A manager reads groups too; a plain user's token cannot.
	wantStatus(t, "manager list", e.do("GET", "/scim/v2/acme/Groups", e.mgrA, nil), 200)
}

func TestCoverageGroupPatchMembers(t *testing.T) {
	e := newEnv(t)
	u1, u2 := e.mk("pm1", nil), e.mk("pm2", nil)
	gid := e.group("PM", u1)
	url := "/scim/v2/acme/Groups/" + gid
	r := e.do("PATCH", url, e.admA, patchBody(op("add", "members", []any{map[string]any{"value": u2}})))
	if r.Status != 200 || len(memberValues(r)) != 2 {
		t.Fatalf("add: %d %s", r.Status, r.Raw)
	}
	r = e.do("PATCH", url, e.admA, patchBody(op("remove", `members[value eq "`+u1+`"]`, nil)))
	if r.Status != 200 || len(memberValues(r)) != 1 {
		t.Errorf("remove filtered: %d %s", r.Status, r.Raw)
	}
	r = e.do("PATCH", url, e.admA, patchBody(op("replace", "members", []any{})))
	if r.Status != 200 || len(memberValues(r)) != 0 {
		t.Errorf("replace empty: %d %s", r.Status, r.Raw)
	}
	r = e.do("PATCH", url, e.admA, patchBody(op("replace", "externalId", "ext-9"), op("replace", "displayName", "PM2")))
	if r.Status != 200 || r.str("externalId") != "ext-9" || r.str("displayName") != "PM2" {
		t.Errorf("fields: %d %s", r.Status, r.Raw)
	}
	r = e.do("PATCH", url, e.admA, patchBody(op("add", "members", "u")))
	wantStatus(t, "bad member value", r, 400)
	r = e.do("PATCH", url, e.admA, patchBody(op("add", "members", []any{map[string]any{"value": "ghost"}})))
	if r.Status < 400 {
		t.Errorf("ghost member accepted: %d %s", r.Status, r.Raw)
	}
	// PUT without members keeps them; with a list replaces them.
	e.do("PATCH", url, e.admA, patchBody(op("add", "members", []any{map[string]any{"value": u1}})))
	r = e.do("PUT", url, e.admA, map[string]any{"displayName": "PM2"})
	if len(memberValues(r)) != 1 {
		t.Errorf("put keeps members: %s", r.Raw)
	}
	r = e.do("PUT", url, e.admA, map[string]any{"displayName": "PM2", "members": []any{}})
	if len(memberValues(r)) != 0 {
		t.Errorf("put clears members: %s", r.Raw)
	}
}

func TestCoverageOrganizations(t *testing.T) {
	e := newEnv(t)
	base := "/scim/v2/Organizations"
	wantStatus(t, "admin refused", e.do("GET", base, e.admA, nil), 403)
	wantStatus(t, "manager refused", e.do("GET", base, e.mgrA, nil), 403)
	wantStatus(t, "no token", e.do("GET", base, "", nil), 401)
	wantStatus(t, "list method", e.do("PUT", base, e.super, map[string]any{}), 405)
	wantStatus(t, "item method", e.do("POST", base+"/x", e.super, map[string]any{}), 405)
	wantStatus(t, "extra segment", e.do("GET", base+"/a/b", e.super, nil), 404)
	wantStatus(t, "unknown", e.do("GET", base+"/nope", e.super, nil), 404)

	wantStatus(t, "create bad body", e.do("POST", base, e.super, "{"), 400)
	wantStatus(t, "create no name", e.do("POST", base, e.super, map[string]any{"displayName": "X"}), 400)
	wantStatus(t, "create name type", e.do("POST", base, e.super, map[string]any{"name": []any{}}), 400)
	wantStatus(t, "create displayName type", e.do("POST", base, e.super, map[string]any{"name": "o1", "displayName": []any{}}), 400)
	wantStatus(t, "settings type", e.do("POST", base, e.super, map[string]any{"name": "o1", "settings": "x"}), 400)
	wantStatus(t, "settings bool", e.do("POST", base, e.super, map[string]any{"name": "o1", "settings": map[string]any{"passwordLogin": []any{}}}), 400)
	wantStatus(t, "settings int", e.do("POST", base, e.super, map[string]any{"name": "o1", "settings": map[string]any{"sessionTtl": 1.5}}), 400)
	wantStatus(t, "settings int type", e.do("POST", base, e.super, map[string]any{"name": "o1", "settings": map[string]any{"sessionIdle": "x"}}), 400)

	r := e.do("POST", base, e.super, map[string]any{"name": "initech", "displayName": "Initech", "settings": map[string]any{
		"passwordLogin": true, "passwordReset": true, "passkeyLogin": false, "requireMfa": "false", "sessionTtl": 3600, "sessionIdle": 600}})
	if r.Status != 201 {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	wantStatus(t, "duplicate", e.do("POST", base, e.super, map[string]any{"name": "initech"}), 409)

	r = e.do("GET", base+"?filter="+qs(`name eq "initech"`), e.super, nil)
	if r.total() != 1 {
		t.Errorf("filter: %s", r.Raw)
	}
	r = e.do("GET", base+"?filter="+qs(`displayName sw "Init"`)+"&sortBy=name", e.super, nil)
	if r.total() != 1 {
		t.Errorf("sw filter: %s", r.Raw)
	}
	wantStatus(t, "list bad filter", e.do("GET", base+"?filter="+qs("name eq"), e.super, nil), 400)
	r = e.do("GET", base+"/"+id+"?attributes=name", e.super, nil)
	if r.Status != 200 || r.str("name") != "initech" || r.str("displayName") != "" {
		t.Errorf("get attrs: %s", r.Raw)
	}

	url := base + "/" + id
	etag := r.Header.Get("ETag")
	wantStatus(t, "put stale", e.do("PUT", url, e.super, map[string]any{"name": "initech"}, "If-Match", `W/"1"`), 412)
	r = e.do("PUT", url, e.super, map[string]any{"name": "initech", "displayName": "Initech 2"}, "If-Match", etag)
	if r.Status != 200 || r.str("displayName") != "Initech 2" {
		t.Errorf("put: %d %s", r.Status, r.Raw)
	}
	r = e.do("PUT", url, e.super, map[string]any{"name": "initech", "displayName": "Initech 2"})
	wantStatus(t, "put unchanged", r, 200)
	wantStatus(t, "put bad body", e.do("PUT", url, e.super, "{"), 400)
	wantStatus(t, "put name type", e.do("PUT", url, e.super, map[string]any{"name": []any{}}), 400)
	wantStatus(t, "put unknown", e.do("PUT", base+"/nope", e.super, map[string]any{"name": "x"}), 404)
	r = e.do("PATCH", url, e.super, patchBody(op("replace", "settings.sessionTtl", 7200), op("replace", "primary", true), op("replace", "id", "z")))
	if r.Status != 200 || r.Body["primary"] != false {
		t.Errorf("patch: %d %s", r.Status, r.Raw)
	}
	wantStatus(t, "patch bad body", e.do("PATCH", url, e.super, "{"), 400)
	wantStatus(t, "patch no ops", e.do("PATCH", url, e.super, map[string]any{}), 400)
	wantStatus(t, "patch bad op", e.do("PATCH", url, e.super, patchBody(op("replace", "settings.sessionTtl", "x"))), 400)
	wantStatus(t, "patch unknown", e.do("PATCH", base+"/nope", e.super, patchBody(op("replace", "name", "y"))), 404)

	// The primary organization's sign-in settings, and any deletion by a super admin, need a console session.
	prim := e.Primary.ID
	wantStatus(t, "primary settings", e.do("PATCH", base+"/"+prim, e.super, patchBody(op("replace", "settings.requireMfa", true))), 403)
	wantStatus(t, "super delete", e.do("DELETE", url, e.super, nil), 403)
	wantStatus(t, "super delete cascade", e.do("DELETE", url+"?cascade=true", e.super, nil), 403)
}
