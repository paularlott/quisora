package scim_test

import (
	"testing"
)

// A user's externalId is how a provisioning system finds its people, so only administrators (and the service
// accounts, which act as administrators) set or change it: a manager's token is refused, on create, replace and patch,
// while a replace that sends the value the user already has goes through.
func TestExternalIDIsAdministratorsOnly(t *testing.T) {
	e := newEnv(t)
	r := e.createUser("acme", e.mgrA, map[string]any{"userName": "ext-mgr", "externalId": "fut:1"})
	wantStatus(t, "a manager creating with externalId", r, 400)
	if r.str("scimType") != "invalidValue" {
		t.Errorf("scimType %q", r.str("scimType"))
	}
	if r := e.createUser("acme", e.mgrA, map[string]any{"userName": "ext-mgr"}); r.Status != 201 {
		t.Fatalf("a manager creating without one: %d %s", r.Status, r.Raw)
	}

	id := e.mk("ext-adm", map[string]any{"externalId": "fut:2"})
	if r := e.do("GET", "/scim/v2/acme/Users/"+id, e.admA, nil); r.str("externalId") != "fut:2" {
		t.Fatalf("an administrator's externalId: %s", r.Raw)
	}
	wantStatus(t, "a manager patching it", e.do("PATCH", "/scim/v2/acme/Users/"+id, e.mgrA,
		patchBody(op("replace", "externalId", "fut:3"))), 400)
	wantStatus(t, "a manager removing it", e.do("PATCH", "/scim/v2/acme/Users/"+id, e.mgrA,
		patchBody(op("remove", "externalId", nil))), 400)

	// a manager's replace keeping it as it is, changing something else
	cur := e.do("GET", "/scim/v2/acme/Users/"+id, e.mgrA, nil)
	body := cur.Body
	body["displayName"] = "Ext Admin"
	if r := e.do("PUT", "/scim/v2/acme/Users/"+id, e.mgrA, body); r.Status != 200 || r.str("externalId") != "fut:2" {
		t.Fatalf("a manager's replace keeping it: %d %s", r.Status, r.Raw)
	}
	if r := e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, patchBody(op("replace", "externalId", "fut:4"))); r.Status != 200 ||
		r.str("externalId") != "fut:4" {
		t.Fatalf("an administrator changing it: %d %s", r.Status, r.Raw)
	}
}
