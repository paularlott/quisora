package admin_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

func TestOrgs(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")

	r := su.get("/api/orgs")
	want(t, r, 200)
	if r.total() != 3 || len(r.items()) != 3 { // primary, acme, globex
		t.Fatalf("list: %s", r.Raw)
	}
	if r.Header.Get("Api-Version") != web.APIVersionLatest {
		t.Error("Api-Version not echoed")
	}
	first := r.items()[0].(map[string]any)
	if first["users"] == nil || first["settings"] == nil || first["id"] == "" {
		t.Errorf("org shape: %v", first)
	}

	// search, sort, pagination
	r = su.get("/api/orgs?q=glob")
	if r.total() != 1 || r.items()[0].(map[string]any)["name"] != "globex" {
		t.Fatalf("search: %s", r.Raw)
	}
	r = su.get("/api/orgs?sort=name&desc=1")
	if r.items()[0].(map[string]any)["name"] != "primary" {
		t.Fatalf("sort desc: %s", r.Raw)
	}
	r = su.get("/api/orgs?sort=name&limit=2&offset=2")
	if r.total() != 3 || len(r.items()) != 1 {
		t.Fatalf("page: %s", r.Raw)
	}
	wantField(t, su.get("/api/orgs?sort=password"), 422, "")

	// create
	r = su.post("/api/orgs", map[string]any{"name": "initech", "display_name": "Initech"})
	want(t, r, 201)
	wantField(t, su.post("/api/orgs", map[string]any{"name": "Bad Name"}), 422, "name")
	wantField(t, su.post("/api/orgs", map[string]any{"name": "admin"}), 422, "name") // reserved
	want(t, su.post("/api/orgs", map[string]any{"name": "initech"}), 409)
	want(t, su.post("/api/orgs", map[string]any{"name": "x1", "bogus": 1}), 400)

	// read + update
	want(t, su.get("/api/orgs/initech"), 200)
	r = su.patch("/api/orgs/initech", map[string]any{"display_name": "Initech Ltd"})
	want(t, r, 200)
	if r.str("display_name") != "Initech Ltd" {
		t.Fatal(string(r.Raw))
	}
	want(t, su.get("/api/orgs/nope"), 404)

	// delete: refuses a non-empty org without cascade, primary is protected
	want(t, su.delete("/api/orgs/globex"), 409)
	want(t, su.delete("/api/orgs/primary"), 409)
	want(t, su.delete("/api/orgs/globex?cascade=1"), 200)
	want(t, su.get("/api/orgs/globex"), 404)
	want(t, su.delete("/api/orgs/initech"), 200)

	// permissions
	ad := w.as("admin")
	r = ad.get("/api/orgs")
	if r.total() != 1 || r.items()[0].(map[string]any)["name"] != "acme" {
		t.Fatalf("admin sees %s", r.Raw)
	}
	if r.items()[0].(map[string]any)["users"] != nil {
		t.Error("user counts are for super admins only")
	}
	want(t, ad.post("/api/orgs", map[string]any{"name": "mine"}), 403)
	want(t, ad.delete("/api/orgs/acme"), 403)
	want(t, ad.get("/api/orgs/primary"), 404)
	want(t, ad.patch("/api/orgs/acme", map[string]any{"display_name": "Acme Inc"}), 403) // super admins only
	want(t, w.as("manager").patch("/api/orgs/acme", map[string]any{"display_name": "x"}), 403)
}

func TestSettings(t *testing.T) {
	w := newWorld(t)
	su, ad := w.as("super"), w.as("admin")
	// the organization's own administrators read its settings (the tenant pages show them) but do not change them
	r := ad.get(A)
	want(t, r, 200)
	if r.JSON["settings"] == nil {
		t.Fatalf("settings missing: %s", r.Raw)
	}
	want(t, ad.patch(A, map[string]any{"settings": map[string]any{"password_login": true}}), 403)
	r = su.patch(A, map[string]any{"settings": map[string]any{"password_login": true, "password_reset": true, "passkey_login": false,
		"require_mfa": true, "session_ttl": 3600, "session_idle": 600}})
	want(t, r, 200)
	o, _ := w.env.Svc.Orgs.Get(context.Background(), w.acme.ID)
	if !o.Settings.RequireMFA || o.Settings.PasskeyLogin || !o.Settings.PasswordReset || o.Settings.SessionTTL != 3600 {
		t.Fatalf("not saved: %+v", o.Settings)
	}
	want(t, su.patch(A, map[string]any{"settings": map[string]any{"session_ttl": -1}}), 422)
	wantField(t, su.patch(A, map[string]any{"name": "Not Valid"}), 422, "name")
	r = su.patch(A, map[string]any{"name": "acme2", "display_name": "Acme Two"})
	want(t, r, 200)
	want(t, su.get("/api/orgs/acme"), 404) // renamed: the URL name changed
	want(t, su.get("/api/orgs/acme2"), 200)
}

// A PATCH that names some settings leaves the others as they are: an omitted switch is not "off". Before, the whole
// settings object was replaced, so {"settings":{"self_registration":true}} opened a members-only tenant to the whole
// organization and dropped its second-factor requirement.
func TestPatchPartialSettingsKeepsTheOthers(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	r := ad.post(A+"/tenants", map[string]any{"name": "partial", "display_name": "P", "settings": map[string]any{
		"members_only": true, "require_mfa": true, "password_login": true, "passkey_login": true, "all_providers": true}})
	want(t, r, 201)
	T := A + "/tenants/" + r.str("id")
	r = ad.patch(T, map[string]any{"settings": map[string]any{"self_registration": true}})
	want(t, r, 200)
	set, _ := r.JSON["settings"].(map[string]any)
	for _, k := range []string{"self_registration", "members_only", "require_mfa", "password_login", "passkey_login", "all_providers"} {
		if set[k] != true {
			t.Errorf("tenant %s = %v after a PATCH that did not name it: %s", k, set[k], r.Raw)
		}
	}
	// A PATCH without settings leaves them alone too.
	want(t, ad.patch(T, map[string]any{"display_name": "Renamed"}), 200)
	if r = ad.get(T); r.JSON["settings"].(map[string]any)["members_only"] != true {
		t.Errorf("members_only lost: %s", r.Raw)
	}

	su := w.as("super")
	r = su.get(A)
	want(t, r, 200)
	before, _ := r.JSON["settings"].(map[string]any)
	r = su.patch(A, map[string]any{"settings": map[string]any{"require_mfa": true}})
	want(t, r, 200)
	after, _ := r.JSON["settings"].(map[string]any)
	for k, v := range before {
		if k != "require_mfa" && after[k] != v {
			t.Errorf("org %s changed from %v to %v by a PATCH that did not name it", k, v, after[k])
		}
	}
	if after["require_mfa"] != true {
		t.Errorf("require_mfa not set: %s", r.Raw)
	}
}

// Who pulled the last emergency sign-out, and why, is for those who manage the organization's users: a plain user
// reading their organization does not see it.
func TestLastSignOutHiddenFromUsers(t *testing.T) {
	w := newWorld(t)
	if _, err := w.env.Svc.SignOutOrg(context.Background(), service.System, w.acme.ID,
		service.SignOutOptions{Reason: "suspected phishing"}); err != nil {
		t.Fatal(err)
	}
	for who, visible := range map[string]bool{"user": false, "manager": true, "admin": true} {
		r := w.as(who).get(A)
		want(t, r, 200)
		if _, ok := r.JSON["last_sign_out"]; ok != visible {
			t.Errorf("%s: last_sign_out shown=%v, want %v", who, ok, visible)
		}
	}
}
