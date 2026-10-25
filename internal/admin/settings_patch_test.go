package admin_test

import "testing"

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
