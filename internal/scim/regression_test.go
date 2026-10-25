package scim_test

import "testing"

// The display name is the full name, and a filter on it finds the user.
func TestFilterDisplayNameFullName(t *testing.T) {
	e := newEnv(t)
	e.mk("jsmith", map[string]any{"name": map[string]any{"givenName": "John", "familyName": "Smith"}})
	r := e.do("GET", "/scim/v2/acme/Users?filter="+qs(`displayName eq "John Smith"`), e.admA, nil)
	if r.Status != 200 || r.total() != 1 {
		t.Fatalf("displayName eq on a full name: %d results (status %d): %s", r.total(), r.Status, r.Raw)
	}
}

// RFC 7644 §3.5.2.3: replacing a complex attribute sets the sub-attributes given and leaves the others unchanged.
func TestPatchReplaceNameKeepsFamilyName(t *testing.T) {
	e := newEnv(t)
	id := e.mk("jsmith", map[string]any{"name": map[string]any{"givenName": "John", "familyName": "Smith"}})
	r := e.patch(id, op("replace", "name", map[string]any{"givenName": "Jo"}))
	if r.Status != 200 {
		t.Fatalf("patch: %d %s", r.Status, r.Raw)
	}
	if r.str("name", "givenName") != "Jo" || r.str("name", "familyName") != "Smith" {
		t.Fatalf("replace of name with only givenName: %s", r.Raw)
	}
}

// displayName is derived from the name, so it is read-only, and the Schemas endpoint says so: a PATCH of it alone
// changes nothing.
func TestDisplayNameIsReadOnly(t *testing.T) {
	e := newEnv(t)
	id := e.mk("jsmith", map[string]any{"name": map[string]any{"givenName": "John", "familyName": "Smith"}})
	r := e.patch(id, op("replace", "displayName", "Johnny S"))
	if r.Status != 200 || r.str("displayName") != "John Smith" {
		t.Fatalf("patch of displayName: %d %s", r.Status, r.Raw)
	}
	s := e.do("GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "", nil)
	attrs, _ := s.Body["attributes"].([]any)
	for _, a := range attrs {
		if m, _ := a.(map[string]any); m["name"] == "displayName" {
			if m["mutability"] != "readOnly" {
				t.Fatalf("displayName mutability %v", m["mutability"])
			}
			return
		}
	}
	t.Fatal("displayName not in the User schema")
}

func TestDiscoveryExtraSegmentIsNotFound(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/scim/v2/Schemas/a/b", "/scim/v2/ResourceTypes/a/b"} {
		if r := e.do("GET", p, "", nil); r.Status != 404 {
			t.Errorf("GET %s: %d, want 404", p, r.Status)
		}
	}
}

// id eq and an email value path are served by one read (not a scan of the organization), and stay within it.
func TestFilterByIDAndEmailValuePath(t *testing.T) {
	e := newEnv(t)
	id := e.mk("jsmith", map[string]any{"name": map[string]any{"givenName": "John", "familyName": "Smith"}})
	other := e.mkUser(e.orgB, "elsewhere", "user")
	for filter, want := range map[string]int{
		`id eq "` + id + `"`:                                 1,
		`id eq "` + other.ID + `"`:                           0, // another organization's user
		`emails[type eq "work"].value eq "jsmith@acme.test"`: 1,
		`emails[type eq "work"].value eq "nobody@acme.test"`: 0,
	} {
		r := e.do("GET", "/scim/v2/acme/Users?filter="+qs(filter), e.admA, nil)
		if r.Status != 200 || r.total() != want {
			t.Errorf("%s: %d results (status %d), want %d", filter, r.total(), r.Status, want)
		}
	}
}
