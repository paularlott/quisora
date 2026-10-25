package scim_test

import "testing"

func TestCoveragePatchRefusals(t *testing.T) {
	e := newEnv(t)
	id := e.mk("pr1", map[string]any{"title": "Dev"})
	url := "/scim/v2/acme/Users/" + id
	for name, body := range map[string]any{
		"not an object":       `[]`,
		"no operations":       map[string]any{"schemas": []string{}},
		"empty operations":    map[string]any{"Operations": []any{}},
		"operations not list": map[string]any{"Operations": "x"},
		"operation not obj":   map[string]any{"Operations": []any{"x"}},
		"unknown op":          patchBody(op("move", "title", "x")),
		"missing op":          map[string]any{"Operations": []any{map[string]any{"path": "title", "value": "x"}}},
		"no value":            map[string]any{"Operations": []any{map[string]any{"op": "add", "path": "title"}}},
		"bad path":            patchBody(op("replace", "title[", "x")),
		"path filter bad":     patchBody(op("replace", `emails[type eq`, "x")),
		"pathless remove":     patchBody(op("remove", "", nil)),
		"pathless non-object": patchBody(op("replace", "", "x")),
		"unknown schema":      patchBody(op("replace", "urn:bogus:schema:attr", "x")),
		"ext not object":      patchBody(op("add", entURN, "x")),
		"core not object":     patchBody(op("replace", "", map[string]any{"urn:ietf:params:scim:schemas:core:2.0:User": "x"})),
		"ext value not obj":   patchBody(op("replace", "", map[string]any{entURN: "x"})),
		"bad key path":        patchBody(op("replace", "", map[string]any{"title[": "x"})),
		"bad sub key":         patchBody(op("replace", "", map[string]any{entURN: map[string]any{"a[": "x"}})),
		"bad core sub key":    patchBody(op("replace", "", map[string]any{"urn:ietf:params:scim:schemas:core:2.0:User": map[string]any{"a[": "x"}})),
		"filtered not object": patchBody(op("add", `emails[type eq "work"]`, "x")),
		"active not bool":     patchBody(op("replace", "active", "maybe")),
		"role invalid":        patchBody(op("replace", idpURN+":role", "emperor")),
		"name not object":     patchBody(op("replace", "name", "x")),
		"userName bad type":   patchBody(op("replace", "userName", []any{})),
		"password":            patchBody(op("replace", "password", "x")),
		"later op fails":      patchBody(op("replace", "title", "ok"), op("replace", "active", "maybe")),
	} {
		if r := e.do("PATCH", url, e.admA, body); r.Status != 400 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	// A refused patch changes nothing.
	if g := e.do("GET", url, e.admA, nil); g.str("title") != "Dev" {
		t.Errorf("atomic: %s", g.Raw)
	}
}

func TestCoveragePatchExtensionsAndPaths(t *testing.T) {
	e := newEnv(t)
	id := e.mk("pe1", nil)
	// Whole extension: add merges, replace swaps, remove drops.
	r := e.patch(id, op("add", entURN, map[string]any{"department": "Ops"}))
	if r.Status != 200 || r.str(entURN, "department") != "Ops" {
		t.Fatalf("add ext: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("add", entURN, map[string]any{"division": "EMEA"}))
	if r.str(entURN, "department") != "Ops" || r.str(entURN, "division") != "EMEA" {
		t.Errorf("add ext again: %s", r.Raw)
	}
	r = e.patch(id, op("replace", entURN, map[string]any{"costCenter": "C9"}))
	if r.Status != 200 || r.str(entURN, "costCenter") != "C9" || r.str(entURN, "department") != "" {
		t.Errorf("replace ext: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("remove", entURN, nil))
	if r.Status != 200 || r.Body[entURN] != nil {
		t.Errorf("remove ext: %d %s", r.Status, r.Raw)
	}
	// Removing from an extension that is absent is a no-op; so is removing an absent attribute.
	wantStatus(t, "remove absent ext attr", e.patch(id, op("remove", entURN+":department", nil)), 200)
	wantStatus(t, "remove absent attr", e.patch(id, op("remove", "title", nil)), 200)
	wantStatus(t, "remove absent filtered", e.patch(id, op("remove", `emails[type eq "other"]`, nil)), 200)
	// Core URN-prefixed paths and values.
	core := "urn:ietf:params:scim:schemas:core:2.0:User"
	r = e.patch(id, op("replace", core+":title", "Core"))
	if r.Status != 200 || r.str("title") != "Core" {
		t.Errorf("core urn path: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("replace", "", map[string]any{core: map[string]any{"title": "Core2"}, "active": false}))
	if r.Status != 200 || r.str("title") != "Core2" || r.Body["active"] != false {
		t.Errorf("core object value: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("add", "", map[string]any{entURN: map[string]any{"department": "X"}}))
	if r.Status != 200 || r.str(entURN, "department") != "X" {
		t.Errorf("ext object value: %d %s", r.Status, r.Raw)
	}
	// Read-only attributes, id, meta, groups, are left alone.
	for _, p := range []string{"id", "meta", "groups", "schemas"} {
		wantStatus(t, "readonly "+p, e.patch(id, op("replace", p, "x")), 200)
	}
	// Role and tags through the quisora extension.
	r = e.patch(id, op("replace", idpURN+":tags", []any{"a", "b"}))
	if r.Status != 200 || len(r.Body[idpURN].(map[string]any)["tags"].([]any)) != 2 {
		t.Errorf("tags: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("remove", idpURN+":tags", nil))
	if r.Status != 200 || len(r.Body[idpURN].(map[string]any)["tags"].([]any)) != 0 {
		t.Errorf("tags remove: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("replace", idpURN+":validUntil", "2099-01-01T00:00:00Z"))
	if r.Status != 200 || r.str(idpURN, "validUntil") == "" {
		t.Errorf("validUntil: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("remove", idpURN+":validUntil", nil))
	if r.Status != 200 || r.str(idpURN, "validUntil") != "" {
		t.Errorf("validUntil remove: %d %s", r.Status, r.Raw)
	}
}

func TestCoveragePatchMultiValued(t *testing.T) {
	e := newEnv(t)
	id := e.mk("pm1", nil)
	em := func(v string, primary bool) map[string]any {
		return map[string]any{"value": v, "type": "work", "primary": primary}
	}
	// Add: new element, existing element (updated), several primaries (the new one wins).
	r := e.patch(id, op("add", "emails", []any{em("pm1b@acme.test", false)}))
	if r.Status != 200 || len(r.list("emails")) != 2 {
		t.Fatalf("add email: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("add", "emails", []any{em("pm1b@acme.test", true)}))
	if r.Status != 200 || len(r.list("emails")) != 2 {
		t.Errorf("add existing email: %d %s", r.Status, r.Raw)
	}
	r = e.patch(id, op("add", "emails", []any{em("pm1c@acme.test", true), "pm1d@acme.test"}))
	_ = r
	// Replace with several primaries; the last wins.
	r = e.patch(id, op("replace", "emails", []any{em("a1@acme.test", true), map[string]any{"value": "a2@acme.test", "primary": "true"}}))
	if r.Status != 200 {
		t.Errorf("replace emails: %d %s", r.Status, r.Raw)
	}
	// Filtered: sub-attribute on matching elements, a new element when none matches, whole-element replace.
	r = e.patch(id, op("replace", `emails[type eq "work"].primary`, true))
	wantStatus(t, "filtered primary", r, 200)
	r = e.patch(id, op("add", `emails[type eq "home"].value`, "home@acme.test"))
	wantStatus(t, "filtered new element", r, 200)
	r = e.patch(id, op("replace", `emails[type eq "home"]`, map[string]any{"value": "home2@acme.test", "type": "home"}))
	wantStatus(t, "filtered whole", r, 200)
	r = e.patch(id, op("add", `emails[type eq "other"]`, map[string]any{"value": "other@acme.test", "primary": "true"}))
	wantStatus(t, "filtered new whole", r, 200)
	r = e.patch(id, op("remove", `emails[type eq "other"]`, nil))
	wantStatus(t, "filtered remove", r, 200)
	r = e.patch(id, op("remove", `emails[type eq "home"].type`, nil))
	wantStatus(t, "filtered remove sub", r, 200)
	r = e.patch(id, op("remove", "emails.type", nil))
	wantStatus(t, "remove sub of multi", r, 200)
	r = e.patch(id, op("replace", "emails.type", "work"))
	wantStatus(t, "set sub of multi", r, 200)
	r = e.patch(id, op("remove", "emails", []any{map[string]any{"value": "a2@acme.test"}}))
	wantStatus(t, "remove listed value", r, 200)
	// Sub-attributes of a complex attribute: a name that is absent is created; removing one clears it.
	r = e.patch(id, op("remove", "name.familyName", nil))
	wantStatus(t, "remove family", r, 200)
	r = e.patch(id, op("add", "name", map[string]any{"familyName": "Added"}))
	if r.Status != 200 || r.str("name", "familyName") != "Added" {
		t.Errorf("add name: %d %s", r.Status, r.Raw)
	}
	// Phone numbers and addresses are accepted and ignored in every shape.
	ph := map[string]any{"value": "+441632960961", "type": "work"}
	wantStatus(t, "phones", e.patch(id, op("add", "phoneNumbers", []any{ph})), 200)
	wantStatus(t, "addresses", e.patch(id, op("add", "addresses", []any{ph})), 200)
	wantStatus(t, "phone sub", e.patch(id, op("add", "phoneNumbers.value", "+441632960961")), 200)
	wantStatus(t, "phone filtered", e.patch(id, op("add", `phoneNumbers[type eq "work"]`, ph)), 200)
	wantStatus(t, "remove phones", e.patch(id, op("remove", "phoneNumbers", nil)), 200)
}

func TestCoveragePatchOrgsAndGroupsPaths(t *testing.T) {
	e := newEnv(t)
	u := e.mk("pg1", nil)
	gid := e.group("PG", u)
	url := "/scim/v2/acme/Groups/" + gid
	// Group patches by extension and filtered members paths.
	gURN := "urn:paularlott:quisora:scim:schemas:2.0:Group"
	r := e.do("PATCH", url, e.admA, patchBody(op("replace", gURN+":tags", []any{"x"})))
	if r.Status != 200 {
		t.Errorf("group tags: %d %s", r.Status, r.Raw)
	}
	r = e.do("PATCH", url, e.admA, patchBody(op("remove", gURN+":tags", nil)))
	wantStatus(t, "group tags remove", r, 200)
	r = e.do("PATCH", url, e.admA, patchBody(op("remove", "members", []any{map[string]any{"value": u}})))
	if r.Status != 200 || len(memberValues(r)) != 0 {
		t.Errorf("remove listed member: %d %s", r.Status, r.Raw)
	}
	r = e.do("PATCH", url, e.admA, patchBody(op("replace", "", map[string]any{"displayName": "PG2", "members": []any{map[string]any{"value": u}}})))
	if r.Status != 200 || len(memberValues(r)) != 1 || r.str("displayName") != "PG2" {
		t.Errorf("pathless: %d %s", r.Status, r.Raw)
	}
	r = e.do("PATCH", url, e.admA, patchBody(op("replace", "unknownAttr", "x")))
	wantStatus(t, "unknown attribute", r, 200)
	r = e.do("PATCH", url, e.admA, patchBody(op("remove", "displayName", nil)))
	wantStatus(t, "remove required", r, 400)
}
