package scim_test

import "testing"

func TestReviewGroupPatchAtomicity(t *testing.T) {
	e := newEnv(t)
	uid := e.mk("review-u", nil)
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
func TestReviewMembershipChangesETag(t *testing.T) {
	e := newEnv(t)
	uid := e.mk("review-v", nil)
	id := e.group("ETag")
	path := "/scim/v2/acme/Groups/" + id
	before := e.do("GET", path, e.admA, nil)
	tag := before.Header.Get("ETag")
	r := e.do("PATCH", path, e.admA, patchBody(op("add", "members", []any{map[string]any{"value": uid}})))
	if r.Status != 200 {
		t.Fatalf("patch: %d %s", r.Status, r.Raw)
	}
	after := e.do("GET", path, e.admA, nil, "If-None-Match", tag)
	if after.Status != 200 {
		t.Fatalf("changed resource with old ETag returns %d; original tag %s patch tag %s", after.Status, tag, r.Header.Get("ETag"))
	}
}
