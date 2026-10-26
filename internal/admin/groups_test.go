package admin_test

import (
	"testing"
)

func TestGroups(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	r := ad.post(A+"/groups", map[string]any{"display_name": "Engineering", "external_id": "eng"})
	want(t, r, 201)
	gid := r.str("id")
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "Design"}), 201)
	wantField(t, ad.post(A+"/groups", map[string]any{"display_name": "engineering"}), 409, "display_name")
	wantField(t, ad.post(A+"/groups", map[string]any{}), 422, "display_name")

	r = ad.get(A + "/groups?sort=display_name")
	if r.total() != 2 || r.items()[0].(map[string]any)["display_name"] != "Design" {
		t.Fatal(string(r.Raw))
	}
	if ad.get(A+"/groups?q=eng").total() != 1 {
		t.Fatal("search")
	}
	want(t, ad.patch(A+"/groups/"+gid, map[string]any{"display_name": "Eng"}), 200)

	// members
	uid := w.users["user"].ID
	want(t, ad.put(A+"/groups/"+gid+"/members/"+uid, nil), 200)
	want(t, ad.put(A+"/groups/"+gid+"/members/"+uid, nil), 200) // idempotent
	want(t, ad.put(A+"/groups/"+gid+"/members/"+w.users["manager"].ID, nil), 200)
	wantField(t, ad.put(A+"/groups/"+gid+"/members/"+w.users["other"].ID, nil), 422, "members")
	wantField(t, ad.put(A+"/groups/"+gid+"/members/ghost", nil), 422, "members")
	want(t, ad.delete(A+"/groups/"+gid+"/members/ghost"), 200) // removing a non-member is a no-op
	r = ad.get(A + "/groups/" + gid + "/members")
	if r.total() != 2 || len(r.items()) != 2 {
		t.Fatal(string(r.Raw))
	}
	if len(ad.get(A+"/groups/"+gid+"/members?limit=1&offset=1").items()) != 1 {
		t.Fatal("member paging")
	}
	g := ad.get(AU + "/" + uid)
	if gs, _ := g.JSON["groups"].([]any); len(gs) != 1 {
		t.Fatalf("user groups: %s", g.Raw)
	}
	want(t, ad.delete(A+"/groups/"+gid+"/members/"+uid), 200)
	if ad.get(A+"/groups/"+gid+"/members").total() != 1 {
		t.Fatal("remove member")
	}
	// a manager adds plain users and takes them out; the group itself, and the memberships of managers and
	// administrators (their own included), are for administrators
	mg := w.as("manager")
	want(t, mg.put(A+"/groups/"+gid+"/members/"+uid, nil), 200)
	want(t, mg.delete(A+"/groups/"+gid+"/members/"+uid), 200)
	want(t, mg.delete(A+"/groups/"+gid+"/members/"+w.users["manager"].ID), 403)
	want(t, mg.put(A+"/groups/"+gid+"/members/"+w.users["admin"].ID, nil), 403)
	want(t, mg.patch(A+"/groups/"+gid, map[string]any{"display_name": "Mine"}), 403)
	want(t, mg.patch(A+"/groups/"+gid, map[string]any{"tags": []string{"x"}}), 403)
	want(t, mg.delete(A+"/groups/"+gid), 403)
	want(t, ad.delete(A+"/groups/"+gid), 200)
	want(t, ad.get(A+"/groups/"+gid+"/members"), 404)
	// groups of another org are invisible
	gr := w.as("other").post(G+"/groups", map[string]any{"display_name": "Theirs"})
	want(t, gr, 201)
	want(t, ad.patch(A+"/groups/"+gr.str("id"), map[string]any{"display_name": "x"}), 404)
}
