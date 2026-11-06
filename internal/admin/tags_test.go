package admin_test

import (
	"net/url"
	"slices"
	"testing"
)

func TestTagsAPI(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	strs := func(m map[string]any) []string {
		var out []string
		l, ok := m["tags"].([]any)
		if !ok {
			t.Fatalf("tags is not a list: %v", m["tags"])
		}
		for _, v := range l {
			out = append(out, v.(string))
		}
		return out
	}

	// users: create, update, get, list, validation
	r := ad.post(AU, map[string]any{"given_name": "T", "username": "tagme", "email": "tagme@x.example", "tags": []string{"b", "dept:finance", "b"}})
	want(t, r, 201)
	if got := strs(r.JSON); !slices.Equal(got, []string{"b", "dept:finance"}) {
		t.Fatalf("create tags %v", got)
	}
	id := r.str("id")
	r = ad.post(AU, map[string]any{"given_name": "T", "username": "plain", "email": "plain@x.example"})
	want(t, r, 201)
	if got := strs(r.JSON); len(got) != 0 {
		t.Fatalf("untagged user tags %v", got)
	}
	other := r.str("id")
	wantField(t, ad.patch(AU+"/"+id, map[string]any{"tags": []string{"x y"}}), 422, "tags")
	wantField(t, ad.post(AU, map[string]any{"given_name": "T", "username": "bad", "email": "bad@x.example", "tags": []string{"-nope"}}), 422, "tags")
	r = ad.patch(AU+"/"+id, map[string]any{"tags": []string{"sales", "dept:finance"}})
	want(t, r, 200)
	if got := strs(r.JSON); !slices.Equal(got, []string{"dept:finance", "sales"}) {
		t.Fatalf("update tags %v", got)
	}
	// untouched by an update without tags
	r = ad.patch(AU+"/"+id, map[string]any{"family_name": "x"})
	if got := strs(r.JSON); len(got) != 2 {
		t.Fatalf("tags lost: %v", got)
	}
	r = ad.get(AU + "/" + id)
	if got := strs(r.JSON); len(got) != 2 {
		t.Fatalf("get tags %v", got)
	}
	// ?tag filter: exact match, combines with paging, search finds tags
	r = ad.get(AU + "?tag=sales")
	want(t, r, 200)
	if r.total() != 1 || r.items()[0].(map[string]any)["id"] != id {
		t.Fatalf("tag filter: %s", r.Raw)
	}
	if r = ad.get(AU + "?tag=sale"); r.total() != 0 {
		t.Fatalf("tag filter must be exact: %s", r.Raw)
	}
	if r = ad.get(AU + "?tag=" + url.QueryEscape("dept:finance") + "&limit=1"); r.total() != 1 || len(r.items()) != 1 {
		t.Fatalf("namespaced tag: %s", r.Raw)
	}
	if r = ad.get(AU + "?tag=sales&offset=1"); r.total() != 1 || len(r.items()) != 0 {
		t.Fatalf("offset past the matches: %s", r.Raw)
	}
	// a search that finds nobody by name finds the users with exactly that tag; never a tag's prefix, and a name it
	// also starts comes first
	if r = ad.get(AU + "?q=" + url.QueryEscape("dept:finance")); r.total() != 1 || r.items()[0].(map[string]any)["id"] != id {
		t.Fatalf("search by tag: %s", r.Raw)
	}
	if r = ad.get(AU + "?q=dept:fin"); r.total() != 0 {
		t.Fatalf("search must match a whole tag: %s", r.Raw)
	}
	want(t, ad.post(AU, map[string]any{"given_name": "S", "username": "salesperson", "email": "sp@x.example"}), 201)
	if r = ad.get(AU + "?q=sales"); r.total() != 1 || r.items()[0].(map[string]any)["username"] != "salesperson" {
		t.Fatalf("a name the search starts comes before a tag: %s", r.Raw)
	}
	// ?external_id= and ?email=: an exact, indexed lookup of one user
	want(t, ad.patch(AU+"/"+id, map[string]any{"external_id": "app:7"}), 200)
	if r = ad.get(AU + "?external_id=" + url.QueryEscape("app:7")); r.total() != 1 || r.items()[0].(map[string]any)["id"] != id {
		t.Fatalf("external_id lookup: %s", r.Raw)
	}
	if r = ad.get(AU + "?email=" + url.QueryEscape("TAGME@x.example")); r.total() != 1 || r.items()[0].(map[string]any)["id"] != id {
		t.Fatalf("email lookup ignores case: %s", r.Raw)
	}
	if r = ad.get(AU + "?external_id=app:8"); r.Status != 200 || r.total() != 0 {
		t.Fatalf("no such external id: %d %s", r.Status, r.Raw)
	}
	// clear
	r = ad.patch(AU+"/"+other, map[string]any{"tags": []string{}})
	want(t, r, 200)
	// a manager may tag a plain user
	if r = w.as("manager").patch(AU+"/"+other, map[string]any{"tags": []string{"by-manager"}}); r.Status != 200 {
		t.Fatalf("manager tag: %d %s", r.Status, r.Raw)
	}

	// groups
	r = ad.post(A+"/groups", map[string]any{"display_name": "Tagged", "tags": []string{"team:b", "team:a"}})
	want(t, r, 201)
	if got := strs(r.JSON); !slices.Equal(got, []string{"team:a", "team:b"}) {
		t.Fatalf("group create tags %v", got)
	}
	gid := r.str("id")
	wantField(t, ad.patch(A+"/groups/"+gid, map[string]any{"tags": []string{"a b"}}), 422, "tags")
	r = ad.patch(A+"/groups/"+gid, map[string]any{"tags": []string{"only"}})
	want(t, r, 200)
	if got := strs(r.JSON); !slices.Equal(got, []string{"only"}) {
		t.Fatalf("group update tags %v", got)
	}
	r = ad.get(A + "/groups/" + gid)
	if got := strs(r.JSON); !slices.Equal(got, []string{"only"}) {
		t.Fatalf("group get tags %v", got)
	}
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "Untagged"}), 201)
	r = ad.get(A + "/groups?sort=display_name")
	for _, it := range r.items() {
		strs(it.(map[string]any)) // never null
	}
	if ad.get(A+"/groups?tag=only").total() != 1 || ad.get(A+"/groups?tag=onl").total() != 0 {
		t.Fatal("group tag filter")
	}
}
