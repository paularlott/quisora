package admin_test

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAudit(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "First"}), 201)
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "Second"}), 201)
	r := ad.get(A + "/audit")
	want(t, r, 200)
	if r.total() < 2 {
		t.Fatal(string(r.Raw))
	}
	if first := r.items()[0].(map[string]any); first["action"] != "group.create" || first["target"] != "Second" {
		t.Fatalf("newest first expected: %v", first)
	}
	r = ad.get(A + "/audit?q=First")
	if r.total() != 1 {
		t.Fatalf("search: %s", r.Raw)
	}
	r = ad.get(A + "/audit?sort=created&desc=0&limit=1")
	if first := r.items()[0].(map[string]any); first["action"] == "group.create" && first["target"] == "Second" {
		t.Fatalf("ascending sort should start with the oldest: %v", first)
	}
	want(t, ad.get(A+"/audit?sort=ip"), 422)
	if n := len(ad.get(A + "/audit?limit=1").items()); n != 1 {
		t.Fatal("limit")
	}
	// the other org's events are not visible here
	want(t, w.as("other").post(G+"/groups", map[string]any{"display_name": "Theirs"}), 201)
	if ad.get(A+"/audit?q=Theirs").total() != 0 {
		t.Fatal("cross-org audit leak")
	}

	// filters: a family of actions, one action, an outcome, a time range; the search covers the IP address
	r = ad.get(A + "/audit?action_group=GROUP.")
	want(t, r, 200)
	if r.total() < 2 {
		t.Fatalf("action group: %s", r.Raw)
	}
	for _, it := range r.items() {
		if a := it.(map[string]any)["action"].(string); !strings.HasPrefix(a, "group.") {
			t.Fatalf("action group returned %s", a)
		}
	}
	if n := ad.get(A + "/audit?action=group.create&q=First").total(); n != 1 {
		t.Fatalf("action and search: %d", n)
	}
	if n := ad.get(A + "/audit?action=group.delete").total(); n != 0 {
		t.Fatalf("an action that did not happen: %d", n)
	}
	for _, it := range ad.get(A + "/audit?outcome=success").items() {
		if o := it.(map[string]any)["outcome"]; o != "success" {
			t.Fatalf("outcome filter returned %v", o)
		}
	}
	all := ad.get(A + "/audit").total()
	past, future := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if n := ad.get(A + "/audit?from=" + past + "&to=" + future).total(); n != all {
		t.Fatalf("the last hour: %d of %d", n, all)
	}
	if n := ad.get(A + "/audit?from=" + future).total(); n != 0 {
		t.Fatalf("from the future: %d", n)
	}
	if ip, _ := ad.get(A + "/audit").items()[0].(map[string]any)["ip"].(string); ip != "" {
		if n := ad.get(A + "/audit?q=" + url.QueryEscape(ip)).total(); n == 0 {
			t.Fatalf("search by IP address %s found nothing", ip)
		}
	}
	want(t, ad.get(A+"/audit?outcome=maybe"), 422)
	want(t, ad.get(A+"/audit?from=yesterday"), 422)
	want(t, ad.get(A+"/audit?from="+future+"&to="+past), 422)
	// every organization (super admins), narrowed to one; the same filters are checked there
	su := w.as("super")
	if n := su.get("/api/audit?org=globex&q=Theirs").total(); n != 1 {
		t.Fatalf("all organizations, narrowed to one: %d", n)
	}
	if n := su.get("/api/audit?q=Theirs").total(); n != 1 {
		t.Fatalf("all organizations: %d", n)
	}
	want(t, su.get("/api/audit?org=nope"), 404)
	want(t, su.get("/api/audit?from=yesterday"), 422)
	want(t, su.get("/api/audit?to=tomorrow"), 422)
}
