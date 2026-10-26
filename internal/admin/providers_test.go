package admin_test

import (
	"strings"
	"testing"
)

func TestProviders(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	in := map[string]any{"type": "oidc", "name": "SSO", "issuer": "https://login.example.com", "client_id": "cid", "client_secret": "hunter2-secret"}
	r := ad.post(A+"/providers", in)
	want(t, r, 201)
	if r.JSON["has_secret"] != true || strings.Contains(string(r.Raw), "hunter2") || r.JSON["client_secret"] != nil {
		t.Fatalf("secret handling: %s", r.Raw)
	}
	id := r.str("id")
	wantField(t, ad.post(A+"/providers", in), 409, "name")
	wantField(t, ad.post(A+"/providers", map[string]any{"type": "oidc", "name": "X", "issuer": "http://x", "client_id": "a", "client_secret": "b"}), 422, "issuer")
	wantField(t, ad.post(A+"/providers", map[string]any{"type": "oidc", "name": "Y", "issuer": "https://x.example", "client_id": "a"}), 422, "client_secret")
	want(t, ad.post(A+"/providers", map[string]any{}), 422)

	// link_by_email defaults to on and can be switched off
	if r.JSON["link_by_email"] != true {
		t.Fatalf("link_by_email default: %s", r.Raw)
	}
	r = ad.patch(A+"/providers/"+id, map[string]any{"link_by_email": false})
	want(t, r, 200)
	if r.JSON["link_by_email"] != false || ad.get(A + "/providers/" + id).JSON["link_by_email"] != false {
		t.Fatalf("link_by_email off: %s", r.Raw)
	}
	r = ad.patch(A+"/providers/"+id, map[string]any{"name": "SSO 2", "client_secret": ""}) // blank keeps the secret
	want(t, r, 200)
	if r.JSON["has_secret"] != true || r.str("name") != "SSO 2" {
		t.Fatal(string(r.Raw))
	}
	r = ad.get(A + "/providers?sort=type")
	if r.total() != 1 || strings.Contains(string(r.Raw), "hunter2") {
		t.Fatal(string(r.Raw))
	}
	want(t, w.as("other").patch(A+"/providers/"+id, map[string]any{"name": "hax"}), 404)
	want(t, ad.delete(A+"/providers/"+id), 200)
	want(t, ad.delete(A+"/providers/"+id), 404)
}
