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

// A super admin sets up an organization provider through the console's API: it names the source organization and
// nothing else, and the application it signs in with appears in that organization (its secret nowhere). An
// organization's administrator may read it but not create, change or delete one.
func TestOrganizationProviders(t *testing.T) {
	w := newWorld(t)
	su, ad := w.as("super"), w.as("admin")
	in := map[string]any{"type": "organization", "source_org": "globex"}
	want(t, ad.post(A+"/providers", in), 403)
	wantField(t, su.post(A+"/providers", map[string]any{"type": "organization"}), 422, "source_org")
	wantField(t, su.post(A+"/providers", map[string]any{"type": "organization", "source_org": "acme"}), 422, "source_org")
	if n := su.get("/api/orgs/globex/clients").total(); n != 0 {
		t.Fatalf("refused requests made %d clients", n)
	}

	r := su.post(A+"/providers", in)
	want(t, r, 201)
	if r.str("type") != "organization" || r.str("source_org") != w.other.ID || r.str("name") != "Globex" ||
		r.str("issuer") != w.env.Cfg.OrgIssuer(w.other.ID) || r.JSON["has_secret"] != true || r.str("client_id") == "" ||
		r.JSON["auto_provision"] != false || r.JSON["trust_mfa"] != false || strings.Contains(string(r.Raw), "client_secret") {
		t.Fatalf("provider: %s", r.Raw)
	}
	id := r.str("id")
	cl := su.get("/api/orgs/globex/clients")
	if cl.total() != 1 || !strings.Contains(string(cl.Raw), r.str("client_id")) || !strings.Contains(string(cl.Raw), "Sign-in to Acme") ||
		!strings.Contains(string(cl.Raw), w.env.Cfg.Server.PublicURL+"/o/"+w.acme.ID+"/login/callback/"+id) {
		t.Fatalf("clients of the source organization: %s", cl.Raw)
	}

	if g := ad.get(A + "/providers/" + id); g.Status != 200 || g.str("source_org") != w.other.ID {
		t.Fatalf("admin reading: %s", g.Raw)
	}
	want(t, ad.patch(A+"/providers/"+id, map[string]any{"name": "mine"}), 403)
	want(t, ad.delete(A+"/providers/"+id), 403)
	want(t, su.patch(A+"/providers/"+id, map[string]any{"name": "Guests", "auto_provision": true}), 200)

	want(t, su.delete(A+"/providers/"+id), 200)
	if n := su.get("/api/orgs/globex/clients").total(); n != 0 {
		t.Fatalf("the client outlived its provider: %d", n)
	}
}
