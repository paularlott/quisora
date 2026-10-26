package admin_test

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClients(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	r := ad.post(A+"/clients", map[string]any{"name": "Portal", "redirect_uris": []string{"https://p.example/cb"}})
	want(t, r, 201)
	secret, id := r.str("secret"), r.str("id")
	if !strings.HasPrefix(secret, "qsrs_") || id == "" {
		t.Fatalf("create: %s", r.Raw)
	}
	r = ad.get(A + "/clients")
	if strings.Contains(string(r.Raw), secret) || strings.Contains(string(r.Raw), "secret_hash") || strings.Contains(string(r.Raw), "SecretHash") {
		t.Fatal("secret leaked in the list")
	}
	if r.total() != 1 {
		t.Fatal(string(r.Raw))
	}
	wantField(t, ad.post(A+"/clients", map[string]any{"name": "Bad", "redirect_uris": []string{"ftp://x"}}), 422, "redirect_uris")
	wantField(t, ad.post(A+"/clients", map[string]any{"redirect_uris": []string{"https://p.example/cb"}}), 422, "name")
	want(t, ad.post(A+"/clients", map[string]any{"name": "SA", "grant_types": []string{"client_credentials"}}), 201)
	// super-only flag: SCIM
	want(t, ad.post(A+"/clients", map[string]any{"name": "SA2", "scim": true, "grant_types": []string{"client_credentials"}}), 403)
	want(t, w.as("super").post(A+"/clients", map[string]any{"name": "SA3", "scim": true, "grant_types": []string{"client_credentials"}}), 201)
	// the former "serves every organization" flag is gone: the strict decoder refuses it
	want(t, ad.patch(A+"/clients/"+id, map[string]any{"all_orgs": true}), 400)

	r = ad.patch(A+"/clients/"+id, map[string]any{"name": "Portal 2", "enabled": false})
	want(t, r, 200)
	if r.str("name") != "Portal 2" || r.JSON["enabled"] != false || r.str("secret") != "" {
		t.Fatal(string(r.Raw))
	}

	r = ad.post(A+"/clients/"+id+"/secret", nil)
	want(t, r, 200)
	if r.str("secret") == "" || r.str("secret") == secret || r.str("client_id") != id {
		t.Fatal(string(r.Raw))
	}

	// public clients: no secret is issued and there is nothing to rotate
	r = ad.post(A+"/clients", map[string]any{"name": "SPA", "token_endpoint_auth_method": "none", "redirect_uris": []string{"com.example.app:/callback"}})
	want(t, r, 201)
	if r.str("secret") != "" {
		t.Fatalf("public client got a secret: %s", r.Raw)
	}
	wantField(t, ad.post(A+"/clients/"+r.str("id")+"/secret", nil), 422, "token_endpoint_auth_method")
	wantField(t, ad.post(A+"/clients", map[string]any{"name": "Bad SPA", "token_endpoint_auth_method": "none", "grant_types": []string{"client_credentials"}}), 422, "grant_types")

	want(t, ad.delete(A+"/clients/"+id), 200)
	want(t, ad.delete(A+"/clients/"+id), 404)
	if ad.get(A+"/clients?q=zzz").total() != 0 {
		t.Fatal("search")
	}
	if ad.get(A + "/clients?sort=name&desc=1").items()[0].(map[string]any)["name"] != "SPA" {
		t.Fatal("sort")
	}
}

// Single-record GETs used by the live-update dialogs, and client operations stay scoped to the organization and its
// tenants.
func TestClientScopeAndGets(t *testing.T) {
	w := newWorld(t)
	ad, su := w.as("admin"), w.as("super")
	A, G := "/api/orgs/acme", "/api/orgs/globex"
	ta := ad.post(A+"/tenants", map[string]any{"name": "a1", "display_name": "A1"})
	tb := ad.post(A+"/tenants", map[string]any{"name": "a2", "display_name": "A2"})
	tg := su.post(G+"/tenants", map[string]any{"name": "g1", "display_name": "G1"})
	want(t, ta, 201)
	want(t, tb, 201)
	want(t, tg, 201)
	c := ad.post(A+"/clients", map[string]any{"name": "One", "tenant_id": ta.str("id"), "redirect_uris": []string{"https://o.example/cb"}})
	want(t, c, 201)
	cid := c.str("id")
	gc := su.post(G+"/clients", map[string]any{"name": "Theirs", "tenant_id": tg.str("id"), "redirect_uris": []string{"https://t.example/cb"}})
	want(t, gc, 201)

	// the list for a tenant holds only that tenant's clients
	if r := ad.get(A + "/clients?tenant=" + ta.str("id")); r.total() != 1 {
		t.Fatalf("tenant a1 clients: %s", r.Raw)
	}
	if r := ad.get(A + "/clients?tenant=" + tb.str("id")); r.total() != 0 {
		t.Fatalf("tenant a2 clients: %s", r.Raw)
	}
	// another organization's tenant id yields nothing, never its clients
	if r := ad.get(A + "/clients?tenant=" + tg.str("id")); r.total() != 0 {
		t.Fatalf("foreign tenant filter leaked: %s", r.Raw)
	}
	// moving a client to a tenant of the same org works; to another org's tenant it does not
	want(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": tb.str("id")}), 200)
	if ad.get(A+"/clients?tenant="+ta.str("id")).total() != 0 || ad.get(A+"/clients?tenant="+tb.str("id")).total() != 1 {
		t.Fatal("client did not move between tenants")
	}
	wantField(t, ad.patch(A+"/clients/"+cid, map[string]any{"tenant_id": tg.str("id")}), 422, "tenant_id")
	// GET one client: own org only; another org's client is a 404 through either org path
	if r := ad.get(A + "/clients/" + cid); r.str("name") != "One" || r.str("tenant_id") != tb.str("id") {
		t.Fatalf("get client: %s", r.Raw)
	}
	want(t, ad.get(A+"/clients/"+gc.str("id")), 404)
	want(t, ad.get(G+"/clients/"+cid), 404)
	want(t, ad.patch(A+"/clients/"+gc.str("id"), map[string]any{"name": "x"}), 404)
	want(t, ad.delete(A+"/clients/"+gc.str("id")), 404)
	want(t, ad.post(A+"/clients/"+gc.str("id")+"/secret", nil), 404)
	// groups and providers can be read one by one too (dialogs compare against the stored record)
	g := ad.post(A+"/groups", map[string]any{"display_name": "Ops"})
	want(t, g, 201)
	if ad.get(A+"/groups/"+g.str("id")).str("display_name") != "Ops" {
		t.Fatal("get group")
	}
	want(t, ad.get(G+"/groups/"+g.str("id")), 404)
	p := ad.post(A+"/providers", map[string]any{"type": "oidc", "name": "SSO", "issuer": "https://sso.example", "client_id": "x", "client_secret": "y"})
	want(t, p, 201)
	if ad.get(A+"/providers/"+p.str("id")).str("name") != "SSO" {
		t.Fatal("get provider")
	}
	want(t, ad.get(G+"/providers/"+p.str("id")), 404)
}

func TestClientListFieldsRoundTrip(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	A := "/api/orgs/acme"
	body := map[string]any{"name": "Lists", "redirect_uris": []string{"https://a.example/cb", " ", "com.example.app:/callback", "https://a.example/cb2"},
		"post_logout_redirect_uris": []string{"https://a.example/bye", "https://a.example/bye2"},
		"backchannel_logout_uri":    "https://a.example/logout",
		"scopes":                    []string{"openid", "email", "orders:read", "billing.write"}}
	c := ad.post(A+"/clients", body)
	want(t, c, 201)
	got := ad.get(A + "/clients/" + c.str("id"))
	for k, wantJSON := range map[string]string{
		"redirect_uris":             `["https://a.example/cb","com.example.app:/callback","https://a.example/cb2"]`,
		"post_logout_redirect_uris": `["https://a.example/bye","https://a.example/bye2"]`,
		"scopes":                    `["openid","email","orders:read","billing.write"]`,
	} {
		b, _ := json.Marshal(got.JSON[k])
		if string(b) != wantJSON {
			t.Errorf("%s = %s, want %s", k, b, wantJSON)
		}
	}
	if got.str("backchannel_logout_uri") != "https://a.example/logout" {
		t.Errorf("backchannel: %s", got.Raw)
	}
	// a bad row is reported on its field with the offending value first; nothing is stored
	r := ad.patch(A+"/clients/"+c.str("id"), map[string]any{"redirect_uris": []string{"https://a.example/cb", "http://nope.example/cb"}})
	wantField(t, r, 422, "redirect_uris")
	if !strings.HasPrefix(r.str("error"), "http://nope.example/cb ") {
		t.Errorf("message should start with the value: %s", r.Raw)
	}
	wantField(t, ad.patch(A+"/clients/"+c.str("id"), map[string]any{"scopes": []string{"openid", "bad scope"}}), 422, "scopes")
	if g := ad.get(A + "/clients/" + c.str("id")); len(g.JSON["redirect_uris"].([]any)) != 3 {
		t.Errorf("failed update changed the client: %s", g.Raw)
	}
}

func TestClientRequirePKCE(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	r := ad.post(A+"/clients", map[string]any{"name": "Legacy", "redirect_uris": []string{"https://l.example/cb"}, "require_pkce": false})
	want(t, r, 201)
	if r.JSON["require_pkce"] != false || r.str("secret") == "" {
		t.Fatalf("create: %s", r.Raw)
	}
	id := r.str("id")
	if g := ad.get(A + "/clients/" + id); g.JSON["require_pkce"] != false {
		t.Fatalf("get: %s", g.Raw)
	}
	if p := ad.patch(A+"/clients/"+id, map[string]any{"require_pkce": true}); p.JSON["require_pkce"] != true {
		t.Fatalf("patch: %s", p.Raw)
	}
	r = ad.post(A+"/clients", map[string]any{"name": "Default", "redirect_uris": []string{"https://d.example/cb"}})
	if r.JSON["require_pkce"] != true {
		t.Fatalf("default: %s", r.Raw)
	}
	want(t, ad.post(A+"/clients", map[string]any{"name": "SPA", "redirect_uris": []string{"https://s.example/cb"},
		"token_endpoint_auth_method": "none", "require_pkce": false}), 422)
}
