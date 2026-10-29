package app

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// The deployment flow, over HTTP as a deployment tool drives it: a primary-org service account with orgs:create makes an
// organization and its first service account, which sets the organization up through the management API; the routes
// its scopes do not name stay closed, an application's own client_credentials token opens none, and the organization's
// creator deletes it again (orgs:delete), which ends its service account.
func TestServiceAccountDeployFlow(t *testing.T) {
	a, hc, base := startApp(t, "sqlite")
	ctx := context.Background()
	primary, err := a.Svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deploy, deploySecret, err := a.Svc.CreateServiceAccount(ctx, service.System, primary.ID, service.ServiceAccountInput{
		Name: ptr("deploy"), Scopes: ptr([]string{service.ScopeOrgsCreate, service.ScopeOrgsDelete})})
	if err != nil {
		t.Fatal(err)
	}
	token := func(orgID, id, secret string) string {
		t.Helper()
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}
		code, tok := doJSON(t, hc, "POST", base+"/o/"+orgID+"/oauth/token",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, strings.NewReader(form.Encode()))
		if code != 200 {
			t.Fatalf("client_credentials %d %v", code, tok)
		}
		return tok["access_token"].(string)
	}
	call := func(tok, method, path string, body any) (int, map[string]any) {
		t.Helper()
		hdr := map[string]string{"Authorization": "Bearer " + tok, "Api-Version": web.APIVersionLatest, "Content-Type": "application/json"}
		var r *strings.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = strings.NewReader(string(b))
		} else {
			r = strings.NewReader("")
		}
		return doJSON(t, hc, method, base+path, hdr, r)
	}
	deployTok := token(primary.ID, deploy.ID, deploySecret)

	code, created := call(deployTok, "POST", "/api/orgs", map[string]any{"name": "fortix-one", "service_account": map[string]any{
		"name": "setup", "scopes": []string{"users", "manage_admins", "import", "groups", "tenants", "clients", "providers", "access"}}})
	if code != 201 {
		t.Fatalf("create org %d %v", code, created)
	}
	orgID := created["id"].(string)
	sa := created["service_account"].(map[string]any)
	if sa["secret"] == "" || sa["token_endpoint"] != a.Cfg.OrgEndpoints(orgID).Token {
		t.Fatalf("first service account %v", sa)
	}
	setup := token(orgID, sa["id"].(string), sa["secret"].(string))

	// The new account sets its organization up.
	for _, c := range []struct {
		path string
		body map[string]any
	}{
		{"/tenants", map[string]any{"name": "customers"}},
		{"/users", map[string]any{"given_name": "Ada", "username": "ada", "email": "ada@fortix.test", "role": "admin"}},
		{"/users", map[string]any{"given_name": "Bob", "username": "bob", "email": "bob@fortix.test", "totp_secret": "JBSWY3DPEHPK3PXP"}},
		{"/clients", map[string]any{"name": "Freedom3", "redirect_uris": []string{"https://f3.fortix.test/cb"}}},
	} {
		if code, out := call(setup, "POST", "/api/orgs/fortix-one"+c.path, c.body); code != 201 {
			t.Errorf("POST %s: %d %v", c.path, code, out)
		}
	}
	if code, _ := call(setup, "GET", "/api/orgs/fortix-one", nil); code != 200 {
		t.Errorf("reads its organization: %d", code)
	}
	// The organization's id names it too, as under /o/.
	if code, out := call(setup, "GET", "/api/orgs/"+orgID+"/tenants", nil); code != 200 || out["total"] != float64(2) { // default and customers
		t.Errorf("tenants by organization id: %d %v", code, out)
	}
	// Groups and their members: groups is also an OpenID Connect scope, which a token without a user never carries,
	// but a service account's is its own and is kept.
	_, carol := call(setup, "POST", "/api/orgs/fortix-one/users", map[string]any{"given_name": "Carol", "username": "carol", "email": "carol@fortix.test"})
	code, g := call(setup, "POST", "/api/orgs/fortix-one/groups", map[string]any{"display_name": "Staff"})
	if code != 201 {
		t.Fatalf("create group: %d %v", code, g)
	}
	members := "/api/orgs/fortix-one/groups/" + g["id"].(string) + "/members"
	if code, out := call(setup, "PUT", members+"/"+carol["id"].(string), nil); code != 200 && code != 204 {
		t.Errorf("add member: %d %v", code, out)
	}
	if code, out := call(setup, "GET", members, nil); code != 200 || out["total"] != float64(1) {
		t.Errorf("list members: %d %v", code, out)
	}
	if code, out := call(setup, "DELETE", members+"/"+carol["id"].(string), nil); code != 200 && code != 204 {
		t.Errorf("remove member: %d %v", code, out)
	}
	// What its scopes do not name stays closed: the organization's settings, its audit log, other orgs.
	for _, c := range []struct{ method, path string }{
		{"PATCH", "/api/orgs/fortix-one"}, {"GET", "/api/orgs/fortix-one/audit"},
		{"GET", "/api/orgs/fortix-one/service-accounts"}, {"GET", "/api/orgs"}, {"POST", "/api/orgs"},
	} {
		if code, _ := call(setup, c.method, c.path, map[string]any{}); code != 403 {
			t.Errorf("%s %s: %d, want 403", c.method, c.path, code)
		}
	}
	if code, _ := call(setup, "GET", "/api/orgs/"+primary.Name+"/users", nil); code != 404 {
		t.Errorf("another organization's users: %d", code)
	}
	if code, _ := call(deployTok, "GET", "/api/orgs/fortix-one/users", nil); code != 403 {
		t.Errorf("the deploy account reads the new organization's users: %d", code)
	}

	// An application with client_credentials whose own scopes happen to share a name is not a service account.
	app, appSecret, err := a.Svc.CreateClient(ctx, service.System, orgID, service.ClientInput{Name: ptr("lookalike"),
		GrantTypes: ptr([]string{"client_credentials"}), Scopes: ptr([]string{"users"})})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := call(token(orgID, app.ID, appSecret), "GET", "/api/orgs/fortix-one/users", nil); code != 401 {
		t.Errorf("an application's token on the management API: %d", code)
	}

	// The creator deletes it, and with it the account it made.
	if code, out := call(deployTok, "DELETE", "/api/orgs/"+orgID+"?cascade=1", nil); code != 200 {
		t.Fatalf("delete org %d %v", code, out)
	}
	if code, _ := call(setup, "GET", "/api/orgs/fortix-one", nil); code != 401 && code != 404 {
		t.Errorf("the deleted organization's service account: %d", code)
	}
}
