package admin_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// asServiceAccount returns a caller that acts as a new service account of org with scopes (made by the system, as a
// super admin would): its bearer stands for the account's token, resolved as the app resolves one.
func (w *world) asServiceAccount(org *model.Org, scopes ...string) *caller {
	sa, _, err := w.env.Svc.CreateServiceAccount(context.Background(), service.System, org.ID,
		service.ServiceAccountInput{Name: ptr("sa"), Scopes: &scopes})
	if err != nil {
		w.t.Fatal(err)
	}
	w.env.Server.Bearer = func(ctx context.Context, r *http.Request, token string) (*service.Actor, error) {
		id, ok := strings.CutPrefix(token, "sa:")
		if !ok {
			t, u, err := w.env.Svc.ValidateAPIToken(ctx, token)
			if err != nil {
				return nil, err
			}
			return service.ActorForToken(t, u, web.ClientIP(r)), nil
		}
		c, err := w.env.Svc.Clients.Get(ctx, id)
		if err != nil || !c.Enabled {
			return nil, service.ErrBadToken
		}
		return service.ActorForServiceAccount(c, c.Scopes, web.ClientIP(r)), nil
	}
	return &caller{w: w, c: detach(w.env.Client()), bearer: "sa:" + sa.ID}
}

// guardRefused reports whether r is the management API's refusal of a service account for want of the route's scope.
func guardRefused(r resp) bool {
	return r.Status == 403 && (strings.Contains(r.str("error"), "does not have the") || strings.Contains(r.str("error"), "Service accounts cannot"))
}

// Every management route opens to a service account only through the scope it names: an account holding every other
// scope is refused, an account holding just that one gets through (a route that names none stays closed to all).
func TestServiceAccountScopeSweep(t *testing.T) {
	w := newWorld(t)
	primary, err := w.env.Svc.PrimaryOrg(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	all := append(slices.Clone(service.ServiceAccountScopes), service.PrimaryServiceAccountScopes...)
	for _, rt := range w.mod.Routes() {
		if rt.Scope == web.AnyScope {
			continue
		}
		p := concretePath(rt.Path, "acme", "nope")
		var body any
		if rt.Method != "GET" && rt.Method != "DELETE" {
			body = map[string]any{}
		}
		others := slices.DeleteFunc(slices.Clone(all), func(sc string) bool { return sc == rt.Scope })
		if r := w.asServiceAccount(primary, others...).do(rt.Method, p, body); !guardRefused(r) {
			t.Errorf("%s %s without %q: %d %s", rt.Method, p, rt.Scope, r.Status, r.Raw)
		}
		if rt.Scope == "" {
			continue
		}
		org := w.acme
		if slices.Contains(service.PrimaryServiceAccountScopes, rt.Scope) {
			org = primary
		}
		if r := w.asServiceAccount(org, rt.Scope).do(rt.Method, p, body); guardRefused(r) {
			t.Errorf("%s %s with %q: %d %s", rt.Method, p, rt.Scope, r.Status, r.Raw)
		}
	}
}

// The service account endpoints: an org admin makes one (its secret shown once, with where it gets tokens), lists,
// changes, rotates and deletes it; a manager does not see them; private_key_jwt gets no secret and has none to rotate.
func TestServiceAccountEndpoints(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	const SA = A + "/service-accounts"
	r := ad.post(SA, map[string]any{"name": "freedom3", "scopes": []string{"users", "access"}})
	want(t, r, 201)
	id, secret := r.str("id"), r.str("secret")
	if !strings.HasPrefix(secret, "qsrs_") || !strings.HasSuffix(r.str("token_endpoint"), "/o/"+w.acme.ID+"/oauth/token") {
		t.Fatalf("create: %s", r.Raw)
	}
	l := ad.get(SA)
	if l.total() != 1 || strings.Contains(string(l.Raw), secret) || strings.Contains(string(l.Raw), `"secret"`) {
		t.Fatalf("list: %s", l.Raw)
	}
	if ad.get(A+"/clients").total() != 0 {
		t.Fatal("a service account is listed among the clients")
	}
	want(t, ad.get(A+"/clients/"+id), 404)
	r = ad.patch(SA+"/"+id, map[string]any{"scopes": []string{"users"}, "enabled": false})
	want(t, r, 200)
	if r.JSON["enabled"] != false || len(r.JSON["scopes"].([]any)) != 1 {
		t.Fatalf("update: %s", r.Raw)
	}
	r = ad.post(SA+"/"+id+"/secret", nil)
	want(t, r, 200)
	if r.str("secret") == "" || r.str("secret") == secret {
		t.Fatalf("rotate: %s", r.Raw)
	}
	wantField(t, ad.post(SA, map[string]any{"name": "x", "scopes": []string{"import"}}), 422, "scopes")
	wantField(t, ad.post(SA, map[string]any{"name": "x", "scopes": []string{"users"}, "token_endpoint_auth_method": "none"}), 422, "token_endpoint_auth_method")
	jwt := ad.post(SA, map[string]any{"name": "keys", "scopes": []string{"users"}, "token_endpoint_auth_method": "private_key_jwt",
		"jwks_uri": "https://deploy.example/jwks"})
	want(t, jwt, 201)
	if _, has := jwt.JSON["secret"]; has {
		t.Fatalf("private_key_jwt got a secret: %s", jwt.Raw)
	}
	wantField(t, ad.post(SA+"/"+jwt.str("id")+"/secret", nil), 422, "token_endpoint_auth_method")
	want(t, w.as("manager").get(SA), 403)
	want(t, ad.delete(SA+"/"+id), 200)
	want(t, ad.get(SA+"/"+id), 404)
}

// Creating an organization may make its first service account, returned with its secret; a bad one makes nothing.
func TestCreateOrgWithServiceAccount(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")
	r := su.post("/api/orgs", map[string]any{"name": "fortix", "service_account": map[string]any{"name": "setup", "scopes": []string{"users", "import"}}})
	want(t, r, 201)
	sa, _ := r.JSON["service_account"].(map[string]any)
	if sa == nil || sa["secret"] == "" || sa["name"] != "setup" {
		t.Fatalf("create: %s", r.Raw)
	}
	if r := su.post("/api/orgs", map[string]any{"name": "plain"}); r.Status != 201 || r.JSON["service_account"] != nil {
		t.Fatalf("without one: %d %s", r.Status, r.Raw)
	}
	wantField(t, su.post("/api/orgs", map[string]any{"name": "bad", "service_account": map[string]any{"name": "x", "scopes": []string{"orgs:create"}}}), 422, "service_account.scopes")
	want(t, su.get("/api/orgs/bad"), 404)
	// a personal API token makes no service account (its scopes would outlive the token), nor the organization
	wantField(t, w.withBearer("super", "admin").post("/api/orgs", map[string]any{"name": "bytoken",
		"service_account": map[string]any{"name": "x", "scopes": []string{"users"}}}), 403, "reauth")
	want(t, su.get("/api/orgs/bytoken"), 404)
}
