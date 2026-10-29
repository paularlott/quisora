package scim_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

func TestAuthentication(t *testing.T) {
	e := newEnv(t)
	plain := e.mkUser(e.orgA, "plain", model.RoleUser)
	cases := []struct {
		name  string
		token string
		hdr   []string
		want  int
	}{
		{"no token", "", nil, 401},
		{"garbage", "nope", nil, 401},
		{"unknown api token", "qsr_abc_def", nil, 401},
		{"valid", e.admA, nil, 200},
		{"wrong scheme", "", []string{"Authorization", "Basic " + e.admA}, 401},
		{"DPoP scheme", "", []string{"Authorization", "DPoP garbage"}, 401},
		{"lowercase scheme", "", []string{"Authorization", "bearer " + e.admA}, 200},
	}
	for _, tc := range cases {
		r := e.do("GET", "/scim/v2/acme/Users", tc.token, nil, tc.hdr...)
		if r.Status != tc.want {
			t.Errorf("%s: %d %s", tc.name, r.Status, r.Raw)
		}
		if tc.want == 401 {
			if r.Header.Get("WWW-Authenticate") == "" || r.str("status") != "401" ||
				r.list("schemas")[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
				t.Errorf("%s: 401 shape %s %v", tc.name, r.Raw, r.Header)
			}
		}
	}
	// Scope: tokens without scim are refused, and roles that cannot use SCIM cannot even hold the scope.
	apiOnly := e.token(e.users["adm-a"], "api")
	if r := e.do("GET", "/scim/v2/acme/Users", apiOnly, nil); r.Status != 403 {
		t.Errorf("token without scim scope: %d", r.Status)
	}
	if _, _, err := e.Svc.CreateAPIToken(e.ctx, service.ActorForUser(plain, ""), service.APITokenInput{Name: "x", Scopes: []string{"scim"}}); err == nil {
		t.Fatal("plain user got scim scope")
	}
	// An owner demoted after minting loses access.
	mgr := e.mkUser(e.orgA, "will-demote", model.RoleManager)
	tok := e.token(mgr, "scim")
	if r := e.do("GET", "/scim/v2/acme/Users", tok, nil); r.Status != 200 {
		t.Fatal(r.Status)
	}
	if _, err := e.Svc.UpdateUser(e.ctx, service.System, mgr.ID, service.UserInput{Role: ptr(model.RoleUser)}); err != nil {
		t.Fatal(err)
	}
	// A token whose scopes now exceed its owner's role is no longer valid at all.
	if r := e.do("GET", "/scim/v2/acme/Users", tok, nil); r.Status != 401 {
		t.Errorf("demoted owner: %d", r.Status)
	}
	// Disabled owner.
	if _, err := e.Svc.UpdateUser(e.ctx, service.ActorForUser(e.users["adm-a"], ""), mgr.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if r := e.do("GET", "/scim/v2/acme/Users", tok, nil); r.Status != 401 {
		t.Errorf("disabled owner: %d", r.Status)
	}
}

func TestClientCredentialsVerifier(t *testing.T) {
	e := newEnv(t)
	cl, _, err := e.Svc.CreateServiceAccount(e.ctx, service.ActorForUser(e.Admin, ""), e.orgA.ID, service.ServiceAccountInput{Name: ptr("entra"),
		Scopes: ptr([]string{"scim"})})
	if err != nil {
		t.Fatal(err)
	}
	e.verify = func(_ *http.Request, _, b string) (*service.Actor, error) {
		if b == "jwt-for-entra" {
			return service.ActorForServiceAccount(cl, cl.Scopes, ""), nil
		}
		if b == "jwt-no-scope" {
			return service.ActorForServiceAccount(cl, []string{"openid"}, ""), nil
		}
		return nil, service.ErrBadToken
	}
	r := e.createUser("acme", "jwt-for-entra", map[string]any{"userName": "from-entra"})
	if r.Status != 201 {
		t.Fatalf("create via client: %d %s", r.Status, r.Raw)
	}
	// The client is bound to its own org.
	if r := e.do("GET", "/scim/v2/globex/Users", "jwt-for-entra", nil); r.Status != 404 {
		t.Errorf("client in other org: %d", r.Status)
	}
	// It may create managers but never admins.
	r = e.createUser("acme", "jwt-for-entra", map[string]any{"userName": "mgr", quisoraURN: map[string]any{"role": "manager"}})
	if r.Status != 201 {
		t.Errorf("client creating manager: %d %s", r.Status, r.Raw)
	}
	r = e.createUser("acme", "jwt-for-entra", map[string]any{"userName": "boss", quisoraURN: map[string]any{"role": "admin"}})
	if r.Status != 403 {
		t.Errorf("client creating admin: %d %s", r.Status, r.Raw)
	}
	// Groups work (it acts as an org admin).
	if r := e.do("POST", "/scim/v2/acme/Groups", "jwt-for-entra", map[string]any{"displayName": "Entra group"}); r.Status != 201 {
		t.Errorf("client creating group: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/Users", "jwt-no-scope", nil); r.Status != 403 {
		t.Errorf("verifier actor without scim scope: %d", r.Status)
	}
	if r := e.do("GET", "/scim/v2/acme/Users", "jwt-bogus", nil); r.Status != 401 {
		t.Errorf("rejected bearer: %d", r.Status)
	}
	// One form only: without the organization in the path there is no Users resource.
	if r := e.do("GET", "/scim/v2/Users?filter="+qs(`userName eq "from-entra"`), "jwt-for-entra", nil); r.Status != 404 {
		t.Errorf("org-less path: %d %s", r.Status, r.Raw)
	}
}

// A provisioning client's access token that cannot be checked (the store failed, not the token) is answered 503, as
// a personal API token is: 401 would make the client treat its token as revoked, and the failure would count against
// its address.
func TestAccessTokenStoreFailureIsUnavailable(t *testing.T) {
	e := newEnv(t)
	e.verify = func(r *http.Request, scheme, tok string) (*service.Actor, error) {
		return nil, fmt.Errorf("%w: the client could not be read", service.ErrUnavailable)
	}
	if r := e.do("GET", "/scim/v2/acme/Users", "jwt-for-entra", nil); r.Status != http.StatusServiceUnavailable {
		t.Fatalf("store failure while checking an access token: %d %s", r.Status, r.Raw)
	}
	e.verify = func(r *http.Request, scheme, tok string) (*service.Actor, error) { return nil, service.ErrBadToken }
	if r := e.do("GET", "/scim/v2/acme/Users", "jwt-for-entra", nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("control: a bad token: %d %s", r.Status, r.Raw)
	}
}

// Failed bearer authentications count against the address (shared with the management API): past the limit every
// SCIM request from it is refused before its token is looked at, the right one too.
func TestBearerFailuresAreRateLimited(t *testing.T) {
	e := newEnv(t)
	for i := range web.BearerFailuresPerOrgMin {
		if r := e.do("GET", "/scim/v2/acme/Users", "qsr_nosuch_secret", nil); r.Status != 401 {
			t.Fatalf("failure %d: %d %s", i+1, r.Status, r.Raw)
		}
	}
	r := e.do("GET", "/scim/v2/acme/Users", e.admA, nil)
	if r.Status != 429 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("valid token after the limit: %d %s", r.Status, r.Raw)
	}
}

// One organization's bad token, retried from an address shared with other tenants (an identity provider's provisioning
// egress), does not stop another organization's valid token from that address, however many organizations fail from
// it: only the budget of each organization counts. Made-up organization names are answered 404 before any token is
// looked at, and cost nothing.
func TestBearerFailuresAreCountedPerOrganization(t *testing.T) {
	e := newEnv(t)
	for range web.BearerFailuresPerOrgMin {
		e.do("GET", "/scim/v2/"+e.orgA.Name+"/Users", "qsr_nosuch_secret", nil)
	}
	if r := e.do("GET", "/scim/v2/"+e.orgA.Name+"/Users", e.admA, nil); r.Status != 429 {
		t.Fatalf("valid token of the organization whose budget is spent: %d %s", r.Status, r.Raw)
	}
	for i := range 10 { // ten tenants with expired tokens
		name := fmt.Sprintf("tenant-%d", i)
		e.org(name)
		for range web.BearerFailuresPerOrgMin {
			e.do("GET", "/scim/v2/"+name+"/Users", "qsr_nosuch_secret", nil)
		}
	}
	if r := e.do("GET", "/scim/v2/"+e.orgB.Name+"/Users", e.admB, nil); r.Status != 200 {
		t.Fatalf("valid token of another organization from an address where ten others failed: %d %s", r.Status, r.Raw)
	}
	for i := range 3 * web.BearerFailuresPerOrgMin {
		if r := e.do("GET", fmt.Sprintf("/scim/v2/made-up-%d/Users", i), "qsr_nosuch_secret", nil); r.Status != 404 {
			t.Fatalf("unknown organization %d: %d %s, want 404 before the token is looked at", i, r.Status, r.Raw)
		}
	}
	if r := e.do("GET", "/scim/v2/"+e.orgB.Name+"/Users", e.admB, nil); r.Status != 200 {
		t.Fatalf("valid token after requests for made-up organizations: %d %s", r.Status, r.Raw)
	}
}
