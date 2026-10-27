package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// secondOrg makes organization "acme" with a user who can sign in, next to the primary one.
func (h *harness) secondOrg() (*model.Org, *model.User) {
	h.t.Helper()
	ctx := context.Background()
	org, err := h.env.Svc.CreateOrg(ctx, h.admin, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")})
	if err != nil {
		h.t.Fatal(err)
	}
	pw := "correct horse battery"
	u, err := h.env.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: ptr("Bob"), Username: ptr("bob"), Email: ptr("bob@acme.test"),
		Password: &pw, Verified: ptr(true)})
	if err != nil {
		h.t.Fatal(err)
	}
	return org, u
}

// selfRegTenant is a tenant of organization orgID owning resource and allowing self-registered applications.
func (h *harness) selfRegTenant(orgID, name, resource string) *model.Tenant {
	h.t.Helper()
	set := model.DefaultTenantSettings()
	set.SelfRegistration, set.RequireMFA = true, false // the test sessions have no second factor
	tn, err := h.env.Svc.CreateTenant(context.Background(), h.admin, orgID,
		service.TenantInput{Name: ptr(name), Settings: &set, Resources: &[]string{resource}})
	if err != nil {
		h.t.Fatal(err)
	}
	return tn
}

// metadataServer serves one Client ID Metadata Document, for the application named by its URL, and makes the provider
// trust it. It returns the application as a client (its id the document's URL, as the application sends it).
func (h *harness) metadataServer(redirect string) *model.Client {
	h.t.Helper()
	var id string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Shared AI","redirect_uris":["` + redirect + `"],
			"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`))
	}))
	h.t.Cleanup(ts.Close)
	h.p.HTTP = ts.Client()
	id = ts.URL + "/client.json"
	return &model.Client{Meta: model.Meta{ID: id}, RedirectURIs: []string{redirect}}
}

// A token is its organization's: another organization's userinfo and introspection endpoints do not know it, though the
// organization's own take it by its id or by its name, and each organization's metadata document is its own, with its
// issuer and endpoints.
func TestTokensBelongToTheirOrganization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	org2, _ := h.secondOrg()
	rs2, rs2Secret, err := h.env.Svc.CreateClient(ctx, h.admin, org2.ID, service.ClientInput{Name: ptr("rs"),
		GrantTypes: &[]string{"client_credentials"}, IntrospectOrg: ptr(true), Scopes: &[]string{"api"}})
	if err != nil {
		t.Fatal(err)
	}

	userinfo := func(base string) int {
		return h.get(h.http, base+"/oauth/userinfo", "Authorization", "Bearer "+at).StatusCode
	}
	if st := userinfo(orgBase); st != 200 {
		t.Fatalf("userinfo at its own organization: %d", st)
	}
	if st := userinfo("/o/" + h.env.Primary.Name); st != 200 {
		t.Fatalf("userinfo at its own organization by name: %d", st)
	}
	if st := userinfo(web.OrgPath(org2.ID, "")); st != http.StatusUnauthorized {
		t.Fatalf("userinfo at another organization: %d, want 401", st)
	}
	// the verification a resource server in this process makes does not take it for another organization's either
	if _, err := h.p.verifyIn(ctx, org2.ID, at); err == nil {
		t.Error("an organization verified another's token")
	}
	if cl, err := h.p.verifyIn(ctx, h.env.Primary.ID, at); err != nil || cl.Iss != h.issuer() {
		t.Errorf("an organization's own token: %v %v", cl, err)
	}
	// introspection, even by a client allowed to see every token of its organization
	if got := h.introspect(rs2, rs2Secret, at); got["active"] != false {
		t.Errorf("another organization's token introspected: %v", got)
	}
	rs1, rs1Secret := h.newClient(func(in *service.ClientInput) { in.IntrospectOrg = ptr(true) })
	if got := h.introspect(rs1, rs1Secret, at); got["active"] != true {
		t.Errorf("an organization's token introspected by its own resource server: %v", got)
	}

	// each organization's metadata document is its own
	for _, org := range []*model.Org{h.env.Primary, org2} {
		var d map[string]any
		resp := h.get(h.http, web.OrgPath(org.ID, "/.well-known/openid-configuration"))
		if err := json.Unmarshal([]byte(body(resp)), &d); err != nil {
			t.Fatal(err)
		}
		iss := h.env.Cfg.OrgIssuer(org.ID)
		if d["issuer"] != iss || d["token_endpoint"] != iss+"/oauth/token" || d["jwks_uri"] != iss+"/oauth/jwks" {
			t.Errorf("%s: %v", org.Name, d)
		}
	}
}

// A client belongs to its organization: at another's endpoints it is unknown, and the answer is the one an unknown
// client gets.
func TestClientsBelongToTheirOrganization(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.GrantTypes = ptr([]string{"authorization_code", "refresh_token", "client_credentials", service.GrantDeviceCode})
		in.FirstParty = ptr(false)
	})
	org2, u2 := h.secondOrg()
	unknown := &model.Client{Meta: model.Meta{ID: "c_nobody"}, OrgID: org2.ID, AuthMethod: model.AuthMethodSecretPost, RedirectURIs: cl.RedirectURIs}

	// the endpoints that authenticate the client answer 401 invalid_client, whether it is unknown or another's
	form := url.Values{"grant_type": {"client_credentials"}}
	for _, path := range []string{"/oauth/token", "/oauth/introspect", "/oauth/revoke", "/oauth/par", "/oauth/device_authorization"} {
		f := url.Values{"token": {"x"}, "response_type": {"code"}, "redirect_uri": {cl.RedirectURIs[0]}}
		for k, v := range form {
			f[k] = v
		}
		other := h.clientPost(web.OrgPath(org2.ID, path), f, cl, secret)
		none := h.clientPost(web.OrgPath(org2.ID, path), f, unknown, secret)
		if other.status != http.StatusUnauthorized || other.str("error") != "invalid_client" ||
			other.status != none.status || other.str("error") != none.str("error") || other.str("error_description") != none.str("error_description") {
			t.Errorf("%s: another organization's client %d %v, an unknown one %d %v", path, other.status, other.m, none.status, none.m)
		}
		if own := h.clientPost(h.at(cl, path), f, cl, secret); own.status == http.StatusUnauthorized {
			t.Errorf("%s: the client is unknown at its own organization: %v", path, own.m)
		}
	}

	// the authorization endpoint and sign-out name an application the same way
	c, _ := h.session(u2)
	_, ch := pkce()
	page := func(path string, q url.Values) (int, string) {
		resp := h.get(c, web.OrgPath(org2.ID, path+"?"+q.Encode()))
		return resp.StatusCode, body(resp)
	}
	aq := authzQuery(cl, ch, nil)
	st, text := page("/oauth/authorize", aq)
	st2, text2 := page("/oauth/authorize", authzQuery(unknown, ch, nil))
	if st != http.StatusBadRequest || !strings.Contains(text, "not recognised") || st != st2 || len(text) < 100 || !strings.Contains(text2, "not recognised") {
		t.Errorf("authorize: %d %.80q, an unknown client: %d", st, text, st2)
	}
	if st, _ := page("/oauth/logout", url.Values{"client_id": {cl.ID}}); st != http.StatusBadRequest {
		t.Errorf("logout naming another organization's client: %d", st)
	}
}

// A sign-in in progress is its organization's: another's endpoints do not resume it, show its consent screen, nor take
// its decision.
func TestFlowsBelongToTheirOrganization(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	org2, u2 := h.secondOrg()
	c, _ := h.session(h.user)
	_, ch := pkce()
	consent := h.authorize(c, authzQuery(cl, ch, nil))
	flow := consent.Query().Get("flow")
	if consent.Path != orgBase+"/oauth/consent" || flow == "" {
		t.Fatalf("no consent step: %s", consent)
	}

	c2, csrf2 := h.session(u2) // a browser signed in to the other organization, carrying the flow's cookie
	h.copyFlowCookies(c, c2)
	if resp := h.get(c2, web.OrgPath(org2.ID, "/oauth/consent?flow="+flow)); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("another organization's consent page: %d", resp.StatusCode)
	}
	if resp := h.get(c2, web.OrgPath(org2.ID, "/oauth/authorize/resume?flow="+flow)); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("another organization's resume: %d", resp.StatusCode)
	}
	if resp := h.get(c2, web.OrgPath(org2.ID, "/oauth/authorize/cancel?flow="+flow)); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("another organization's cancel: %d", resp.StatusCode)
	}
	if st, _ := h.decideConsentIn(org2.ID, c2, csrf2, flow, true); st != http.StatusNotFound {
		t.Errorf("another organization's decision: %d", st)
	}
	// it is still there for its own organization
	if resp := h.get(c, consent.String()); resp.StatusCode != http.StatusOK {
		t.Errorf("the flow after another organization's attempts: %d", resp.StatusCode)
	}
}

// The same metadata-document application in two organizations is two applications: each stored in its organization,
// limited to the resources of its organization's tenants, and its tokens its organization's own.
func TestMetadataApplicationInTwoOrganizations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	org2, u2 := h.secondOrg()
	resA, resB := mcpResource, "https://mcp.acme.example/mcp"
	h.selfRegTenant(h.env.Primary.ID, "mcp", resA)
	h.selfRegTenant(org2.ID, "mcp", resB)
	app := h.metadataServer("http://127.0.0.1:44020/callback")

	// each organization lets it in for its own resource only
	c, _ := h.session(h.user)
	_, ch := pkce()
	notRecognised := func(orgID, resource string) {
		t.Helper()
		resp := h.get(c, web.OrgPath(orgID, "/oauth/authorize?"+authzQuery(app, ch, url.Values{"resource": {resource}}).Encode()))
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body(resp), "not recognised") {
			t.Errorf("%s: %s: %d", orgID, resource, resp.StatusCode)
		}
	}
	notRecognised(org2.ID, resA) // another organization's resource
	notRecognised(h.env.Primary.ID, resB)

	rA, _ := h.publicLoginIn(h.env.Primary, h.user, app, url.Values{"resource": {resA}})
	rB, _ := h.publicLoginIn(org2, u2, app, url.Values{"resource": {resB}})
	if rA.status != 200 || rB.status != 200 {
		t.Fatalf("tokens: %d %v / %d %v", rA.status, rA.m, rB.status, rB.m)
	}
	atA, atB := claimsOf(t, rA.str("access_token")), claimsOf(t, rB.str("access_token"))
	if atA["iss"] != h.issuer() || atB["iss"] != h.env.Cfg.OrgIssuer(org2.ID) || atA["client_id"] != app.ID || atB["client_id"] != app.ID ||
		atA["aud"] == nil || atB["sub"] != u2.ID {
		t.Errorf("claims: %v / %v", atA, atB)
	}

	// two records, one per organization
	for _, org := range []*model.Org{h.env.Primary, org2} {
		got, err := h.env.Svc.Clients.Get(ctx, model.ClientRecordID(org.ID, app.ID))
		if err != nil || got.OrgID != org.ID || got.TenantID != "" || got.ClientID() != app.ID || !got.IsMetadataClient() {
			t.Errorf("the record of %s: %+v %v", org.Name, got, err)
		}
	}
	if _, err := h.env.Svc.Clients.Get(ctx, app.ID); err == nil {
		t.Error("a record under the document's URL")
	}
	for _, org := range []*model.Org{h.env.Primary, org2} {
		if l, _ := h.env.Svc.SelfRegisteredApps(ctx, h.admin, org.ID); len(l) != 1 || l[0].ClientID != app.ID {
			t.Errorf("%s lists %+v", org.Name, l)
		}
	}

	// a refresh token and an access token of one organization are nothing to the other's endpoints
	refresh := func(orgID, rt string) tokResp {
		return h.post(web.OrgPath(orgID, "/oauth/token"), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt},
			"client_id": {app.ID}}, "", "")
	}
	if r := refresh(org2.ID, rA.str("refresh_token")); r.status != 400 || r.str("error") != "invalid_grant" {
		t.Errorf("refresh token of the first organization at the second: %d %v", r.status, r.m)
	}
	again := refresh(h.env.Primary.ID, rA.str("refresh_token")) // (a public client's refresh tokens rotate)
	if again.status != 200 {
		t.Errorf("refresh token at its own organization: %d %v", again.status, again.m)
	}
	if st := h.get(h.http, web.OrgPath(org2.ID, "/oauth/userinfo"), "Authorization", "Bearer "+rA.str("access_token")).StatusCode; st != http.StatusUnauthorized {
		t.Errorf("access token of the first organization at the second's userinfo: %d", st)
	}
	// revoking at the other organization (the same client_id there) ends nothing here
	if r := h.post(web.OrgPath(org2.ID, "/oauth/revoke"), url.Values{"token": {rA.str("access_token")}, "client_id": {app.ID}}, "", ""); r.status != 200 {
		t.Errorf("revoke: %d %v", r.status, r.m)
	}
	if r := refresh(h.env.Primary.ID, again.str("refresh_token")); r.status != 200 {
		t.Errorf("the first organization's grant ended by the second's revocation: %d %v", r.status, r.m)
	}
}

// Two organizations may own the same resource: an application signed in to the same API in each gets tokens of its
// organization, and an API that accepts one organization's tokens does not take the other's.
func TestSameResourceInTwoOrganizations(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	org2, u2 := h.secondOrg()
	h.selfRegTenant(h.env.Primary.ID, "mcp", mcpResource)
	h.selfRegTenant(org2.ID, "mcp", mcpResource)
	app := h.metadataServer("http://127.0.0.1:44021/callback")
	extra := url.Values{"resource": {mcpResource}}
	rA, _ := h.publicLoginIn(h.env.Primary, h.user, app, extra)
	rB, _ := h.publicLoginIn(org2, u2, app, extra)
	if rA.status != 200 || rB.status != 200 {
		t.Fatalf("tokens: %d %v / %d %v", rA.status, rA.m, rB.status, rB.m)
	}
	atA, atB := rA.str("access_token"), rB.str("access_token")
	claimsA, claimsB := claimsOf(t, atA), claimsOf(t, atB)
	if !strings.Contains(joinAny(claimsA["aud"]), mcpResource) || !strings.Contains(joinAny(claimsB["aud"]), mcpResource) {
		t.Fatalf("audiences: %v / %v", claimsA["aud"], claimsB["aud"])
	}
	if claimsA["iss"] == claimsB["iss"] || claimsA["iss"] != h.issuer() || claimsB["iss"] != h.env.Cfg.OrgIssuer(org2.ID) {
		t.Errorf("both organizations' tokens for the resource carry one issuer: %v / %v", claimsA["iss"], claimsB["iss"])
	}

	// the API's own checks: a resource server of each organization introspects its own organization's token only
	ctx := context.Background()
	rsFor := func(org *model.Org) (*model.Client, string) {
		c, secret, err := h.env.Svc.CreateClient(ctx, h.admin, org.ID, service.ClientInput{Name: ptr("mcp server"),
			GrantTypes: &[]string{"client_credentials"}, IntrospectOrg: ptr(true), Scopes: &[]string{"api"}})
		if err != nil {
			t.Fatal(err)
		}
		return c, secret
	}
	rsA, secA := rsFor(h.env.Primary)
	rsB, secB := rsFor(org2)
	for _, x := range []struct {
		name   string
		rs     *model.Client
		secret string
		token  string
		active bool
	}{{"A's server, A's token", rsA, secA, atA, true}, {"A's server, B's token", rsA, secA, atB, false},
		{"B's server, B's token", rsB, secB, atB, true}, {"B's server, A's token", rsB, secB, atA, false}} {
		if got := h.introspect(x.rs, x.secret, x.token); got["active"] != x.active {
			t.Errorf("%s: %v", x.name, got)
		}
	}
}

func joinAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return strings.Join(strsOf(v), " ")
}
