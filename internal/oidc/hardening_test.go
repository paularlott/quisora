package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// Personal API tokens: only a token made for applications (the api scope) is active to them, only to the clients
// in its audience when it has one, and introspection names its scope and audience.
func TestIntrospectAPITokenScopeAndAudience(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	rs, rsSecret := h.newClient(nil)
	other, otherSecret := h.newClient(nil)

	// A token for Quisora's own APIs is no application's business.
	_, adminTok, err := h.env.Svc.CreateAPIToken(ctx, h.admin, service.APITokenInput{Name: "ops", Scopes: []string{service.ScopeAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	if m := h.introspect(rs, rsSecret, adminTok); m["active"] != false || len(m) != 1 {
		t.Fatalf("admin-scope token introspected: %v", m)
	}
	// Mixing api with Quisora's own scopes is refused at mint.
	if _, _, err := h.env.Svc.CreateAPIToken(ctx, h.admin, service.APITokenInput{Name: "mix", Scopes: []string{service.ScopeAPI, service.ScopeAdmin}}); err == nil {
		t.Fatal("minted an api+admin token")
	}

	// An api token without an audience: any confidential client of the org.
	_, open, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "open", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if m := h.introspect(other, otherSecret, open); m["active"] != true || m["scope"] != "api" || m["aud"] != nil {
		t.Fatalf("open api token: %v", m)
	}

	// With an audience: only the listed client.
	_, scoped, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "rs only",
		Scopes: []string{"api"}, Audience: []string{rs.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if m := h.introspect(rs, rsSecret, scoped); m["active"] != true || m["aud"] != rs.ID || m["scope"] != "api" {
		t.Fatalf("audience client: %v", m)
	}
	if m := h.clientPost("/oauth/introspect", url.Values{"token": {scoped}}, other, otherSecret); len(m.m) != 1 || m.m["active"] != false {
		t.Fatalf("client outside the audience: %v", m.m)
	}
	// An audience is for api tokens, and names clients of the owner's organization only.
	if _, _, err := h.env.Svc.CreateAPIToken(ctx, h.admin, service.APITokenInput{Name: "x", Scopes: []string{service.ScopeAdmin},
		Audience: []string{rs.ID}}); err == nil {
		t.Fatal("audience on an admin token")
	}
	if _, _, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "x", Scopes: []string{"api"},
		Audience: []string{"no-such-client"}}); err == nil {
		t.Fatal("unknown audience accepted")
	}
}

// Resource indicators (RFC 8707): a client may name only the resources registered for it, at the authorization
// endpoint and with client_credentials; the consent page shows them and consent is remembered per resource set.
func TestResourceIndicatorsAllowList(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.FirstParty = ptr(false)
		in.Name = ptr("Billing App")
		in.Resources = &[]string{"https://api.example/a", "https://api.example/b"}
	})
	c, csrf := h.session(h.user)
	v, ch := pkce()

	// unlisted: invalid_target back to the client
	if u := h.authorize(c, authzQuery(cl, ch, url.Values{"resource": {"https://evil.example/"}})); u.Query().Get("error") != "invalid_target" {
		t.Fatalf("unlisted resource at authorize: %s", u)
	}
	cc := h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"https://evil.example/"}}, cl, secret)
	if cc.m["error"] != "invalid_target" {
		t.Fatalf("unlisted resource with client_credentials: %v", cc.m)
	}
	cc = h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"https://api.example/b"}}, cl, secret)
	if aud, _ := claimsOf(t, cc.str("access_token"))["aud"].([]any); len(aud) != 2 || aud[1] != "https://api.example/b" {
		t.Fatalf("client_credentials aud: %v (%v)", aud, cc.m)
	}

	// listed: the consent page names it, and the access token is for it
	u := h.authorize(c, authzQuery(cl, ch, url.Values{"resource": {"https://api.example/a"}}))
	if u.Path != "/oauth/consent" {
		t.Fatalf("expected consent: %s", u)
	}
	flowID := u.Query().Get("flow")
	if page := body(h.get(c, u.RequestURI())); !strings.Contains(page, "https://api.example/a") {
		t.Fatalf("consent page does not show the resource: %s", page)
	}
	approve := func(flow string) string {
		b, _ := json.Marshal(map[string]any{"flow": flow, "approve": true})
		req, _ := http.NewRequest("POST", h.env.URL+"/api-internal/oauth/consent", strings.NewReader(string(b)))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]string
		_ = json.Unmarshal([]byte(body(r)), &out)
		return out["redirect"]
	}
	code := loc(t, h.get(c, approve(flowID))).Query().Get("code")
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, secret)
	if aud, _ := claimsOf(t, r.str("access_token"))["aud"].([]any); len(aud) != 2 || aud[0] != cl.ID || aud[1] != "https://api.example/a" {
		t.Fatalf("aud: %v (%v)", aud, r.m)
	}

	// consent is remembered for that resource ...
	_, ch2 := pkce()
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"resource": {"https://api.example/a"}, "prompt": {"none"}})); u.Query().Get("code") == "" {
		t.Fatalf("consent for the same resource not remembered: %s", u)
	}
	// ... but not for another one
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"resource": {"https://api.example/b"}, "prompt": {"none"}})); u.Query().Get("error") != "consent_required" {
		t.Fatalf("consent for another resource: %s", u)
	}
	if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"resource": {"https://api.example/b"}})); u.Path != "/oauth/consent" {
		t.Fatalf("another resource without consent: %s", u)
	}
	// Discovery is unchanged.
	if d := h.get(c, "/.well-known/openid-configuration"); d.StatusCode != 200 {
		t.Fatalf("discovery: %d", d.StatusCode)
	}
}

// Addresses Quisora itself calls are https only, and a client's jwks_uri is fetched through the SSRF guard.
func TestOutboundClientURIs(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	for _, bad := range []string{"http://rp.example/logout", "http://127.0.0.1/logout", "com.example.app:/logout", "https://rp.example/x#frag", "https:///nohost"} {
		if _, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("x"),
			RedirectURIs: &[]string{rpCallback}, BackchannelURI: ptr(bad)}); err == nil {
			t.Errorf("back-channel URI %q accepted", bad)
		}
		if _, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("x"),
			RedirectURIs: &[]string{rpCallback}, JWKSURI: ptr(bad)}); err == nil {
			t.Errorf("jwks_uri %q accepted", bad)
		}
	}
	if _, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("ok"),
		RedirectURIs: &[]string{rpCallback}, BackchannelURI: ptr("https://rp.example/logout")}); err != nil {
		t.Errorf("https back-channel URI: %v", err)
	}
	// The provider's own client (not the test one) refuses loopback addresses for client JWKS.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"keys":[]}`)) }))
	defer srv.Close()
	p := New(h.env.Server)
	if _, err := p.fetch(ctx, srv.URL+"/jwks", 1024); err == nil {
		t.Fatal("client JWKS fetched from a loopback address")
	}
	if keys := p.remoteKeys(ctx, srv.URL+"/jwks", true); len(keys) != 0 {
		t.Fatal("keys from a loopback jwks_uri")
	}
}
