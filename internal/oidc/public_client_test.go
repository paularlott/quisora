package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

func TestPublicClientFlow(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	r, _ := h.publicLogin(cl, nil)
	if r.status != 200 || r.str("access_token") == "" || r.str("id_token") == "" {
		t.Fatalf("%v", r)
	}
	rt := r.str("refresh_token")
	if len(strings.Split(rt, ".")) != 3 {
		t.Fatalf("public client refresh token must rotate: %s", rt)
	}
	c, _ := h.session(h.user)
	// PKCE is mandatory at authorize for public clients too
	_, ch3 := pkce()
	if u := h.authorize(c, authzQuery(cl, ch3, url.Values{"code_challenge": {""}, "code_challenge_method": {""}})); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("%s", u)
	}
	// refresh rotation and reuse detection, with client_id only
	rf := func(tok string) tokResp {
		return h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {cl.ID}}, "", "")
	}
	r1 := rf(rt)
	if r1.status != 200 || r1.str("refresh_token") == "" || r1.str("refresh_token") == rt {
		t.Fatalf("%v", r1)
	}
	if rf(rt).status != 400 {
		t.Fatal("old public refresh token accepted")
	}
	if rf(r1.str("refresh_token")).status != 400 {
		t.Fatal("reuse did not revoke the family")
	}
	// the private-use scheme redirect is accepted exactly
	if u := h.authorize(c, authzQuery(cl, ch3, url.Values{"redirect_uri": {"com.example.app:/cb"}})); u.Path != "/oauth/consent" {
		t.Fatalf("private scheme: %s", u)
	}
	if resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, ch3, url.Values{"redirect_uri": {"com.example.app:/other"}}).Encode()); resp.StatusCode != 400 {
		t.Fatal("private scheme prefix accepted")
	}
}

func TestPublicClientTokenEndpointRules(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	conf, _ := h.newClient(nil)
	// client_credentials is never available to public clients (even if misconfigured)
	if r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}}, "", ""); r.status != 400 || r.m["error"] != "unauthorized_client" {
		t.Fatalf("cc for public: %v", r)
	}
	// a public client presenting a secret (post or basic) or an assertion is refused
	for name, r := range map[string]tokResp{
		"post":  h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}, "client_id": {cl.ID}, "client_secret": {"qsrs_x"}}, "", ""),
		"basic": h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}}, cl.ID, "qsrs_x"),
		"jwt": h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}, "client_id": {cl.ID},
			"client_assertion_type": {assertionType}, "client_assertion": {"x.y.z"}}, "", ""),
	} {
		if r.status != 401 {
			t.Errorf("%s: public client with credentials got %d", name, r.status)
		}
	}
	// a confidential client never falls back to "none"
	if r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {conf.ID}}, "", ""); r.status != 401 {
		t.Fatalf("confidential client authenticated without a secret: %d", r.status)
	}
	// unknown public client
	if r := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"nope"}}, "", ""); r.status != 401 {
		t.Fatal(r.status)
	}
}

func TestPublicClientVerifier(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	run := func(verifier func(v string) string) tokResp {
		c, csrf := h.session(h.user)
		v, ch := pkce()
		u := h.authorize(c, authzQuery(cl, ch, nil))
		_, redirect := h.decideConsent(c, csrf, u.Query().Get("flow"), true)
		code := loc(t, h.get(c, redirect)).Query().Get("code")
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cl.ID}, "redirect_uri": {cl.RedirectURIs[0]}}
		if vv := verifier(v); vv != "" {
			f.Set("code_verifier", vv)
		}
		return h.post("/oauth/token", f, "", "")
	}
	if r := run(func(v string) string { return v }); r.status != 200 {
		t.Fatalf("%v", r)
	}
	if r := run(func(string) string { return "" }); r.status != 400 || r.m["error"] != "invalid_grant" {
		t.Fatalf("missing verifier: %v", r)
	}
	if r := run(func(string) string { return strings.Repeat("b", 43) }); r.status != 400 || r.m["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %v", r)
	}
}

func TestPublicClientCORS(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	other := h.publicClient(func(in *service.ClientInput) { in.RedirectURIs = &[]string{"https://other.example/cb"} })
	preflight := func(path, origin string) *http.Response {
		req, _ := http.NewRequest("OPTIONS", h.env.URL+path, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
		resp, err := h.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for _, path := range []string{"/oauth/token", "/oauth/revoke", "/oauth/userinfo"} {
		resp := preflight(path, "https://spa.example")
		if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Origin") != "https://spa.example" ||
			!strings.Contains(resp.Header.Get("Vary"), "Origin") || resp.Header.Get("Access-Control-Allow-Credentials") != "" ||
			!strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "DPoP") || len(resp.Header.Values("Vary")) != 1 ||
			!strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Authorization") ||
			resp.Header.Get("Access-Control-Max-Age") == "" {
			t.Errorf("%s preflight: %d %v", path, resp.StatusCode, resp.Header)
		}
		// loopback on any port
		if resp := preflight(path, "http://127.0.0.1:5173"); resp.Header.Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5173" {
			t.Errorf("%s: loopback origin refused", path)
		}
		for _, o := range []string{"https://evil.example", "http://spa.example", "https://spa.example:8443", "http://localhost:5173", "null"} {
			if resp := preflight(path, o); resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s: origin %s allowed", path, o)
			}
		}
	}
	// actual requests
	r := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {cl.ID}}, "", "", "Origin", "https://spa.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "https://spa.example" || !strings.Contains(r.hdr.Get("Vary"), "Origin") {
		t.Errorf("token actual: %v", r.hdr)
	}
	// the origin of ANOTHER public client does not work for this client
	r = h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {cl.ID}}, "", "", "Origin", "https://other.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Error("cross-client origin allowed on token endpoint")
	}
	r = h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {other.ID}}, "", "", "Origin", "https://other.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "https://other.example" {
		t.Error("own origin refused")
	}
	// userinfo for a public client's token from its origin, and not from another
	pr, _ := h.publicLogin(cl, nil)
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"), "Origin", "https://spa.example")
	if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "https://spa.example" {
		t.Errorf("userinfo CORS: %d %v", resp.StatusCode, resp.Header)
	}
	resp = h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"), "Origin", "https://other.example")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("userinfo CORS for another client's origin")
	}
	// no Origin header, no CORS headers
	resp = h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"))
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS without Origin")
	}
	// a disabled public client's origin stops being allowed once evicted
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(cl.ID)
	if resp := preflight("/oauth/token", "https://spa.example"); resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("disabled client's origin still allowed")
	}
}

func TestPublicClientRevokeAndIntrospect(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	r, _ := h.publicLogin(cl, nil)
	rt := r.str("refresh_token")
	// introspection is for confidential clients only
	if x := h.post("/oauth/introspect", url.Values{"token": {r.str("access_token")}, "client_id": {cl.ID}}, "", ""); x.status != 401 || x.m["error"] != "invalid_client" {
		t.Fatalf("public introspect: %v", x)
	}
	// a public client may revoke its own refresh token
	if x := h.post("/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}}, "", ""); x.status != 200 {
		t.Fatalf("revoke: %d", x.status)
	}
	if x := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {cl.ID}}, "", ""); x.status != 400 {
		t.Fatal("revoked token still refreshes")
	}
	// but not someone else's
	r2, _ := h.publicLogin(cl, nil)
	other := h.publicClient(nil)
	h.post("/oauth/revoke", url.Values{"token": {r2.str("refresh_token")}, "client_id": {other.ID}}, "", "")
	if x := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r2.str("refresh_token")}, "client_id": {cl.ID}}, "", ""); x.status != 200 {
		t.Fatal("foreign public client revoked a token")
	}
}

// The CORS origin cache is bounded like every cache here (cacheTTL), whatever the store: within the bound it is
// served, past it read again.
func TestOriginCacheTTL(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	r := httptest.NewRequest("OPTIONS", "/oauth/token", nil)
	first := h.p.publicOrigins(r)
	if h.p.publicOrigins(r) != first {
		t.Error("the origins were read again within the bound")
	}
	first.at = time.Now().Add(-cacheTTL - time.Second)
	if h.p.publicOrigins(r) == first {
		t.Errorf("the origins were not read again after %v", cacheTTL+time.Second)
	}
}
