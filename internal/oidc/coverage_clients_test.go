package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestCoverageParseKeys(t *testing.T) {
	ks := newAssertionKeys(t)
	es, ed := ks[0], ks[1]
	var js JWKS
	_ = json.Unmarshal([]byte(es.jwks), &js)
	var je JWKS
	_ = json.Unmarshal([]byte(ed.jwks), &je)
	enc := js.Keys[0]
	enc.Use = "enc"
	broken := JWK{Kty: "EC", Crv: "P-256", X: "AA", Y: "AA", Kid: "broken"}
	wrongAlg := je.Keys[0]
	wrongAlg.Alg = AlgES256
	got := parseKeys([]JWK{enc, broken, wrongAlg, js.Keys[0], je.Keys[0]})
	if len(got) != 2 || got[0].alg != AlgES256 || got[1].alg != AlgEdDSA {
		t.Fatalf("%+v", got)
	}
	e := &oauthError{code: "invalid_request", desc: "x"}
	if e.Error() != "invalid_request: x" {
		t.Fatal(e.Error())
	}
	if !sameHTU("https://a.example", "https://a.example/") || sameHTU("::", "https://a.example/") || sameHTU("/path", "https://a.example/path") {
		t.Fatal("sameHTU")
	}
}

func TestCoverageClientAuthenticationShapes(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) })
	basic := func(raw string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw)) }
	cc := url.Values{"grant_type": {"client_credentials"}}
	req := func(auth string, form url.Values) tokResp {
		return h.post("/oauth/token", form, "", "", "Authorization", auth)
	}
	for name, tc := range map[string]struct {
		auth string
		form url.Values
	}{
		"scheme":       {"Bearer abc", cc},
		"not base64":   {"Basic !!!", cc},
		"no colon":     {basic("nocolon"), cc},
		"bad id esc":   {basic("%zz:" + secret), cc},
		"bad pw esc":   {basic(cl.ID + ":%zz"), cc},
		"id mismatch":  {basic(cl.ID + ":" + secret), url.Values{"grant_type": {"client_credentials"}, "client_id": {"other"}}},
		"wrong secret": {basic(cl.ID + ":wrong"), cc},
	} {
		if r := req(tc.auth, tc.form); r.status != 401 || r.m["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
	// two methods at once
	if r := h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}, cl.ID, secret); r.m["error"] != "invalid_request" {
		t.Errorf("basic and post: %v", r.m)
	}
	// a long client id is cut for the failure budget, not refused differently
	long := strings.Repeat("x", 300)
	if r := h.post("/oauth/token", cc, long, "s"); r.status != 401 {
		t.Errorf("long id: %d", r.status)
	}
}

func TestCoverageClientAssertionRefusals(t *testing.T) {
	k := newAssertionKeys(t)[0]
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKS = ptr(k.jwks)
	})
	post := func(f url.Values) tokResp {
		f.Set("grant_type", "client_credentials")
		return h.post("/oauth/token", f, "", "")
	}
	good := h.assertion(k, h.assertionClaims(cl, nil))
	for name, f := range map[string]url.Values{
		"garbage":            {"client_assertion": {"x.y.z"}, "client_assertion_type": {assertionType}},
		"payload not claims": {"client_assertion": {h.assertion(k, nil)}, "client_assertion_type": {assertionType}},
		"client_id differs":  {"client_assertion": {h.assertion(k, h.assertionClaims(cl, nil))}, "client_assertion_type": {assertionType}, "client_id": {"other"}},
		"with secret":        {"client_assertion": {good}, "client_assertion_type": {assertionType}, "client_secret": {"s"}},
		"wrong type":         {"client_assertion": {good}, "client_assertion_type": {"nope"}},
	} {
		if name == "payload not claims" {
			// a payload that is not a JSON object
			tok, err := signJWT(k.alg, k.priv, mkHeader(k.alg, "ck1", "JWT"), []byte(`[1]`))
			if err != nil {
				t.Fatal(err)
			}
			f["client_assertion"] = []string{tok}
		}
		if r := post(f); r.status != 401 && r.status != 400 {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
}

func TestCoverageRemoteJWKSFailures(t *testing.T) {
	k := newAssertionKeys(t)[0]
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/notjson":
			_, _ = w.Write([]byte("not json"))
		case "/huge":
			_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("a", jwksMaxBytes) + `"}`))
		default:
			_, _ = w.Write([]byte(k.jwks))
		}
	}))
	defer srv.Close()
	h := setup(t, nil)
	for _, path := range []string{"/notjson", "/huge", "/missing-port"} {
		uri := srv.URL + path
		if path == "/missing-port" {
			uri = "https://127.0.0.1:1/jwks" // refused
		}
		cl, _ := h.newClient(func(in *service.ClientInput) {
			in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
			in.JWKSURI = ptr(uri)
		})
		if r := h.ccWithAssertion(cl, h.assertion(k, h.assertionClaims(cl, nil))); r.status != 401 {
			t.Errorf("%s: %d %v", path, r.status, r.m)
		}
	}
	// a cache grown past its bound is emptied before the next entry
	h.p.jwksMu.Lock()
	for i := range 5001 {
		h.p.remoteKey[fmt.Sprintf("https://filler.example/%d", i)] = &remoteJWKS{}
	}
	h.p.jwksMu.Unlock()
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/ok")
	})
	if r := h.ccWithAssertion(cl, h.assertion(k, h.assertionClaims(cl, nil))); r.status != 200 {
		t.Fatalf("%d %v", r.status, r.m)
	}
	h.p.jwksMu.Lock()
	n := len(h.p.remoteKey)
	h.p.jwksMu.Unlock()
	if n > 10 {
		t.Fatalf("cache not emptied: %d", n)
	}
}
