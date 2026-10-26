package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// The discovery documents and the key set are read-only views of the default configuration, so the subtests share one
// harness.
func TestDiscovery(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	document := func(path string) map[string]any {
		t.Helper()
		var d map[string]any
		if err := json.Unmarshal([]byte(body(h.get(h.http, path))), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}

	t.Run("documents", func(t *testing.T) {
		for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
			resp := h.get(h.http, path, "Origin", "https://anywhere.example")
			if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
				t.Errorf("%s: no CORS", path)
			}
			var d map[string]any
			if err := json.Unmarshal([]byte(body(resp)), &d); err != nil {
				t.Fatal(err)
			}
			if d["issuer"] != h.env.URL || d["token_endpoint"] != h.env.URL+"/oauth/token" {
				t.Errorf("%s: %v", path, d)
			}
			if m, _ := d["token_endpoint_auth_methods_supported"].([]any); !slices.Contains(m, any("none")) || slices.Contains(m, any("")) {
				t.Errorf("auth methods %v", m)
			}
			if m, _ := d["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
				t.Errorf("pkce methods %v", m)
			}
		}
	})

	t.Run("jwks", func(t *testing.T) {
		resp := h.get(h.http, "/oauth/jwks", "Origin", "https://anywhere.example")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "*" ||
			!strings.Contains(resp.Header.Get("Cache-Control"), "max-age") {
			t.Errorf("jwks headers %d %v", resp.StatusCode, resp.Header)
		}
		first := body(resp)
		set, err := ParseJWKS([]byte(first))
		if err != nil || len(set) != 1 || set[0].Kty != "EC" || set[0].Alg != AlgES256 || set[0].Kid == "" {
			t.Fatalf("jwks %+v %v", set, err)
		}
		if again := body(h.get(h.http, "/oauth/jwks")); again != first { // served from the cache
			t.Errorf("the key set changed between two reads: %s", again)
		}
	})

	t.Run("cors", func(t *testing.T) {
		// no CORS on the token endpoint for an unknown origin
		if r := h.post("/oauth/token", url.Values{}, "", "", "Origin", "https://evil.example"); r.hdr.Get("Access-Control-Allow-Origin") != "" {
			t.Error("token endpoint leaked CORS")
		}
		// the public documents answer a preflight
		rec := httptest.NewRecorder()
		handlePreflight(rec, httptest.NewRequest(http.MethodOptions, "/.well-known/openid-configuration", nil))
		if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") == "" {
			t.Errorf("preflight: %d %v", rec.Code, rec.Header())
		}
	})

	t.Run("features", func(t *testing.T) {
		d := document("/.well-known/openid-configuration")
		issuer := h.env.Cfg.Issuer()
		// Public clients revoke their own tokens, so revocation lists "none"; introspection is confidential only.
		if !slices.Contains(strsOf(d["revocation_endpoint_auth_methods_supported"]), "none") ||
			slices.Contains(strsOf(d["introspection_endpoint_auth_methods_supported"]), "none") {
			t.Errorf("auth methods: %v / %v", d["revocation_endpoint_auth_methods_supported"], d["introspection_endpoint_auth_methods_supported"])
		}
		if d["pushed_authorization_request_endpoint"] != issuer+"/oauth/par" || d["require_pushed_authorization_requests"] != false {
			t.Errorf("par: %v %v", d["pushed_authorization_request_endpoint"], d["require_pushed_authorization_requests"])
		}
		if !slices.Contains(strsOf(d["claims_supported"]), "tags") {
			t.Errorf("claims_supported lacks tags: %v", d["claims_supported"])
		}
		for _, f := range []string{"id_token_signing_alg_values_supported", "token_endpoint_auth_signing_alg_values_supported",
			"dpop_signing_alg_values_supported"} {
			if algs := strsOf(d[f]); len(algs) != 4 || algs[3] != AlgPS256 {
				t.Errorf("%s: %v", f, d[f])
			}
		}
		if d["device_authorization_endpoint"] != issuer+"/oauth/device_authorization" ||
			!slices.Contains(strsOf(d["grant_types_supported"]), service.GrantDeviceCode) {
			t.Errorf("device: %v %v", d["device_authorization_endpoint"], d["grant_types_supported"])
		}
		if d["registration_endpoint"] != h.env.URL+"/oauth/register" || d["client_id_metadata_document_supported"] != true {
			t.Errorf("registration: %v %v", d["registration_endpoint"], d["client_id_metadata_document_supported"])
		}
	})
}
