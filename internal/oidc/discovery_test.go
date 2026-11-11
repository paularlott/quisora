package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
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

	// The four addresses of the primary organization's metadata documents: under its path, and with the well-known
	// segment in front of it (RFC 8414 §3.1, where MCP clients look).
	wellKnown := func(org string) []string {
		var out []string
		for _, doc := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
			out = append(out, "/o/"+org+doc, doc+"/o/"+org)
		}
		return out
	}

	t.Run("documents", func(t *testing.T) {
		for _, path := range wellKnown(h.env.Primary.ID) {
			resp := h.get(h.http, path, "Origin", "https://anywhere.example")
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
				t.Errorf("%s: %d, CORS %q", path, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
			}
			var d map[string]any
			if err := json.Unmarshal([]byte(body(resp)), &d); err != nil {
				t.Fatal(err)
			}
			// The issuer is the organization's, and every endpoint is under it: a client that discovers the
			// organization never reaches another's.
			iss := h.issuer()
			if d["issuer"] != iss || d["token_endpoint"] != iss+"/oauth/token" {
				t.Errorf("%s: %v", path, d)
			}
			for k, v := range d {
				if u, ok := v.(string); ok && strings.HasPrefix(u, h.env.URL) && !strings.HasPrefix(u, iss) {
					t.Errorf("%s: %s %s is not under the issuer %s", path, k, u, iss)
				}
			}
			if m, _ := d["token_endpoint_auth_methods_supported"].([]any); !slices.Contains(m, any("none")) || slices.Contains(m, any("")) {
				t.Errorf("auth methods %v", m)
			}
			if m, _ := d["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
				t.Errorf("pkce methods %v", m)
			}
		}
	})

	// A document says "issuer": the address it is served at, so one asked for by the organization's name is sent to the
	// id form (permanently, with the same method) instead of being served with an issuer that is not its address.
	t.Run("name redirects to id", func(t *testing.T) {
		byName, byID := wellKnown(h.env.Primary.Name), wellKnown(h.env.Primary.ID)
		for i, path := range byName {
			resp := h.get(h.http, path, "Origin", "https://anywhere.example")
			body(resp)
			if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != byID[i] ||
				resp.Header.Get("Access-Control-Allow-Origin") != "*" {
				t.Errorf("%s: %d %q (CORS %q), want 308 to %s", path, resp.StatusCode, resp.Header.Get("Location"),
					resp.Header.Get("Access-Control-Allow-Origin"), byID[i])
			}
		}
		for _, path := range wellKnown("no-such-organization") {
			if resp := h.get(h.http, path); resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s: %d, want 404", path, resp.StatusCode)
			}
		}
		// the other endpoints take either form
		if resp := h.get(h.http, "/o/"+h.env.Primary.Name+"/oauth/jwks"); resp.StatusCode != http.StatusOK {
			t.Errorf("jwks by name: %d", resp.StatusCode)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		resp := h.get(h.http, h.orgBase+"/oauth/jwks", "Origin", "https://anywhere.example")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "*" ||
			!strings.Contains(resp.Header.Get("Cache-Control"), "max-age") {
			t.Errorf("jwks headers %d %v", resp.StatusCode, resp.Header)
		}
		first := body(resp)
		set, err := ParseJWKS([]byte(first))
		if err != nil || len(set) != 1 || set[0].Kty != "EC" || set[0].Alg != AlgES256 || set[0].Kid == "" {
			t.Fatalf("jwks %+v %v", set, err)
		}
		if again := body(h.get(h.http, h.orgBase+"/oauth/jwks")); again != first { // served from the cache
			t.Errorf("the key set changed between two reads: %s", again)
		}
	})

	t.Run("cors", func(t *testing.T) {
		// no CORS on the token endpoint for an unknown origin
		if r := h.post(h.orgBase+"/oauth/token", url.Values{}, "", "", "Origin", "https://evil.example"); r.hdr.Get("Access-Control-Allow-Origin") != "" {
			t.Error("token endpoint leaked CORS")
		}
		// the public documents answer a preflight
		rec := httptest.NewRecorder()
		handlePreflight(rec, httptest.NewRequest(http.MethodOptions, h.orgBase+"/.well-known/openid-configuration", nil))
		if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") == "" {
			t.Errorf("preflight: %d %v", rec.Code, rec.Header())
		}
	})

	t.Run("features", func(t *testing.T) {
		d := document(h.orgBase + "/.well-known/openid-configuration")
		issuer := h.issuer()
		// Public clients revoke their own tokens, so revocation lists "none"; introspection is confidential only.
		if !slices.Contains(strsOf(d["revocation_endpoint_auth_methods_supported"]), "none") ||
			slices.Contains(strsOf(d["introspection_endpoint_auth_methods_supported"]), "none") {
			t.Errorf("auth methods: %v / %v", d["revocation_endpoint_auth_methods_supported"], d["introspection_endpoint_auth_methods_supported"])
		}
		if d["pushed_authorization_request_endpoint"] != issuer+"/oauth/par" || d["require_pushed_authorization_requests"] != false {
			t.Errorf("par: %v %v", d["pushed_authorization_request_endpoint"], d["require_pushed_authorization_requests"])
		}
		if !slices.Contains(strsOf(d["claims_supported"]), "picture") {
			t.Errorf("claims_supported lacks picture: %v", d["claims_supported"])
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
		if d["registration_endpoint"] != issuer+"/oauth/register" || d["client_id_metadata_document_supported"] != true {
			t.Errorf("registration: %v %v", d["registration_endpoint"], d["client_id_metadata_document_supported"])
		}
	})
}

// keyListErr fails every listing of the signing keys with err.
type keyListErr struct {
	store.Store
	err error
}

func (s keyListErr) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindKey {
		return nil, s.err
	}
	return s.Store.List(ctx, kind, q)
}

// Past the cache's bound, a store that refuses (unavailable: one of the keys may have been revoked since) makes the
// JWKS unavailable rather than publish the keys last loaded; a store that fails otherwise keeps them standing in.
func TestJWKSPastItsBoundNotServedWhileTheStoreRefuses(t *testing.T) {
	h := setup(t, nil)
	if resp := h.get(h.http, h.orgBase+"/oauth/jwks"); resp.StatusCode != 200 {
		t.Fatalf("setup: %d", resp.StatusCode)
	}
	good := h.env.Svc.Keys.S
	stale := func() { // the cached set is due for a reload
		ks := *h.p.keySet.Load()
		ks.loaded = time.Time{}
		h.p.keySet.Store(&ks)
	}
	h.env.Svc.Keys.S = keyListErr{good, errors.New("database hiccup")}
	stale()
	if resp := h.get(h.http, h.orgBase+"/oauth/jwks"); resp.StatusCode != 200 {
		t.Fatalf("a store that cannot be read: %d, want the keys last loaded", resp.StatusCode)
	}
	h.env.Svc.Keys.S = keyListErr{good, store.ErrUnavailable}
	stale()
	if resp := h.get(h.http, h.orgBase+"/oauth/jwks"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a store that refuses, past the bound: %d, want 503", resp.StatusCode)
	}
	h.env.Svc.Keys.S = good
	stale()
	if resp := h.get(h.http, h.orgBase+"/oauth/jwks"); resp.StatusCode != 200 {
		t.Fatalf("once the store answers again: %d", resp.StatusCode)
	}
}
