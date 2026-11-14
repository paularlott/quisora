package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A client authenticates only the way it is registered to (token_endpoint_auth_method).
func TestClientAuthMethodEnforced(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	post, psecret := h.newClient(nil) // client_secret_post
	basic, bsecret := h.newClient(func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) })
	// a Basic client: client_credentials with the secret works, a wrong one is refused
	if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, basic.ID, bsecret); r.status != 200 || r.str("scope") != "api" {
		t.Errorf("client_credentials over Basic: %d %v", r.status, r.m)
	}
	if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}}, basic.ID, bsecret+"x"); r.status != 401 {
		t.Errorf("wrong secret over Basic: %d", r.status)
	}
	tok := url.Values{"token": {"x"}}
	if r := h.post(h.orgBase+"/oauth/introspect", tok, post.ID, psecret); r.status != 401 {
		t.Errorf("post client over Basic: %d", r.status)
	}
	if r := h.post(h.orgBase+"/oauth/introspect", url.Values{"token": {"x"}, "client_id": {basic.ID}, "client_secret": {bsecret}}, "", ""); r.status != 401 {
		t.Errorf("basic client over the form: %d", r.status)
	}
	for _, c := range []struct {
		cl     *model.Client
		secret string
	}{{post, psecret}, {basic, bsecret}} {
		if r := h.clientPost(h.orgBase+"/oauth/introspect", tok, c.cl, c.secret); r.status != 200 {
			t.Errorf("%s the registered way: %d", c.cl.AuthMethod, r.status)
		}
	}
}

// Failed client authentication is limited per client, and per address; each subtest starts from a clean budget.
func TestClientAuthFailureLimit(t *testing.T) {
	t.Parallel()
	// Failed client authentications are limited per client and IP address: past the limit failures answer 429, but the
	// right secret still works, and other clients from the same address are not affected.
	t.Run("failures of one client", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		other, _ := h.newClient(nil)
		form := func(c *model.Client, s string) url.Values {
			return url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ID}, "client_secret": {s}}
		}
		for i := 0; i < clientAuthFailuresPerMin; i++ {
			if r := h.post(h.orgBase+"/oauth/token", form(cl, "wrong"), "", ""); r.status != 401 {
				t.Fatalf("attempt %d: %d", i, r.status)
			}
		}
		r := h.post(h.orgBase+"/oauth/token", form(cl, "wrong"), "", "")
		if r.status != 429 || r.hdr.Get("Retry-After") == "" || r.str("error") != "invalid_client" {
			t.Fatalf("over the limit: %d %v", r.status, r.m)
		}
		// over the limit even the right secret is refused (guessing cannot go on, and a hit teaches nothing)
		if r := h.post(h.orgBase+"/oauth/token", form(cl, secret), "", ""); r.status != 429 {
			t.Errorf("right secret while limited: %d", r.status)
		}
		if r := h.post(h.orgBase+"/oauth/token", form(other, "wrong"), "", ""); r.status != 401 {
			t.Errorf("another client from the same address: %d", r.status)
		}
	})

	// Failures that need no secret (unknown client ids, no client authentication at all) do not lock out real clients from
	// the same address while under the address ceiling: not one sending client_id, nor a private_key_jwt client leaving
	// it out (RFC 7523 §3).
	t.Run("failures that need no secret", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		k := newAssertionKeys(t)[0]
		jc, _ := h.newClient(func(in *service.ClientInput) {
			in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
			in.JWKS = ptr(k.jwks)
		})
		for i := 0; i <= clientAuthFailuresPerMin; i++ {
			h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {fmt.Sprintf("nope-%d", i)},
				"client_secret": {"x"}}, "", "")
			h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}}, "", "")
			h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType},
				"client_assertion": {"x.y.z"}}, "", "")
		}
		if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}, "client_secret": {secret}}, "", ""); r.status != 200 {
			t.Errorf("client_secret_post after the burst: %d %v", r.status, r.m)
		}
		for _, path := range []string{h.orgBase + "/oauth/introspect", h.orgBase + "/oauth/revoke"} {
			if r := h.post(path, url.Values{"token": {"x"}, "client_id": {cl.ID}, "client_secret": {secret}}, "", ""); r.status != 200 {
				t.Errorf("%s after the burst: %d %v", path, r.status, r.m)
			}
		}
		if r := h.ccWithAssertion(jc, h.assertion(k, h.assertionClaims(jc, nil))); r.status != 200 {
			t.Errorf("private_key_jwt without client_id after the burst: %d %v", r.status, r.m)
		}
	})

	// Making up a new client id for every attempt does not get a fresh budget forever: past the address ceiling every
	// attempt from that address is refused, a wrong secret of a real client's included; one that proves its secret is
	// not (a confidential client's failures are its own, and behind a shared address other clients' must not keep it
	// from its users).
	t.Run("new client ids per address", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		for i := 0; i < failuresPerIPMin; i++ {
			if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {fmt.Sprintf("made-up-%d", i)},
				"client_secret": {"x"}}, "", ""); r.status != 401 {
				t.Fatalf("attempt %d: %d", i, r.status)
			}
		}
		r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"made-up-last"}, "client_secret": {"x"}}, "", "")
		if r.status != 429 || r.str("error") != "temporarily_unavailable" { // "try again": not a verdict on a client's credentials
			t.Fatalf("past the address ceiling: %d %v", r.status, r.m)
		}
		if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}, "client_secret": {"wrong"}}, "", ""); r.status != 429 {
			t.Errorf("real client's wrong secret from the same address past the ceiling: %d", r.status)
		}
		if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}, "client_secret": {secret}}, "", ""); r.status != 200 {
			t.Errorf("real client's right secret from the same address past the ceiling: %d", r.status)
		}
	})

	// The Basic user name is form-urlencoded (RFC 6749 §2.3.1): encoding the client id differently does not get a
	// fresh budget for guessing its secret.
	t.Run("percent-encoded client id", func(t *testing.T) {
		h := setup(t, nil)
		cl, _ := h.newClient(nil)
		for i := 0; i < clientAuthFailuresPerMin; i++ {
			h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}}, cl.ID, "wrong")
		}
		enc := ""
		for _, b := range []byte(cl.ID) {
			enc += fmt.Sprintf("%%%02X", b)
		}
		req, _ := http.NewRequest(http.MethodPost, h.env.URL+h.orgBase+"/oauth/token", strings.NewReader("grant_type=client_credentials"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(enc, "wrong")
		resp, err := h.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 429 {
			t.Errorf("percent-encoded client id past the limit: %d", resp.StatusCode)
		}
	})
}

func TestPrivateKeyJWT(t *testing.T) {
	t.Parallel()
	for _, k := range newAssertionKeys(t) {
		t.Run(k.alg, func(t *testing.T) {
			h := setup(t, nil)
			cl, secret := h.newClient(func(in *service.ClientInput) {
				in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
				in.JWKS = ptr(k.jwks)
			})
			claims := h.assertionClaims(cl, nil)
			if r := h.ccWithAssertion(cl, h.assertion(k, claims)); r.status != 200 {
				t.Fatalf("valid assertion: %v", r.m)
			}
			// jti replay
			if r := h.ccWithAssertion(cl, h.assertion(k, claims)); r.status != 401 {
				t.Fatalf("replayed jti accepted: %d", r.status)
			}
			// issuer as audience is fine
			if r := h.ccWithAssertion(cl, h.assertion(k, h.assertionClaims(cl, func(m map[string]any) { m["aud"] = []string{h.issuer()} }))); r.status != 200 {
				t.Fatalf("issuer audience: %v", r.m)
			}
			for name, edit := range map[string]func(map[string]any){
				"wrong aud":     func(m map[string]any) { m["aud"] = "https://other.example/token" },
				"expired":       func(m map[string]any) { m["exp"] = time.Now().Add(-5 * time.Minute).Unix() },
				"too long":      func(m map[string]any) { m["exp"] = time.Now().Add(time.Hour).Unix() },
				"no exp":        func(m map[string]any) { delete(m, "exp") },
				"no jti":        func(m map[string]any) { delete(m, "jti") },
				"iss!=sub":      func(m map[string]any) { m["sub"] = "someone" },
				"wrong iss":     func(m map[string]any) { m["iss"] = "x"; m["sub"] = "x" },
				"future iat":    func(m map[string]any) { m["iat"] = time.Now().Add(time.Hour).Unix() },
				"not yet valid": func(m map[string]any) { m["nbf"] = time.Now().Add(time.Hour).Unix() },
			} {
				if r := h.ccWithAssertion(cl, h.assertion(k, h.assertionClaims(cl, edit))); r.status != 401 {
					t.Errorf("%s accepted (%d)", name, r.status)
				}
			}
			// signed by a different key
			rogue := newAssertionKeys(t)
			for _, rk := range rogue {
				if rk.alg == k.alg {
					if r := h.ccWithAssertion(cl, h.assertion(rk, h.assertionClaims(cl, nil))); r.status != 401 {
						t.Error("rogue key accepted")
					}
				}
			}
			// the shared secret cannot be used instead, and an assertion needs the right assertion type
			if r := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret); r.status != 401 {
				t.Errorf("secret accepted for private_key_jwt client: %d", r.status)
			}
			bad := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_assertion": {h.assertion(k, h.assertionClaims(cl, nil))}}, "", "")
			if bad.status != 400 || bad.str("error") != "invalid_request" {
				t.Errorf("missing assertion type: %d %v", bad.status, bad.m)
			}
			// a confidential-secret client cannot use an assertion
			sc, _ := h.newClient(nil)
			if r := h.ccWithAssertion(sc, h.assertion(k, h.assertionClaims(sc, nil))); r.status != 401 {
				t.Error("assertion accepted for secret client")
			}
			// unknown/forged header alg
			parts := strings.Split(h.assertion(k, h.assertionClaims(cl, nil)), ".")
			parts[0] = b64.EncodeToString([]byte(`{"alg":"none"}`))
			if r := h.ccWithAssertion(cl, strings.Join(parts[:2], ".")+"."); r.status != 401 {
				t.Error("alg none accepted")
			}
		})
	}
}

func TestPrivateKeyJWTWithJWKSURI(t *testing.T) {
	t.Parallel()
	keys := newAssertionKeys(t)
	k := keys[0]
	jwks := k.jwks
	srv, hits := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(jwks)) })
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/jwks")
	})
	for range 3 {
		if r := h.ccWithAssertion(cl, h.assertion(k, h.assertionClaims(cl, nil))); r.status != 200 {
			t.Fatalf("%v", r.m)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("jwks fetched %d times, want 1 (cached)", hits.Load())
	}
	// key rotation at the client: new key published, unknown kid triggers one refetch
	nk := newAssertionKeys(t)[0]
	j, _ := EncodeJWK(nk.priv.Public(), "ck2", nk.alg)
	jb, _ := json.Marshal(JWKS{Keys: []JWK{j}})
	jwks = string(jb)
	h.p.remoteKey[srv.URL+"/jwks"].forced = time.Time{}
	rb, _ := json.Marshal(h.assertionClaims(cl, nil))
	rot, err := signJWT(nk.alg, nk.priv, mkHeader(nk.alg, "ck2", "JWT"), rb)
	if err != nil {
		t.Fatal(err)
	}
	if r := h.ccWithAssertion(cl, rot); r.status != 200 {
		t.Fatalf("rotated client key: %v", r.m)
	}
}

// The provider's own HTTP client (not the test one) refuses loopback, private and link-local addresses unless the
// configuration allows them, for the fetch itself and for a client's jwks_uri.
func TestSafeClientBlocksPrivateAddresses(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	p := New(h.env.Server)
	k := newAssertionKeys(t)[0]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(k.jwks)) }))
	defer srv.Close()
	ctx := context.Background()
	if _, err := p.fetch(ctx, srv.URL, jwksMaxBytes); err == nil {
		t.Fatal("loopback fetch allowed")
	}
	if keys := p.remoteKeys(ctx, srv.URL+"/jwks", true); len(keys) != 0 {
		t.Fatal("keys from a loopback jwks_uri")
	}
	h.env.Server.Cfg.Server.AllowedNetworks = []string{"127.0.0.1"} // read at each connection
	if _, err := p.fetch(ctx, srv.URL, jwksMaxBytes); err != nil {
		t.Fatalf("loopback in allowed_networks: %v", err)
	}
	h.env.Server.Cfg.Server.AllowedNetworks = nil
	h.env.Server.Cfg.Server.AllowPrivateNetworks = true
	if _, err := p.fetch(ctx, srv.URL, jwksMaxBytes); err != nil {
		t.Fatalf("loopback with allow_private_networks: %v", err)
	}
	if keys := p.remoteKeys(ctx, srv.URL+"/other", true); len(keys) != 1 { // another uri: the refused one is backing off
		t.Fatalf("keys from a loopback jwks_uri once allowed: %d", len(keys))
	}
	if _, err := p.fetch(ctx, "http://169.254.169.254/latest/meta-data", jwksMaxBytes); err == nil {
		t.Fatal("metadata address reachable")
	}
}

// RFC 7523 §3 / RFC 9126 §2: a client assertion may name the endpoint it is presented at as its audience, besides
// the issuer and the token endpoint; an assertion made for another endpoint is not taken at this one.
func TestAssertionAudienceMayBeTheEndpointCalled(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	k := newAssertionKeys(t)[0]
	c := h.jwtClient(k, nil)
	introspect := func(aud string) tokResp {
		tok := h.assertion(k, h.assertionClaims(c, func(m map[string]any) { m["aud"] = aud }))
		return h.post(h.orgBase+"/oauth/introspect", url.Values{"token": {"x"}, "client_assertion_type": {assertionType},
			"client_assertion": {tok}}, "", "")
	}
	if r := introspect(h.env.URL + h.orgBase + "/oauth/introspect"); r.status != 200 {
		t.Fatalf("aud = the introspection endpoint: %d %v", r.status, r.m)
	}
	if r := introspect(h.env.URL + h.orgBase + "/oauth/revoke"); r.status != 401 {
		t.Fatalf("aud = another endpoint: %d %v", r.status, r.m)
	}
}

// A jwks_uri is refetched for an unknown kid at most once per interval, never for a known kid with a bad signature, and
// a failing endpoint is backed off exponentially up to a cap. The interval is an hour here and the test moves the
// clock-dependent state into the past instead of waiting.
func TestJWKSURIRefetchPolicy(t *testing.T) {
	oldForce, oldMax := jwksForceEvery, jwksBackoffMax
	jwksForceEvery, jwksBackoffMax = time.Hour, 3*time.Hour
	defer func() { jwksForceEvery, jwksBackoffMax = oldForce, oldMax }()

	keys := newAssertionKeys(t)
	good, other := keys[0], newAssertionKeys(t)[0] // same alg, same kid "ck1", different key
	var hits, badHits atomic.Int32                 // requests for the good key set and for the failing one
	srv, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			badHits.Add(1)
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		hits.Add(1)
		_, _ = w.Write([]byte(good.jwks))
	})
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/jwks")
	})
	assertionWith := func(c *model.Client, k assertionKey, kid string) string {
		b, _ := json.Marshal(h.assertionClaims(c, nil))
		tok, err := signJWT(k.alg, k.priv, mkHeader(k.alg, kid, "JWT"), b)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	// elapse lets d pass for the forced-refetch interval and the backoff of one key set
	elapse := func(uri string, d time.Duration) {
		h.p.jwksMu.Lock()
		defer h.p.jwksMu.Unlock()
		rj := h.p.remoteKey[uri]
		rj.forced, rj.retryAt = rj.forced.Add(-d), rj.retryAt.Add(-d)
	}
	// retryIn is how long the key set is backed off for
	retryIn := func(uri string) time.Duration {
		h.p.jwksMu.Lock()
		defer h.p.jwksMu.Unlock()
		return time.Until(h.p.remoteKey[uri].retryAt)
	}
	if r := h.ccWithAssertion(cl, assertionWith(cl, good, "ck1")); r.status != 200 {
		t.Fatal(r.m)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	// known kid, wrong signature: never refetch, even after the interval
	elapse(srv.URL+"/jwks", 2*time.Hour)
	for range 5 {
		if r := h.ccWithAssertion(cl, assertionWith(cl, other, "ck1")); r.status != 401 {
			t.Fatalf("bogus assertion accepted: %v", r.m)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("known kid caused refetch: %d", hits.Load())
	}
	// unknown kid: at most one refetch per interval
	for range 5 {
		h.ccWithAssertion(cl, assertionWith(cl, other, "nope"))
	}
	if hits.Load() != 2 {
		t.Fatalf("unknown kid refetches: %d, want 2 total", hits.Load())
	}
	elapse(srv.URL+"/jwks", 2*time.Hour)
	for range 5 {
		h.ccWithAssertion(cl, assertionWith(cl, other, "nope"))
	}
	if hits.Load() != 3 {
		t.Fatalf("after interval: %d, want 3 total", hits.Load())
	}

	// failing endpoint: exponential backoff
	bad, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/bad")
	})
	badURI := srv.URL + "/bad"
	try := func() {
		for range 4 {
			h.ccWithAssertion(bad, assertionWith(bad, good, "ck1"))
		}
	}
	try()
	if badHits.Load() != 1 {
		t.Fatalf("failing uri hit %d times in a burst", badHits.Load())
	}
	if d := retryIn(badURI); d < 50*time.Minute || d > time.Hour {
		t.Fatalf("first backoff %v, want the interval (an hour)", d)
	}
	elapse(badURI, time.Hour+time.Minute) // past the first backoff
	try()
	if badHits.Load() != 2 {
		t.Fatalf("after first backoff: %d", badHits.Load())
	}
	if d := retryIn(badURI); d < 110*time.Minute || d > 2*time.Hour {
		t.Fatalf("second backoff %v, want twice the interval", d)
	}
	elapse(badURI, time.Hour+time.Minute) // inside the doubled backoff
	try()
	if badHits.Load() != 2 {
		t.Fatalf("backoff did not grow: %d", badHits.Load())
	}
	elapse(badURI, time.Hour)
	try()
	if badHits.Load() != 3 {
		t.Fatalf("after second backoff: %d", badHits.Load())
	}
	// the delay is capped
	for range 40 {
		elapse(badURI, 24*time.Hour)
		h.p.remoteKeys(context.Background(), badURI, false)
	}
	if d := retryIn(badURI); d > jwksBackoffMax {
		t.Fatalf("backoff %v exceeds cap", d)
	}
}

// Requests that need a client's keys while nobody has fetched them yet wait for one fetch, rather than each making
// its own (from inside a token request, each up to the fetch timeout).
func TestRemoteKeysFetchedOnceAtATime(t *testing.T) {
	t.Parallel()
	k := newAssertionKeys(t)[0]
	srv, hits := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // widens the window in which the concurrent callers overlap
		_, _ = w.Write([]byte(k.jwks))
	})
	h := setup(t, nil)
	h.p.HTTP = srv.Client()
	var wg sync.WaitGroup
	var empty atomic.Int32
	for range 12 {
		wg.Go(func() {
			if len(h.p.remoteKeys(context.Background(), srv.URL+"/jwks", false)) == 0 {
				empty.Add(1)
			}
		})
	}
	wg.Wait()
	if n := hits.Load(); n != 1 || empty.Load() != 0 {
		t.Fatalf("%d fetches for 12 concurrent requests (%d got no keys)", n, empty.Load())
	}
}

func TestJWKSKeyFiltering(t *testing.T) {
	t.Parallel()
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
}

func TestClientAuthMalformedCredentials(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) })
	basic := func(raw string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw)) }
	cc := url.Values{"grant_type": {"client_credentials"}}
	req := func(auth string, form url.Values) tokResp {
		return h.post(h.orgBase+"/oauth/token", form, "", "", "Authorization", auth)
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
	if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}, cl.ID, secret); r.m["error"] != "invalid_request" {
		t.Errorf("basic and post: %v", r.m)
	}
	// a very long client id is an ordinary authentication failure
	long := strings.Repeat("x", 300)
	if r := h.post(h.orgBase+"/oauth/token", cc, long, "s"); r.status != 401 {
		t.Errorf("long id: %d", r.status)
	}
}

// An assertion that is malformed, names another client, or arrives alongside another credential is refused.
func TestPrivateKeyJWTRefusals(t *testing.T) {
	t.Parallel()
	k := newAssertionKeys(t)[0]
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKS = ptr(k.jwks)
	})
	notObject, err := signJWT(k.alg, k.priv, mkHeader(k.alg, "ck1", "JWT"), []byte(`[1]`))
	if err != nil {
		t.Fatal(err)
	}
	good := h.assertion(k, h.assertionClaims(cl, nil))
	for name, tc := range map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"garbage":            {url.Values{"client_assertion": {"x.y.z"}, "client_assertion_type": {assertionType}}, 401, "invalid_client"},
		"payload not claims": {url.Values{"client_assertion": {h.assertion(k, nil)}, "client_assertion_type": {assertionType}}, 401, "invalid_client"},
		"payload not object": {url.Values{"client_assertion": {notObject}, "client_assertion_type": {assertionType}}, 401, "invalid_client"},
		"client_id differs":  {url.Values{"client_assertion": {good}, "client_assertion_type": {assertionType}, "client_id": {"other"}}, 401, "invalid_client"},
		"with secret":        {url.Values{"client_assertion": {good}, "client_assertion_type": {assertionType}, "client_secret": {"s"}}, 400, "invalid_request"},
		"wrong type":         {url.Values{"client_assertion": {good}, "client_assertion_type": {"nope"}}, 400, "invalid_request"},
	} {
		tc.form.Set("grant_type", "client_credentials")
		if r := h.post(h.orgBase+"/oauth/token", tc.form, "", ""); r.status != tc.status || r.str("error") != tc.code {
			t.Errorf("%s: %d %v, want %d %s", name, r.status, r.m, tc.status, tc.code)
		}
	}
}

func TestPrivateKeyJWTRemoteKeyFetchFailures(t *testing.T) {
	t.Parallel()
	k := newAssertionKeys(t)[0]
	srv, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/notjson":
			_, _ = w.Write([]byte("not json"))
		case "/huge":
			_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("a", jwksMaxBytes) + `"}`))
		default:
			_, _ = w.Write([]byte(k.jwks))
		}
	})
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
}

// Past its bound the client JWKS cache drops the entries asked for longest ago, one at a time, not every client's:
// clients churning through jwks_uris (registering them by the thousand) make a client in use fetch its keys again
// no sooner than they would have anyway.
func TestRemoteKeysCacheEvictsLeastRecentlyUsed(t *testing.T) {
	t.Parallel()
	k := newAssertionKeys(t)[0]
	var mu sync.Mutex
	hits := map[string]int{}
	srv, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		_, _ = w.Write([]byte(k.jwks))
	})
	fetches := func(path string) int { mu.Lock(); defer mu.Unlock(); return hits[path] }
	h := setup(t, nil)
	inUse, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/in-use")
	})
	if r := h.ccWithAssertion(inUse, h.assertion(k, h.assertionClaims(inUse, nil))); r.status != 200 {
		t.Fatalf("%d %v", r.status, r.m)
	}
	// Others' entries, older than the one in use, fill the cache past its bound.
	h.p.jwksMu.Lock()
	for i := range remoteKeyMax {
		h.p.remoteKey[fmt.Sprintf("https://filler.example/%d", i)] = &remoteJWKS{used: time.Now().Add(-time.Hour)}
	}
	h.p.jwksMu.Unlock()
	newcomer, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/new")
	})
	if r := h.ccWithAssertion(newcomer, h.assertion(k, h.assertionClaims(newcomer, nil))); r.status != 200 {
		t.Fatalf("%d %v", r.status, r.m)
	}
	h.p.jwksMu.Lock()
	n, kept := len(h.p.remoteKey), h.p.remoteKey[srv.URL+"/in-use"] != nil
	h.p.jwksMu.Unlock()
	if n > remoteKeyMax || n < remoteKeyMax-1 {
		t.Fatalf("cache holds %d entries, want one entry dropped to stay within %d", n, remoteKeyMax)
	}
	if !kept {
		t.Fatal("the entry in use was dropped")
	}
	if r := h.ccWithAssertion(inUse, h.assertion(k, h.assertionClaims(inUse, nil))); r.status != 200 || fetches("/in-use") != 1 {
		t.Fatalf("client in use after others' churn: %d, %d fetches of its keys, want 1", r.status, fetches("/in-use"))
	}
}

// A rate-limit counter that cannot be used refuses the request (a limit never fails open), but as "unavailable", not
// as a limit that was reached: a valid client is told to retry (503), not that it failed too often (429). A
// failure already decided is not changed by a counter that cannot record it.
func TestClientAuthCounterFailureIsUnavailable(t *testing.T) {
	t.Parallel()
	counters := errors.New("counter owner did not answer")
	form := func(c *model.Client, s string) url.Values {
		return url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ID}, "client_secret": {s}}
	}
	t.Run("valid client", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		h.useEph(func(op, ns string) error {
			if op == "incr" && ns == nsRateOIDC {
				return counters
			}
			return nil
		})
		r := h.post(h.orgBase+"/oauth/token", form(cl, secret), "", "")
		expectUnavailable(t, "valid client, counter failing", r)
		if r.hdr.Get("Retry-After") == "" {
			t.Errorf("no Retry-After: %v", r.hdr)
		}
	})
	t.Run("failed authentication", func(t *testing.T) {
		h := setup(t, nil)
		cl, _ := h.newClient(nil)
		var calls atomic.Int32
		h.useEph(func(op, ns string) error { // the two reads before the check succeed, counting the failure does not
			if op == "incr" && ns == nsRateOIDC && calls.Add(1) > 2 {
				return counters
			}
			return nil
		})
		if r := h.post(h.orgBase+"/oauth/token", form(cl, "wrong"), "", ""); r.status != 401 || r.str("error") != "invalid_client" {
			t.Fatalf("wrong secret, failure not countable: %d %v, want the original 401 invalid_client", r.status, r.m)
		}
	})
}

// A requester that hangs up while a client's keys are being fetched does not end the fetch: the keys are every
// caller's, and a failed fetch backs off for all, so sending an assertion with an unknown kid and hanging up must not
// keep a private_key_jwt client from authenticating (after a restart or a key rotation).
func TestRemoteKeysFetchOutlivesItsRequester(t *testing.T) {
	t.Parallel()
	k := newAssertionKeys(t)[0]
	ctx, hangUp := context.WithCancel(context.Background())
	srv, hits := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		hangUp() // while the keys are on their way
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(k.jwks))
	})
	h := setup(t, nil)
	h.p.HTTP = srv.Client()
	uri := srv.URL + "/jwks"
	h.p.remoteKeys(ctx, uri, true)
	if keys := h.p.remoteKeys(context.Background(), uri, false); len(keys) == 0 || hits.Load() != 1 {
		t.Fatalf("after the requester hung up: %d keys, %d fetches", len(keys), hits.Load())
	}
}
