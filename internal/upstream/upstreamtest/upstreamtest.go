// Package upstreamtest provides fake upstream identity providers (an OpenID Connect provider and GitHub) for tests.
package upstreamtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

// HTTPClient returns a client that trusts the fakes' self-signed certificates and does not follow redirects.
func HTTPClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ---------------------------------------------------------------------------------------------------------------
// Fake OpenID provider

// FakeOIDC is an OpenID provider over TLS: discovery, JWKS (RSA and EC keys), token and userinfo endpoints.
type FakeOIDC struct {
	T      *testing.T
	Srv    *httptest.Server
	RSAKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	KID    string

	Mu          sync.Mutex
	pending     map[string]*pendingCode // code -> authorization request
	JWKSFetches int
	BasicOnly   bool
	UserInfo    map[string]any
	GotBasic    bool
	IssuerOver  string // discovery "issuer" override

	// Refresh tokens: IssueRefresh adds one to each code exchange; RotateRefresh makes each refresh return a new one
	// (the used one stops working); RefreshFail answers refresh requests with that HTTP status (a transient failure).
	IssueRefresh  bool
	RotateRefresh bool
	RefreshFail   int
	RefreshCalls  int
	RefreshDelay  time.Duration   // how long a refresh request waits before it is answered (a slow provider)
	refresh       map[string]bool // live refresh tokens
	refreshSeq    int
}

type pendingCode struct {
	nonce, challenge string
	claims           map[string]any
}

// NewFakeOIDC starts a fake provider for client "cid" / secret "s3cret".
func NewFakeOIDC(t *testing.T) *FakeOIDC {
	f := &FakeOIDC{T: t, pending: map[string]*pendingCode{}, KID: "k1"}
	f.RSAKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := f.Srv.URL
		if f.IssuerOver != "" {
			iss = f.IssuerOver
		}
		methods := []string{"client_secret_post", "client_secret_basic"}
		if f.BasicOnly {
			methods = []string{"client_secret_basic"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "authorization_endpoint": f.Srv.URL + "/authorize",
			"token_endpoint": f.Srv.URL + "/token", "jwks_uri": f.Srv.URL + "/jwks", "userinfo_endpoint": f.Srv.URL + "/userinfo",
			"token_endpoint_auth_methods_supported": methods})
	})
	// Microsoft-style directories: /<tenant>/v2.0/.well-known/openid-configuration, the issuer a {tenantid} template
	// for "organizations" (tests point upstream.Service.MicrosoftAuthority here).
	mux.HandleFunc("GET /{tenant}/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		t := r.PathValue("tenant")
		if t == "organizations" {
			t = "{tenantid}"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.Srv.URL + "/" + t + "/v2.0", "authorization_endpoint": f.Srv.URL + "/authorize",
			"token_endpoint": f.Srv.URL + "/token", "jwks_uri": f.Srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		f.Mu.Lock()
		f.JWKSFetches++
		kid, rk, ek := f.KID, f.RSAKey, f.ecKey
		f.Mu.Unlock()
		rsaJWK := map[string]any{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": b64.EncodeToString(rk.N.Bytes()),
			"e": b64.EncodeToString(big.NewInt(int64(rk.E)).Bytes())}
		ecJWK := map[string]any{"kty": "EC", "kid": kid + "-ec", "use": "sig", "crv": "P-256",
			"x": b64.EncodeToString(ek.X.FillBytes(make([]byte, 32))), "y": b64.EncodeToString(ek.Y.FillBytes(make([]byte, 32)))}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK, ecJWK}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if _, _, ok := r.BasicAuth(); ok {
			f.GotBasic = true
		} else if r.Form.Get("client_secret") != "s3cret" || r.Form.Get("client_id") != "cid" {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			f.Mu.Lock()
			f.RefreshCalls++
			delay := f.RefreshDelay
			f.Mu.Unlock()
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
			f.Mu.Lock()
			defer f.Mu.Unlock()
			if f.RefreshFail != 0 {
				http.Error(w, `{"error":"temporarily_unavailable"}`, f.RefreshFail)
				return
			}
			rt := r.Form.Get("refresh_token")
			if !f.refresh[rt] {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			out := map[string]any{"access_token": "at-r", "token_type": "Bearer"}
			if f.RotateRefresh {
				delete(f.refresh, rt)
				out["refresh_token"] = f.newRefreshLocked()
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		f.Mu.Lock()
		pc := f.pending[r.Form.Get("code")]
		delete(f.pending, r.Form.Get("code"))
		f.Mu.Unlock()
		if pc == nil || r.Form.Get("redirect_uri") == "" {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if b64.EncodeToString(h[:]) != pc.challenge {
			http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, 400)
			return
		}
		claims := map[string]any{"iss": f.Srv.URL, "aud": "cid", "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "nonce": pc.nonce}
		for k, v := range pc.claims {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		alg, _ := claims["_alg"].(string)
		delete(claims, "_alg")
		kid, _ := claims["_kid"].(string)
		delete(claims, "_kid")
		out := map[string]any{"id_token": f.Sign(alg, kid, claims), "access_token": "at-1", "token_type": "Bearer"}
		f.Mu.Lock()
		if f.IssueRefresh {
			out["refresh_token"] = f.newRefreshLocked()
		}
		f.Mu.Unlock()
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			http.Error(w, "no", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(f.UserInfo)
	})
	f.Srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.Srv.Close)
	return f
}

// newRefreshLocked issues a refresh token (f.Mu held).
func (f *FakeOIDC) newRefreshLocked() string {
	if f.refresh == nil {
		f.refresh = map[string]bool{}
	}
	f.refreshSeq++
	rt := "rt-" + strconv.Itoa(f.refreshSeq)
	f.refresh[rt] = true
	return rt
}

// RevokeRefresh makes every refresh token issued so far invalid (the account left, or was blocked): the provider
// answers invalid_grant from now on.
func (f *FakeOIDC) RevokeRefresh() {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	clear(f.refresh)
}

// LiveRefresh returns the refresh tokens the provider still accepts.
func (f *FakeOIDC) LiveRefresh() []string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	var out []string
	for k := range f.refresh {
		out = append(out, k)
	}
	return out
}

// sign builds an id token. alg "" = RS256; "ES256"; "none"; "HS256" (forged with the RSA public key bytes);
// "RS256-other" signs with an unrelated key.
// Sign builds an id token. alg "" = RS256; "ES256"; "none"; "HS256"; "RS256-other" signs with an unrelated key.
func (f *FakeOIDC) Sign(alg, kid string, claims map[string]any) string {
	if alg == "" {
		alg = "RS256"
	}
	hdr := map[string]any{"alg": alg, "typ": "JWT"}
	if kid == "" {
		kid = f.KID
		if alg == "ES256" {
			kid += "-ec"
		}
	}
	hdr["kid"] = kid
	enc := func(v any) string { b, _ := json.Marshal(v); return b64.EncodeToString(b) }
	in := enc(hdr) + "." + enc(claims)
	h := sha256.Sum256([]byte(in))
	switch alg {
	case "none":
		return in + "."
	case "HS256":
		return in + "." + b64.EncodeToString([]byte("whatever"))
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, f.ecKey, h[:])
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		return in + "." + b64.EncodeToString(sig)
	case "RS256-other":
		hdr["alg"] = "RS256"
		in = enc(hdr) + "." + enc(claims)
		h = sha256.Sum256([]byte(in))
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, h[:])
		return in + "." + b64.EncodeToString(sig)
	}
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.RSAKey, crypto.SHA256, h[:])
	return in + "." + b64.EncodeToString(sig)
}

// authorize plays the provider's authorization endpoint for the URL Begin returned and returns the code.
func (f *FakeOIDC) Authorize(authURL string, claims map[string]any) string {
	u, err := url.Parse(authURL)
	if err != nil || !strings.HasPrefix(authURL, f.Srv.URL+"/authorize") {
		f.T.Fatalf("bad authorization url %q", authURL)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" ||
		q.Get("client_id") != "cid" || !strings.Contains(q.Get("scope"), "openid") {
		f.T.Fatalf("authorization request missing parameters: %v", q)
	}
	code := "code-" + q.Get("state")
	f.Mu.Lock()
	f.pending[code] = &pendingCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), claims: claims}
	f.Mu.Unlock()
	return code
}

// ---------------------------------------------------------------------------------------------------------------
// Fake GitHub

// FakeGitHub fakes the GitHub OAuth token endpoint and the /user and /user/emails APIs (client secret "gh-secret").
type FakeGitHub struct {
	Srv    *httptest.Server
	Emails []map[string]any
	ID     int64
	Login  string
	mu     sync.Mutex
	codes  map[string]string // code -> challenge
}

// NewFakeGitHub starts the fake.
func NewFakeGitHub(t *testing.T) *FakeGitHub {
	g := &FakeGitHub{ID: 583231, Login: "octocat", codes: map[string]string{},
		Emails: []map[string]any{{"email": "octo@example.com", "primary": true, "verified": true}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		g.mu.Lock()
		ch, ok := g.codes[r.Form.Get("code")]
		delete(g.codes, r.Form.Get("code"))
		g.mu.Unlock()
		h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || r.Form.Get("client_secret") != "gh-secret" || b64.EncodeToString(h[:]) != ch {
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad_verification_code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gho_x", "token_type": "bearer"})
	})
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer gho_x" || r.Header.Get("User-Agent") == "" {
			http.Error(w, "no", 401)
			return false
		}
		return true
	}
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": g.ID, "login": g.Login, "name": "The Octocat",
				"email": "public@example.com"}) // the profile email is ignored: only /user/emails is trusted
		}
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			_ = json.NewEncoder(w).Encode(g.Emails)
		}
	})
	g.Srv = httptest.NewTLSServer(mux)
	t.Cleanup(g.Srv.Close)
	return g
}

func (g *FakeGitHub) Authorize(authURL string) string {
	u, _ := url.Parse(authURL)
	q := u.Query()
	code := "gh-" + q.Get("state")
	g.mu.Lock()
	g.codes[code] = q.Get("code_challenge")
	g.mu.Unlock()
	return code
}
