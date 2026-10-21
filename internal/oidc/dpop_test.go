package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

type dpopKey struct {
	alg  string
	priv crypto.Signer
	jwk  JWK
	jkt  string
}

func newDPoPKey(t testing.TB, alg string) dpopKey {
	t.Helper()
	var priv crypto.Signer
	switch alg {
	case AlgES256:
		priv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgEdDSA:
		_, priv, _ = ed25519.GenerateKey(rand.Reader)
	}
	j, err := EncodeJWK(priv.Public(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	return dpopKey{alg: alg, priv: priv, jwk: j, jkt: thumbprint(j)}
}

// proof makes a DPoP proof for method and path on the harness's server; edit may change the header and claims
// (a nil value removes a member).
func (h *harness) proof(k dpopKey, method, path string, edit func(hdr, cl map[string]any)) string {
	h.t.Helper()
	hdr := map[string]any{"typ": dpopTyp, "alg": k.alg, "jwk": k.jwk}
	cl := map[string]any{"jti": secureID(), "htm": method, "htu": h.env.Cfg.Issuer() + path, "iat": time.Now().Unix(),
		"nonce": h.p.dpopNonce(time.Now())}
	if edit != nil {
		edit(hdr, cl)
	}
	for _, m := range []map[string]any{hdr, cl} {
		for key, v := range m {
			if v == nil {
				delete(m, key)
			}
		}
	}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(cl)
	tok, err := signJWT(k.alg, k.priv, b64.EncodeToString(hb), pb)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func secureID() string { return b64.EncodeToString(randBytes(16)) }

func ath(tok string) string { sum := sha256.Sum256([]byte(tok)); return b64.EncodeToString(sum[:]) }

// tokenDPoP is a token request authenticated as c (secret "" for a public client) carrying proof.
func (h *harness) tokenDPoP(form url.Values, c *model.Client, secret, proof string) tokResp {
	h.t.Helper()
	f := url.Values{}
	for k, v := range form {
		f[k] = v
	}
	f.Set("client_id", c.ID)
	if secret != "" {
		f.Set("client_secret", secret)
	}
	if proof == "" {
		return h.post("/oauth/token", f, "", "")
	}
	return h.post("/oauth/token", f, "", "", "DPoP", proof)
}

func (h *harness) userinfoDPoP(auth, proof string) *http.Response {
	h.t.Helper()
	hdr := []string{"Authorization", auth}
	if proof != "" {
		hdr = append(hdr, "DPoP", proof)
	}
	return h.get(h.http, "/oauth/userinfo", hdr...)
}

func TestDPoPCodeFlowAndUserinfo(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	k := newDPoPKey(t, AlgES256)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}

	// without a nonce: told to use one
	r := h.tokenDPoP(form, cl, secret, h.proof(k, "POST", "/oauth/token", func(_, c map[string]any) { c["nonce"] = nil }))
	nonce := r.hdr.Get("DPoP-Nonce")
	if r.status != 400 || r.m["error"] != "use_dpop_nonce" || nonce == "" {
		t.Fatalf("no nonce: %d %v", r.status, r.m)
	}
	// with the nonce it was given
	r = h.tokenDPoP(form, cl, secret, h.proof(k, "POST", "/oauth/token", func(_, c map[string]any) { c["nonce"] = nonce }))
	if r.status != 200 || r.str("token_type") != "DPoP" || r.hdr.Get("DPoP-Nonce") == "" {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	at := r.str("access_token")
	if cnf, _ := claimsOf(t, at)["cnf"].(map[string]any); cnf["jkt"] != k.jkt {
		t.Fatalf("cnf: %v", claimsOf(t, at))
	}

	// userinfo: the DPoP scheme with a proof of the key, for this request
	good := func() string {
		return h.proof(k, "GET", "/oauth/userinfo", func(_, c map[string]any) { c["ath"] = ath(at); c["nonce"] = nil })
	}
	if resp := h.userinfoDPoP("DPoP "+at, good()); resp.StatusCode != 200 {
		t.Fatalf("userinfo: %d %s", resp.StatusCode, body(resp))
	}
	other := newDPoPKey(t, AlgEdDSA)
	replayed := good()
	h.userinfoDPoP("DPoP "+at, replayed).Body.Close()
	for name, tc := range map[string]struct{ auth, proof string }{
		"bearer scheme":   {"Bearer " + at, ""},
		"bearer + proof":  {"Bearer " + at, good()},
		"no proof":        {"DPoP " + at, ""},
		"other key":       {"DPoP " + at, h.proof(other, "GET", "/oauth/userinfo", func(_, c map[string]any) { c["ath"] = ath(at) })},
		"no ath":          {"DPoP " + at, h.proof(k, "GET", "/oauth/userinfo", nil)},
		"wrong ath":       {"DPoP " + at, h.proof(k, "GET", "/oauth/userinfo", func(_, c map[string]any) { c["ath"] = ath("x") })},
		"wrong method":    {"DPoP " + at, h.proof(k, "POST", "/oauth/userinfo", func(_, c map[string]any) { c["ath"] = ath(at) })},
		"token endpoint":  {"DPoP " + at, h.proof(k, "GET", "/oauth/token", func(_, c map[string]any) { c["ath"] = ath(at) })},
		"replayed proof":  {"DPoP " + at, replayed},
		"bad nonce":       {"DPoP " + at, h.proof(k, "GET", "/oauth/userinfo", func(_, c map[string]any) { c["ath"] = ath(at); c["nonce"] = "1.x" })},
		"unbound as DPoP": {"DPoP " + h.login1(cl, secret), ""},
	} {
		resp := h.userinfoDPoP(tc.auth, tc.proof)
		body(resp)
		if resp.StatusCode != 401 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
		if strings.HasPrefix(tc.auth, "DPoP") && !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "DPoP ") {
			t.Errorf("%s: challenge %q", name, resp.Header.Get("WWW-Authenticate"))
		}
	}

	// introspection shows the binding
	if m := h.introspect(cl, secret, at); m["token_type"] != "DPoP" || m["cnf"].(map[string]any)["jkt"] != k.jkt {
		t.Fatalf("introspect: %v", m)
	}
	// a confidential client's refresh tokens are bound to its authentication, not the key: a refresh without a
	// proof gets a bearer token
	if rr := h.refreshWith(cl, secret, r.str("refresh_token")); rr.status != 200 || rr.str("token_type") != "Bearer" {
		t.Fatalf("refresh: %v", rr.m)
	}
}

// login1 returns an access token from a plain (bearer) sign-in.
func (h *harness) login1(cl *model.Client, secret string) string {
	r, _ := h.login(cl, secret, nil)
	return r.str("access_token")
}

func TestDPoPPublicClientRefreshBound(t *testing.T) {
	h := setup(t, nil)
	pub := h.publicClient(func(in *service.ClientInput) { in.FirstParty = ptr(true) })
	k := newDPoPKey(t, AlgEdDSA)
	c, _ := h.session(h.user)
	v, ch := pkce()
	u := h.authorize(c, authzQuery(pub, ch, nil))
	r := h.tokenDPoP(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")},
		"redirect_uri": {pub.RedirectURIs[0]}, "code_verifier": {v}}, pub, "", h.proof(k, "POST", "/oauth/token", nil))
	if r.status != 200 || r.str("token_type") != "DPoP" {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	rt := r.str("refresh_token")
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if x := h.tokenDPoP(refresh, pub, "", ""); x.m["error"] != "invalid_grant" {
		t.Fatalf("refresh without proof: %v", x.m)
	}
	if x := h.tokenDPoP(refresh, pub, "", h.proof(newDPoPKey(t, AlgES256), "POST", "/oauth/token", nil)); x.m["error"] != "invalid_grant" {
		t.Fatalf("refresh with another key: %v", x.m)
	}
	// the failed attempts did not use the token up
	x := h.tokenDPoP(refresh, pub, "", h.proof(k, "POST", "/oauth/token", nil))
	if x.status != 200 || x.str("token_type") != "DPoP" || x.str("refresh_token") == "" {
		t.Fatalf("refresh with the key: %d %v", x.status, x.m)
	}
}

func TestDPoPProofChecks(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	k := newDPoPKey(t, AlgES256)
	other := newDPoPKey(t, AlgES256)
	cc := url.Values{"grant_type": {"client_credentials"}}
	priv := k.priv.(*ecdsa.PrivateKey)
	withD := map[string]any{"kty": "EC", "crv": "P-256", "x": k.jwk.X, "y": k.jwk.Y, "d": b64.EncodeToString(priv.D.Bytes())}
	used := h.proof(k, "POST", "/oauth/token", nil)
	if r := h.tokenDPoP(cc, cl, secret, used); r.status != 200 || r.str("token_type") != "DPoP" {
		t.Fatalf("good proof: %d %v", r.status, r.m)
	}
	oldNonce := h.p.dpopNonce(time.Now().Add(-dpopNonceSteps * dpopNonceStep))
	badSig := func() string {
		p := h.proof(k, "POST", "/oauth/token", nil)
		o := h.proof(other, "POST", "/oauth/token", nil)
		return p[:strings.LastIndexByte(p, '.')] + o[strings.LastIndexByte(o, '.'):]
	}()
	for name, edit := range map[string]func(hdr, c map[string]any){
		"typ":         func(hd, _ map[string]any) { hd["typ"] = "JWT" },
		"no jwk":      func(hd, _ map[string]any) { hd["jwk"] = nil },
		"private jwk": func(hd, _ map[string]any) { hd["jwk"] = withD },
		"other jwk":   func(hd, _ map[string]any) { hd["jwk"] = other.jwk },
		"alg":         func(hd, _ map[string]any) { hd["alg"] = AlgEdDSA },
		"htm":         func(_, c map[string]any) { c["htm"] = "GET" },
		"htu":         func(_, c map[string]any) { c["htu"] = "https://evil.example/oauth/token" },
		"no jti":      func(_, c map[string]any) { c["jti"] = nil },
		"old iat":     func(_, c map[string]any) { c["iat"] = time.Now().Add(-dpopMaxAge - time.Minute).Unix() },
		"future iat":  func(_, c map[string]any) { c["iat"] = time.Now().Add(5 * time.Minute).Unix() },
		"no iat":      func(_, c map[string]any) { c["iat"] = nil },
	} {
		if r := h.tokenDPoP(cc, cl, secret, h.proof(k, "POST", "/oauth/token", edit)); r.m["error"] != "invalid_dpop_proof" {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
	for name, proof := range map[string]string{"replay": used, "signature": badSig, "garbage": "x.y.z"} {
		if r := h.tokenDPoP(cc, cl, secret, proof); r.m["error"] != "invalid_dpop_proof" {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
	for name, n := range map[string]any{"expired nonce": oldNonce, "forged nonce": "999.AAAA", "future nonce": h.p.dpopNonce(time.Now().Add(time.Hour))} {
		r := h.tokenDPoP(cc, cl, secret, h.proof(k, "POST", "/oauth/token", func(_, c map[string]any) { c["nonce"] = n }))
		if r.m["error"] != "use_dpop_nonce" || r.hdr.Get("DPoP-Nonce") == "" {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
	// two proofs
	f := url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}, "client_secret": {secret}}
	req, _ := http.NewRequest("POST", h.env.URL+"/oauth/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("DPoP", h.proof(k, "POST", "/oauth/token", nil))
	req.Header.Add("DPoP", h.proof(k, "POST", "/oauth/token", nil))
	resp, err := h.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(resp); resp.StatusCode != 400 || !strings.Contains(b, "invalid_dpop_proof") {
		t.Errorf("two proofs: %d %s", resp.StatusCode, b)
	}
}

func TestDPoPBoundClient(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.DPoPBound = ptr(true) })
	cc := url.Values{"grant_type": {"client_credentials"}}
	if r := h.tokenDPoP(cc, cl, secret, ""); r.m["error"] != "invalid_dpop_proof" {
		t.Fatalf("no proof: %v", r.m)
	}
	k := newDPoPKey(t, AlgEdDSA)
	r := h.tokenDPoP(cc, cl, secret, h.proof(k, "POST", "/oauth/token", nil))
	if r.status != 200 || r.str("token_type") != "DPoP" {
		t.Fatalf("proof: %v", r.m)
	}
	// a resource server in this process (SCIM) sees the binding through VerifyRequestToken
	at := r.str("access_token")
	k2 := newDPoPKey(t, AlgES256)
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	if _, err := h.p.VerifyRequestToken(req, "Bearer", at); err == nil {
		t.Fatal("bound token accepted as a bearer token")
	}
	req.Header.Set("DPoP", h.proof(k2, "GET", "/scim/v2/Users", func(_, c map[string]any) { c["ath"] = ath(at) }))
	if _, err := h.p.VerifyRequestToken(req, "DPoP", at); err == nil {
		t.Fatal("proof of another key accepted")
	}
	req.Header.Set("DPoP", h.proof(k, "GET", "/scim/v2/Users", func(_, c map[string]any) { c["ath"] = ath(at); c["nonce"] = nil }))
	if cl, err := h.p.VerifyRequestToken(req, "DPoP", at); err != nil || cl.Cnf.JKT != k.jkt {
		t.Fatalf("proof of the key: %v", err)
	}
}

func TestDPoPJKTBindsCode(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	k := newDPoPKey(t, AlgES256)
	c, _ := h.session(h.user)
	exchange := func(code, v string, proof string) tokResp {
		return h.tokenDPoP(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
			"code_verifier": {v}}, cl, secret, proof)
	}
	v, ch := pkce()
	code := h.getCode(c, cl, ch, url.Values{"dpop_jkt": {k.jkt}})
	if r := exchange(code, v, h.proof(newDPoPKey(t, AlgES256), "POST", "/oauth/token", nil)); r.m["error"] != "invalid_grant" {
		t.Fatalf("other key: %v", r.m)
	}
	v, ch = pkce()
	code = h.getCode(c, cl, ch, url.Values{"dpop_jkt": {k.jkt}})
	if r := exchange(code, v, ""); r.m["error"] != "invalid_grant" {
		t.Fatalf("no proof: %v", r.m)
	}
	v, ch = pkce()
	code = h.getCode(c, cl, ch, url.Values{"dpop_jkt": {k.jkt}})
	if r := exchange(code, v, h.proof(k, "POST", "/oauth/token", nil)); r.status != 200 || r.str("token_type") != "DPoP" {
		t.Fatalf("the key: %v", r.m)
	}
	if u := h.authorize(c, authzQuery(cl, ch, url.Values{"dpop_jkt": {"short"}})); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("bad dpop_jkt: %s", u)
	}

	// a proof sent with a pushed request binds the code the same way
	v, ch = pkce()
	f := url.Values{}
	for key, val := range authzQuery(cl, ch, nil) {
		if key != "client_id" {
			f[key] = val
		}
	}
	f.Set("client_id", cl.ID)
	f.Set("client_secret", secret)
	pr := h.post("/oauth/par", f, "", "", "DPoP", h.proof(k, "POST", "/oauth/par", nil))
	if pr.status != 201 {
		t.Fatalf("push: %d %v", pr.status, pr.m)
	}
	u := h.authorize(c, pushedQuery(cl, pr.str("request_uri")))
	if r := exchange(u.Query().Get("code"), v, ""); r.m["error"] != "invalid_grant" {
		t.Fatalf("pushed with proof, redeemed without: %v", r.m)
	}
	// a pushed dpop_jkt that is not the proof's key is refused
	f.Set("dpop_jkt", newDPoPKey(t, AlgEdDSA).jkt)
	if pr := h.post("/oauth/par", f, "", "", "DPoP", h.proof(k, "POST", "/oauth/par", nil)); pr.m["error"] != "invalid_dpop_proof" {
		t.Fatalf("mismatched dpop_jkt: %v", pr.m)
	}
}

func TestDPoPDiscoveryAndThumbprint(t *testing.T) {
	h := setup(t, nil)
	var d map[string]any
	_ = json.Unmarshal([]byte(body(h.get(h.http, "/.well-known/openid-configuration"))), &d)
	if algs, _ := d["dpop_signing_alg_values_supported"].([]any); len(algs) != 3 {
		t.Fatalf("%v", d["dpop_signing_alg_values_supported"])
	}
	// RFC 7638 §3.1 example
	j := JWK{Kty: "RSA", E: "AQAB", N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
	if got := thumbprint(j); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %s", got)
	}
	if !sameHTU("HTTPS://Example.com:443/oauth/token?x=1#f", "https://example.com/oauth/token") ||
		sameHTU("https://example.com/oauth/token/", "https://example.com/oauth/token") {
		t.Fatal("htu comparison")
	}
}
