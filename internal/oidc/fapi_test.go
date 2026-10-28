package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestPS256ClientKeysAndIDTokens(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	// client assertions: an RSA key declared PS256, and one without alg (either RSA scheme)
	for name, k := range map[string]assertionKey{"declared": rsaAssertionKey(t, AlgPS256, AlgPS256),
		"undeclared": rsaAssertionKey(t, AlgPS256, "")} {
		c := h.jwtClient(k, nil)
		if r := h.ccWithAssertion(c, h.assertion(k, h.assertionClaims(c, nil))); r.status != 200 {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
	// a key declared PS256 does not verify RS256 signatures
	k := rsaAssertionKey(t, AlgRS256, AlgPS256)
	c := h.jwtClient(k, nil)
	if r := h.ccWithAssertion(c, h.assertion(k, h.assertionClaims(c, nil))); r.status != 401 {
		t.Errorf("RS256 with a PS256 key: %d %v", r.status, r.m)
	}

	// ID tokens signed with PS256 for a client that asks for it; the key is published and verifies them
	ps, secret := h.newClient(func(in *service.ClientInput) { in.SigningAlg = ptr(AlgPS256) })
	r, _ := h.login(ps, secret, nil)
	id := r.str("id_token")
	if headerOf(t, id)["alg"] != AlgPS256 || headerOf(t, r.str("access_token"))["alg"] != AlgPS256 {
		t.Fatalf("headers: %v", headerOf(t, id))
	}
	pj, err := ParseJWT(id)
	if err != nil {
		t.Fatal(err)
	}
	key := h.p.keyByKID(context.Background(), pj.Header.Kid)
	if key == nil || key.alg != AlgPS256 || pj.Verify(key.pub) != nil {
		t.Fatal("PS256 ID token does not verify with its published key")
	}
	if _, err := h.p.verifyAccessToken(context.Background(), r.str("access_token")); err != nil {
		t.Fatalf("PS256 access token: %v", err)
	}
	jwks := body(h.get(h.http, h.orgBase+"/oauth/jwks"))
	if !strings.Contains(jwks, `"alg":"PS256"`) {
		t.Fatalf("jwks: %s", jwks)
	}
}

func TestFAPIClientSettings(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	k := newAssertionKeys(t)[0]
	c := h.jwtClient(k, func(in *service.ClientInput) { in.FAPI = ptr(true); in.RotateRefresh = ptr(true) })
	if !c.FAPI || !c.RequirePAR || !c.DPoPBound || c.RotateRefresh {
		t.Fatalf("profile settings: %+v", c)
	}
	// turning a required setting off again is overridden while the profile is on
	c, err := h.env.Svc.UpdateClient(ctx, h.admin, c.ID, service.ClientInput{RequirePAR: ptr(false), DPoPBound: ptr(false)})
	if err != nil || !c.RequirePAR || !c.DPoPBound {
		t.Fatalf("update: %v %+v", err, c)
	}
	for name, edit := range map[string]func(*service.ClientInput){
		"client secret": func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) },
		"public":        func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodNone) },
		"RS256":         func(in *service.ClientInput) { in.SigningAlg = ptr(AlgRS256) },
		"no PKCE":       func(in *service.ClientInput) { in.RequirePKCE = ptr(false) },
	} {
		in := service.ClientInput{Name: ptr("fapi"), RedirectURIs: &[]string{rpCallback}, FAPI: ptr(true),
			AuthMethod: ptr(model.AuthMethodPrivateJWT), JWKS: ptr(k.jwks)}
		edit(&in)
		if _, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFAPIAssertionsAndProofs(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ec := newAssertionKeys(t)[0]
	c := h.jwtClient(ec, func(in *service.ClientInput) { in.FAPI = ptr(true) })
	key := newDPoPKey(t, AlgES256)
	cc := func(assertion, proof string) tokResp {
		f := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType}, "client_assertion": {assertion}}
		if proof == "" {
			return h.post(h.orgBase+"/oauth/token", f, "", "")
		}
		return h.post(h.orgBase+"/oauth/token", f, "", "", "DPoP", proof)
	}
	iss := h.issuer()
	good := func(k assertionKey) string {
		return h.assertion(k, h.assertionClaims(c, func(m map[string]any) { m["aud"] = iss }))
	}
	proof := func() string { return h.proof(key, "POST", h.orgBase+"/oauth/token", nil) }
	if r := cc(good(ec), proof()); r.status != 200 || r.str("token_type") != "DPoP" {
		t.Fatalf("FAPI client credentials: %d %v", r.status, r.m)
	}
	for name, aud := range map[string]any{"token endpoint": iss + h.orgBase + "/oauth/token", "array": []string{iss},
		"other": "https://other.example"} {
		a := h.assertion(ec, h.assertionClaims(c, func(m map[string]any) { m["aud"] = aud }))
		if r := cc(a, proof()); r.status != 401 || r.m["error"] != "invalid_client" {
			t.Errorf("aud %s: %d %v", name, r.status, r.m)
		}
	}
	if r := cc(good(ec), ""); r.m["error"] != "invalid_dpop_proof" {
		t.Errorf("no proof: %v", r.m)
	}
	// no RS256 assertions, even with a registered RSA key
	rk := rsaAssertionKey(t, AlgRS256, "")
	rc := h.jwtClient(rk, func(in *service.ClientInput) { in.FAPI = ptr(true) })
	ra := h.assertion(rk, h.assertionClaims(rc, func(m map[string]any) { m["aud"] = iss }))
	if r := cc(ra, proof()); r.status != 401 {
		t.Errorf("RS256 assertion: %d %v", r.status, r.m)
	}
	pk := rk
	pk.alg = AlgPS256
	if r := cc(h.assertion(pk, h.assertionClaims(rc, func(m map[string]any) { m["aud"] = iss })), proof()); r.status != 200 {
		t.Errorf("PS256 assertion: %d %v", r.status, r.m)
	}
	// no RS256 DPoP proofs from a FAPI client; other clients may use them
	rsaProofKey := func() dpopKey {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		j, _ := EncodeJWK(priv.Public(), "", "")
		return dpopKey{alg: AlgRS256, priv: crypto.Signer(priv), jwk: j, jkt: thumbprint(j)}
	}()
	if r := cc(good(ec), h.proof(rsaProofKey, "POST", h.orgBase+"/oauth/token", nil)); r.m["error"] != "invalid_dpop_proof" {
		t.Errorf("RS256 proof: %v", r.m)
	}
	other, osecret := h.newClient(nil)
	if r := h.tokenDPoP(url.Values{"grant_type": {"client_credentials"}}, other, osecret, h.proof(rsaProofKey, "POST", h.orgBase+"/oauth/token", nil)); r.status != 200 {
		t.Errorf("RS256 proof, ordinary client: %v", r.m)
	}
	// the non-FAPI client keeps accepting the token endpoint as audience
	plain := h.jwtClient(ec, nil)
	if r := h.ccWithAssertion(plain, h.assertion(ec, h.assertionClaims(plain, nil))); r.status != 200 {
		t.Errorf("ordinary private_key_jwt client: %v", r.m)
	}
}

func TestFAPICodeFlow(t *testing.T) {
	t.Parallel()
	h := setup(t, func(cfg *config.Config) { cfg.Tokens.CodeTTL = 600 })
	ec := newAssertionKeys(t)[0]
	c := h.jwtClient(ec, func(in *service.ClientInput) { in.FAPI = ptr(true) })
	key := newDPoPKey(t, AlgEdDSA)
	iss := h.issuer()
	assertion := func() string {
		return h.assertion(ec, h.assertionClaims(c, func(m map[string]any) { m["aud"] = iss }))
	}
	browser, _ := h.session(h.user)
	v, ch := pkce()
	// not pushed: refused
	if u := h.authorize(browser, authzQuery(c, ch, nil)); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("unpushed: %s", u)
	}
	f := url.Values{"client_assertion_type": {assertionType}, "client_assertion": {assertion()}}
	for k, val := range authzQuery(c, ch, nil) {
		if k != "client_id" {
			f[k] = val
		}
	}
	pr := h.post(h.orgBase+"/oauth/par", f, "", "", "DPoP", h.proof(key, "POST", h.orgBase+"/oauth/par", nil))
	if pr.status != 201 {
		t.Fatalf("push: %d %v", pr.status, pr.m)
	}
	u := h.authorize(browser, pushedQuery(c, pr.str("request_uri")))
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize: %s", u)
	}
	// the code lasts 60 seconds whatever tokens.code_ttl says
	if h.p.codeTTL(c) != fapiCodeTTL || h.p.codeTTL(&model.Client{}) != 600*time.Second {
		t.Fatalf("code ttl %v", h.p.codeTTL(c))
	}
	r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
		"code_verifier": {v}, "client_assertion_type": {assertionType}, "client_assertion": {assertion()}}, "", "",
		"DPoP", h.proof(key, "POST", h.orgBase+"/oauth/token", nil))
	if r.status != 200 || r.str("token_type") != "DPoP" || r.str("refresh_token") == "" {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	// refresh tokens do not rotate: the same one works again
	rt := r.str("refresh_token")
	for i := 0; i < 2; i++ {
		x := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt},
			"client_assertion_type": {assertionType}, "client_assertion": {assertion()}}, "", "",
			"DPoP", h.proof(key, "POST", h.orgBase+"/oauth/token", nil))
		if x.status != 200 || x.str("refresh_token") != "" {
			t.Fatalf("refresh %d: %d %v", i, x.status, x.m)
		}
	}
}
