package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/service"
)

func TestCoverageDPoPProofRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	k := newDPoPKey(t, AlgES256)
	cc := url.Values{"grant_type": {"client_credentials"}}
	wrong := func(name, proof string) {
		t.Helper()
		if r := h.tokenDPoP(cc, cl, secret, proof); r.m["error"] != "invalid_dpop_proof" {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
	wrong("too large", h.proof(k, "POST", "/oauth/token", func(_, c map[string]any) { c["pad"] = strings.Repeat("a", maxDPoPProof) }))
	wrong("jwk is not an object", h.proof(k, "POST", "/oauth/token", func(hd, _ map[string]any) { hd["jwk"] = "x" }))
	wrong("jwk member of the wrong type", h.proof(k, "POST", "/oauth/token", func(hd, _ map[string]any) {
		hd["jwk"] = map[string]any{"kty": "EC", "crv": 1}
	}))
	wrong("jwk not a point on the curve", h.proof(k, "POST", "/oauth/token", func(hd, _ map[string]any) {
		hd["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}
	}))
	wrong("htu unparsable", h.proof(k, "POST", "/oauth/token", func(_, c map[string]any) { c["htu"] = "::" }))
	// claims that are not an object
	hb, _ := json.Marshal(map[string]any{"typ": dpopTyp, "alg": k.alg, "jwk": k.jwk})
	tok, err := signJWT(k.alg, k.priv, b64.EncodeToString(hb), []byte(`[1]`))
	if err != nil {
		t.Fatal(err)
	}
	wrong("claims not an object", tok)
	// an ath that is not the token's hash, at userinfo
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid"}})
	resp := h.userinfoDPoP("DPoP "+r.str("access_token"), h.proof(k, "GET", "/oauth/userinfo", func(_, c map[string]any) { c["ath"] = ath("other") }))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ath: %d", resp.StatusCode)
	}
	body(resp)

	// nonces: not a number, a bad MAC for a current step, not base64
	cur := time.Now().Unix() / int64(dpopNonceStep/time.Second)
	for name, n := range map[string]string{
		"not a number": "abc.def",
		"wrong mac":    strings.Join([]string{itoa(cur), b64.EncodeToString(make([]byte, 16))}, "."),
		"not base64":   itoa(cur) + ".!!!",
		"no dot":       "12345",
	} {
		if h.p.validNonce(n, time.Now()) {
			t.Errorf("%s accepted", name)
		}
	}
	if !h.p.validNonce(h.p.dpopNonce(time.Now()), time.Now()) {
		t.Fatal("a current nonce refused")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestCoverageParRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	k := newDPoPKey(t, AlgES256)
	push := func(q url.Values, proof string) tokResp {
		f := url.Values{}
		for key, v := range q {
			f[key] = v
		}
		f.Set("client_id", cl.ID)
		f.Set("client_secret", secret)
		if proof == "" {
			return h.post("/oauth/par", f, "", "")
		}
		return h.post("/oauth/par", f, "", "", "DPoP", proof)
	}
	// a long state
	tokenErr(t, push(authzQuery(cl, ch, url.Values{"state": {strings.Repeat("s", 2049)}}), ""), 400, "invalid_request")
	// the key in dpop_jkt is not the proof's
	other := newDPoPKey(t, AlgES256)
	q := authzQuery(cl, ch, url.Values{"dpop_jkt": {other.jkt}})
	tokenErr(t, push(q, h.proof(k, "POST", "/oauth/par", nil)), 400, "invalid_dpop_proof")
	// a proof, valid and matching, binds the request to its key
	q = authzQuery(cl, ch, url.Values{"dpop_jkt": {k.jkt}})
	if r := push(q, h.proof(k, "POST", "/oauth/par", nil)); r.status != 201 {
		t.Fatalf("%d %v", r.status, r.m)
	}
	// a proof without the server's nonce gets one
	if r := push(authzQuery(cl, ch, nil), h.proof(k, "POST", "/oauth/par", func(_, c map[string]any) { c["nonce"] = nil })); r.m["error"] != "use_dpop_nonce" {
		t.Fatalf("%d %v", r.status, r.m)
	}
	// too large a request
	tokenErr(t, push(authzQuery(cl, ch, url.Values{"login_hint": {strings.Repeat("h", parMaxParams)}}), ""), 400, "invalid_request")
	// a push that cannot be stored
	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsPAR {
			return ephemeral.ErrFull
		}
		return nil
	})
	expectUnavailable(t, "par full", push(authzQuery(cl, ch, nil), ""))
	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsPAR {
			return errors.New("boom")
		}
		return nil
	})
	if r := push(authzQuery(cl, ch, nil), ""); r.status != 500 {
		t.Fatalf("%d %v", r.status, r.m)
	}
}

func TestCoverageLoadPushedRefusals(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	eph := h.env.Server.Eph
	if _, _, _, err := h.p.loadPushed(ctx, "", parURNPrefix+"x"); err == nil {
		t.Fatal("no client")
	}
	if _, _, _, err := h.p.loadPushed(ctx, "c", parURNPrefix); err == nil {
		t.Fatal("no id")
	}
	if _, _, _, err := h.p.loadPushed(ctx, "c", parURNPrefix+strings.Repeat("i", 201)); err == nil {
		t.Fatal("long id")
	}
	if _, _, _, err := h.p.loadPushed(ctx, "c", parURNPrefix+"unknown"); err == nil {
		t.Fatal("unknown id")
	}
	put := func(v []byte) string {
		id, err := eph.New(ctx, nsPAR, v, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	if _, _, _, err := h.p.loadPushed(ctx, "c", parURNPrefix+put([]byte("not json"))); err == nil {
		t.Fatal("not json")
	}
	bad, _ := json.Marshal(pushedRequest{ClientID: "c", Params: "a=%zz"})
	if _, _, _, err := h.p.loadPushed(ctx, "c", parURNPrefix+put(bad)); err == nil {
		t.Fatal("unparsable params")
	}
	if _, _, _, err := h.p.loadPushed(ctx, "other", parURNPrefix+put(bad)); err == nil {
		t.Fatal("another client's request")
	}
	// startPushed and usePushed on what is gone or unreadable
	if !h.p.startPushed(ctx, "gone") {
		t.Fatal("startPushed of a missing request is used")
	}
	if !h.p.startPushed(ctx, put([]byte("not json"))) {
		t.Fatal("startPushed of garbage is used")
	}
	if h.p.usePushed(ctx, "gone") || h.p.usePushed(ctx, put([]byte("not json"))) {
		t.Fatal("usePushed of garbage")
	}
}

func TestCoverageLogoutRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	other, _ := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	idt := r.str("id_token")
	c, csrf := h.session(h.user)
	status := func(q url.Values) int {
		resp := h.get(c, "/oauth/logout?"+q.Encode())
		body(resp)
		return resp.StatusCode
	}
	// a token of the wrong kind as hint
	if st := status(url.Values{"id_token_hint": {r.str("access_token")}}); st != 400 {
		t.Errorf("access token hint: %d", st)
	}
	if st := status(url.Values{"id_token_hint": {h.forge(typLogout, mustJSON(map[string]any{"iss": h.p.issuer, "aud": cl.ID, "sub": "x"}))}}); st != 400 {
		t.Errorf("logout token hint: %d", st)
	}
	// an ID token hint of claims that make no sense (signed by us)
	if st := status(url.Values{"id_token_hint": {h.forge(typJWT, mustJSON(map[string]any{"iss": "https://x"}))}}); st != 400 {
		t.Errorf("hint claims: %d", st)
	}
	// a client_id that is not the hint's audience; an unknown client; a disabled one
	if st := status(url.Values{"id_token_hint": {idt}, "client_id": {other.ID}}); st != 400 {
		t.Errorf("client_id vs audience: %d", st)
	}
	if st := status(url.Values{"client_id": {"nosuchclient"}}); st != 400 {
		t.Errorf("unknown client: %d", st)
	}
	// a redirect with no client to check it against
	if st := status(url.Values{"post_logout_redirect_uri": {"https://rp.example/bye"}}); st != 400 {
		t.Errorf("redirect without client: %d", st)
	}
	// no hint for this session: the user is asked to confirm, never signed out silently
	resp := h.get(c, "/oauth/logout?"+url.Values{"client_id": {cl.ID}, "state": {strings.Repeat("s", 3000)},
		"post_logout_redirect_uri": {"https://rp.example/bye"}}.Encode())
	if page := body(resp); resp.StatusCode != 200 || !strings.Contains(page, "/oauth/logout/confirm") {
		t.Fatalf("confirmation: %d", resp.StatusCode)
	}

	// confirm: an unknown request, an unreadable body
	post := func(form string) *http.Response {
		req, _ := http.NewRequest("POST", h.env.URL+"/oauth/logout/confirm", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := post("id=nosuch&csrf=" + url.QueryEscape(csrf)); resp.StatusCode != 400 {
		t.Errorf("expired request: %d", resp.StatusCode)
	}
	if resp := post("%zz"); resp.StatusCode != 400 {
		t.Errorf("unreadable: %d", resp.StatusCode)
	}
	// unreadable logout query
	resp = h.get(c, "/oauth/logout?%zz")
	if body(resp); resp.StatusCode != 400 {
		t.Errorf("unreadable query: %d", resp.StatusCode)
	}
	// a disabled client cannot name a redirect
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	if st := status(url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}}); st != 400 {
		t.Errorf("disabled client: %d", st)
	}
}
