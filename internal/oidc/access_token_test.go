package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// forge signs claims with the provider's own key (what only the provider can do), with the given typ header.
func (h *harness) forge(typ string, payload []byte) string {
	h.t.Helper()
	key, err := h.p.signingKey(context.Background(), h.env.Cfg.Tokens.SigningAlg)
	if err != nil {
		h.t.Fatal(err)
	}
	tok, err := key.sign(typ, payload)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func (h *harness) forgeAccess(cl *model.Client, edit func(map[string]any)) string {
	now := time.Now()
	m := map[string]any{"iss": h.issuer(), "sub": h.user.ID, "client_id": cl.ID, "aud": []string{cl.ID}, "scope": "openid",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": secureID()}
	if edit != nil {
		edit(m)
	}
	for k, v := range m {
		if v == nil {
			delete(m, k)
		}
	}
	return h.forge(typAccess, mustJSON(m))
}

func TestVerifyAccessTokenRefusals(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	ctx := context.Background()
	if _, err := h.p.verifyAccessToken(ctx, h.forgeAccess(cl, nil)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, tok := range map[string]string{
		"id token typ":  h.forge(typJWT, mustJSON(map[string]any{"iss": h.issuer()})),
		"claims shape":  h.forge(typAccess, []byte(`[1]`)),
		"issuer":        h.forgeAccess(cl, func(m map[string]any) { m["iss"] = "https://evil.example" }),
		"no expiry":     h.forgeAccess(cl, func(m map[string]any) { m["exp"] = nil }),
		"expired":       h.forgeAccess(cl, func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"not yet":       h.forgeAccess(cl, func(m map[string]any) { m["nbf"] = time.Now().Add(time.Hour).Unix() }),
		"future iat":    h.forgeAccess(cl, func(m map[string]any) { m["iat"] = time.Now().Add(time.Hour).Unix() }),
		"no subject":    h.forgeAccess(cl, func(m map[string]any) { m["sub"] = nil }),
		"no client":     h.forgeAccess(cl, func(m map[string]any) { m["client_id"] = nil }),
		"unknown user":  h.forgeAccess(cl, func(m map[string]any) { m["sub"] = "nosuchuser" }),
		"unknown app":   h.forgeAccess(cl, func(m map[string]any) { m["client_id"] = "nosuchclient" }),
		"revoked grant": h.forgeAccess(cl, func(m map[string]any) { m["gid"] = "nosuchgrant" }),
	} {
		if _, err := h.p.verifyAccessToken(ctx, tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a key that is not published, and a published key id with another algorithm
	ks, err := h.p.keys(ctx)
	if err != nil || len(ks.list) == 0 {
		t.Fatalf("keys: %v", err)
	}
	real := ks.list[0]
	var other assertionKey
	for _, k := range newAssertionKeys(t) {
		if k.alg != real.alg {
			other = k
		}
	}
	fake := func(kid string) string {
		b := mustJSON(map[string]any{"iss": h.issuer(), "sub": h.user.ID, "client_id": cl.ID, "exp": time.Now().Add(time.Minute).Unix()})
		tok, err := signJWT(other.alg, other.priv, mkHeader(other.alg, kid, typAccess), b)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	for _, kid := range []string{"nokey", real.rec.ID} {
		if _, err := h.p.verifyAccessToken(ctx, fake(kid)); err == nil {
			t.Errorf("kid %s: accepted", kid)
		}
	}
}
