package upstream

import (
	"crypto"
	"testing"
)

func TestSplitJWTRejectsMalformed(t *testing.T) {
	good := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30.c2ln" // {"alg":"RS256","kid":"k1"} . {} . sig
	h, payload, in, sig, err := splitJWT(good)
	if err != nil || h.Alg != "RS256" || h.Kid != "k1" || string(payload) != "{}" || string(sig) != "sig" ||
		string(in) != "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30" {
		t.Fatalf("good token: %+v %q %q %q %v", h, payload, in, sig, err)
	}
	for name, tok := range map[string]string{
		"empty":             "",
		"two parts":         "a.b",
		"four parts":        "a.b.c.d",
		"header not base64": "!!!.e30.c2ln",
		"header not json":   "bm90anNvbg.e30.c2ln",
		"payload bad":       "eyJhbGciOiJSUzI1NiJ9.!!!.c2ln",
		"signature bad":     "eyJhbGciOiJSUzI1NiJ9.e30.!!!",
		"padded base64":     "eyJhbGciOiJSUzI1NiJ9==.e30.c2ln",
	} {
		if _, _, _, _, err := splitJWT(tok); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestHashFor(t *testing.T) {
	for alg, want := range map[string]crypto.Hash{"RS256": crypto.SHA256, "ES256": crypto.SHA256, "PS256": crypto.SHA256,
		"RS384": crypto.SHA384, "ES384": crypto.SHA384, "RS512": crypto.SHA512} {
		if got := hashFor(alg); got != want {
			t.Errorf("%s: %v", alg, got)
		}
	}
}

func TestPickKey(t *testing.T) {
	one := []verifyKey{{kid: "a"}}
	two := []verifyKey{{kid: "a"}, {kid: "b"}}
	if k := pickKey(one, ""); k == nil || k.kid != "a" {
		t.Fatal("a single key is unambiguous without a kid")
	}
	if pickKey(two, "") != nil || pickKey(nil, "") != nil {
		t.Fatal("no kid with several keys (or none) must pick nothing")
	}
	if k := pickKey(two, "b"); k == nil || k.kid != "b" {
		t.Fatal("kid lookup")
	}
	if pickKey(two, "c") != nil {
		t.Fatal("unknown kid")
	}
}

// rsaJWK is an RSA JWK with an odd modulus of bits bits and exponent e: not a real key (none is needed to be refused
// or kept), and a 16384-bit one costs nothing to make.
func rsaJWK(bits int, e []byte) jwk {
	n := make([]byte, bits/8)
	for i := range n {
		n[i] = 0xa5
	}
	n[0], n[len(n)-1] = 0xc1, 0x01
	return jwk{Kty: "RSA", Kid: "k", N: rawB64.EncodeToString(n), E: rawB64.EncodeToString(e)}
}

// A provider's JWKS (an administrator may point a provider at their own issuer) gives RSA keys of 2048 to 8192 bits
// with a sound exponent, and at most maxKeys keys: a 16384-bit modulus is never kept, so no token is verified with it.
func TestParseKeysBoundsRSA(t *testing.T) {
	f4 := []byte{1, 0, 1}
	for name, c := range map[string]struct {
		k    jwk
		kept bool
	}{
		"2048":               {rsaJWK(2048, f4), true},
		"8192":               {rsaJWK(8192, f4), true},
		"1024":               {rsaJWK(1024, f4), false},
		"16384":              {rsaJWK(16384, f4), false},
		"even exponent":      {rsaJWK(2048, []byte{1, 0, 0}), false},
		"exponent 1":         {rsaJWK(2048, []byte{1}), false},
		"exponent over 2^31": {rsaJWK(2048, []byte{0xff, 0xff, 0xff, 0xff}), false},
		"exponent 2^31-1":    {rsaJWK(2048, []byte{0x7f, 0xff, 0xff, 0xff}), true},
	} {
		if got := len(parseKeys(jwks{Keys: []jwk{c.k}})) == 1; got != c.kept {
			t.Errorf("%s: kept %v", name, got)
		}
	}
	many := make([]jwk, maxKeys+50)
	for i := range many {
		many[i] = rsaJWK(2048, f4)
	}
	if n := len(parseKeys(jwks{Keys: many})); n != maxKeys {
		t.Errorf("%d keys taken", n)
	}
}
