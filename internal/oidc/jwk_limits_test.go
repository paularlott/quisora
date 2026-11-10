package oidc

import (
	"encoding/json"
	"strings"
	"testing"
)

// rsaTestJWK is an RSA JWK with an odd modulus of bits bits and exponent e: not a real key (none is needed to be
// refused or kept), and a 16384-bit one costs nothing to make.
func rsaTestJWK(bits int, e []byte) JWK {
	n := make([]byte, bits/8)
	for i := range n {
		n[i] = 0xa5
	}
	n[0], n[len(n)-1] = 0xc1, 0x01
	return JWK{Kty: "RSA", N: b64.EncodeToString(n), E: b64.EncodeToString(e)}
}

// RSA keys from JWKs are 2048 to 8192 bits with an odd exponent from 3 to 2^31-1: verification costs grow with the
// square of the modulus, and a DPoP proof (unauthenticated) or a client's jwks_uri chooses the key.
func TestJWKBoundsRSA(t *testing.T) {
	f4 := []byte{1, 0, 1}
	for name, c := range map[string]struct {
		j  JWK
		ok bool
	}{
		"2048":               {rsaTestJWK(2048, f4), true},
		"8192":               {rsaTestJWK(8192, f4), true},
		"1024":               {rsaTestJWK(1024, f4), false},
		"16384":              {rsaTestJWK(16384, f4), false},
		"even exponent":      {rsaTestJWK(2048, []byte{1, 0, 0}), false},
		"exponent over 2^31": {rsaTestJWK(2048, []byte{0xff, 0xff, 0xff, 0xff}), false},
		"exponent 2^31-1":    {rsaTestJWK(2048, []byte{0x7f, 0xff, 0xff, 0xff}), true},
	} {
		if _, err := c.j.PublicKey(); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A DPoP proof whose jwk is a 16384-bit RSA key is refused when its key is read, before its signature is checked.
func TestDPoPProofKeyRefusesHugeRSA(t *testing.T) {
	hdr, _ := json.Marshal(map[string]any{"typ": dpopTyp, "alg": AlgRS256, "jwk": rsaTestJWK(16384, []byte{1, 0, 1})})
	if _, err := proofKey(b64.EncodeToString(hdr)); err == nil || !strings.Contains(err.Error(), "not a supported public key") {
		t.Fatalf("got %v", err)
	}
}

// A JWKS gives at most maxJWKSKeys keys.
func TestParseJWKSCapsKeys(t *testing.T) {
	keys := make([]JWK, maxJWKSKeys+50)
	for i := range keys {
		keys[i] = rsaTestJWK(2048, []byte{1, 0, 1})
	}
	data, _ := json.Marshal(JWKS{Keys: keys})
	if got, err := ParseJWKS(data); err != nil || len(got) != maxJWKSKeys {
		t.Fatalf("%d keys, %v", len(got), err)
	}
}
