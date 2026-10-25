package oidc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"testing"
)

func TestCoverageParseJWTPayloadEncoding(t *testing.T) {
	hdr := b64.EncodeToString([]byte(`{"alg":"ES256"}`))
	if _, err := ParseJWT(hdr + ".!!!.AAAA"); err == nil {
		t.Fatal("bad payload encoding accepted")
	}
}

func TestCoverageVerifyRefusesSmallRSA(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for _, alg := range []string{AlgRS256, AlgPS256} {
		if verifySig(alg, &small.PublicKey, []byte("x"), []byte("sig")) {
			t.Errorf("%s: small key accepted", alg)
		}
		if verifySig(alg, "not a key", []byte("x"), []byte("sig")) {
			t.Errorf("%s: wrong key type accepted", alg)
		}
	}
	if verifySig("HS256", []byte("k"), []byte("x"), []byte("sig")) {
		t.Fatal("unknown algorithm verified")
	}
}

func TestCoverageSignJWTUnsupported(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := signJWT("HS256", ed, "h", []byte("p")); err == nil {
		t.Fatal("HS256 signed")
	}
}

func TestCoverageDERToRawMalformed(t *testing.T) {
	long := func(size int) []byte {
		// SEQUENCE { INTEGER r, INTEGER s } with each integer size bytes: long-form length
		in := append([]byte{0x02, byte(size)}, make([]byte, size)...)
		body := append(append([]byte{}, in...), in...)
		return append([]byte{0x30, 0x81, byte(len(body))}, body...)
	}
	if raw, err := derToRaw(long(66), 64); err != nil || len(raw) != 128 {
		t.Fatalf("long form: %v", err)
	}
	for name, der := range map[string][]byte{
		"empty":            nil,
		"wrong tag":        {0x31, 0x00},
		"long form 2 byte": {0x30, 0x82, 0x00, 0x00},
		"long form short":  {0x30, 0x81},
		"truncated":        {0x30, 0x05, 0x02, 0x01},
		"not integers":     {0x30, 0x02, 0x04, 0x00},
		"only one":         {0x30, 0x03, 0x02, 0x01, 0x01},
		"too big":          append([]byte{0x30, 0x26, 0x02, 0x21, 0x01}, append(make([]byte, 32), 0x02, 0x01, 0x01)...),
	} {
		if _, err := derToRaw(der, 32); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCoverageClaimTypesRefuseJunk(t *testing.T) {
	var n NumericDate
	if json.Unmarshal([]byte(`"soon"`), &n) == nil {
		t.Error("NumericDate string")
	}
	var a Audience
	if json.Unmarshal([]byte(`"bad\q"`), &a) == nil {
		t.Error("Audience bad string")
	}
	if json.Unmarshal([]byte(`5`), &a) == nil {
		t.Error("Audience number")
	}
}

func TestCoverageJWKRefusals(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := EncodeJWK(&p384.PublicKey, "k", ""); err == nil {
		t.Error("P-384 encoded")
	}
	if _, err := EncodeJWK("nope", "k", ""); err == nil {
		t.Error("unsupported key type encoded")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	sj, _ := EncodeJWK(&small.PublicKey, "k", "")
	for name, j := range map[string]JWK{
		"EC curve":     {Kty: "EC", Crv: "P-384"},
		"OKP curve":    {Kty: "OKP", Crv: "X25519"},
		"OKP size":     {Kty: "OKP", Crv: "Ed25519", X: "AA"},
		"RSA missing":  {Kty: "RSA"},
		"RSA small":    sj,
		"unknown type": {Kty: "oct"},
	} {
		if _, err := j.PublicKey(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if (JWK{Kty: "oct"}).KeyAlg() != "" {
		t.Error("KeyAlg of an unknown type")
	}
}

func TestCoverageParsePrivateRefusals(t *testing.T) {
	if _, _, _, err := parsePrivate([]byte("junk")); err == nil {
		t.Error("junk parsed")
	}
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(x)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := parsePrivate(der); err == nil {
		t.Error("X25519 private key accepted for signing")
	}
}
