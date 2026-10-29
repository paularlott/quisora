package oidc

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

type testKey struct {
	alg  string
	priv crypto.Signer
}

func genKeys(t testing.TB) []testKey {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return []testKey{{AlgES256, ec}, {AlgEdDSA, ed}, {AlgRS256, rs}}
}

func signWith(t testing.TB, k testKey, kid, typ, payload string) string {
	t.Helper()
	tok, err := signJWT(k.alg, k.priv, mkHeader(k.alg, kid, typ), []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestSignVerifyAllAlgs(t *testing.T) {
	t.Parallel()
	for _, k := range genKeys(t) {
		t.Run(k.alg, func(t *testing.T) {
			tok := signWith(t, k, "kid1", "JWT", `{"sub":"u1","n":1}`)
			p, err := ParseJWT(tok)
			if err != nil {
				t.Fatal(err)
			}
			if p.Header.Alg != k.alg || p.Header.Kid != "kid1" || p.Header.Typ != "JWT" {
				t.Fatalf("header %+v", p.Header)
			}
			if err := p.Verify(k.priv.Public()); err != nil {
				t.Fatal(err)
			}
			if string(p.Payload) != `{"sub":"u1","n":1}` {
				t.Fatalf("payload %s", p.Payload)
			}
		})
	}
}

// decodeIndependently verifies a token with nothing but the standard library, as a third-party library would.
func decodeIndependently(t *testing.T, tok string, pub crypto.PublicKey) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal("not 3 parts")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]string
	if err := json.Unmarshal(hb, &h); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(parts[0] + "." + parts[1])
	switch h["alg"] {
	case "ES256":
		if len(sig) != 64 { // RFC 7518 §3.4: exactly r||s, 32 bytes each
			t.Fatalf("ES256 signature is %d bytes", len(sig))
		}
		d := sha256.Sum256(input)
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub.(*ecdsa.PublicKey), d[:], r, s) {
			t.Fatal("ES256 signature does not verify")
		}
	case "EdDSA":
		if !ed25519.Verify(pub.(ed25519.PublicKey), input, sig) {
			t.Fatal("EdDSA signature does not verify")
		}
	case "RS256":
		d := sha256.Sum256(input)
		if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, d[:], sig); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("alg %q", h["alg"])
	}
}

func TestCrossCheckWithStdlib(t *testing.T) {
	t.Parallel()
	for _, k := range genKeys(t) {
		for range 20 { // ES256 DER->raw conversion has length edge cases (leading zeros): exercise many
			tok := signWith(t, k, "k", "at+jwt", `{"a":"b"}`)
			decodeIndependently(t, tok, k.priv.Public())
		}
	}
}

func TestVerifyRejectsForgeries(t *testing.T) {
	t.Parallel()
	keys := genKeys(t)
	other := genKeys(t)
	for i, k := range keys {
		tok := signWith(t, k, "k", "JWT", `{"sub":"a"}`)
		p, _ := ParseJWT(tok)

		// wrong key of the same type
		if p.Verify(other[i].priv.Public()) == nil {
			t.Errorf("%s: verified with the wrong key", k.alg)
		}
		// key of a different type
		for j, o := range keys {
			if j != i && p.Verify(o.priv.Public()) == nil {
				t.Errorf("%s: verified with a %s key", k.alg, o.alg)
			}
		}
		// tampered payload
		parts := strings.Split(tok, ".")
		parts[1] = b64.EncodeToString([]byte(`{"sub":"admin"}`))
		if p2, err := ParseJWT(strings.Join(parts, ".")); err == nil && p2.Verify(k.priv.Public()) == nil {
			t.Errorf("%s: tampered payload verified", k.alg)
		}
		// tampered signature (flip one bit)
		raw, _ := b64.DecodeString(strings.Split(tok, ".")[2])
		raw[len(raw)/2] ^= 1
		forged := strings.Join(strings.Split(tok, ".")[:2], ".") + "." + b64.EncodeToString(raw)
		if p3, err := ParseJWT(forged); err == nil && p3.Verify(k.priv.Public()) == nil {
			t.Errorf("%s: tampered signature verified", k.alg)
		}
		// truncated / empty signature
		for _, s := range []string{"", b64.EncodeToString(raw[:len(raw)-1])} {
			bad := strings.Join(strings.Split(tok, ".")[:2], ".") + "." + s
			if p4, err := ParseJWT(bad); err == nil && p4.Verify(k.priv.Public()) == nil {
				t.Errorf("%s: short signature verified", k.alg)
			}
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	t.Parallel()
	ec := genKeys(t)[0]
	good := signWith(t, ec, "k", "JWT", `{}`)
	hdr := func(s string) string { return b64.EncodeToString([]byte(s)) }
	body := b64.EncodeToString([]byte(`{}`))
	cases := map[string]string{
		"empty":                 "",
		"one part":              "abc",
		"two parts":             "abc.def",
		"four parts":            good + ".x",
		"empty header":          "." + body + ".c2ln",
		"empty signature":       hdr(`{"alg":"ES256"}`) + "." + body + ".",
		"alg none":              hdr(`{"alg":"none"}`) + "." + body + ".c2ln",
		"alg None":              hdr(`{"alg":"None"}`) + "." + body + ".c2ln",
		"alg HS256":             hdr(`{"alg":"HS256"}`) + "." + body + ".c2ln",
		"alg empty":             hdr(`{"alg":""}`) + "." + body + ".c2ln",
		"alg missing":           hdr(`{"typ":"JWT"}`) + "." + body + ".c2ln",
		"alg ES384":             hdr(`{"alg":"ES384"}`) + "." + body + ".c2ln",
		"alg PS384":             hdr(`{"alg":"PS384"}`) + "." + body + ".c2ln",
		"crit":                  hdr(`{"alg":"ES256","crit":["x"],"x":1}`) + "." + body + ".c2ln",
		"header not json":       hdr(`not json`) + "." + body + ".c2ln",
		"padded base64":         hdr(`{"alg":"ES256"}`) + "=." + body + ".c2ln",
		"std base64 chars":      "e+/=." + body + ".c2ln",
		"payload not base64url": hdr(`{"alg":"ES256"}`) + ".!!!.AAAA",
		"huge":                  good + strings.Repeat("A", maxJWTSize),
	}
	for name, tok := range cases {
		if _, err := ParseJWT(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The classic attack: sign with HMAC using the server's public key as the secret and hope the verifier trusts
// the header's alg. ParseJWT never accepts HS256 and Verify binds the algorithm to the key type.
func TestAlgConfusion(t *testing.T) {
	t.Parallel()
	keys := genKeys(t)
	rsaKey := keys[2].priv.(*rsa.PrivateKey)
	pubJWK, _ := EncodeJWK(&rsaKey.PublicKey, "k", AlgRS256)
	pubJSON, _ := json.Marshal(pubJWK)

	h := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"k","typ":"JWT"}`))
	pl := b64.EncodeToString([]byte(`{"sub":"admin"}`))
	mac := hmac.New(sha256.New, pubJSON)
	mac.Write([]byte(h + "." + pl))
	tok := h + "." + pl + "." + b64.EncodeToString(mac.Sum(nil))
	if _, err := ParseJWT(tok); err == nil {
		t.Fatal("HS256 token accepted")
	}

	// RS256 header over an EC key (and vice versa): the key type decides, not the header.
	ecTok := signWith(t, keys[0], "k", "JWT", `{}`)
	parts := strings.Split(ecTok, ".")
	parts[0] = b64.EncodeToString([]byte(`{"alg":"RS256","kid":"k"}`))
	p, err := ParseJWT(strings.Join(parts, "."))
	if err != nil {
		t.Fatal(err)
	}
	if p.Verify(keys[0].priv.Public()) == nil {
		t.Fatal("RS256-labelled token verified with an EC key")
	}
	// EdDSA header, EC signature
	parts[0] = b64.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k"}`))
	p, _ = ParseJWT(strings.Join(parts, "."))
	if p.Verify(keys[1].priv.Public()) == nil || p.Verify(keys[0].priv.Public()) == nil {
		t.Fatal("EdDSA-labelled token verified")
	}
}

// Signatures are refused for keys that are too small, of the wrong type for the algorithm, or for an unknown algorithm.
func TestVerifyRefusesUnsuitableKeys(t *testing.T) {
	t.Parallel()
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tok := signWith(t, testKey{AlgRS256, small}, "k", "JWT", `{}`)
	p, _ := ParseJWT(tok)
	if p.Verify(&small.PublicKey) == nil {
		t.Fatal("1024-bit RSA verified")
	}
	j, _ := EncodeJWK(&small.PublicKey, "k", AlgRS256)
	if _, err := j.PublicKey(); err == nil {
		t.Fatal("1024-bit RSA JWK accepted")
	}
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

func TestJWKRoundTrip(t *testing.T) {
	t.Parallel()
	for _, k := range genKeys(t) {
		j, err := EncodeJWK(k.priv.Public(), "kid-"+k.alg, k.alg)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(j)
		set, err := ParseJWKS([]byte(`{"keys":[` + string(b) + `]}`))
		if err != nil || len(set) != 1 {
			t.Fatal(err, set)
		}
		pub, err := set[0].PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		tok := signWith(t, k, set[0].Kid, "JWT", `{}`)
		p, _ := ParseJWT(tok)
		if err := p.Verify(pub); err != nil {
			t.Fatalf("%s: %v", k.alg, err)
		}
		if set[0].KeyAlg() != k.alg {
			t.Fatalf("KeyAlg %s", set[0].KeyAlg())
		}
		// bare JWK
		one, err := ParseJWKS(b)
		if err != nil || len(one) != 1 {
			t.Fatal("bare JWK", err)
		}
	}
	if _, err := ParseJWKS([]byte(`{"foo":1}`)); err == nil {
		t.Fatal("non-JWK accepted")
	}
}

func TestJWKRejectsBadPoints(t *testing.T) {
	t.Parallel()
	ec := genKeys(t)[0].priv.(*ecdsa.PrivateKey)
	j, _ := EncodeJWK(&ec.PublicKey, "k", AlgES256)
	// not on the curve
	bad := j
	bad.Y = b64.EncodeToString(make([]byte, 32))
	if _, err := bad.PublicKey(); err == nil {
		t.Fatal("off-curve point accepted")
	}
	// wrong curve label / short coordinates
	bad = j
	bad.Crv = "P-384"
	if _, err := bad.PublicKey(); err == nil {
		t.Fatal("P-384 accepted")
	}
	bad = j
	bad.X = "AAAA"
	if _, err := bad.PublicKey(); err == nil {
		t.Fatal("short x accepted")
	}
	if _, err := (JWK{Kty: "oct"}).PublicKey(); err == nil {
		t.Fatal("oct accepted")
	}
	// keys that cannot be published or used
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := EncodeJWK(&p384.PublicKey, "k", ""); err == nil {
		t.Error("P-384 encoded")
	}
	if _, err := EncodeJWK("nope", "k", ""); err == nil {
		t.Error("unsupported key type encoded")
	}
	for name, j := range map[string]JWK{
		"OKP curve":   {Kty: "OKP", Crv: "X25519"},
		"OKP size":    {Kty: "OKP", Crv: "Ed25519", X: "AA"},
		"RSA missing": {Kty: "RSA"},
	} {
		if _, err := j.PublicKey(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if (JWK{Kty: "oct"}).KeyAlg() != "" {
		t.Error("KeyAlg of an unknown type")
	}
}

func TestAppendJSONString(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "plain", `quo"te`, `back\slash`, "tab\tnl\ncr\r", "ctl\x00\x01\x1f", "<script>&", "héllo ☃ 😀",
		"bad\xffutf8", "sep  ", "\b\f"} {
		out := appendJSONString(nil, s)
		var back string
		if err := json.Unmarshal(out, &back); err != nil {
			t.Fatalf("%q: %v (%s)", s, err, out)
		}
		want := strings.ToValidUTF8(s, "�")
		if back != want {
			t.Errorf("%q: got %q want %q", s, back, want)
		}
	}
}

func TestDERToRaw(t *testing.T) {
	t.Parallel()
	// r or s with leading zero bytes must be left-padded to 32 bytes
	der := []byte{0x30, 0x08, 0x02, 0x02, 0x00, 0xff, 0x02, 0x02, 0x01, 0x02}
	raw, err := derToRaw(der, 32)
	if err != nil || len(raw) != 64 || raw[31] != 0xff || raw[63] != 0x02 || raw[62] != 0x01 || raw[30] != 0 {
		t.Fatalf("%x %v", raw, err)
	}
	// a long-form length
	long := func(size int) []byte {
		// SEQUENCE { INTEGER r, INTEGER s } with each integer size bytes
		in := append([]byte{0x02, byte(size)}, make([]byte, size)...)
		body := append(append([]byte{}, in...), in...)
		return append([]byte{0x30, 0x81, byte(len(body))}, body...)
	}
	if raw, err := derToRaw(long(66), 64); err != nil || len(raw) != 128 {
		t.Fatalf("long form: %v", err)
	}
	for name, der := range map[string][]byte{
		"empty":             nil,
		"no length":         {0x30},
		"wrong tag":         {0x31, 0x00},
		"long form 2 byte":  {0x30, 0x82, 0x00, 0x00},
		"long form short":   {0x30, 0x81},
		"truncated":         {0x30, 0x05, 0x02, 0x01},
		"truncated integer": {0x30, 0x02, 0x02, 0x00},
		"not integers":      {0x30, 0x02, 0x04, 0x00},
		"only one":          {0x30, 0x03, 0x02, 0x01, 0x01},
		"too big":           append([]byte{0x30, 0x26, 0x02, 0x21, 0x01}, append(make([]byte, 32), 0x02, 0x01, 0x01)...),
	} {
		if _, err := derToRaw(der, 32); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestClaimsParsing(t *testing.T) {
	t.Parallel()
	var c Claims
	if err := json.Unmarshal([]byte(`{"aud":"a","exp":1.5e9,"iat":1700000000,"scope":"openid email"}`), &c); err != nil {
		t.Fatal(err)
	}
	if !c.Aud.Has("a") || c.Exp != 1500000000 || !c.HasScope("email") || c.HasScope("groups") {
		t.Fatalf("%+v", c)
	}
	if err := json.Unmarshal([]byte(`{"aud":["a","b"]}`), &c); err != nil || !c.Aud.Has("b") {
		t.Fatal(err, c.Aud)
	}
	// types that are not what the claim is
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

func TestMFASatisfied(t *testing.T) {
	t.Parallel()
	cases := []struct {
		amr  []string
		want bool
	}{
		{nil, false}, {[]string{"pwd"}, false}, {[]string{"otp"}, false}, {[]string{"pwd", "otp"}, true},
		{[]string{"mfa"}, true}, {[]string{"hwk"}, false}, {[]string{"swk"}, false}, {[]string{"hwk", "user"}, true},
		{[]string{"swk", "user"}, true}, {[]string{"pwd", "user"}, false},
	}
	for _, c := range cases {
		if MFASatisfied(c.amr) != c.want {
			t.Errorf("%v: want %v", c.amr, c.want)
		}
	}
}

// --- benchmarks ------------------------------------------------------------------------------------------------

func BenchmarkJWTSign(b *testing.B) {
	for _, k := range genKeys(b) {
		hdr := mkHeader(k.alg, "kid", typAccess)
		payload := []byte(`{"iss":"https://quisora.example.com","sub":"034nmRmWuek830Rq7vfC3T","aud":"034nmRmWuT4ZrzffAjJgxn","client_id":"034nmRmWuT4ZrzffAjJgxn","scope":"openid profile email","exp":1900000000,"iat":1800000000,"jti":"AAAAAAAAAAAAAAAAAAAAAA","auth_time":1800000000,"acr":"urn:quisora:acr:basic","amr":["pwd"],"org":"034nmRmWucodP0rMzZbwBg","org_name":"acme","org_role":"user"}`)
		b.Run(k.alg, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := signJWT(k.alg, k.priv, hdr, payload); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkJWTVerify(b *testing.B) {
	for _, k := range genKeys(b) {
		tok := signWith(b, k, "kid", typAccess, `{"iss":"https://quisora.example.com","sub":"034nmRmWuek830Rq7vfC3T","scope":"openid profile email","exp":1900000000}`)
		pub := k.priv.Public()
		b.Run(k.alg, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					p, err := ParseJWT(tok)
					if err != nil {
						b.Fatal(err)
					}
					if err := p.Verify(pub); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// Keys that cannot sign are refused as signing material: an unsupported algorithm, junk, a key type with no signature.
func TestSigningKeyInputsRefused(t *testing.T) {
	t.Parallel()
	t.Run("unsupported algorithm", func(t *testing.T) {
		_, ed, _ := ed25519.GenerateKey(rand.Reader)
		if _, err := signJWT("HS256", ed, "h", []byte("p")); err == nil {
			t.Fatal("HS256 signed")
		}
	})

	t.Run("private key parsing", func(t *testing.T) {
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
	})
}
