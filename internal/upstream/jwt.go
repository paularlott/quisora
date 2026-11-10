package upstream

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash
	_ "crypto/sha512" // registers SHA-384/512
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// A deliberately small JWT/JWK implementation: it verifies compact JWS tokens signed with RS256/RS384/RS512,
// PS256 or ES256/ES384 against a JWKS, which covers every mainstream OpenID provider. The key type is taken from
// the JWK, never from the token, and "none"/HMAC algorithms are rejected, so algorithm confusion is impossible.

var errBadToken = errors.New("malformed token")

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type verifyKey struct {
	kid string
	alg string // from the JWK; "" when unspecified
	pub crypto.PublicKey
}

var rawB64 = base64.RawURLEncoding

// Limits of the keys taken from a provider's JWKS (which an organization's administrator may point at an issuer of
// their own): RSA keys of 2048 to 8192 bits with an odd exponent from 3 to 2^31-1 (RSA verification costs grow with
// the square of the modulus: a far larger one would hold a core for seconds per token), and the first maxKeys keys.
const (
	minRSABits = 2048
	maxRSABits = 8192
	maxKeys    = 100
)

func parseKeys(set jwks) []verifyKey {
	var out []verifyKey
	for _, k := range set.Keys[:min(len(set.Keys), maxKeys)] {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := rawB64.DecodeString(k.N)
			e, err2 := rawB64.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(n) > maxRSABits/8+1 || len(e) == 0 || len(e) > 4 {
				continue
			}
			ev := 0
			for _, b := range e {
				ev = ev<<8 | int(b)
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ev}
			if pub.N.BitLen() < minRSABits || pub.N.BitLen() > maxRSABits || ev < 3 || ev > 1<<31-1 || ev%2 == 0 {
				continue
			}
			out = append(out, verifyKey{kid: k.Kid, alg: k.Alg, pub: pub})
		case "EC":
			var c elliptic.Curve
			switch k.Crv {
			case "P-256":
				c = elliptic.P256()
			case "P-384":
				c = elliptic.P384()
			default:
				continue
			}
			x, err1 := rawB64.DecodeString(k.X)
			y, err2 := rawB64.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			pub := &ecdsa.PublicKey{Curve: c, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !c.IsOnCurve(pub.X, pub.Y) {
				continue
			}
			out = append(out, verifyKey{kid: k.Kid, alg: k.Alg, pub: pub})
		}
	}
	return out
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// splitJWT parses a compact JWS without verifying it.
func splitJWT(tok string) (h header, payload, signingInput, sig []byte, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return h, nil, nil, nil, errBadToken
	}
	hb, err := rawB64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &h) != nil {
		return h, nil, nil, nil, errBadToken
	}
	if payload, err = rawB64.DecodeString(parts[1]); err != nil {
		return h, nil, nil, nil, errBadToken
	}
	if sig, err = rawB64.DecodeString(parts[2]); err != nil {
		return h, nil, nil, nil, errBadToken
	}
	return h, payload, []byte(parts[0] + "." + parts[1]), sig, nil
}

// verifySignature checks sig over signingInput with the key, requiring alg to suit the key's type.
func verifySignature(alg string, k verifyKey, signingInput, sig []byte) error {
	if k.alg != "" && k.alg != alg {
		return errors.New("key is for a different algorithm")
	}
	switch alg {
	case "RS256", "RS384", "RS512", "PS256":
		pub, ok := k.pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type does not match algorithm")
		}
		h := hashFor(alg)
		hh := h.New()
		hh.Write(signingInput)
		if alg == "PS256" {
			return rsa.VerifyPSS(pub, h, hh.Sum(nil), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(pub, h, hh.Sum(nil), sig)
	case "ES256", "ES384":
		pub, ok := k.pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("key type does not match algorithm")
		}
		want := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384()}[alg]
		if pub.Curve != want {
			return errors.New("curve does not match algorithm")
		}
		size := (want.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errors.New("bad signature length")
		}
		hh := hashFor(alg).New()
		hh.Write(signingInput)
		if !ecdsa.Verify(pub, hh.Sum(nil), new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])) {
			return errors.New("signature mismatch")
		}
		return nil
	}
	return fmt.Errorf("unsupported algorithm %q", alg)
}

func hashFor(alg string) crypto.Hash {
	switch alg {
	case "RS384", "ES384":
		return crypto.SHA384
	case "RS512":
		return crypto.SHA512
	}
	return crypto.SHA256
}
