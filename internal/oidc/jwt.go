package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A minimal JWT / JWK implementation: ES256, EdDSA and RS256 only, strict header checks. Tokens are produced by
// hand-written JSON appenders (no reflection) because signing is on the hot path of the token endpoint.

// Signature algorithms (RFC 7518 / RFC 8037).
const (
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
	AlgRS256 = "RS256"
)

// ValidAlg reports whether alg is a signature algorithm this package implements.
func ValidAlg(alg string) bool { return alg == AlgES256 || alg == AlgEdDSA || alg == AlgRS256 }

var (
	// ErrInvalidToken is returned for any malformed, forged or unacceptable JWT. Callers never learn which check
	// failed; the wrapped detail is for logs only.
	ErrInvalidToken = errors.New("oidc: invalid token")
	b64             = base64.RawURLEncoding
	b64strict       = base64.RawURLEncoding.Strict()
)

const maxJWTSize = 16 << 10

func badToken(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, a...))
}

// Header is the JOSE header of a compact JWS.
type Header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid,omitempty"`
	Typ  string   `json:"typ,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// Parsed is a syntactically valid compact JWS whose signature has not been checked yet.
type Parsed struct {
	Header  Header
	Payload []byte
	input   string // "<header>.<payload>", the signed bytes
	sig     []byte
}

// ParseJWT splits and decodes a compact JWS and applies the strict header checks (algorithm allow-list, no "none",
// no critical extensions). It does not verify the signature: call Verify.
func ParseJWT(tok string) (*Parsed, error) {
	if len(tok) > maxJWTSize {
		return nil, badToken("too large")
	}
	i := strings.IndexByte(tok, '.')
	if i <= 0 {
		return nil, badToken("not a JWS")
	}
	j := strings.IndexByte(tok[i+1:], '.')
	if j <= 0 {
		return nil, badToken("not a JWS")
	}
	j += i + 1
	if strings.IndexByte(tok[j+1:], '.') >= 0 || j+1 >= len(tok) {
		return nil, badToken("not a JWS")
	}
	hb, err := b64strict.DecodeString(tok[:i])
	if err != nil {
		return nil, badToken("header encoding")
	}
	p := &Parsed{input: tok[:j]}
	if err := json.Unmarshal(hb, &p.Header); err != nil {
		return nil, badToken("header JSON")
	}
	if !ValidAlg(p.Header.Alg) { // rejects "none" and every algorithm we do not implement (including HS*)
		return nil, badToken("algorithm %q not allowed", p.Header.Alg)
	}
	if len(p.Header.Crit) > 0 {
		return nil, badToken("critical header extensions are not supported")
	}
	if p.Payload, err = b64strict.DecodeString(tok[i+1 : j]); err != nil {
		return nil, badToken("payload encoding")
	}
	if p.sig, err = b64strict.DecodeString(tok[j+1:]); err != nil {
		return nil, badToken("signature encoding")
	}
	return p, nil
}

// Verify checks the signature against pub. The key type must match the header algorithm (so an RSA public key can
// never be used as an HMAC secret, nor an EC key accepted for RS256).
func (p *Parsed) Verify(pub crypto.PublicKey) error {
	if !verifySig(p.Header.Alg, pub, []byte(p.input), p.sig) {
		return badToken("signature")
	}
	return nil
}

func verifySig(alg string, pub crypto.PublicKey, input, sig []byte) bool {
	switch alg {
	case AlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() || len(sig) != 64 {
			return false
		}
		h := sha256.Sum256(input)
		return ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case AlgEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		return ok && len(k) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(k, input, sig)
	case AlgRS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < 2048 {
			return false
		}
		h := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	}
	return false
}

// signJWT returns header.payload.signature where header is the already base64url-encoded JOSE header.
func signJWT(alg string, priv crypto.Signer, hdr string, payload []byte) (string, error) {
	n := len(hdr) + 1 + b64.EncodedLen(len(payload))
	buf := make([]byte, n, n+1+b64.EncodedLen(512))
	copy(buf, hdr)
	buf[len(hdr)] = '.'
	b64.Encode(buf[len(hdr)+1:], payload)
	var sig []byte
	switch alg {
	case AlgES256:
		h := sha256.Sum256(buf)
		der, err := ecdsa.SignASN1(randReader, priv.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			return "", err
		}
		if sig, err = derToRaw(der, 32); err != nil {
			return "", err
		}
	case AlgEdDSA:
		sig = ed25519.Sign(priv.(ed25519.PrivateKey), buf)
	case AlgRS256:
		h := sha256.Sum256(buf)
		var err error
		if sig, err = rsa.SignPKCS1v15(randReader, priv.(*rsa.PrivateKey), crypto.SHA256, h[:]); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("oidc: unsupported alg %q", alg)
	}
	buf = append(buf, '.')
	buf = b64.AppendEncode(buf, sig)
	return string(buf), nil
}

// derToRaw converts an ASN.1 ECDSA signature to the fixed-width r||s form JWS requires.
func derToRaw(der []byte, size int) ([]byte, error) {
	read := func(b []byte, tag byte) (content, rest []byte, ok bool) {
		if len(b) < 2 || b[0] != tag {
			return nil, nil, false
		}
		l, off := int(b[1]), 2
		if l&0x80 != 0 {
			if l != 0x81 || len(b) < 3 {
				return nil, nil, false
			}
			l, off = int(b[2]), 3
		}
		if len(b) < off+l {
			return nil, nil, false
		}
		return b[off : off+l], b[off+l:], true
	}
	seq, _, ok := read(der, 0x30)
	if !ok {
		return nil, errors.New("oidc: bad ECDSA signature")
	}
	out := make([]byte, 2*size)
	for i := range 2 {
		var v []byte
		if v, seq, ok = read(seq, 0x02); !ok {
			return nil, errors.New("oidc: bad ECDSA signature")
		}
		for len(v) > 0 && v[0] == 0 {
			v = v[1:]
		}
		if len(v) > size {
			return nil, errors.New("oidc: bad ECDSA signature")
		}
		copy(out[i*size+size-len(v):(i+1)*size], v)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Claims

// NumericDate is a JWT NumericDate (seconds since the epoch; fractions are truncated).
type NumericDate int64

func (n *NumericDate) UnmarshalJSON(b []byte) error {
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return err
	}
	*n = NumericDate(f)
	return nil
}

// Audience is the "aud" claim: a string or an array of strings.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*a = Audience{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*a = l
	return nil
}

// Has reports whether aud is one of the audiences.
func (a Audience) Has(aud string) bool {
	for _, v := range a {
		if v == aud {
			return true
		}
	}
	return false
}

// Claims is the union of the claims this provider reads from access tokens, ID tokens, client assertions and
// logout hints.
type Claims struct {
	Iss        string                     `json:"iss"`
	Sub        string                     `json:"sub"`
	Aud        Audience                   `json:"aud"`
	Exp        NumericDate                `json:"exp"`
	Iat        NumericDate                `json:"iat"`
	Nbf        NumericDate                `json:"nbf"`
	Jti        string                     `json:"jti"`
	ClientID   string                     `json:"client_id"`
	Scope      string                     `json:"scope"`
	AuthTime   NumericDate                `json:"auth_time"`
	ACR        string                     `json:"acr"`
	AMR        []string                   `json:"amr"`
	SID        string                     `json:"sid"`
	GID        string                     `json:"gid"` // refresh grant the token was issued from (access tokens)
	Org        string                     `json:"org"`
	OrgName    string                     `json:"org_name"`
	Tenant     string                     `json:"tenant"`
	TenantName string                     `json:"tenant_name"`
	Role       string                     `json:"role"`
	Groups     []string                   `json:"groups"`
	Tags       []string                   `json:"tags"`
	Roles      []string                   `json:"roles"`
	Nonce      string                     `json:"nonce"`
	Events     map[string]json.RawMessage `json:"events"`
	Email      string                     `json:"email"`
	EmailVerif bool                       `json:"email_verified"`
	Name       string                     `json:"name"`
	Username   string                     `json:"preferred_username"`
	// UserinfoClaims are the claims requested one by one for userinfo (access tokens).
	UserinfoClaims []string `json:"userinfo_claims"`
}

// Scopes splits the scope claim.
func (c *Claims) Scopes() []string { return strings.Fields(c.Scope) }

// HasScope reports whether the scope claim holds s.
func (c *Claims) HasScope(s string) bool {
	for _, v := range strings.Fields(c.Scope) {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------------------------
// JSON appenders

const hexDigits = "0123456789abcdef"

// appendJSONString appends s as a JSON string literal.
func appendJSONString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, s[start:i]...)
			b = append(b, `�`...)
			i += size
			start = i
			continue
		}
		if r == ' ' || r == ' ' {
			b = append(b, s[start:i]...)
			b = append(b, '\\', 'u', '2', '0', '2', hexDigits[r&0xf])
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// obj builds a flat JSON object.
type obj struct {
	b     []byte
	comma bool
}

func newObj(capacity int) *obj { return &obj{b: append(make([]byte, 0, capacity), '{')} }

func (o *obj) key(k string) {
	if o.comma {
		o.b = append(o.b, ',')
	}
	o.comma = true
	o.b = append(o.b, '"')
	o.b = append(o.b, k...)
	o.b = append(o.b, '"', ':')
}
func (o *obj) str(k, v string) { o.key(k); o.b = appendJSONString(o.b, v) }
func (o *obj) strIf(k, v string) {
	if v != "" {
		o.str(k, v)
	}
}
func (o *obj) num(k string, v int64) { o.key(k); o.b = strconv.AppendInt(o.b, v, 10) }
func (o *obj) boolean(k string, v bool) {
	o.key(k)
	o.b = strconv.AppendBool(o.b, v)
}
func (o *obj) strs(k string, v []string) {
	o.key(k)
	o.b = append(o.b, '[')
	for i, s := range v {
		if i > 0 {
			o.b = append(o.b, ',')
		}
		o.b = appendJSONString(o.b, s)
	}
	o.b = append(o.b, ']')
}
func (o *obj) raw(k, v string) { o.key(k); o.b = append(o.b, v...) }
func (o *obj) bytes() []byte   { return append(o.b, '}') }

// ---------------------------------------------------------------------------------------------------------------
// JWK / JWKS

// JWK is a public JSON Web Key (RFC 7517) as published and as read from client registrations.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// EncodeJWK builds the public JWK of a key.
func EncodeJWK(pub crypto.PublicKey, kid, alg string) (JWK, error) {
	j := JWK{Kid: kid, Alg: alg, Use: "sig"}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return j, errors.New("oidc: only P-256 EC keys are supported")
		}
		pt, err := k.Bytes()
		if err != nil {
			return j, err
		}
		j.Kty, j.Crv = "EC", "P-256"
		j.X, j.Y = b64.EncodeToString(pt[1:33]), b64.EncodeToString(pt[33:65])
	case ed25519.PublicKey:
		j.Kty, j.Crv, j.X = "OKP", "Ed25519", b64.EncodeToString(k)
	case *rsa.PublicKey:
		j.Kty = "RSA"
		j.N = b64.EncodeToString(k.N.Bytes())
		j.E = b64.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	default:
		return j, fmt.Errorf("oidc: unsupported key type %T", pub)
	}
	return j, nil
}

// PublicKey decodes the JWK into a crypto public key, validating it (EC points must be on the curve, RSA keys at
// least 2048 bits).
func (j JWK) PublicKey() (crypto.PublicKey, error) {
	dec := func(s string) ([]byte, error) { return b64.DecodeString(strings.TrimRight(s, "=")) }
	switch j.Kty {
	case "EC":
		if j.Crv != "P-256" {
			return nil, errors.New("unsupported curve")
		}
		x, err1 := dec(j.X)
		y, err2 := dec(j.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("bad EC coordinates")
		}
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, errors.New("unsupported curve")
		}
		x, err := dec(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad OKP key")
		}
		return ed25519.PublicKey(x), nil
	case "RSA":
		n, err1 := dec(j.N)
		e, err2 := dec(j.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA key")
		}
		k := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if k.N.BitLen() < 2048 || k.E < 3 || k.E%2 == 0 {
			return nil, errors.New("RSA key too small or invalid exponent")
		}
		return k, nil
	}
	return nil, errors.New("unsupported key type")
}

// KeyAlg returns the JWS algorithm a key of this type is used with.
func (j JWK) KeyAlg() string {
	switch j.Kty {
	case "EC":
		return AlgES256
	case "OKP":
		return AlgEdDSA
	case "RSA":
		return AlgRS256
	}
	return ""
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ParseJWKS decodes a key set, or a single bare JWK.
func ParseJWKS(data []byte) ([]JWK, error) {
	var probe struct {
		Keys *[]JWK `json:"keys"`
		JWK
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if probe.Keys != nil {
		return *probe.Keys, nil
	}
	if probe.Kty == "" {
		return nil, errors.New("not a JWK or JWKS")
	}
	return []JWK{probe.JWK}, nil
}

// pkcs8 / parse helpers for stored private keys.
func marshalPrivate(k crypto.PrivateKey) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(k) }

func parsePrivate(der []byte) (crypto.Signer, crypto.PublicKey, string, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, nil, "", err
	}
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		return k, &k.PublicKey, AlgES256, nil
	case ed25519.PrivateKey:
		return k, k.Public(), AlgEdDSA, nil
	case *rsa.PrivateKey:
		return k, &k.PublicKey, AlgRS256, nil
	}
	return nil, nil, "", fmt.Errorf("oidc: unsupported private key type %T", k)
}
