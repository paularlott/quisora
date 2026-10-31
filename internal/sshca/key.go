// Package sshca is the pure part of Quisora's SSH certificate authority (docs/design/ssh-ca.md): parsing and checking
// the public keys people ask certificates for, making CA keys, building and signing OpenSSH user and host
// certificates, and encoding (and reading back) OpenSSH key revocation lists. It holds no store and no policy: the
// service decides who gets which certificate.
package sshca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
)

// MinRSABits is the smallest RSA key a certificate is made for.
const MinRSABits = 2048

// maxKeyLine bounds the public key line a request may carry (a 16384-bit RSA key is under 3 KiB).
const maxKeyLine = 16 << 10

// Errors of ParsePublicKey, for messages a person can act on.
var (
	ErrNotAKey      = errors.New("not an OpenSSH public key: paste the single line of a .pub file")
	ErrCertificate  = errors.New("this is a certificate, not a public key: ask for a certificate for the key itself")
	ErrKeyType      = errors.New("unsupported key type: use ed25519, ecdsa, rsa (2048 bits or more) or a security key (sk-ssh-ed25519, sk-ecdsa)")
	ErrWeakRSA      = errors.New("RSA keys under 2048 bits are not accepted")
	errKeyOptions   = errors.New("the key line carries authorized_keys options: give the key alone")
	errKeyOneLine   = errors.New("give one public key, on one line")
	errKeyTooLong   = errors.New("the public key is too long")
	errBadCAPrivate = errors.New("sshca: the CA key is not an ed25519 OpenSSH private key")
)

// ParsePublicKey parses a public key in authorized_keys form ("ssh-ed25519 AAAA… comment") and checks it may be
// certified: ed25519, ecdsa (P-256, P-384, P-521), RSA of at least 2048 bits, and the security-key types
// sk-ssh-ed25519@openssh.com and sk-ecdsa-sha2-nistp256@openssh.com. A certificate, a DSA key, a short RSA key, a line
// with options or more than one key are refused. comment is the line's comment.
func ParsePublicKey(line string) (key ssh.PublicKey, comment string, err error) {
	line = strings.TrimSpace(line)
	switch {
	case line == "":
		return nil, "", ErrNotAKey
	case len(line) > maxKeyLine:
		return nil, "", errKeyTooLong
	case strings.ContainsAny(line, "\r\n"):
		return nil, "", errKeyOneLine
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	switch {
	case err != nil:
		return nil, "", ErrNotAKey
	case len(options) > 0:
		return nil, "", errKeyOptions
	case len(bytes.TrimSpace(rest)) > 0:
		return nil, "", errKeyOneLine
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return nil, "", ErrCertificate
	}
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
	case ssh.KeyAlgoRSA:
		ck, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return nil, "", ErrKeyType
		}
		rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return nil, "", ErrKeyType
		}
		if rk.N.BitLen() < MinRSABits {
			return nil, "", ErrWeakRSA
		}
	default: // ssh-dss and anything else
		return nil, "", ErrKeyType
	}
	return key, comment, nil
}

// Fingerprint is the SHA256 fingerprint of a public key as OpenSSH shows it ("SHA256:…").
func Fingerprint(key ssh.PublicKey) string { return ssh.FingerprintSHA256(key) }

// AuthorizedKey is key in authorized_keys form without a comment or a line end ("ssh-ed25519 AAAA…").
func AuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// GenerateCA makes an ed25519 CA key: its public half in authorized_keys form (no comment) and its private half as an
// OpenSSH PEM, which the caller seals.
func GenerateCA() (public string, private []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", nil, err
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", nil, err
	}
	return AuthorizedKey(sp), pem.EncodeToMemory(block), nil
}

// ParseCA parses a CA private key made by GenerateCA into a signer. It also takes the raw 32-byte ed25519 seed.
func ParseCA(private []byte) (ssh.Signer, error) {
	if len(private) == ed25519.SeedSize {
		return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(private))
	}
	raw, err := ssh.ParseRawPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBadCAPrivate, err)
	}
	var priv ed25519.PrivateKey
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		priv = *k
	case ed25519.PrivateKey:
		priv = k
	default:
		return nil, errBadCAPrivate
	}
	return ssh.NewSignerFromKey(priv)
}

// ValidSourceAddresses checks the addresses of the critical option source-address — IPv4 or IPv6 addresses or CIDR
// blocks — and returns them normalized (an address without a prefix length is that one address), without repeats. The
// caller bounds the length of list.
func ValidSourceAddresses(list []string) ([]string, error) {
	out := make([]string, 0, len(list))
	seen := make(map[string]bool, len(list))
	for _, raw := range list {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var norm string
		if strings.Contains(raw, "/") {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("%q is not an address or a CIDR block", raw)
			}
			norm = p.Masked().String()
		} else {
			a, err := netip.ParseAddr(raw)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("%q is not an address or a CIDR block", raw)
			}
			norm = a.String()
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, nil
}

// ValidHostName reports whether name is a host principal: a lower-case host name or address (letters, digits and . : _ -),
// at most 253 characters, no wildcards.
func ValidHostName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == ':', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// ValidHostPattern reports whether p is a host pattern: ValidHostName's characters and the wildcards * and ?.
func ValidHostPattern(p string) bool {
	if p == "" || len(p) > 253 {
		return false
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == ':', c == '_', c == '-', c == '*', c == '?':
		default:
			return false
		}
	}
	return true
}

// MatchHost reports whether the host name matches one of the patterns ("*.example.com", "db1.internal"): path.Match
// rules on the lower-cased name, so * stands for any run of characters, dots included (*.example.com matches
// a.b.example.com).
func MatchHost(patterns []string, name string) bool {
	name = strings.ToLower(name)
	for _, p := range patterns {
		if ok, err := path.Match(strings.ToLower(p), name); err == nil && ok {
			return true
		}
	}
	return false
}
