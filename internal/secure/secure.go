// Package secure holds the cryptographic helpers: password hashing, sealing secrets at rest, random tokens and TOTP.
package secure

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// RandomToken returns n random bytes, base64url encoded without padding.
func RandomToken(n int) string { return base64.RawURLEncoding.EncodeToString(RandomBytes(n)) }

// HashSecret hashes a high-entropy, server-generated secret (client secrets, API tokens). Not for passwords.
func HashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// EqualSecret compares a presented secret with a stored HashSecret in constant time.
func EqualSecret(secret string, hash []byte) bool {
	h := HashSecret(secret)
	return len(hash) == len(h) && subtle.ConstantTimeCompare(h[:], hash) == 1
}

// MAC returns HMAC-SHA256(key, msg).
func MAC(key []byte, msg ...string) []byte {
	m := hmac.New(sha256.New, key)
	for i, p := range msg {
		if i > 0 {
			m.Write([]byte{0})
		}
		m.Write([]byte(p))
	}
	return m.Sum(nil)
}

// ---------------------------------------------------------------------------------------------------------------
// Passwords: argon2id with a bounded number of concurrent hashes (each holds ~19 MiB).

const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
)

var ErrBusy = errors.New("secure: password hashing capacity exceeded")

// Hasher hashes and verifies passwords with a concurrency limit.
type Hasher struct{ sem chan struct{} }

// NewHasher allows workers concurrent hashes (0 = GOMAXPROCS).
func NewHasher(workers int) *Hasher {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	return &Hasher{sem: make(chan struct{}, workers)}
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrBusy
	}
}

// Hash returns an encoded argon2id hash of password.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer func() { <-h.sem }()
	salt := RandomBytes(16)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches the encoded hash. An empty hash never matches (but still costs a hash,
// so timing does not reveal whether an account has a password).
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer func() { <-h.sem }()
	var m, t uint32
	var p uint8
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		argon2.IDKey([]byte(password), dummySalt, argonTime, argonMemory, argonThreads, argonKeyLen)
		return false, nil
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

var dummySalt = RandomBytes(16)

// ---------------------------------------------------------------------------------------------------------------
// Sealing secrets at rest (AES-256-GCM).

// Sealer encrypts small secrets with the master key, and MACs values with a key derived from it.
type Sealer struct {
	aead cipher.AEAD
	mac  []byte
}

// NewSealer builds a sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("secure: master key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a, mac: MAC(key, "quisora/mac/v1")}, nil
}

// MAC returns HMAC-SHA256 of msg under a key derived from the master key: values stored alongside it in the database
// prove nothing to someone who has the database but not the key.
func (s *Sealer) MAC(msg ...string) []byte { return MAC(s.mac, msg...) }

// Seal encrypts plaintext; the empty string seals to the empty string.
func (s *Sealer) Seal(plaintext []byte) string {
	if len(plaintext) == 0 {
		return ""
	}
	nonce := RandomBytes(s.aead.NonceSize())
	return "v1:" + base64.RawStdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plaintext, nil))
}

// SealFor encrypts plaintext bound to binding (e.g. "user/<id>/totp"): the value only opens with the same binding,
// so a sealed secret copied onto another record or field is useless.
func (s *Sealer) SealFor(binding string, plaintext []byte) string {
	if len(plaintext) == 0 {
		return ""
	}
	nonce := RandomBytes(s.aead.NonceSize())
	return "v2:" + base64.RawStdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plaintext, []byte(binding)))
}

// OpenFor decrypts a value produced by SealFor with the same binding.
func (s *Sealer) OpenFor(binding, sealed string) ([]byte, error) {
	if sealed == "" {
		return nil, nil
	}
	raw, ok := strings.CutPrefix(sealed, "v2:")
	if !ok {
		return nil, errors.New("secure: unknown sealed format")
	}
	return s.open(raw, []byte(binding))
}

func (s *Sealer) open(raw string, aad []byte) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	n := s.aead.NonceSize()
	if len(b) < n {
		return nil, errors.New("secure: sealed value too short")
	}
	return s.aead.Open(nil, b[:n], b[n:], aad)
}

// Open decrypts a value produced by Seal (unbound; used for short-lived in-memory values).
func (s *Sealer) Open(sealed string) ([]byte, error) {
	if sealed == "" {
		return nil, nil
	}
	raw, ok := strings.CutPrefix(sealed, "v1:")
	if !ok {
		return nil, errors.New("secure: unknown sealed format")
	}
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	n := s.aead.NonceSize()
	if len(b) < n {
		return nil, errors.New("secure: sealed value too short")
	}
	return s.aead.Open(nil, b[:n], b[n:], nil)
}

// RootPool returns the system's trusted roots plus the CA certificates in the PEM file (nil, nil when file is ""):
// the roots for outbound HTTPS to sign-in providers, client JWKS and back-channel logout endpoints.
func RootPool(file string) (*x509.CertPool, error) {
	if file == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("extra_ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("extra_ca_file: %s holds no PEM certificates", file)
	}
	return pool, nil
}
