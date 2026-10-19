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
	"sync/atomic"

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

// Sealer encrypts small secrets with the master key, and MACs values with a key derived from it. It holds a keyring:
// the active master key, which seals and MACs everything new, and previous ones (master key rotation), which only
// open what they sealed and verify what they MACed until it has been re-sealed or has expired. Replace swaps the ring
// in place (a reload of the master keys): whoever holds the Sealer uses the new keys from the next call on.
type Sealer struct {
	ring atomic.Pointer[[]sealKey] // active first
}

func (s *Sealer) keys() []sealKey { return *s.ring.Load() }

// Replace makes s use o's keys (o is not used afterwards).
func (s *Sealer) Replace(o *Sealer) { s.ring.Store(o.ring.Load()) }

func newSealerOf(keys []sealKey) *Sealer {
	s := &Sealer{}
	s.ring.Store(&keys)
	return s
}

type sealKey struct {
	kid  string // public key id, carried by sealed values (KeyID)
	aead cipher.AEAD
	mac  []byte
}

// NewSealer builds a sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) { return NewKeyring(key) }

// NewKeyring builds a sealer whose active key is active, and which also opens values sealed with (and verifies MACs
// made under) the previous keys.
func NewKeyring(active []byte, previous ...[]byte) (*Sealer, error) {
	var keys []sealKey
	for i, key := range append([][]byte{active}, previous...) {
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
		k := sealKey{kid: KeyID(key), aead: a, mac: MAC(key, "quisora/mac/v1")}
		for _, o := range keys {
			if o.kid == k.kid {
				return nil, fmt.Errorf("secure: master key %d is given twice", i+1)
			}
		}
		keys = append(keys, k)
	}
	return newSealerOf(keys), nil
}

// KeyID is a master key's public id (8 characters): sealed values name the key that sealed them by it, and logs and
// the documentation's rotation procedure refer to keys by it. It reveals nothing about the key.
func KeyID(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(MAC(key, "quisora/kid/v1")[:6])
}

// ActiveKeyID is the id of the key that seals now.
func (s *Sealer) ActiveKeyID() string { return s.keys()[0].kid }

// KeyIDs returns the ids of the ring's keys, the active one first.
func (s *Sealer) KeyIDs() []string {
	keys := s.keys()
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.kid
	}
	return out
}

// Previous reports whether the keyring holds keys other than the active one.
func (s *Sealer) Previous() bool { return len(s.keys()) > 1 }

// Keys returns one single-key sealer per key of the ring, the active one first (to find the key something was made
// with: a backup).
func (s *Sealer) Keys() []*Sealer {
	keys := s.keys()
	out := make([]*Sealer, len(keys))
	for i, k := range keys {
		out[i] = newSealerOf([]sealKey{k})
	}
	return out
}

// MAC returns HMAC-SHA256 of msg under a key derived from the active master key: values stored alongside it in the
// database prove nothing to someone who has the database but not the key.
func (s *Sealer) MAC(msg ...string) []byte { return MAC(s.keys()[0].mac, msg...) }

// MACs returns MAC for every key of the ring, the active one first: a value MACed before a rotation still verifies
// while its key is configured.
func (s *Sealer) MACs(msg ...string) [][]byte {
	keys := s.keys()
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = MAC(k.mac, msg...)
	}
	return out
}

// Seal encrypts plaintext (unbound; used for short-lived in-memory values, opened by any key of the ring); the empty
// string seals to the empty string.
func (s *Sealer) Seal(plaintext []byte) string {
	if len(plaintext) == 0 {
		return ""
	}
	a := s.keys()[0].aead
	nonce := RandomBytes(a.NonceSize())
	return "v1:" + base64.RawStdEncoding.EncodeToString(a.Seal(nonce, nonce, plaintext, nil))
}

// SealFor encrypts plaintext bound to binding (e.g. "user/<id>/totp"): the value only opens with the same binding,
// so a sealed secret copied onto another record or field is useless. It names the key that sealed it.
func (s *Sealer) SealFor(binding string, plaintext []byte) string {
	if len(plaintext) == 0 {
		return ""
	}
	k := s.keys()[0]
	nonce := RandomBytes(k.aead.NonceSize())
	return "v3:" + k.kid + ":" + base64.RawStdEncoding.EncodeToString(k.aead.Seal(nonce, nonce, plaintext, []byte(binding)))
}

// ErrUnknownKey means a value was sealed with a master key that is not configured (removed from
// server.previous_master_keys too early).
var ErrUnknownKey = errors.New("secure: sealed with a master key that is not configured")

// OpenFor decrypts a value produced by SealFor with the same binding: with the key it names, or (a value sealed
// before keys were named) with each key of the ring.
func (s *Sealer) OpenFor(binding, sealed string) ([]byte, error) {
	if sealed == "" {
		return nil, nil
	}
	if rest, ok := strings.CutPrefix(sealed, "v3:"); ok {
		kid, raw, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, errors.New("secure: unknown sealed format")
		}
		for _, k := range s.keys() {
			if k.kid == kid {
				return open(k.aead, raw, []byte(binding))
			}
		}
		return nil, ErrUnknownKey
	}
	raw, ok := strings.CutPrefix(sealed, "v2:")
	if !ok {
		return nil, errors.New("secure: unknown sealed format")
	}
	return s.openAny(raw, []byte(binding))
}

// SealedKeyID is the id of the key a SealFor value names; legacy is true for a value from before values named their
// key (any key of the ring that sealed it may be the one). Both are zero for the empty value.
func SealedKeyID(sealed string) (kid string, legacy bool) {
	if rest, ok := strings.CutPrefix(sealed, "v3:"); ok {
		kid, _, _ = strings.Cut(rest, ":")
		return kid, false
	}
	return "", sealed != ""
}

// Stale reports whether a value produced by SealFor is not sealed with the active key (an older key, or a format
// that names none): Reseal brings it up to date.
func (s *Sealer) Stale(sealed string) bool {
	return sealed != "" && !strings.HasPrefix(sealed, "v3:"+s.keys()[0].kid+":")
}

// Reseal returns sealed re-sealed with the active key (unchanged when it already is).
func (s *Sealer) Reseal(binding, sealed string) (string, error) {
	if !s.Stale(sealed) {
		return sealed, nil
	}
	plain, err := s.OpenFor(binding, sealed)
	if err != nil {
		return "", err
	}
	return s.SealFor(binding, plain), nil
}

func (s *Sealer) openAny(raw string, aad []byte) ([]byte, error) {
	var err error
	for _, k := range s.keys() {
		var b []byte
		if b, err = open(k.aead, raw, aad); err == nil {
			return b, nil
		}
	}
	return nil, err
}

func open(a cipher.AEAD, raw string, aad []byte) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	n := a.NonceSize()
	if len(b) < n {
		return nil, errors.New("secure: sealed value too short")
	}
	return a.Open(nil, b[:n], b[n:], aad)
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
	return s.openAny(raw, nil)
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
