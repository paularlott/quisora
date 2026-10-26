package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestSeal(t *testing.T) {
	s, err := NewSealer(RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	sealed := s.Seal([]byte("secret"))
	if sealed == "secret" || sealed == s.Seal([]byte("secret")) {
		t.Fatal("seal not randomised")
	}
	got, err := s.Open(sealed)
	if err != nil || string(got) != "secret" {
		t.Fatal("open failed")
	}
	other, _ := NewSealer(RandomBytes(32))
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("opened with wrong key")
	}
	if s.Seal(nil) != "" {
		t.Fatal("empty seal")
	}
}

func TestSealForBinding(t *testing.T) {
	s, _ := NewSealer(RandomBytes(32))
	v := s.SealFor("user/a/totp", []byte("secret"))
	if got, err := s.OpenFor("user/a/totp", v); err != nil || string(got) != "secret" {
		t.Fatal("open with the right binding")
	}
	if _, err := s.OpenFor("user/b/totp", v); err == nil {
		t.Fatal("a value moved to another record must not open")
	}
	if _, err := s.OpenFor("user/a/totp", s.Seal([]byte("unbound"))); err == nil {
		t.Fatal("an unbound value must not open as a bound secret")
	}
}

// Master key rotation: a value sealed with the old key opens with a keyring whose active key is the new one, is
// reported stale, and re-seals into one that the new key alone opens. A value from before sealed values named their
// key (v2) opens with any key of the ring and is stale too. A key that is not configured is reported as such.
func TestKeyringRotation(t *testing.T) {
	k1, k2 := RandomBytes(32), RandomBytes(32)
	old, _ := NewSealer(k1)
	ring, err := NewKeyring(k2, k1)
	if err != nil {
		t.Fatal(err)
	}
	only2, _ := NewSealer(k2)

	v := old.SealFor("user/u1/totp", []byte("secret"))
	if !strings.HasPrefix(v, "v3:"+KeyID(k1)+":") {
		t.Fatalf("sealed value does not name its key: %s", v)
	}
	if p, err := ring.OpenFor("user/u1/totp", v); err != nil || string(p) != "secret" {
		t.Fatalf("ring opens old value: %q %v", p, err)
	}
	if _, err := only2.OpenFor("user/u1/totp", v); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("the new key alone: %v", err)
	}
	if !ring.Stale(v) || old.Stale(v) {
		t.Fatal("staleness")
	}
	nv, err := ring.Reseal("user/u1/totp", v)
	if err != nil || ring.Stale(nv) {
		t.Fatalf("reseal: %v", err)
	}
	if p, err := only2.OpenFor("user/u1/totp", nv); err != nil || string(p) != "secret" {
		t.Fatalf("new key opens re-sealed value: %q %v", p, err)
	}
	if _, err := ring.OpenFor("user/u2/totp", nv); err == nil {
		t.Fatal("binding not enforced")
	}

	// a value that names no key (the format of development builds before keys were named) is refused
	a, _ := cipher.NewGCM(must(aes.NewCipher(k1)))
	nonce := RandomBytes(a.NonceSize())
	v2 := "v2:" + base64.RawStdEncoding.EncodeToString(a.Seal(nonce, nonce, []byte("legacy"), []byte("b")))
	if _, err := ring.OpenFor("b", v2); err == nil {
		t.Fatal("a value that names no key opened")
	}

	// MACs: the active key's first, then the previous ones
	if m := ring.MACs("x"); len(m) != 2 || !bytes.Equal(m[0], only2.MAC("x")) || !bytes.Equal(m[1], old.MAC("x")) {
		t.Fatal("MACs")
	}
	// unbound values open with any key of the ring
	if p, err := ring.Open(old.Seal([]byte("tmp"))); err != nil || string(p) != "tmp" {
		t.Fatalf("unbound: %v", err)
	}
	if _, err := NewKeyring(k1, k1); err == nil {
		t.Fatal("the same key twice accepted")
	}
}

func TestKeyringMetadataAndReseal(t *testing.T) {
	k1, k2 := RandomBytes(32), RandomBytes(32)
	old, err := NewSealer(k1)
	if err != nil {
		t.Fatal(err)
	}
	sealed := old.SealFor("user/1/totp", []byte("secret"))
	if kid := SealedKeyID(sealed); kid != KeyID(k1) {
		t.Fatalf("kid %q", kid)
	}
	if kid := SealedKeyID(""); kid != "" {
		t.Fatal("empty value names a key")
	}
	if kid := SealedKeyID("v2:abc"); kid != "" {
		t.Fatal("a value in another format names a key")
	}

	ring, err := NewKeyring(k2, k1)
	if err != nil {
		t.Fatal(err)
	}
	if !ring.Previous() || ring.ActiveKeyID() != KeyID(k2) {
		t.Fatal("ring metadata")
	}
	ids := ring.KeyIDs()
	if len(ids) != 2 || ids[0] != KeyID(k2) || ids[1] != KeyID(k1) {
		t.Fatalf("ids %v", ids)
	}
	if got, err := ring.OpenFor("user/1/totp", sealed); err != nil || string(got) != "secret" {
		t.Fatalf("previous key did not open: %v", err)
	}
	if !ring.Stale(sealed) {
		t.Fatal("old-key value not stale")
	}
	// wrong binding refused
	if _, err := ring.OpenFor("user/2/totp", sealed); err == nil {
		t.Fatal("opened under another binding")
	}
	re, err := ring.Reseal("user/1/totp", sealed)
	if err != nil || ring.Stale(re) {
		t.Fatalf("reseal: %v", err)
	}
	if same, _ := ring.Reseal("user/1/totp", re); same != re {
		t.Fatal("fresh value was re-sealed")
	}
	if _, err := ring.Reseal("user/2/totp", sealed); err == nil {
		t.Fatal("reseal under wrong binding succeeded")
	}
	// a ring without the old key reports it unknown, and cannot reseal
	only, _ := NewSealer(k2)
	if _, err := only.OpenFor("user/1/totp", sealed); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err %v", err)
	}
	if _, err := only.Reseal("user/1/totp", sealed); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("reseal err %v", err)
	}
	if only.Previous() {
		t.Fatal("single key has previous")
	}
	// Keys: one sealer per key, only opening what its key sealed
	ks := ring.Keys()
	if len(ks) != 2 || ks[0].ActiveKeyID() != KeyID(k2) {
		t.Fatal("Keys")
	}
	if _, err := ks[1].OpenFor("user/1/totp", sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := ks[0].OpenFor("user/1/totp", sealed); err == nil {
		t.Fatal("wrong single key opened")
	}
	// Replace swaps keys in place
	holder, _ := NewSealer(k1)
	holder.Replace(only)
	if holder.ActiveKeyID() != KeyID(k2) {
		t.Fatal("Replace")
	}
	// short keys
	if _, err := NewKeyring(k1[:16]); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := NewKeyring(k1, k2[:5]); err == nil {
		t.Fatal("short previous key accepted")
	}
}

func TestMalformedSealedValuesAreRefused(t *testing.T) {
	s, _ := NewSealer(RandomBytes(32))
	if s.Seal(nil) != "" || s.SealFor("b", nil) != "" {
		t.Fatal("empty seals to non-empty")
	}
	if b, err := s.Open(""); b != nil || err != nil {
		t.Fatal("empty open")
	}
	if b, err := s.OpenFor("b", ""); b != nil || err != nil {
		t.Fatal("empty openfor")
	}
	if got, err := s.Open(s.Seal([]byte("x"))); err != nil || string(got) != "x" {
		t.Fatal("roundtrip")
	}
	for _, bad := range []string{"v9:abc", "plain", "v3:nocolon", "v3:" + s.ActiveKeyID() + ":!!!", "v3:" + s.ActiveKeyID() + ":QQ", "v2:!!!", "v2:QQ"} {
		if _, err := s.OpenFor("b", bad); err == nil {
			t.Errorf("OpenFor(%q) succeeded", bad)
		}
	}
	for _, bad := range []string{"v3:x", "bogus", "v1:!!!", "v1:QQ"} {
		if _, err := s.Open(bad); err == nil {
			t.Errorf("Open(%q) succeeded", bad)
		}
	}
	// a bound value is not an unbound one
	if _, err := s.Open(s.SealFor("b", []byte("x"))); err == nil {
		t.Fatal("bound value opened unbound")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
