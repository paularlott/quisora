package secure

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h := NewHasher(2)
	ctx := context.Background()
	enc, err := h.Hash(ctx, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.Verify(ctx, "correct horse", enc); !ok {
		t.Fatal("verify failed")
	}
	if ok, _ := h.Verify(ctx, "wrong", enc); ok {
		t.Fatal("wrong password verified")
	}
	if ok, _ := h.Verify(ctx, "x", ""); ok {
		t.Fatal("empty hash verified")
	}
}

func TestHasherBusy(t *testing.T) {
	h := NewHasher(1)
	h.sem <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "x"); err != ErrBusy {
		t.Fatalf("want ErrBusy, got %v", err)
	}
}

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

func TestSecretHash(t *testing.T) {
	tok := RandomToken(32)
	h := HashSecret(tok)
	if !EqualSecret(tok, h) || EqualSecret(tok+"x", h) {
		t.Fatal("secret compare")
	}
}

func TestTOTP(t *testing.T) {
	// RFC 6238 test vector (SHA1, secret "12345678901234567890").
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(59, 0)
	step, ok := VerifyTOTP(secret, "287082", now, 0)
	if !ok || step != 1 {
		t.Fatalf("rfc vector: ok=%v step=%d", ok, step)
	}
	if _, ok := VerifyTOTP(secret, "287082", now, step); ok {
		t.Fatal("replay accepted")
	}
	if _, ok := VerifyTOTP(secret, "000000", now, 0); ok {
		t.Fatal("wrong code accepted")
	}
}

func BenchmarkPasswordVerify(b *testing.B) {
	h := NewHasher(0)
	ctx := context.Background()
	enc, _ := h.Hash(ctx, "password")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h.Verify(ctx, "password", enc)
		}
	})
}

func BenchmarkHashSecret(b *testing.B) {
	tok := RandomToken(32)
	for b.Loop() {
		HashSecret(tok)
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

func TestRootPool(t *testing.T) {
	if p, err := RootPool(""); p != nil || err != nil {
		t.Fatalf("empty: %v %v", p, err)
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0o600)
	if _, err := RootPool(bad); err == nil {
		t.Error("a file without certificates was accepted")
	}
	if _, err := RootPool(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("a missing file was accepted")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	good := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	pool, err := RootPool(good)
	if err != nil || pool == nil {
		t.Fatalf("good: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("the extra CA is not trusted: %v", err)
	}
}
