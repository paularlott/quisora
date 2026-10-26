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

func TestSecretHash(t *testing.T) {
	tok := RandomToken(32)
	h := HashSecret(tok)
	if !EqualSecret(tok, h) || EqualSecret(tok+"x", h) {
		t.Fatal("secret compare")
	}
}

func BenchmarkPasswordVerify(b *testing.B) {
	h := NewHasher(0)
	ctx := context.Background()
	enc, _ := h.Hash(ctx, "", "password")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = h.Verify(ctx, "", "password", enc)
		}
	})
}

func BenchmarkHashSecret(b *testing.B) {
	tok := RandomToken(32)
	for b.Loop() {
		HashSecret(tok)
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
