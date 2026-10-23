package web

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/logger"
)

// makePair writes a fresh certificate for host to certFile and keyFile, as a renewal would.
func makePair(t *testing.T, host, certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	if _, err := LoadOrCreateCert("", "", dir, host); err != nil {
		t.Fatal(err)
	}
	for src, dst := range map[string]string{"self-signed.crt": certFile, "self-signed.key": keyFile} {
		b, err := os.ReadFile(filepath.Join(dir, src))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// a renewal is later than the last load: make sure the modification time says so on coarse file systems
	later := time.Now().Add(time.Duration(len(host)) * time.Second)
	_ = os.Chtimes(certFile, later, later)
	_ = os.Chtimes(keyFile, later, later)
}

func served(t *testing.T, cs *certSource) string {
	t.Helper()
	c, err := cs.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || c == nil || c.Leaf == nil {
		t.Fatal("no certificate served")
	}
	return c.Leaf.Subject.CommonName
}

func TestCertificateReloadsWhenRenewed(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	makePair(t, "a.example", certFile, keyFile)
	cs, err := newCertSource(certFile, keyFile, "", "a.example", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if served(t, cs) != "a.example" || cs.due() {
		t.Fatal("first certificate")
	}

	// renewed on disk: noticed, and served from the next handshake
	makePair(t, "bb.example", certFile, keyFile)
	if !cs.due() {
		t.Fatal("renewal not noticed")
	}
	if err := cs.Reload(); err != nil || served(t, cs) != "bb.example" || cs.due() {
		t.Fatalf("renewal not served: %v", err)
	}

	// a broken renewal (half-written, or a key that does not match) keeps the current certificate
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cs.Reload(); err == nil || served(t, cs) != "bb.example" {
		t.Fatalf("broken pair replaced the certificate: %v", err)
	}
}

func TestCertificateWatchPicksUpRenewal(t *testing.T) {
	old := certCheckEvery
	certCheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { certCheckEvery = old })
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	makePair(t, "a.example", certFile, keyFile)
	cs, err := newCertSource(certFile, keyFile, "", "a.example", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	go cs.watch()
	defer cs.Close()
	makePair(t, "bb.example", certFile, keyFile)
	deadline := time.Now().Add(5 * time.Second)
	for served(t, cs) != "bb.example" {
		if time.Now().After(deadline) {
			t.Fatal("watch did not load the renewed certificate")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSelfSignedRenewedNearExpiry(t *testing.T) {
	cs, err := newCertSource("", "", t.TempDir(), "id.example", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if cs.due() {
		t.Fatal("a fresh self-signed certificate is due")
	}
	c := *cs.cur.Load()
	leaf := *c.Leaf
	leaf.NotAfter = time.Now().Add(24 * time.Hour)
	c.Leaf = &leaf
	cs.cur.Store(&c)
	if !cs.due() {
		t.Fatal("a self-signed certificate a day from expiry is not due")
	}
}
