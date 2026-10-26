package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
)

// Connections off this machine without TLS that verifies the server are warned about; local ones and verified ones
// are not.
func TestTransportWarnings(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*config.Config)
		want string // "" = no warning
	}{
		{"badger", func(c *config.Config) {}, ""},
		{"postgres local", func(c *config.Config) {
			c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://u:p@localhost:5432/q?sslmode=disable"
		}, ""},
		{"postgres plain", func(c *config.Config) {
			c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://u:p@db.example.com/q?sslmode=disable"
		}, "not encrypted"},
		{"postgres require", func(c *config.Config) {
			c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://u:p@db.example.com/q?sslmode=require"
		}, "not verified"},
		{"postgres verify-full", func(c *config.Config) {
			c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://u:p@db.example.com/q?sslmode=verify-full"
		}, ""},
		{"mysql plain", func(c *config.Config) {
			c.Storage.Backend, c.Storage.MySQL.DSN = "mysql", "u:p@tcp(db.example.com:3306)/q"
		}, "not encrypted"},
		{"mysql ca file", func(c *config.Config) {
			c.Storage.Backend, c.Storage.MySQL.DSN, c.Storage.MySQL.CAFile = "mysql", "u:p@tcp(db.example.com:3306)/q", "/ca.pem"
		}, ""},
		{"mariadb skip-verify", func(c *config.Config) {
			c.Storage.Backend, c.Storage.MariaDB.DSN = "mariadb", "u:p@tcp(db.example.com:3306)/q?tls=skip-verify"
		}, "not verified"},
		{"mysql local", func(c *config.Config) {
			c.Storage.Backend, c.Storage.MySQL.DSN = "mysql", "u:p@tcp(127.0.0.1:3306)/q"
		}, ""},
		{"smtp password without tls", func(c *config.Config) {
			c.Mail.SMTPHost, c.Mail.TLS, c.Mail.Password = "smtp.example.com", "none", "pw"
		}, "SMTP password"},
		{"smtp local without tls", func(c *config.Config) {
			c.Mail.SMTPHost, c.Mail.TLS, c.Mail.Password = "127.0.0.1", "none", "pw"
		}, ""},
	} {
		c := config.Default()
		tc.set(c)
		got := strings.Join(transportWarnings(c), "; ")
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
}

// writeCert writes a self-signed certificate and key as PEM files and returns their paths.
func writeCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestCAPool(t *testing.T) {
	if p, err := caPool("", "x"); p != nil || err != nil {
		t.Fatalf("empty: %v %v", p, err)
	}
	if _, err := caPool(filepath.Join(t.TempDir(), "missing"), "setting.a"); err == nil || !strings.Contains(err.Error(), "setting.a") {
		t.Fatalf("missing: %v", err)
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	_ = os.WriteFile(junk, []byte("nothing here"), 0o600)
	if _, err := caPool(junk, "setting.b"); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Fatalf("junk: %v", err)
	}
	cert, _ := writeCert(t)
	if p, err := caPool(cert, "x"); err != nil || p == nil {
		t.Fatalf("valid: %v %v", p, err)
	}
}
