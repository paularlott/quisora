package sqlstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The writer takes its lock at BEGIN; the readers are query-only; the pragmas are URL-encoded.
func TestSQLiteDSN(t *testing.T) {
	w := sqliteDSN("/x/y.db", true)
	r := sqliteDSN("file:/x/y.db?mode=ro", false)
	if !strings.HasPrefix(w, "/x/y.db?") || !strings.Contains(w, "_txlock=immediate") || strings.Contains(w, "query_only") {
		t.Fatal(w)
	}
	if !strings.HasPrefix(r, "file:/x/y.db?mode=ro&") || !strings.Contains(r, "query_only%281%29") || strings.Contains(r, "+") {
		t.Fatal(r)
	}
}

func TestOpenRefusesBadConfigurations(t *testing.T) {
	ctx := t.Context()
	if _, err := Open(ctx, Config{Driver: "oracle"}); err == nil {
		t.Fatal("Open with an unknown driver succeeded")
	}
	if _, err := Open(ctx, Config{Driver: "sqlite"}); err == nil || !strings.Contains(err.Error(), "needs a DSN") {
		t.Fatalf("sqlite without DSN: %v", err)
	}
	if _, err := Open(ctx, Config{Driver: "sqlite", DSN: "/nonexistent-dir-qsr/x/y.db"}); err == nil {
		t.Fatal("sqlite in a missing directory opened")
	}
	if _, err := Open(ctx, Config{Driver: "postgres", DSN: "postgres://%zz"}); err == nil || !strings.Contains(err.Error(), "sqlstore: open") {
		t.Fatalf("bad postgres DSN: %v", err)
	}
	if _, err := Open(ctx, Config{Driver: "mysql", DSN: "not a dsn"}); err == nil || !strings.Contains(err.Error(), "sqlstore: open") {
		t.Fatalf("bad mysql DSN: %v", err)
	}
}

// A server that is not there is a connect error, whatever the pool and TLS settings.
func TestOpenUnreachableServers(t *testing.T) {
	ctx := t.Context()
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	cases := []struct {
		name string
		cfg  Config
	}{
		{"pg", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=2"}},
		{"pg-pool-limits", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=disable", MaxOpenConns: 2, MaxIdleConns: 10}},
		{"pg-verify-full", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=verify-full", RootCAs: pool}},
		{"pg-require", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=require", RootCAs: pool}},
		{"pg-prefer", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=prefer", RootCAs: pool}},
		{"mysql", Config{Driver: "mysql", DSN: "u:p@tcp(127.0.0.1:1)/db"}},
		{"mariadb-ca", Config{Driver: "mariadb", DSN: "u:p@tcp(127.0.0.1:1)/db", RootCAs: pool, MaxOpenConns: 3}},
		{"mysql-ca-unix", Config{Driver: "mysql", DSN: "u:p@unix(/nonexistent.sock)/db", RootCAs: pool}},
		{"mysql-tls-custom", Config{Driver: "mysql", DSN: "u:p@tcp(127.0.0.1:1)/db?tls=skip-verify", RootCAs: pool}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := Open(ctx, c.cfg)
			if err == nil {
				s.Close()
				t.Fatal("opened a database that is not there")
			}
			if !strings.Contains(err.Error(), "sqlstore: connect") {
				t.Fatalf("expected a connect error, got: %v", err)
			}
		})
	}
}

// A server pool serves reads and writes, with 32 connections unless configured.
func TestUseServerPool(t *testing.T) {
	s := &Store{d: mustDialect(t, "mysql")}
	db := openMem(t)
	defer db.Close()
	s.useServerPool(db, Config{MaxOpenConns: 0, MaxIdleConns: 0})
	if s.rdb != db || s.wdb != db || s.rc == nil || s.rc != s.wc {
		t.Fatal("pool wiring")
	}
	if got := db.Stats().MaxOpenConnections; got != 32 {
		t.Fatalf("default max open: %d", got)
	}
	s.useServerPool(db, Config{MaxOpenConns: 4, MaxIdleConns: 9})
	if got := db.Stats().MaxOpenConnections; got != 4 {
		t.Fatalf("max open: %d", got)
	}
}

// The TLS configurations of a PostgreSQL connection's fallbacks: sslmode=prefer falls back to plain, allow to TLS.
func TestFallbackTLS(t *testing.T) {
	for _, c := range []struct {
		mode string
		tls  []bool // per fallback: does it use TLS
	}{{"prefer", []bool{false}}, {"allow", []bool{true}}, {"require", nil}, {"disable", nil}} {
		pc, err := pgx.ParseConfig("postgres://u:p@127.0.0.1:1/db?sslmode=" + c.mode)
		if err != nil {
			t.Fatal(err)
		}
		got := fallbackTLS(pc)
		if len(got) != len(c.tls) {
			t.Fatalf("%s: %d fallbacks, want %d", c.mode, len(got), len(c.tls))
		}
		for i, tc := range got {
			if (tc != nil) != c.tls[i] || tc != pc.Fallbacks[i].TLSConfig {
				t.Errorf("%s: fallback %d TLS %v, want %v (and the fallback's own configuration)", c.mode, i, tc != nil, c.tls[i])
			}
		}
	}
}

// verify-ca: a chain to the configured roots verifies, with its intermediate; anything else does not.
func TestVerifyChain(t *testing.T) {
	mk := func(tmpl, parent *x509.Certificate, pk, parentKey *ecdsa.PrivateKey) *x509.Certificate {
		if parent == nil {
			parent, parentKey = tmpl, pk
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &pk.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now()
	tmpl := func(n int64, cn string, ca bool) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: ca, BasicConstraintsValid: true,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
	}
	rk, ik, lk, ok := key(), key(), key(), key()
	root := mk(tmpl(1, "root", true), nil, rk, nil)
	inter := mk(tmpl(2, "inter", true), root, ik, rk)
	leaf := mk(tmpl(3, "leaf", false), inter, lk, ik)
	other := mk(tmpl(4, "other", true), nil, ok, nil)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	verify := verifyChain(roots)

	if err := verify([][]byte{leaf.Raw, inter.Raw}, nil); err != nil {
		t.Fatalf("valid chain: %v", err)
	}
	if err := verify([][]byte{leaf.Raw}, nil); err == nil {
		t.Fatal("chain without its intermediate verified")
	}
	if err := verify([][]byte{other.Raw}, nil); err == nil {
		t.Fatal("certificate from another CA verified")
	}
	if err := verify(nil, nil); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatalf("empty chain: %v", err)
	}
	if err := verify([][]byte{[]byte("garbage")}, nil); err == nil {
		t.Fatal("garbage certificate verified")
	}
}
