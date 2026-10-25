package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

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

func TestOpenStoreErrors(t *testing.T) {
	ctx := context.Background()
	c := config.Default()
	c.Server.DataDir = t.TempDir()
	c.Storage.Backend = "nonesuch"
	if _, err := OpenStore(ctx, c); err == nil || !strings.Contains(err.Error(), "unknown storage backend") {
		t.Fatalf("unknown: %v", err)
	}
	c.Storage.Backend = "badgerdb"
	c.Storage.BadgerDB.EncryptionKey = "not base64!"
	if _, err := OpenStore(ctx, c); err == nil || !strings.Contains(err.Error(), "encryption_key") {
		t.Fatalf("badger key: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	for _, b := range []string{"postgres", "mysql", "mariadb"} {
		c.Storage.Backend = b
		c.Storage.Postgres.CAFile, c.Storage.MySQL.CAFile, c.Storage.MariaDB.CAFile = missing, missing, missing
		if _, err := OpenStore(ctx, c); err == nil || !strings.Contains(err.Error(), "ca_file") {
			t.Fatalf("%s CA: %v", b, err)
		}
	}
	// an encrypted badger store opens with a valid key
	c.Storage.Backend = "badgerdb"
	c.Storage.BadgerDB.EncryptionKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	st, err := OpenStore(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
}

func TestPurgeLostQueueItems(t *testing.T) {
	c := config.Default()
	c.Server.DataDir, c.Server.Listen = t.TempDir(), "127.0.0.1:1" // nothing listens there
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	// no queue directories yet: nothing to do
	if m, l, err := PurgeLostQueueItems(context.Background(), c, logger.NewNullLogger()); err != nil || m != 0 || l != 0 {
		t.Fatalf("empty: %d %d %v", m, l, err)
	}
	key, _ := masterKey(c)
	mine, _ := newSealer(c, key)
	foreign, _ := secure.NewKeyring(secure.RandomBytes(32))
	put := func(dir, name string, s *secure.Sealer) string {
		d := c.DataPath(dir)
		_ = os.MkdirAll(d, 0o700)
		p := filepath.Join(d, name+".item")
		if err := os.WriteFile(p, []byte(s.SealFor("", []byte("x"))), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	lostMail1, lostMail2 := put(config.DirMailQueue, "a", foreign), put(config.DirMailQueue, "b", foreign)
	keptMail := put(config.DirMailQueue, "c", mine)
	lostLogout := put(config.DirLogoutQueue, "a", foreign)
	m, l, err := PurgeLostQueueItems(context.Background(), c, logger.NewNullLogger())
	if err != nil || m != 2 || l != 1 {
		t.Fatalf("purged %d mail, %d logout: %v", m, l, err)
	}
	for _, p := range []string{lostMail1, lostMail2, lostLogout} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s not purged", p)
		}
	}
	if _, err := os.Stat(keptMail); err != nil {
		t.Fatal("an item of the active key was purged")
	}
	// recorded in the audit log
	st, err := OpenStore(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	evs, _, _ := service.New(c, st, mine).Audits.List(context.Background(), store.ListQuery{})
	st.Close()
	found := false
	for _, e := range evs {
		found = found || e.Action == "queue.purge_lost" && e.Detail["emails"] == "2" && e.Detail["logouts"] == "1"
	}
	if !found {
		t.Fatalf("not audited: %+v", evs)
	}
	// refused while a server answers on server.listen
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	running := *c
	running.Server.Listen = ln.Addr().String()
	if _, _, err := PurgeLostQueueItems(context.Background(), &running, logger.NewNullLogger()); !errors.Is(err, ErrServerRunning) {
		t.Fatalf("a running node: %v", err)
	}
	// a queue directory that is not a directory is an error
	c2 := config.Default()
	c2.Server.DataDir, c2.Server.MasterKey, c2.Server.Listen = t.TempDir(), c.Server.MasterKey, c.Server.Listen
	_ = os.WriteFile(c2.DataPath(config.DirMailQueue), nil, 0o600)
	if _, _, err := PurgeLostQueueItems(context.Background(), c2, logger.NewNullLogger()); err == nil {
		t.Fatal("unreadable mail queue accepted")
	}
	c2.Server.MasterKey = ""
	if _, _, err := PurgeLostQueueItems(context.Background(), c2, logger.NewNullLogger()); err == nil {
		t.Fatal("no master key accepted")
	}
}
