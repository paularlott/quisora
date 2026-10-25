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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
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

// The daily sweep gives up, while the node runs, the queued items no configured key opens that are older than
// lostItemAge; it leaves younger ones (their key may be put back) and every item a configured key opens, and records
// in the audit log only a sweep that removed something.
func TestPurgeLostQueueItems(t *testing.T) {
	a, _, _ := startAppWith(t, "badgerdb", nil)
	ctx := context.Background()
	c := a.Cfg
	foreign, _ := secure.NewKeyring(secure.RandomBytes(32))
	named := func(at time.Time) string { return fmt.Sprintf("%020d-ab", at.UnixNano()) }
	put := func(dir string, at time.Time, s *secure.Sealer) string {
		d := c.DataPath(dir)
		_ = os.MkdirAll(d, 0o700)
		p := filepath.Join(d, named(at)+".item")
		if err := os.WriteFile(p, []byte(s.SealFor("", []byte("x"))), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sweeps := func() int {
		evs, _, _ := a.Svc.Audits.List(ctx, store.ListQuery{})
		n := 0
		for _, e := range evs {
			if e.Action == "queue.purge_lost" {
				n++
			}
		}
		return n
	}
	old := time.Now().Add(-lostItemAge - time.Hour)
	// No SMTP server here: no worker on the mail queue, so an item the active key opens stays there untouched.
	oldMail := put(config.DirMailQueue, old, foreign)
	keptMail := put(config.DirMailQueue, old.Add(time.Second), a.Svc.Sealer)
	oldLogout := put(config.DirLogoutQueue, old, foreign)
	youngLogout := put(config.DirLogoutQueue, time.Now().Add(-time.Hour), foreign)
	before := time.Now().Add(-lostItemAge)
	if m, l, err := a.purgeLostQueueItems(ctx, before); err != nil || m != 1 || l != 1 {
		t.Fatalf("sweep: %d mail, %d logout: %v", m, l, err)
	}
	for _, p := range []string{oldMail, oldLogout} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s not given up", filepath.Base(p))
		}
	}
	for _, p := range []string{keptMail, youngLogout} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s given up", filepath.Base(p))
		}
	}
	if q := a.logoutQueue.Load(); q == nil || q.Queued() != 1 {
		t.Fatal("the logout queue does not count what is left")
	}
	evs, _, _ := a.Svc.Audits.List(ctx, store.ListQuery{})
	found := false
	for _, e := range evs {
		found = found || e.Action == "queue.purge_lost" && e.Detail["emails"] == "1" && e.Detail["logouts"] == "1" &&
			e.Detail["queued_before"] != ""
	}
	if !found {
		t.Fatalf("not audited: %+v", evs)
	}
	if _, _, err := a.purgeLostQueueItems(ctx, before); err != nil || sweeps() != 1 {
		t.Fatalf("a sweep that removed nothing is audited: %v", err)
	}
	// The young lost item does not hold the rotation back: it is a warning only.
	st, err := a.Svc.RotationStatus(ctx)
	if err != nil || st.QueueLost != 1 || st.QueueStale != 0 || !strings.Contains(st.Detail, "given up once") {
		t.Fatalf("status: %+v %v", st, err)
	}
}
