package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// The remote backup keeps only a complete download: it sends the token, and refuses a truncated stream and an
// error answer.
func TestRemoteBackup(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := memstore.New()
	if _, _, err := service.New(config.Default(), st, sealer).Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	var full bytes.Buffer
	if _, err := backup.Write(ctx, st, sealer, &full); err != nil {
		t.Fatal(err)
	}
	zr, _ := gzip.NewReader(bytes.NewReader(full.Bytes()))
	plain, _ := io.ReadAll(zr)
	var cut bytes.Buffer
	zw := gzip.NewWriter(&cut)
	_, _ = zw.Write(plain[:len(plain)/2])
	_ = zw.Close()

	body := full.Bytes()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/backup" || r.URL.Query().Get("plain") != "1" || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"You do not have permission to do that."}`))
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	var out bytes.Buffer
	stats, err := remoteBackup(ctx, srv.URL, "tok", "", true, "", &out)
	if err != nil || stats.Total() == 0 || !bytes.Equal(out.Bytes(), full.Bytes()) {
		t.Fatalf("download: %v (%d records)", err, stats.Total())
	}
	// with a password the download is encrypted here, and opens with that password only
	var enc bytes.Buffer
	if _, err := remoteBackup(ctx, srv.URL, "tok", "", true, "correct horse battery", &enc); err != nil {
		t.Fatal(err)
	}
	if !backup.PasswordProtected(enc.Bytes()) {
		t.Fatal("not encrypted")
	}
	if st, err := backup.Verify(bytes.NewReader(enc.Bytes()), sealer, "correct horse battery"); err != nil || st.Total() != stats.Total() {
		t.Fatalf("verify with the password: %v", err)
	}
	if _, err := backup.Verify(bytes.NewReader(enc.Bytes()), sealer, "wrong horse battery"); !errors.Is(err, backup.ErrPassword) {
		t.Fatalf("verify with a wrong password: %v", err)
	}
	if _, err := remoteBackup(ctx, srv.URL, "wrong", "", true, "", io.Discard); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("refused token: %v", err)
	}
	if _, err := remoteBackup(ctx, srv.URL, "tok", "", false, "", io.Discard); err == nil {
		t.Fatal("an unverified certificate was accepted")
	}
	body = cut.Bytes()
	if _, err := remoteBackup(ctx, srv.URL, "tok", "", true, "", io.Discard); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("truncated download: %v", err)
	}
	if _, err := remoteBackup(ctx, "http://example.com", "tok", "", true, "", io.Discard); err == nil {
		t.Fatal("plain http accepted")
	}
}

func TestBackupPassword(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "pw")
	for body, want := range map[string]string{"secret pass 1\n": "secret pass 1", "a b\r\nrest": "a b", "nolf": "nolf"} {
		_ = os.WriteFile(f, []byte(body), 0o600)
		if got, err := backupPassword(f, true, false); err != nil || got != want {
			t.Fatalf("%q: %q %v", body, got, err)
		}
	}
	_ = os.WriteFile(f, []byte("  \nx"), 0o600)
	if _, err := backupPassword(f, true, false); err == nil || !strings.Contains(err.Error(), "no backup password") {
		t.Fatalf("blank: %v", err)
	}
	if _, err := backupPassword(filepath.Join(dir, "none"), true, false); err == nil || !strings.Contains(err.Error(), "--password-file") {
		t.Fatalf("missing file: %v", err)
	}
	// standard input as a pipe
	old := os.Stdin
	defer func() { os.Stdin = old }()
	r, w, _ := os.Pipe()
	_, _ = io.WriteString(w, "from a pipe pw\nmore")
	w.Close()
	os.Stdin = r
	if got, err := backupPassword("", true, true); err != nil || got != "from a pipe pw" {
		t.Fatalf("stdin: %q %v", got, err)
	}
	r, w, _ = os.Pipe()
	w.Close()
	os.Stdin = r
	if _, err := backupPassword("", true, false); err == nil {
		t.Fatal("empty stdin accepted")
	}
}

func TestSummaryOrdered(t *testing.T) {
	if got := summary(backup.Stats{"users": 2, "orgs": 1}); got != "orgs 1, users 2" {
		t.Fatal(got)
	}
}
