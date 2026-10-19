package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
		if r.URL.Path != "/api/v1/backup" || r.URL.Query().Get("plain") != "1" || r.Header.Get("Authorization") != "Bearer tok" {
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

func TestOnCommandLine(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"--config", "q.toml", "serve"}, false},
		{[]string{"serve", "--master-key", "x"}, true},
		{[]string{"serve", "--master-key=x"}, true},
		{[]string{"serve", "-previous-master-keys=x"}, true},
		{[]string{"serve", "--", "--master-key"}, false},
	} {
		if got := onCommandLine(tc.args, "master-key", "previous-master-keys"); got != tc.want {
			t.Errorf("%v: %v", tc.args, got)
		}
	}
}

// Secrets given as flags are warned about (named with the environment variable and config key to use instead);
// other flags, and a VictoriaLogs URL without credentials, are not.
func TestWarnSecretFlags(t *testing.T) {
	cfg := config.Default()
	var b strings.Builder
	warnSecretFlags(&b, cfg, []string{"serve", "--master-key=x", "--smtp-password", "y", "--data-dir", "d",
		"--audit-victorialogs-url", "http://vl:9428"})
	out := b.String()
	if !strings.Contains(out, "--master-key") || !strings.Contains(out, "QUISORA_MASTER_KEY") ||
		!strings.Contains(out, "--smtp-password") || strings.Contains(out, "data-dir") || strings.Contains(out, "victorialogs") {
		t.Fatalf("warnings:\n%s", out)
	}
	cfg.Audit.VictoriaLogs = "http://user:pw@vl:9428"
	b.Reset()
	warnSecretFlags(&b, cfg, []string{"serve", "--audit-victorialogs-url", cfg.Audit.VictoriaLogs})
	if !strings.Contains(b.String(), "--audit-victorialogs-url") {
		t.Fatal("a VictoriaLogs URL with credentials was not warned about")
	}
}
