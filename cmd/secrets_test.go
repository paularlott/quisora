package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	logpkg "github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
)

// A server whose master keys are in Vault: it reads them at start, and a reload (SIGHUP, or the console's "Read
// secret stores now") reads them again, so a rotation is two edits in Vault and two reloads. Vault being down fails
// the reload and leaves the keys in use as they were.
func TestMasterKeyRotationThroughVault(t *testing.T) {
	var mu sync.Mutex
	kv := map[string]any{}
	down := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if down || r.Header.Get("X-Vault-Token") != "t0k" || r.URL.Path != "/v1/secret/data/quisora" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": kv, "metadata": map[string]any{}}})
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	key := func() string { return base64.StdEncoding.EncodeToString(secure.RandomBytes(32)) }
	old, next := key(), key()
	set := func(master string, previous ...string) {
		mu.Lock()
		defer mu.Unlock()
		kv = map[string]any{"master_key": master}
		if len(previous) > 0 {
			kv["previous_master_key"] = previous[0]
		}
	}
	set(old, "") // no rotation: the previous key slot is empty

	conf := filepath.Join(dir, "quisora.toml")
	_ = os.WriteFile(conf, []byte(`[server]
listen = "127.0.0.1:0"
public_url = "https://127.0.0.1:8443"
data_dir = "`+filepath.Join(dir, "data")+`"
master_key = "vault://secret/data/quisora#master_key"
previous_master_keys = ["vault://secret/data/quisora#previous_master_key"]

[secrets.vault]
address = "`+srv.URL+`"
token = "t0k"
ca_file = "`+ca+`"
`), 0o600)
	cfg := config.Default()
	c := parsed(t, cfg, "--config", conf, "serve")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := prepare(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MasterKey != old {
		t.Fatalf("start: master key %q", cfg.Server.MasterKey)
	}
	a, err := app.Start(ctx, cfg, logpkg.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	reload := reloader(c, a, logpkg.NewNullLogger())
	ids := func() []string { return a.Svc.Sealer.KeyIDs() }
	oldID := ids()[0]

	// step 1: the new key as a previous key everywhere
	set(old, next)
	if r := reload(ctx, true, 0); r.Error != "" || !slices.Contains(r.Changes, "master keys") || ids()[0] != oldID || len(ids()) != 2 {
		t.Fatalf("step 1: %+v %v", r, ids())
	}
	// step 2: the new key active, the old one previous
	set(next, old)
	if r := reload(ctx, true, 0); r.Error != "" || ids()[0] == oldID || ids()[1] != oldID {
		t.Fatalf("step 2: %+v %v", r, ids())
	}
	// emptying the previous slot before every secret is re-sealed is refused, as with keys in the config file
	two := ids()
	set(next, "")
	if r := reload(ctx, true, 0); r.Error == "" || !slices.Equal(ids(), two) {
		t.Fatalf("old key dropped before re-sealing: %+v %v", r, ids())
	}
	set(next, old)
	// Vault down: the reload fails, the keys stay
	before := ids()
	mu.Lock()
	down = true
	mu.Unlock()
	if r := reload(ctx, true, 0); r.Error == "" || !slices.Equal(ids(), before) {
		t.Fatalf("vault down: %+v %v", r, ids())
	}
}

func TestWarnLooseFiles(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("posix permissions")
	}
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	_ = os.WriteFile(tok, []byte("t"), 0o644)
	conf := filepath.Join(dir, "q.toml")
	_ = os.WriteFile(conf, []byte("[server]\nmaster_key = \"abc\"\n"), 0o644)
	cfg := config.Default()
	cfg.Secrets.Vault.TokenFile = tok
	c := parsed(t, cfg, "--config", conf, "serve")
	cfg.Secrets.Vault.TokenFile = tok
	var b strings.Builder
	warnLooseFiles(&b, cfg, c)
	if !strings.Contains(b.String(), tok) {
		t.Fatalf("token file not warned about: %q", b.String())
	}
	if !secretInFile(cfg, c) {
		t.Fatal("a master key in the file is a secret in the file")
	}
	if !strings.Contains(b.String(), conf) {
		t.Fatalf("config file with a secret not warned about: %q", b.String())
	}
	_ = os.Chmod(tok, 0o600)
	_ = os.Chmod(conf, 0o600)
	b.Reset()
	warnLooseFiles(&b, cfg, c)
	if b.Len() != 0 {
		t.Fatalf("0600 files warned about: %q", b.String())
	}
}

// Secrets given as flags are warned about (named with the environment variable and config key to use instead);
// other flags, and a VictoriaLogs URL without credentials, are not.
func TestWarnSecretFlags(t *testing.T) {
	cfg := config.Default()
	var b strings.Builder
	warnSecretFlags(&b, cfg, parsed(t, cfg, "serve", "--master-key=x", "--smtp-password", "y", "--data-dir", "d",
		"--audit-victorialogs-url", "http://vl:9428"))
	out := b.String()
	if !strings.Contains(out, "--master-key") || !strings.Contains(out, "QUISORA_MASTER_KEY") ||
		!strings.Contains(out, "--smtp-password") || strings.Contains(out, "data-dir") || strings.Contains(out, "victorialogs") {
		t.Fatalf("warnings:\n%s", out)
	}
	cfg.Audit.VictoriaLogs = "http://user:pw@vl:9428"
	b.Reset()
	warnSecretFlags(&b, cfg, parsed(t, cfg, "serve", "--audit-victorialogs-url", cfg.Audit.VictoriaLogs))
	if !strings.Contains(b.String(), "--audit-victorialogs-url") {
		t.Fatal("a VictoriaLogs URL with credentials was not warned about")
	}
}
