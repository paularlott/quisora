package secrets

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

// tlsServer starts h over TLS and returns its URL and a CA file trusting it.
func tlsServer(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL, ca
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyRules(t *testing.T) {
	addr, ca := fakeConnect(t)
	ctx := context.Background()
	c := config.Default()
	c.Secrets.OnePassword = config.OnePassword{ConnectURL: addr, ConnectToken: "connect-token", CAFile: ca}
	c.Server.MasterKey = "op://Infra/Quisora/master_key"
	c.Server.PreviousMasterKeys = []string{"op://Infra/Quisora/Old/master_key", "plain-old-key"}
	c.Cluster.Key = "op://Infra/Quisora/password"
	c.Server.PublicURL = "op://not/a/secret/setting" // only secret settings are read from a store

	// only the paths asked for (a reload reads only the keys it applies)
	if err := Apply(ctx, c, "server.previous_master_keys"); err != nil {
		t.Fatal(err)
	}
	if c.Server.MasterKey != "op://Infra/Quisora/master_key" ||
		c.Server.PreviousMasterKeys[0] != "old-mk" || c.Server.PreviousMasterKeys[1] != "plain-old-key" {
		t.Fatalf("paths: %q %v", c.Server.MasterKey, c.Server.PreviousMasterKeys)
	}
	if err := Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if c.Server.MasterKey != "mk-from-1password" || c.Cluster.Key != "pw" || c.Server.PublicURL != "op://not/a/secret/setting" {
		t.Fatalf("all: %q %q %q", c.Server.MasterKey, c.Cluster.Key, c.Server.PublicURL)
	}

	// a reference to a store that is not configured; both 1Password kinds at once; a service account in a build
	// without the onepassword tag
	for name, edit := range map[string]func(*config.Config){
		"no vault": func(c *config.Config) { c.Mail.Password = "vault://kv/x#y" },
		"no op":    func(c *config.Config) { c.Mail.Password = "op://a/b/c" },
		"both kinds": func(c *config.Config) {
			c.Mail.Password = "op://a/b/c"
			c.Secrets.OnePassword = config.OnePassword{ConnectURL: addr, ServiceAccountToken: "ops_x"}
		},
		"no connect token": func(c *config.Config) {
			c.Mail.Password = "op://a/b/c"
			c.Secrets.OnePassword = config.OnePassword{ConnectURL: addr}
		},
	} {
		c := config.Default()
		edit(c)
		err := Apply(ctx, c)
		if err == nil || !strings.HasPrefix(err.Error(), "mail.password: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if serviceAccount == nil {
		c := config.Default()
		c.Mail.Password = "op://a/b/c"
		c.Secrets.OnePassword.ServiceAccountToken = "ops_x"
		if err := Apply(ctx, c); err == nil || !strings.Contains(err.Error(), "-tags onepassword") {
			t.Errorf("service account without the tag: %v", err)
		}
	}

	// nothing to read: no store is contacted, nothing changes
	plain := config.Default()
	plain.Server.MasterKey = "abc"
	if err := Apply(ctx, plain); err != nil || plain.Server.MasterKey != "abc" {
		t.Fatalf("plain: %v", err)
	}
}

func TestPlainHTTP(t *testing.T) {
	var c config.Secrets
	c.Vault.Address, c.OnePassword.ConnectURL = "HTTP://vault:8200", "https://connect"
	if got := PlainHTTP(c); len(got) != 1 || got[0] != "secrets.vault.address" {
		t.Fatalf("got %v", got)
	}
}

func TestCredentialSources(t *testing.T) {
	if v, err := credential("inline", "ignored", "x"); err != nil || v != "inline" {
		t.Fatalf("inline: %q %v", v, err)
	}
	if v, err := credential("", "", "x"); err != nil || v != "" {
		t.Fatalf("none: %q %v", v, err)
	}
	if v, err := credential("", writeFile(t, "  tok  \nsecond\n"), "x"); err != nil || v != "tok" {
		t.Fatalf("file: %q %v", v, err)
	}
	if _, err := credential("", writeFile(t, " \nx"), "what"); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty file: %v", err)
	}
	if _, err := credential("", filepath.Join(t.TempDir(), "missing"), "what"); err == nil || !strings.HasPrefix(err.Error(), "what: ") {
		t.Fatalf("missing file: %v", err)
	}
}

func TestHTTPClientCAFile(t *testing.T) {
	if _, err := httpClient(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing CA file accepted")
	}
	if _, err := httpClient(writeFile(t, "not pem")); err == nil {
		t.Fatal("non-PEM CA file accepted")
	}
	if hc, err := httpClient(""); err != nil || hc == nil {
		t.Fatalf("no CA file: %v", err)
	}
}
