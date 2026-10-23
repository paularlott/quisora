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
	"sync/atomic"
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

// fakeVault serves a KV v2 secret at secret/data/quisora and a KV v1 one at kv/quisora, to token "t0k" or the token
// AppRole sign-in gives.
func fakeVault(t *testing.T, logins *atomic.Int32) (string, string) {
	return tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["role_id"] != "role" || in["secret_id"] != "s3cret" {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{"errors": []string{"invalid role or secret ID"}})
				return
			}
			logins.Add(1)
			writeJSON(w, map[string]any{"auth": map[string]any{"client_token": "from-approle"}})
			return
		}
		if tok := r.Header.Get("X-Vault-Token"); tok != "t0k" && tok != "from-approle" {
			w.WriteHeader(http.StatusForbidden)
			writeJSON(w, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		switch r.URL.Path {
		case "/v1/secret/data/quisora":
			writeJSON(w, map[string]any{"data": map[string]any{"data": map[string]any{"master_key": "mk-from-vault", "value": "v"},
				"metadata": map[string]any{"version": 3}}})
		case "/v1/kv/quisora":
			writeJSON(w, map[string]any{"data": map[string]any{"smtp": "smtp-from-kv1", "n": 42}})
		default:
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"errors": []string{}})
		}
	}))
}

// fakeConnect serves vault "Infra" with item "Quisora" (and two items called "Twin").
func fakeConnect(t *testing.T) (string, string) {
	const vid, iid = "aaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbb"
	return tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer connect-token" {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"message": "Invalid token"})
			return
		}
		filter := r.URL.Query().Get("filter")
		switch r.URL.Path {
		case "/v1/vaults":
			if filter == `name eq "Infra"` {
				writeJSON(w, []map[string]string{{"id": vid, "name": "Infra"}})
				return
			}
			writeJSON(w, []any{})
		case "/v1/vaults/" + vid + "/items":
			switch filter {
			case `title eq "Quisora"`:
				writeJSON(w, []map[string]string{{"id": iid, "title": "Quisora"}})
			case `title eq "Twin"`:
				writeJSON(w, []map[string]string{{"id": "c1", "title": "Twin"}, {"id": "c2", "title": "Twin"}})
			default:
				writeJSON(w, []any{})
			}
		case "/v1/vaults/" + vid + "/items/" + iid:
			writeJSON(w, map[string]any{"id": iid, "title": "Quisora",
				"sections": []map[string]string{{"id": "s1", "label": "Old"}},
				"fields": []map[string]any{
					{"id": "f1", "label": "master_key", "value": "mk-from-1password"},
					{"id": "f2", "label": "master_key", "value": "old-mk", "section": map[string]string{"id": "s1"}},
					{"id": "password", "label": "password", "purpose": "PASSWORD", "value": "pw"},
				}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestVault(t *testing.T) {
	var logins atomic.Int32
	addr, ca := fakeVault(t, &logins)
	ctx := context.Background()
	token := config.Vault{Address: addr, Token: "t0k", CAFile: ca}
	for ref, want := range map[string]string{
		"vault://secret/data/quisora#master_key": "mk-from-vault", // KV v2
		"vault://secret/data/quisora":            "v",             // field "value" by default
		"vault://kv/quisora#smtp":                "smtp-from-kv1", // KV v1
	} {
		r := &resolver{cfg: config.Secrets{Vault: token}}
		if got, err := r.resolve(ctx, ref); err != nil || got != want {
			t.Errorf("%s: %q %v", ref, got, err)
		}
	}
	for ref, wantErr := range map[string]string{
		"vault://secret/data/quisora#nope": `no field "nope"`,
		"vault://kv/quisora#n":             "not a string",
		"vault://missing#x":                "404",
	} {
		r := &resolver{cfg: config.Secrets{Vault: token}}
		if _, err := r.resolve(ctx, ref); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s: %v, want %q", ref, err, wantErr)
		}
	}

	// AppRole, the secret id from a file: one sign-in for every reference of one Apply
	idFile := filepath.Join(t.TempDir(), "secret-id")
	_ = os.WriteFile(idFile, []byte("s3cret\n"), 0o600)
	c := config.Default()
	c.Secrets.Vault = config.Vault{Address: addr, RoleID: "role", SecretIDFile: idFile, CAFile: ca}
	c.Server.MasterKey = "vault://secret/data/quisora#master_key"
	c.Mail.Password = "vault://kv/quisora#smtp"
	if err := Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if c.Server.MasterKey != "mk-from-vault" || c.Mail.Password != "smtp-from-kv1" || logins.Load() != 1 {
		t.Fatalf("approle: %q %q, %d sign-ins", c.Server.MasterKey, c.Mail.Password, logins.Load())
	}

	// not trusted without the CA; a wrong token
	r := &resolver{cfg: config.Secrets{Vault: config.Vault{Address: addr, Token: "t0k"}}}
	if _, err := r.resolve(ctx, "vault://kv/quisora#smtp"); err == nil {
		t.Error("an untrusted certificate was accepted")
	}
	r = &resolver{cfg: config.Secrets{Vault: config.Vault{Address: addr, Token: "wrong", CAFile: ca}}}
	if _, err := r.resolve(ctx, "vault://kv/quisora#smtp"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("wrong token: %v", err)
	}
}

func TestOnePasswordConnect(t *testing.T) {
	addr, ca := fakeConnect(t)
	ctx := context.Background()
	tokenFile := filepath.Join(t.TempDir(), "connect-token")
	_ = os.WriteFile(tokenFile, []byte("connect-token\n"), 0o600)
	op := config.OnePassword{ConnectURL: addr, ConnectTokenFile: tokenFile, CAFile: ca}
	for ref, want := range map[string]string{
		"op://Infra/Quisora/master_key":     "mk-from-1password", // the field outside any section
		"op://Infra/Quisora/Old/master_key": "old-mk",            // the one in section "Old"
		"op://Infra/Quisora/password":       "pw",
	} {
		r := &resolver{cfg: config.Secrets{OnePassword: op}}
		if got, err := r.resolve(ctx, ref); err != nil || got != want {
			t.Errorf("%s: %q %v", ref, got, err)
		}
	}
	for ref, wantErr := range map[string]string{
		"op://Nope/Quisora/master_key": `no vault "Nope"`,
		"op://Infra/Twin/password":     "2 items are called",
		"op://Infra/Quisora/nope":      `no field "nope"`,
		"op://Infra/Quisora/New/x":     `no section "New"`,
		"op://Infra/Quisora":           "op://<vault>/<item>/<field>",
		"op://Infra//master_key":       "op://<vault>/<item>/<field>",
	} {
		r := &resolver{cfg: config.Secrets{OnePassword: op}}
		if _, err := r.resolve(ctx, ref); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s: %v, want %q", ref, err, wantErr)
		}
	}
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
