package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

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

func TestNewVaultValidation(t *testing.T) {
	ctx := context.Background()
	good := httptest.NewServer(http.NotFoundHandler())
	defer good.Close()
	bad := filepath.Join(t.TempDir(), "missing")
	cases := []struct {
		name string
		c    config.Vault
		want string
	}{
		{"no address", config.Vault{}, "no Vault is configured"},
		{"bad scheme", config.Vault{Address: "ftp://host"}, "http(s) URL"},
		{"no host", config.Vault{Address: "http://"}, "http(s) URL"},
		{"bad CA", config.Vault{Address: good.URL, CAFile: bad}, "secrets.vault.ca_file"},
		{"bad token file", config.Vault{Address: good.URL, TokenFile: bad}, "token_file"},
		{"bad secret id file", config.Vault{Address: good.URL, RoleID: "r", SecretIDFile: bad}, "secret_id_file"},
		{"no credentials", config.Vault{Address: good.URL}, "needs a token"},
		{"role without secret", config.Vault{Address: good.URL, RoleID: "r"}, "needs a token"},
		{"secret without role", config.Vault{Address: good.URL, SecretID: "s"}, "needs a token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newVault(ctx, tc.c)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVaultAppRoleMountAndFailures(t *testing.T) {
	ctx := context.Background()
	var gotPath, gotNS string
	mode := "ok"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotNS = r.URL.Path, r.Header.Get("X-Vault-Namespace")
		switch mode {
		case "notoken":
			writeJSON(w, map[string]any{"auth": map[string]any{}})
		case "garbage":
			_, _ = w.Write([]byte("{not json"))
		case "denied":
			w.WriteHeader(http.StatusForbidden)
			writeJSON(w, map[string]any{"errors": []string{"a", "b"}})
		default:
			writeJSON(w, map[string]any{"auth": map[string]any{"client_token": "tok"}})
		}
	}))
	defer srv.Close()
	cfg := config.Vault{Address: srv.URL + "/", RoleID: "r", SecretIDFile: writeFile(t, "sid\n"), AppRoleMount: "/custom/", Namespace: "team"}
	v, err := newVault(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.token != "tok" || gotPath != "/v1/auth/custom/login" || gotNS != "team" {
		t.Fatalf("token %q path %q ns %q", v.token, gotPath, gotNS)
	}
	for _, tc := range []struct{ m, want string }{{"notoken", "returned no token"}, {"garbage", "AppRole sign-in"}, {"denied", "403 Forbidden a; b"}} {
		mode = tc.m
		if _, err := newVault(ctx, cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.m, err)
		}
	}
}

func TestVaultReadErrors(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/kv/v1":
			writeJSON(w, map[string]any{"data": map[string]any{"value": "plain", "n": 1}})
		case "/v1/kv/nested":
			// "data" is itself a field of a v1 secret (no metadata): must not be unwrapped.
			writeJSON(w, map[string]any{"data": map[string]any{"data": map[string]any{"x": "y"}}})
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	v, err := newVault(ctx, config.Vault{Address: srv.URL, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.read(ctx, "/kv/v1/"); err != nil || got != "plain" {
		t.Fatalf("default field: %q %v", got, err)
	}
	if _, err := v.read(ctx, "kv/v1#n"); err == nil || !strings.Contains(err.Error(), "not a string") {
		t.Fatalf("non-string: %v", err)
	}
	if _, err := v.read(ctx, "kv/v1#nope"); err == nil || !strings.Contains(err.Error(), "no field") {
		t.Fatalf("missing: %v", err)
	}
	if _, err := v.read(ctx, "kv/nested#x"); err == nil {
		t.Fatal("v1 secret with a data field was unwrapped")
	}
	if _, err := v.read(ctx, "#field"); err == nil || !strings.Contains(err.Error(), "vault://<path>") {
		t.Fatalf("empty path: %v", err)
	}
	if _, err := v.read(ctx, "kv/boom"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := v.read(cctx, "kv/v1"); err == nil || !strings.HasPrefix(err.Error(), "Vault: ") {
		t.Fatalf("cancelled: %v", err)
	}
	// An invalid method makes the request itself fail to build.
	if err := v.do(ctx, "bad method", "x", nil, nil); err == nil {
		t.Fatal("invalid method accepted")
	}
}
