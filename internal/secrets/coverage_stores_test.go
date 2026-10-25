package secrets

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
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

func TestNewOnePasswordValidation(t *testing.T) {
	ctx := context.Background()
	bad := filepath.Join(t.TempDir(), "missing")
	good := httptest.NewServer(http.NotFoundHandler())
	defer good.Close()
	cases := []struct {
		name string
		c    config.OnePassword
		want string
	}{
		{"bad sa file", config.OnePassword{ServiceAccountTokenFile: bad}, "service_account_token_file"},
		{"both", config.OnePassword{ServiceAccountToken: "sa", ConnectURL: good.URL}, "not both"},
		{"sa without sdk", config.OnePassword{ServiceAccountToken: "sa"}, "onepassword tag"},
		{"nothing", config.OnePassword{}, "no 1Password is configured"},
		{"bad scheme", config.OnePassword{ConnectURL: "gopher://x"}, "http(s) URL"},
		{"bad token file", config.OnePassword{ConnectURL: good.URL, ConnectTokenFile: bad}, "connect_token_file"},
		{"no token", config.OnePassword{ConnectURL: good.URL}, "needs an access token"},
		{"bad CA", config.OnePassword{ConnectURL: good.URL, ConnectToken: "t", CAFile: bad}, "secrets.onepassword.ca_file"},
	}
	saved := serviceAccount
	serviceAccount = nil
	defer func() { serviceAccount = saved }()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newOnePassword(ctx, tc.c)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if r, err := newOnePassword(ctx, config.OnePassword{ConnectURL: good.URL + "/", ConnectToken: "t"}); err != nil {
		t.Fatal(err)
	} else if c := r.(*connect); strings.HasSuffix(c.addr, "/") {
		t.Fatalf("address keeps trailing slash: %q", c.addr)
	}
}

type fakeSA struct {
	reads  []string
	closed bool
}

func (f *fakeSA) read(_ context.Context, ref string) (string, error) {
	f.reads = append(f.reads, ref)
	if strings.HasSuffix(ref, "/boom") {
		return "", errors.New("sdk failed")
	}
	return "sa-" + ref, nil
}
func (f *fakeSA) close() { f.closed = true }

func TestServiceAccountHook(t *testing.T) {
	saved := serviceAccount
	defer func() { serviceAccount = saved }()
	fake := &fakeSA{}
	var gotToken string
	serviceAccount = func(_ context.Context, token string) (opReader, error) {
		gotToken = token
		return fake, nil
	}
	r, err := newOnePassword(context.Background(), config.OnePassword{ServiceAccountTokenFile: writeFile(t, "sa-token\n")})
	if err != nil || r != opReader(fake) || gotToken != "sa-token" {
		t.Fatalf("%v %v %q", r, err, gotToken)
	}
	res := &resolver{cfg: config.Secrets{OnePassword: config.OnePassword{ServiceAccountToken: "x"}}}
	if v, err := res.resolve(context.Background(), "op://a/b/c"); err != nil || v != "sa-op://a/b/c" {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := res.resolve(context.Background(), "op://a/b/boom"); err == nil || !strings.HasPrefix(err.Error(), "op://a/b/boom: ") {
		t.Fatalf("error not wrapped with the reference: %v", err)
	}
	if v, err := res.resolve(context.Background(), "plain"); err != nil || v != "plain" {
		t.Fatalf("plain: %q %v", v, err)
	}
	res.close()
	if !fake.closed {
		t.Fatal("close not forwarded to the store")
	}
	(&resolver{}).close() // no store signed in: nothing to close

	serviceAccount = func(context.Context, string) (opReader, error) { return nil, errors.New("sign-in failed") }
	res = &resolver{cfg: config.Secrets{OnePassword: config.OnePassword{ServiceAccountToken: "x"}}}
	if _, err := res.resolve(context.Background(), "op://a/b/c"); err == nil || !strings.Contains(err.Error(), "sign-in failed") {
		t.Fatalf("%v", err)
	}
	res = &resolver{cfg: config.Secrets{}}
	if _, err := res.resolve(context.Background(), "vault://x#y"); err == nil || !strings.Contains(err.Error(), "no Vault is configured") {
		t.Fatalf("%v", err)
	}
}

func TestConnectReadFailures(t *testing.T) {
	ctx := context.Background()
	const vid, iid = "aaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbb"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vaults":
			writeJSON(w, []map[string]string{{"id": vid, "name": "V"}})
		case "/v1/vaults/" + vid + "/items":
			writeJSON(w, []map[string]string{{"id": iid, "title": "I"}})
		case "/v1/vaults/" + vid + "/items/" + iid:
			writeJSON(w, map[string]any{"id": iid,
				"sections": []map[string]string{{"id": "sec", "label": "Sec"}},
				"fields": []map[string]any{
					{"id": "orphan", "label": "k", "value": "no-section"},
					{"id": "inside", "label": "k", "value": "in-section", "section": map[string]string{"id": "sec"}},
				}})
		case "/v1/vaults/" + vid + "/items/broken":
			_, _ = w.Write([]byte("{"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &connect{addr: srv.URL, token: "t", hc: srv.Client()}
	for ref, want := range map[string]string{
		"op://V/I/sec/k":      "in-section",
		"op://V/I/SEC/K":      "in-section",
		"op://V/I/k":          "no-section",
		"op://V/I/inside":     "in-section",
		"op://V/I/sec/inside": "in-section",
	} {
		if got, err := c.read(ctx, ref); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", ref, got, err, want)
		}
	}
	for ref, want := range map[string]string{
		"op://V/I":            "1Password reference is",
		"op://V//k":           "1Password reference is",
		"op://V/I/none/k":     "no section",
		"op://V/I/sec/orphan": "no field",
		"op://V/I/zzz":        "no field",
		"op://Nope/I/k":       "",
	} {
		if _, err := c.read(ctx, ref); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", ref, err, want)
		}
	}
	// A name that is an id skips the lookup; the item fetch then answers 404 or garbage.
	if _, err := c.read(ctx, "op://V/cccccccccccccccccccccccccc/k"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("unknown item id: %v", err)
	}
	if err := c.get(ctx, "/v1/vaults/"+vid+"/items/broken", &struct{}{}); err == nil {
		t.Error("garbage JSON accepted")
	}
	if err := c.get(ctx, "/%zz", nil); err == nil {
		t.Error("bad path accepted")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.find(cctx, "/v1/vaults", "name", "V", "vault"); err == nil {
		t.Error("cancelled lookup succeeded")
	}
	if _, err := c.find(ctx, "/v1/vaults", "name", `we"ird`, "vault"); err == nil || !strings.Contains(err.Error(), "no vault") {
		t.Errorf("quote in name: %v", err)
	}
}

func TestPlainHTTPEmptyAndMixedCase(t *testing.T) {
	if got := PlainHTTP(config.Secrets{}); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	got := PlainHTTP(config.Secrets{Vault: config.Vault{Address: "HTTP://v"}, OnePassword: config.OnePassword{ConnectURL: "https://o"}})
	if len(got) != 1 || got[0] != "secrets.vault.address" {
		t.Fatalf("%v", got)
	}
}
