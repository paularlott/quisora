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
