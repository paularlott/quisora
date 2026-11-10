package sshcli

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/sshcli/sshclitest"
)

func TestDiscover(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	d, err := te.discover(context.Background(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	if d.Org != "acme" || d.Tenant != "prod" || d.MaxAuthAge != 3600 || !d.HostCerts || d.label() != "quisora:acme/prod" {
		t.Errorf("%+v", d)
	}

	t.Run("not found", func(t *testing.T) {
		_, err := te.discover(context.Background(), f.URL+"/nope")
		if err == nil || !strings.Contains(err.Error(), "never enabled") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("not a discovery document", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) }))
		defer srv.Close()
		if _, err := te.discover(context.Background(), srv.URL); err == nil {
			t.Error("html accepted")
		}
	})
	t.Run("http to a remote host", func(t *testing.T) {
		_, err := te.discover(context.Background(), "http://id.example.com/o/x/ssh/y")
		if err == nil || !strings.Contains(err.Error(), "only https") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("plain endpoint for a remote host in the document", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"org":"a","tenant":"b","token_endpoint":"http://evil.example.com/token"}`))
		}))
		defer srv.Close()
		if _, err := te.discover(context.Background(), srv.URL); err == nil {
			t.Error("a plain-http endpoint on another host was accepted")
		}
	})
}

// TLS: an unknown certificate is refused, --ca-cert trusts it, --insecure ignores it (with a warning).
func TestTLSOptions(t *testing.T) {
	f := sshclitest.NewTLS()
	defer f.Close()

	te := newTestEnv(t)
	if _, err := te.discover(context.Background(), f.URL); err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}

	te = newTestEnv(t)
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw}), 0o644)
	te.CACert = pemFile
	if _, err := te.discover(context.Background(), f.URL); err != nil {
		t.Fatalf("--ca-cert: %v", err)
	}

	te = newTestEnv(t)
	te.Insecure = true
	if _, err := te.discover(context.Background(), f.URL); err != nil {
		t.Fatalf("--insecure: %v", err)
	}
	mustContain(t, "warning", te.err.String(), "not verified")

	te = newTestEnv(t)
	te.CACert = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := te.discover(context.Background(), f.URL); err == nil {
		t.Error("a missing --ca-cert was accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("nope"), 0o644)
	te.CACert = bad
	if _, err := te.discover(context.Background(), f.URL); err == nil {
		t.Error("a --ca-cert without a certificate was accepted")
	}
}

func TestStatusNone(t *testing.T) {
	te := newTestEnv(t)
	if err := te.Status(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "status", te.out.String(), "No Quisora certificates.")
}

// The CLI follows redirects within the server's origin only: a 307 from the token endpoint to another host or port
// would post the form, client secret included, there.
func TestClientRefusesRedirectsToAnotherOrigin(t *testing.T) {
	var reached bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/elsewhere":
			http.Redirect(w, r, other.URL+"/token", http.StatusTemporaryRedirect)
		case "/here":
			http.Redirect(w, r, "/token", http.StatusTemporaryRedirect)
		}
	}))
	defer srv.Close()
	c, err := newTestEnv(t).client()
	if err != nil {
		t.Fatal(err)
	}
	form := strings.NewReader("client_secret=s3cret")
	if resp, err := c.Post(srv.URL+"/elsewhere", "application/x-www-form-urlencoded", form); err == nil {
		resp.Body.Close()
		t.Error("a redirect to another origin was followed")
	}
	if reached {
		t.Error("the form reached the other origin")
	}
	resp, err := c.Post(srv.URL+"/here", "application/x-www-form-urlencoded", strings.NewReader("x=1"))
	if err != nil {
		t.Fatalf("a redirect within the origin: %v", err)
	}
	resp.Body.Close()
}

// A redirect stays at the server when it writes out or leaves off the scheme's default port, or upgrades http to https
// on the same host; never to another host or port, nor back from https to http.
func TestSameServer(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{"https://id.example.com:443/ssh", "https://id.example.com/token", true},
		{"https://id.example.com/ssh", "https://ID.example.com:443/token", true},
		{"http://id.example.com/ssh", "https://id.example.com/ssh", true},
		{"http://id.example.com:80/ssh", "https://id.example.com:443/ssh", true},
		{"https://id.example.com:8443/ssh", "https://id.example.com:8443/token", true},
		{"https://id.example.com/ssh", "http://id.example.com/ssh", false},
		{"https://id.example.com/ssh", "https://id.example.com:8443/ssh", false},
		{"http://id.example.com:8080/ssh", "https://id.example.com:8080/ssh", false},
		{"http://id.example.com/ssh", "https://other.example.com/ssh", false},
		{"https://id.example.com/ssh", "https://other.example.com/ssh", false},
	} {
		from, _ := url.Parse(tc.from)
		to, _ := url.Parse(tc.to)
		if got := sameServer(from, to); got != tc.want {
			t.Errorf("%s to %s: %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}
