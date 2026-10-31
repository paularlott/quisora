package sshcli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/sshcli/sshclitest"
	"golang.org/x/crypto/ssh"
)

func hostKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	p := filepath.Join(t.TempDir(), "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(sp), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, sp
}

// host-sign: client credentials the way a service account is registered by default (client_secret_post), the default
// principal is the fully qualified host name, the certificate is written beside the key and the sshd_config line
// printed.
func TestHostSign(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	keyFile, pub := hostKey(t)
	te := newTestEnv(t)
	te.Hostname = func() (string, error) { return "Web1", nil }
	te.LookupCNAME = func(_ context.Context, h string) (string, error) { return "web1.example.com.", nil }

	err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, ClientID: f.ClientID, Secret: f.ClientSecret})
	if err != nil {
		t.Fatalf("host-sign: %v", err)
	}
	certFile := strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"
	if got := strings.TrimSpace(te.out.String()); got != "HostCertificate "+certFile {
		t.Errorf("output %q", got)
	}
	cert := parseCert(t, certFile)
	if cert.CertType != ssh.HostCert || !slices.Equal(cert.ValidPrincipals, []string{"web1.example.com"}) {
		t.Errorf("certificate: type %d principals %v", cert.CertType, cert.ValidPrincipals)
	}
	if string(cert.Key.Marshal()) != string(pub.Marshal()) {
		t.Error("the certificate is for another key")
	}
	forms := f.TokenForms()
	if len(forms) != 1 || forms[0].Get("grant_type") != "client_credentials" || forms[0].Get("scope") != "ssh:host" {
		t.Errorf("token request %v", forms)
	}
	if got := f.TokenMethods(); !slices.Equal(got, []string{"post"}) {
		t.Errorf("the client authenticated with %v, want one client_secret_post request", got)
	}
	if st, _ := os.Stat(certFile); st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	if out := keygenL(t, certFile); out != "" {
		mustContain(t, "ssh-keygen -L", out, "host certificate", "web1.example.com")
	}
	mustNotContain(t, "output", te.out.String()+te.err.String(), "host-token", f.ClientSecret)
}

// A client authenticates at the token endpoint the way it was registered to, and nothing else is accepted: auto (the
// default) tries client_secret_post and, when the server does not know the client that way, client_secret_basic once;
// post and basic try that one only. Secrets with characters that need form-encoding work in both.
func TestHostSignAuthMethod(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	keyFile, _ := hostKey(t)
	for _, c := range []struct {
		registered, option string
		want               []string // the requests made; nil: it fails
	}{
		{"post", "", []string{"post"}},
		{"post", "auto", []string{"post"}},
		{"post", "post", []string{"post"}},
		{"post", "basic", nil},
		{"basic", "", []string{"post", "basic"}},
		{"basic", "auto", []string{"post", "basic"}},
		{"basic", "basic", []string{"basic"}},
		{"basic", "post", nil},
	} {
		t.Run(c.registered+" registered, "+cmpOr(c.option, "default"), func(t *testing.T) {
			f.AuthMethod = c.registered
			before := len(f.TokenMethods())
			te := newTestEnv(t)
			err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Principals: []string{"a.example.com"},
				ClientID: f.ClientID, Secret: f.ClientSecret, AuthMethod: c.option})
			got := f.TokenMethods()[before:]
			if c.want == nil {
				if err == nil || !strings.Contains(err.Error(), "bad client credentials") {
					t.Errorf("got %v", err)
				}
				if len(got) != 1 {
					t.Errorf("requests %v: an explicit method is not retried", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("host-sign: %v\n%s", err, te.err)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("requests %v, want %v", got, c.want)
			}
		})
	}

	t.Run("a wrong secret is tried both ways and says so", func(t *testing.T) {
		f.AuthMethod = "post"
		before := len(f.TokenMethods())
		te := newTestEnv(t)
		err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Principals: []string{"a.example.com"},
			ClientID: f.ClientID, Secret: "wrong"})
		if err == nil || !strings.Contains(err.Error(), "bad client credentials") || !strings.Contains(err.Error(), "tried client_secret_post, then client_secret_basic") {
			t.Errorf("got %v", err)
		}
		if got := f.TokenMethods()[before:]; !slices.Equal(got, []string{"post", "basic"}) {
			t.Errorf("requests %v", got)
		}
	})
	t.Run("only invalid_client is retried", func(t *testing.T) {
		f.AuthMethod = "basic"
		f.Fail["token"] = http.StatusBadGateway
		defer delete(f.Fail, "token")
		te := newTestEnv(t)
		err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Principals: []string{"a.example.com"},
			ClientID: f.ClientID, Secret: f.ClientSecret})
		if err == nil || strings.Contains(err.Error(), "tried") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("an unknown method", func(t *testing.T) {
		te := newTestEnv(t)
		err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, ClientID: f.ClientID, Secret: f.ClientSecret, AuthMethod: "jwt"})
		if err == nil || !strings.Contains(err.Error(), "--auth-method") {
			t.Errorf("got %v", err)
		}
	})
}

// --ttl asks for a certificate of that many days (the API's ttl_days).
func TestHostSignTTL(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	keyFile, _ := hostKey(t)
	te := newTestEnv(t)
	if err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Token: "host-token",
		Principals: []string{"a.example.com"}, TTLDays: 30}); err != nil {
		t.Fatal(err)
	}
	if got := f.SignBodies()[0]["ttl_days"]; got != float64(30) {
		t.Errorf("sign request %v", f.SignBodies()[0])
	}
	if left := time.Until(time.Unix(int64(parseCert(t, strings.TrimSuffix(keyFile, ".pub")+"-cert.pub").ValidBefore), 0)); left > 30*24*time.Hour || left < 30*24*time.Hour-time.Minute {
		t.Errorf("valid for %v, asked for 30 days", left)
	}
	// without it the request has no ttl_days, and the tenant's lifetime applies
	if err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Token: "host-token", Principals: []string{"a.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.SignBodies()[1]["ttl_days"]; ok {
		t.Errorf("sign request %v", f.SignBodies()[1])
	}
	// the server's refusal is shown
	err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Token: "host-token", Principals: []string{"a.example.com"}, TTLDays: 365})
	if err == nil || !strings.Contains(err.Error(), "ttl_days") {
		t.Errorf("got %v", err)
	}
	if err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Token: "host-token", TTLDays: -1}); err == nil {
		t.Error("a negative ttl was accepted")
	}
}

func TestHostSignOptions(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	keyFile, _ := hostKey(t)

	t.Run("token and explicit principals", func(t *testing.T) {
		te := newTestEnv(t)
		err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Token: "host-token",
			Principals: []string{"db1.example.com", "db.example.com"}})
		if err != nil {
			t.Fatal(err)
		}
		cert := parseCert(t, strings.TrimSuffix(keyFile, ".pub")+"-cert.pub")
		if !slices.Equal(cert.ValidPrincipals, []string{"db.example.com", "db1.example.com"}) {
			t.Errorf("principals %v", cert.ValidPrincipals)
		}
	})
	t.Run("a principal outside the patterns shows the server's reason", func(t *testing.T) {
		te := newTestEnv(t)
		err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Token: "host-token", Principals: []string{"evil.test"}})
		if err == nil || !strings.Contains(err.Error(), `principal "evil.test" matches no host pattern`) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad secret", func(t *testing.T) {
		te := newTestEnv(t)
		err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, ClientID: f.ClientID, Secret: "wrong", Principals: []string{"a.example.com"}})
		if err == nil || !strings.Contains(err.Error(), "bad client credentials") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("rejected token", func(t *testing.T) {
		te := newTestEnv(t)
		err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Token: "stale", Principals: []string{"a.example.com"}})
		if err == nil || !strings.Contains(err.Error(), "access token") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no credentials", func(t *testing.T) {
		te := newTestEnv(t)
		if err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile}); err == nil {
			t.Fatal("no credentials accepted")
		}
	})
	t.Run("not a public key", func(t *testing.T) {
		te := newTestEnv(t)
		bad := filepath.Join(t.TempDir(), "x.pub")
		_ = os.WriteFile(bad, []byte("hello"), 0o644)
		if err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: bad, Token: "host-token"}); err == nil {
			t.Fatal("garbage accepted")
		}
	})
}

// The host's name: a dotted hostname is used as it is (lower case), a bare one is resolved, and an unresolvable one
// stays bare.
func TestFQDN(t *testing.T) {
	for _, c := range []struct {
		host, cname string
		lookupErr   bool
		want        string
	}{
		{"Db1.Example.COM.", "", false, "db1.example.com"},
		{"web1", "web1.example.com.", false, "web1.example.com"},
		{"web1", "web1", false, "web1"},
		{"web1", "", true, "web1"},
	} {
		e := &Env{Hostname: func() (string, error) { return c.host, nil },
			LookupCNAME: func(context.Context, string) (string, error) {
				if c.lookupErr {
					return "", errors.New("no such host")
				}
				return c.cname, nil
			}}
		if got, err := e.fqdn(context.Background()); err != nil || got != c.want {
			t.Errorf("%q: %q %v, want %q", c.host, got, err, c.want)
		}
	}
}
