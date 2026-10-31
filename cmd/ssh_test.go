package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/sshcli/sshclitest"
	"golang.org/x/crypto/ssh"
)

// sshEnv is a throwaway installation whose configuration is unusable: the ssh commands must not read it.
func brokenConfigEnv(t *testing.T) env {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	e := newEnv(t, "")
	if err := os.WriteFile(e.conf, []byte("[server]\nmaster_key = \"not a key\"\nlisten = \"bad\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func writePub(t *testing.T, name string) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(sp), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, sp
}

// ssh login --device with --key, status and logout, run through the command tree with a configuration that would
// fail validation: no config file, master key or store is needed.
func TestSSHLoginDevice(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.Interval = 1
	e := brokenConfigEnv(t)
	pubFile, pub := writePub(t, "id_work.pub")
	key := strings.TrimSuffix(pubFile, ".pub")

	out, errOut, err := e.run(t, "", "ssh", "login", "--device", "--key", key, "--principal", "ops", "--ttl", "2h", f.URL)
	if err != nil {
		t.Fatalf("login: %v\n%s", err, errOut)
	}
	mustContain(t, "stdout", out, "Signed in to acme/prod", "Principals: ops", key+"-cert.pub")
	mustContain(t, "stderr", errOut, "WDJB-MJHT")
	if strings.Contains(out+errOut, "user-token") {
		t.Error("a token was printed")
	}
	b := mustRead(t, key+"-cert.pub")
	got, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	cert := got.(*ssh.Certificate)
	if string(cert.Key.Marshal()) != string(pub.Marshal()) || !slices.Equal(cert.ValidPrincipals, []string{"ops"}) {
		t.Errorf("certificate %v", cert.ValidPrincipals)
	}
	if body := f.SignBodies()[0]; body["ttl"] != float64(7200) {
		t.Errorf("ttl %v", body["ttl"])
	}

	// without --key and without an agent: files under ~/.ssh/quisora (HOME is the test's directory)
	if _, errOut, err = e.run(t, "", "ssh", "login", "--device", f.URL); err != nil {
		t.Fatalf("login: %v\n%s", err, errOut)
	}
	files := filepath.Join(e.dir, ".ssh", "quisora", "acme-prod")
	pemBytes := mustRead(t, files)
	if blk, _ := pem.Decode(pemBytes); blk == nil || blk.Type != "OPENSSH PRIVATE KEY" {
		t.Error("no OpenSSH private key written")
	}
	out, _, err = e.run(t, "", "ssh", "status")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "status", out, "file", "acme-prod-cert.pub", "ops,paul")
	out, _, err = e.run(t, "", "ssh", "logout", f.URL)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "logout", out, "from "+filepath.Join(e.dir, ".ssh", "quisora"))
	if _, err := os.Stat(files); !os.IsNotExist(err) {
		t.Error("logout left the key")
	}
}

func TestSSHHostSign(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	e := brokenConfigEnv(t)
	keyFile, _ := writePub(t, "ssh_host_ed25519_key.pub")
	t.Setenv("QUISORA_CLIENT_SECRET", f.ClientSecret)

	out, errOut, err := e.run(t, "", "ssh", "host-sign", "--client-id", f.ClientID, "--principal", "a.example.com", "--principal", "b.example.com", f.URL, keyFile)
	if err != nil {
		t.Fatalf("host-sign: %v\n%s", err, errOut)
	}
	certFile := strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"
	if strings.TrimSpace(out) != "HostCertificate "+certFile {
		t.Errorf("stdout %q", out)
	}
	got, _, _, _, err := ssh.ParseAuthorizedKey(mustRead(t, certFile))
	if err != nil {
		t.Fatal(err)
	}
	if c := got.(*ssh.Certificate); c.CertType != ssh.HostCert || !slices.Equal(c.ValidPrincipals, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("certificate %d %v", c.CertType, c.ValidPrincipals)
	}

	// the default is --auth-method auto: a service account registered for client_secret_basic works as well, and --auth-method
	// picks the one method; --ttl is days
	f.AuthMethod = "basic"
	n := len(f.TokenMethods())
	if _, errOut, err = e.run(t, "", "ssh", "host-sign", "--client-id", f.ClientID, "--principal", "a.example.com", "--ttl", "30d", f.URL, keyFile); err != nil {
		t.Fatalf("host-sign against a client_secret_basic account: %v\n%s", err, errOut)
	}
	if got := f.TokenMethods()[n:]; !slices.Equal(got, []string{"post", "basic"}) {
		t.Errorf("auto tried %v", got)
	}
	if body := f.SignBodies()[len(f.SignBodies())-1]; body["ttl_days"] != float64(30) {
		t.Errorf("sign request %v", body)
	}
	n = len(f.TokenMethods())
	if _, errOut, err = e.run(t, "", "ssh", "host-sign", "--client-id", f.ClientID, "--auth-method", "basic", "--principal", "a.example.com", f.URL, keyFile); err != nil {
		t.Fatalf("--auth-method basic: %v\n%s", err, errOut)
	}
	if got := f.TokenMethods()[n:]; !slices.Equal(got, []string{"basic"}) {
		t.Errorf("--auth-method basic made %v", got)
	}
	if _, _, err = e.run(t, "", "ssh", "host-sign", "--client-id", f.ClientID, "--auth-method", "post", "--principal", "a.example.com", f.URL, keyFile); err == nil {
		t.Error("--auth-method post worked for a client_secret_basic account")
	}
	f.AuthMethod = "post"

	// a token from the environment
	t.Setenv("QUISORA_CLIENT_SECRET", "")
	t.Setenv("QUISORA_TOKEN", "host-token")
	if _, errOut, err = e.run(t, "", "ssh", "host-sign", "--principal", "c.example.com", f.URL, keyFile); err != nil {
		t.Fatalf("host-sign with a token: %v\n%s", err, errOut)
	}
	// no credentials at all
	t.Setenv("QUISORA_TOKEN", "")
	if _, _, err = e.run(t, "", "ssh", "host-sign", f.URL, keyFile); err == nil || !strings.Contains(err.Error(), "--token") {
		t.Errorf("no credentials: %v", err)
	}
}

func TestSSHFetch(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	e := brokenConfigEnv(t)
	d := t.TempDir()
	ca, krl, hosts := filepath.Join(d, "ca.pub"), filepath.Join(d, "q.krl"), filepath.Join(d, "known_hosts")

	out, errOut, err := e.run(t, "", "ssh", "fetch", "--ca-file", ca, "--krl-file", krl, "--known-hosts-file", hosts, f.URL)
	if err != nil {
		t.Fatalf("fetch: %v\n%s", err, errOut)
	}
	mustContain(t, "stdout", out, "updated "+ca, "updated "+krl, "updated "+hosts)
	old := string(mustRead(t, ca))

	// a failing server: exit status non-zero (the error is returned), files kept
	f.Fail["krl"] = 500
	f.Body["ca.pub"] = []byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshclitest.New().UserCA.PublicKey()))) + "\n")
	if _, _, err = e.run(t, "", "ssh", "fetch", "--ca-file", ca, "--krl-file", krl, f.URL); err == nil {
		t.Fatal("fetch succeeded against a failing server")
	}
	if string(mustRead(t, ca)) != old {
		t.Error("the CA file changed")
	}
	// a missing argument
	if _, _, err = e.run(t, "", "ssh", "fetch"); err == nil {
		t.Error("fetch without a URL succeeded")
	}
}

func TestSSHTLSFlags(t *testing.T) {
	f := sshclitest.NewTLS()
	defer f.Close()
	e := brokenConfigEnv(t)
	d := t.TempDir()
	ca, krl := filepath.Join(d, "ca.pub"), filepath.Join(d, "q.krl")
	args := []string{"ssh", "fetch", "--ca-file", ca, "--krl-file", krl}
	if _, _, err := e.run(t, "", append(args, f.URL)...); err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
	pemFile := filepath.Join(d, "server.pem")
	_ = os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw}), 0o644)
	if _, _, err := e.run(t, "", append(args, "--ca-cert", pemFile, f.URL)...); err != nil {
		t.Fatalf("--ca-cert: %v", err)
	}
	_ = os.Remove(ca)
	if _, errOut, err := e.run(t, "", append(args, "--insecure", f.URL)...); err != nil || !strings.Contains(errOut, "not verified") {
		t.Fatalf("--insecure: %v %q", err, errOut)
	}
}

func TestSSHBadArguments(t *testing.T) {
	e := brokenConfigEnv(t)
	for _, args := range [][]string{
		{"ssh", "login", "--ttl", "soon", "https://x.invalid/o/a/ssh/b"},
		{"ssh", "login", "--ttl", "0", "https://x.invalid/o/a/ssh/b"},
		{"ssh", "login", "--ttl", "30s", "https://x.invalid/o/a/ssh/b"}, // the server signs for 60 seconds at least
		{"ssh", "login", "--device", "--no-browser", "https://x.invalid/o/a/ssh/b"},
		{"ssh", "login"},
		{"ssh", "host-sign", "https://x.invalid/o/a/ssh/b"},
		{"ssh", "host-sign", "--token", "t", "--ttl", "0", "https://x.invalid/o/a/ssh/b", "k.pub"},
		{"ssh", "host-sign", "--token", "t", "--ttl", "36h", "https://x.invalid/o/a/ssh/b", "k.pub"},
		{"ssh", "host-sign", "--token", "t", "--auth-method", "jwt", "https://x.invalid/o/a/ssh/b", "k.pub"},
	} {
		if _, _, err := e.run(t, "", args...); err == nil {
			t.Errorf("%v succeeded", args)
		}
	}
	// the group alone shows its help
	out, _, err := e.run(t, "", "ssh")
	if err != nil || !strings.Contains(out, "host-sign") {
		t.Errorf("help: %v\n%s", err, out)
	}
}

func TestParseTTL(t *testing.T) {
	for _, in := range []string{"1", "59", "59s", "0", "-5m", "soon"} {
		if _, err := parseTTL(in); err == nil || !strings.Contains(err.Error(), "at least 60 seconds") {
			t.Errorf("%q: %v", in, err)
		}
	}
	for in, want := range map[string]int{"": 0, "2h": 7200, "90m": 5400, "3600": 3600, "60": 60, "1m": 60} {
		if d, err := parseTTL(in); err != nil || int(d.Seconds()) != want {
			t.Errorf("%q: %v %v", in, d, err)
		}
	}
}

func TestParseHostTTL(t *testing.T) {
	for _, in := range []string{"0", "0d", "-1", "-3d", "1.5d", "36h", "90m", "soon", "d", "366", "400d"} {
		if _, err := parseHostTTL(in); err == nil || !strings.Contains(err.Error(), "whole number of days") {
			t.Errorf("%q: %v", in, err)
		}
	}
	for in, want := range map[string]int{"": 0, "1": 1, "30": 30, "30d": 30, "90d": 90, "48h": 2, "2160h": 90, "365": 365} {
		if d, err := parseHostTTL(in); err != nil || d != want {
			t.Errorf("%q: %v %v", in, d, err)
		}
	}
}

// --no-agent writes the files without looking for an agent: no warning that there is none (without the flag there is
// one when SSH_AUTH_SOCK is not set).
func TestSSHLoginNoAgent(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.Interval = 1
	e := brokenConfigEnv(t)
	_, errOut, err := e.run(t, "", "ssh", "login", "--device", f.URL)
	if err != nil || !strings.Contains(errOut, "warning: no ssh-agent") {
		t.Fatalf("login: %v\n%s", err, errOut)
	}
	_, errOut, err = e.run(t, "", "ssh", "login", "--device", "--no-agent", f.URL)
	if err != nil || strings.Contains(errOut, "warning") {
		t.Fatalf("login --no-agent: %v\n%s", err, errOut)
	}
	mustRead(t, filepath.Join(e.dir, ".ssh", "quisora", "acme-prod"))
}

func mustContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s lacks %q:\n%s", what, sub, s)
		}
	}
}
