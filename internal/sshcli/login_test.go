package sshcli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/sshcli/sshclitest"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func browse(f *sshclitest.Fake) func(string) error {
	return func(u string) error {
		go func() { _ = f.Browse(u) }()
		return nil
	}
}

// checkUserCert verifies a certificate as sshd would: signed by the CA, valid now, for the principal.
func checkUserCert(t *testing.T, f *sshclitest.Fake, c *ssh.Certificate, principal string) {
	t.Helper()
	chk := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		return string(k.Marshal()) == string(f.UserCA.PublicKey().Marshal())
	}}
	if err := chk.CheckCert(principal, c); err != nil {
		t.Fatalf("certificate for %s: %v", principal, err)
	}
}

// The browser flow end to end: the test is the browser. The certificate is added to the agent with a lifetime, the
// request carries PKCE, state, nonce, the acr and max_age of discovery, and no token is printed.
func TestLoginBrowserAgent(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	ag, sock := serveAgent(t)
	te := newTestEnv(t)
	te.AgentSock, te.OpenBrowser = sock, browse(f)

	if err := te.Login(context.Background(), LoginOptions{URL: f.URL}); err != nil {
		t.Fatalf("login: %v\n%s", err, te.err)
	}

	a := f.Auth()
	for k, want := range map[string]string{"response_type": "code", "client_id": "ssh-client", "scope": "openid profile",
		"code_challenge_method": "S256", "acr_values": "urn:quisora:acr:mfa", "max_age": "3600"} {
		if a.Get(k) != want {
			t.Errorf("authorization %s = %q, want %q", k, a.Get(k), want)
		}
	}
	if len(a.Get("state")) < 16 || len(a.Get("nonce")) < 16 || len(a.Get("code_challenge")) < 40 {
		t.Errorf("weak state, nonce or challenge: %v", a)
	}
	ru, _ := url.Parse(a.Get("redirect_uri"))
	if ru.Hostname() != "127.0.0.1" || ru.Path != "/callback" || ru.Port() == "" {
		t.Errorf("redirect_uri %s", a.Get("redirect_uri"))
	}

	keys, err := ag.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("agent keys: %v %v", keys, err)
	}
	if keys[0].Comment != "quisora:acme/prod" || !strings.HasSuffix(keys[0].Format, "-cert-v01@openssh.com") {
		t.Fatalf("agent key: %s %s", keys[0].Format, keys[0].Comment)
	}
	pub, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	cert := pub.(*ssh.Certificate)
	checkUserCert(t, f, cert, "paul")
	checkUserCert(t, f, cert, "ops")
	if len(ag.lifetimes) != 1 || ag.lifetimes[0] < 8*3600-60 || ag.lifetimes[0] > 8*3600 {
		t.Errorf("agent lifetime %v: want the certificate's remaining 8 h", ag.lifetimes)
	}
	mustContain(t, "output", te.out.String(), "acme/prod", "ops, paul", "Added to ssh-agent")
	mustNotContain(t, "output", te.out.String()+te.err.String(), "user-token", "PRIVATE KEY")

	// the public key and the certificate are also in the Quisora directory, with no private key, so that ~/.ssh/config can
	// name them (IdentityFile <path>.pub, CertificateFile <path>-cert.pub, IdentitiesOnly yes)
	base := filepath.Join(te.Dir, "acme-prod")
	if got := parseCert(t, base+"-cert.pub"); string(got.Marshal()) != string(cert.Marshal()) {
		t.Error("the certificate file is not the one in the agent")
	}
	if b, _ := os.ReadFile(base + ".pub"); string(b) != string(ssh.MarshalAuthorizedKey(cert.Key)) {
		t.Errorf("the public key file: %q", b)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Errorf("a private key was written beside a key in the agent: %v", err)
	}
	mustContain(t, "output", te.out.String(), base+".pub", base+"-cert.pub", "IdentitiesOnly yes")

	// a second login replaces the first certificate of the tenant
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL}); err != nil {
		t.Fatal(err)
	}
	if keys, _ = ag.List(); len(keys) != 1 {
		t.Fatalf("after a second login the agent holds %d keys", len(keys))
	}

	// status lists it, logout removes it
	te.out.b.Reset()
	if err := te.Status(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "status", te.out.String(), "agent", "quisora:acme/prod", "ops,paul", "left)", "file (no key)", base+"-cert.pub")
	te.out.b.Reset()
	if err := te.Logout(context.Background(), f.URL); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "logout", te.out.String(), "Removed 1 from ssh-agent and 1 from "+te.Dir)
	for _, p := range []string{base + ".pub", base + "-cert.pub"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived logout", p)
		}
	}
	if keys, _ = ag.List(); len(keys) != 0 {
		t.Fatalf("logout left %d keys", len(keys))
	}
	te.out.b.Reset()
	if err := te.Status(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "status", te.out.String(), "No Quisora certificates.")
}

// Logout with a URL removes that tenant's certificates only, without one all of Quisora's; keys that are not
// Quisora's are left alone.
func TestLogoutScope(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	ag, sock := serveAgent(t)
	te := newTestEnv(t)
	te.AgentSock, te.OpenBrowser = sock, browse(f)
	_, mine, _ := ed25519.GenerateKey(rand.Reader)
	if err := ag.Add(agent.AddedKey{PrivateKey: mine, Comment: "mine"}); err != nil {
		t.Fatal(err)
	}
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL}); err != nil {
		t.Fatal(err)
	}
	// a certificate of another tenant
	op, other, _ := ed25519.GenerateKey(rand.Reader)
	opub, _ := ssh.NewPublicKey(op)
	cert := &ssh.Certificate{Key: opub, CertType: ssh.UserCert, ValidPrincipals: []string{"x"}, ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
	if err := cert.SignCert(rand.Reader, f.UserCA); err != nil {
		t.Fatal(err)
	}
	if err := ag.Add(agent.AddedKey{PrivateKey: other, Certificate: cert, Comment: "quisora:other/dev"}); err != nil {
		t.Fatal(err)
	}

	if err := te.Logout(context.Background(), f.URL); err != nil {
		t.Fatal(err)
	}
	comments := func() []string {
		keys, _ := ag.List()
		var out []string
		for _, k := range keys {
			out = append(out, k.Comment)
		}
		slices.Sort(out)
		return out
	}
	if got := comments(); !slices.Equal(got, []string{"mine", "quisora:other/dev"}) {
		t.Fatalf("after logout of acme/prod the agent holds %v", got)
	}
	if err := te.Logout(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got := comments(); !slices.Equal(got, []string{"mine"}) {
		t.Fatalf("after logout of everything the agent holds %v", got)
	}
}

// The browser flow refuses a stray request, a wrong nonce, a refusal, and gives up after the timeout.
func TestLoginBrowserFailures(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()

	t.Run("stray callback is ignored", func(t *testing.T) {
		te := newTestEnv(t)
		te.OpenBrowser = func(u string) error {
			go func() {
				au, _ := url.Parse(u)
				redirect, _ := url.Parse(au.Query().Get("redirect_uri"))
				resp, err := http.Get(redirect.String() + "?code=x&state=wrong")
				if err == nil {
					if resp.StatusCode != http.StatusBadRequest {
						t.Errorf("stray callback answered %d", resp.StatusCode)
					}
					resp.Body.Close()
				}
				_ = f.Browse(u)
			}()
			return nil
		}
		if err := te.Login(context.Background(), LoginOptions{URL: f.URL}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		f.WrongNonce = true
		defer func() { f.WrongNonce = false }()
		te := newTestEnv(t)
		te.OpenBrowser = browse(f)
		err := te.Login(context.Background(), LoginOptions{URL: f.URL})
		if err == nil || !strings.Contains(err.Error(), "nonce") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("refused in the browser", func(t *testing.T) {
		te := newTestEnv(t)
		te.OpenBrowser = func(u string) error {
			go func() {
				au, _ := url.Parse(u)
				q := au.Query()
				back := url.Values{"error": {"access_denied"}, "error_description": {"a second factor is required"}, "state": {q.Get("state")}}
				if resp, err := http.Get(q.Get("redirect_uri") + "?" + back.Encode()); err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		}
		err := te.Login(context.Background(), LoginOptions{URL: f.URL})
		if err == nil || !strings.Contains(err.Error(), "a second factor is required") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		te := newTestEnv(t)
		te.Timeout = 100 * time.Millisecond
		te.OpenBrowser = func(string) error { return nil }
		err := te.Login(context.Background(), LoginOptions{URL: f.URL})
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a principal the user may not have", func(t *testing.T) {
		te := newTestEnv(t)
		te.OpenBrowser = browse(f)
		err := te.Login(context.Background(), LoginOptions{URL: f.URL, Principals: []string{"root"}})
		if err == nil || !strings.Contains(err.Error(), `principal "root" is not allowed`) {
			t.Fatalf("the server's error_description is not shown: %v", err)
		}
	})
}

// --no-browser prints the URL and does not open anything.
func TestLoginNoBrowser(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	te.OpenBrowser = func(string) error { t.Error("the browser was opened"); return nil }
	done := make(chan error, 1)
	go func() { done <- te.Login(context.Background(), LoginOptions{URL: f.URL, NoBrowser: true}) }()
	var authURL string
	for range 200 {
		for _, l := range strings.Fields(te.err.String()) {
			if strings.Contains(l, "/authorize?") {
				authURL = l
			}
		}
		if authURL != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if authURL == "" {
		t.Fatalf("no URL printed:\n%s", te.err)
	}
	if err := f.Browse(authURL); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// With --key the certificate is made for that key and written next to it; the agent is not used. A principal subset
// and a TTL are passed on.
func TestLoginKeyFile(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	ag, sock := serveAgent(t)
	te := newTestEnv(t)
	te.AgentSock, te.OpenBrowser = sock, browse(f)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key := filepath.Join(t.TempDir(), "id_work")
	if err := os.WriteFile(key+".pub", ssh.MarshalAuthorizedKey(sp), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Key: key, Principals: []string{"ops"}, TTL: time.Hour}); err != nil {
		t.Fatalf("login: %v\n%s", err, te.err)
	}
	cert := parseCert(t, key+"-cert.pub")
	checkUserCert(t, f, cert, "ops")
	if string(cert.Key.Marshal()) != string(sp.Marshal()) {
		t.Error("the certificate is for another key")
	}
	if !slices.Equal(cert.ValidPrincipals, []string{"ops"}) {
		t.Errorf("principals %v", cert.ValidPrincipals)
	}
	if left := time.Until(time.Unix(int64(cert.ValidBefore), 0)); left > time.Hour || left < time.Hour-time.Minute {
		t.Errorf("valid for %s, asked for 1h", left)
	}
	body := f.SignBodies()[0]
	if body["ttl"] != float64(3600) || body["principals"].([]any)[0] != "ops" {
		t.Errorf("sign request %v", body)
	}
	if keys, _ := ag.List(); len(keys) != 0 {
		t.Error("the agent was used with --key")
	}
	if out := keygenL(t, key+"-cert.pub"); out != "" {
		mustContain(t, "ssh-keygen -L", out, "user certificate", "Principals:", "ops", "permit-pty")
	}
	// the .pub name works too
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Key: key + ".pub"}); err != nil {
		t.Fatal(err)
	}
	// a missing key
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Key: key + "_nope"}); err == nil {
		t.Error("a missing key was accepted")
	}
}

// The device flow: pending, slow_down (five seconds more), then success; without an agent the key and certificate are
// written to the Quisora directory, which ssh-keygen and x/crypto read.
func TestLoginDeviceFiles(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.SetDeviceAnswers("authorization_pending", "slow_down", "ok")
	te := newTestEnv(t)
	te.OpenBrowser = func(string) error { t.Error("the browser was opened"); return nil }

	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true}); err != nil {
		t.Fatalf("login: %v\n%s", err, te.err)
	}
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}
	if got := te.slept(); !slices.Equal(got, want) {
		t.Errorf("poll waits %v, want %v", got, want)
	}
	mustContain(t, "progress", te.err.String(), "WDJB-MJHT", "/device/verify?user_code=WDJB-MJHT", "no ssh-agent")
	mustNotContain(t, "progress", te.out.String()+te.err.String(), "user-token", "device_code")
	forms := f.TokenForms()
	if len(forms) != 3 || forms[0].Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || forms[0].Get("client_id") != "ssh-client" {
		t.Errorf("token requests %v", forms)
	}

	base := filepath.Join(te.Dir, "acme-prod")
	st, err := os.Stat(base)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("private key: %v %v", st, err)
	}
	if st, _ = os.Stat(te.Dir); st.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", st.Mode().Perm())
	}
	for _, p := range []string{base + ".pub", base + "-cert.pub"} {
		if st, err = os.Stat(p); err != nil || st.Mode().Perm() != 0o644 {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	pemBytes, _ := os.ReadFile(base)
	if blk, _ := pem.Decode(pemBytes); blk == nil || blk.Type != "OPENSSH PRIVATE KEY" {
		t.Fatalf("private key is not in OpenSSH format: %s", pemBytes[:min(40, len(pemBytes))])
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, base+"-cert.pub")
	checkUserCert(t, f, cert, "paul")
	if string(cert.Key.Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Error("the certificate is not for the written key")
	}
	if out := keygenL(t, base+"-cert.pub"); out != "" {
		mustContain(t, "ssh-keygen -L", out, "user certificate", "paul", "ops", "Signing CA: ED25519")
	}
	mustContain(t, "output", te.out.String(), "ssh -i "+base)

	// status shows the file, logout removes the three files
	te.out.b.Reset()
	if err := te.Status(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "status", te.out.String(), "file", base+"-cert.pub", "ops,paul")
	if err := te.Logout(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{base, base + ".pub", base + "-cert.pub"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived logout", p)
		}
	}
}

func TestLoginDeviceFailures(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	for answer, want := range map[string]string{"access_denied": "was refused", "expired_token": "expired"} {
		f.SetDeviceAnswers("authorization_pending", answer)
		te := newTestEnv(t)
		err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", answer, err, want)
		}
		if _, err := os.Stat(te.Dir); err == nil {
			t.Errorf("%s: files were written", answer)
		}
	}
}

// An agent that cannot be reached falls back to files, with a warning.
func TestLoginAgentUnreachable(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	te.AgentSock = filepath.Join(t.TempDir(), "gone.sock")
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "warning", te.err.String(), "no ssh-agent", "writing the key to a file")
	if _, err := os.Stat(filepath.Join(te.Dir, "acme-prod-cert.pub")); err != nil {
		t.Error(err)
	}
}

// The key a login without an agent left is not the key of a login with one: the later login removes it, so that ssh
// does not pair the new certificate with the old private key.
func TestLoginAgentRemovesAStaleKeyFile(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.SetDeviceAnswers("ok", "ok")
	te := newTestEnv(t)
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true}); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(te.Dir, "acme-prod")
	if _, err := os.Stat(base); err != nil {
		t.Fatal(err)
	}
	_, te.AgentSock = serveAgent(t)
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Errorf("the private key of the earlier login is still beside the new certificate: %v", err)
	}
	if _, err := os.Stat(base + "-cert.pub"); err != nil {
		t.Error(err)
	}
}

// An agent that does not take the key (it is locked, or keeps its keys to itself) does not cost the user the certificate
// they signed in for: it is written, with the key, to files, with a warning.
func TestLoginAgentRefusesTheKey(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	for name, setup := range map[string]func(t *testing.T) string{
		"locked": func(t *testing.T) string {
			ag, sock := serveAgent(t)
			if err := ag.Lock([]byte("pw")); err != nil {
				t.Fatal(err)
			}
			return sock
		},
		"refusing": func(t *testing.T) string { return serveAgentOf(t, refusingAgent{agent.NewKeyring()}) },
	} {
		t.Run(name, func(t *testing.T) {
			te := newTestEnv(t)
			te.AgentSock, te.OpenBrowser = setup(t), browse(f)
			if err := te.Login(context.Background(), LoginOptions{URL: f.URL}); err != nil {
				t.Fatalf("login: %v\n%s", err, te.err)
			}
			mustContain(t, "warning", te.err.String(), "ssh-agent did not take the key", "writing the key to a file instead")
			base := filepath.Join(te.Dir, "acme-prod")
			signer, err := ssh.ParsePrivateKey([]byte(read(t, base)))
			if err != nil {
				t.Fatal(err)
			}
			cert := parseCert(t, base+"-cert.pub")
			checkUserCert(t, f, cert, "paul")
			if string(cert.Key.Marshal()) != string(signer.PublicKey().Marshal()) {
				t.Error("the certificate is not for the written key")
			}
			mustContain(t, "output", te.out.String(), "ssh -i "+base)
			mustNotContain(t, "output", te.out.String(), "Added to ssh-agent")
		})
	}
}

// --no-agent writes the files and leaves the agent alone, with nothing to warn about.
func TestLoginNoAgent(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	ag, sock := serveAgent(t)
	te := newTestEnv(t)
	te.AgentSock, te.OpenBrowser = sock, browse(f)
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, NoAgent: true}); err != nil {
		t.Fatalf("login: %v\n%s", err, te.err)
	}
	if keys, _ := ag.List(); len(keys) != 0 {
		t.Errorf("the agent holds %d keys", len(keys))
	}
	base := filepath.Join(te.Dir, "acme-prod")
	for _, p := range []string{base, base + ".pub", base + "-cert.pub"} {
		if _, err := os.Stat(p); err != nil {
			t.Error(err)
		}
	}
	mustNotContain(t, "stderr", te.err.String(), "warning", "ssh-agent")
	mustContain(t, "output", te.out.String(), "ssh -i "+base)
}

// On Windows the agent is a named pipe, not a socket: the key is kept in files, and nothing is said of SSH_AUTH_SOCK, an
// agent to start or eval; the agent in SSH_AUTH_SOCK (there is none on Windows, so a test's) is not touched.
func TestLoginWindows(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	ag, sock := serveAgent(t)
	te := newTestEnv(t)
	te.GOOS, te.AgentSock, te.OpenBrowser = "windows", sock, browse(f)
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL}); err != nil {
		t.Fatalf("login: %v\n%s", err, te.err)
	}
	if keys, _ := ag.List(); len(keys) != 0 {
		t.Errorf("the agent holds %d keys", len(keys))
	}
	base := filepath.Join(te.Dir, "acme-prod")
	for _, p := range []string{base, base + ".pub", base + "-cert.pub"} {
		if _, err := os.Stat(p); err != nil {
			t.Error(err)
		}
	}
	all := te.out.String() + te.err.String()
	mustContain(t, "output", all, "are in "+base+", "+base+".pub and "+base+"-cert.pub", "ssh-agent is not used on Windows", "ssh -i "+base)
	mustNotContain(t, "output", all, "SSH_AUTH_SOCK", "eval", "no ssh-agent", "warning", "{")

	te.out.b.Reset()
	if err := te.Status(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "status", te.out.String(), "file", base+"-cert.pub")
	mustNotContain(t, "status", te.out.String()+te.err.String(), "agent", "warning")
	te.out.b.Reset()
	if err := te.Logout(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "logout", te.out.String(), "Removed 1 from "+te.Dir)
	mustNotContain(t, "logout", te.out.String()+te.err.String(), "agent", "warning")
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Error("logout left the key")
	}
}

// The server signs certificates of 60 seconds to the tenant's lifetime: a shorter --ttl is refused before anything is
// asked of the server.
func TestLoginRefusesATTLUnderAMinute(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	for _, ttl := range []time.Duration{time.Second, 59 * time.Second, -time.Minute} {
		err := te.Login(context.Background(), LoginOptions{URL: f.URL, TTL: ttl})
		if err == nil || !strings.Contains(err.Error(), "at least 60 seconds") {
			t.Errorf("ttl %v: %v", ttl, err)
		}
	}
	if p := f.Paths(); len(p) != 0 {
		t.Errorf("the server was asked: %v", p)
	}
}

// A tenant whose SSH is turned off says so in its discovery document: login stops with that said, and signs in to nothing.
func TestLoginWhileSSHIsOff(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.Off = true
	te := newTestEnv(t)
	te.OpenBrowser = func(string) error { t.Error("the browser was opened"); return nil }
	for _, device := range []bool{false, true} {
		err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: device})
		if err == nil || !strings.Contains(err.Error(), "SSH certificates are turned off for the tenant acme/prod") {
			t.Errorf("device %v: %v", device, err)
		}
	}
	for _, p := range f.Paths() {
		if p != "GET /o/org1/ssh/prod" {
			t.Errorf("a request after discovery: %s", p)
		}
	}
	keyFile, _ := hostKey(t)
	err := te.HostSign(context.Background(), HostSignOptions{URL: f.URL, KeyFile: keyFile, Token: "t"})
	if err == nil || !strings.Contains(err.Error(), "turned off") {
		t.Errorf("host-sign: %v", err)
	}
}

// The device authorization request carries what the browser flow's does: the acr_values and max_age of the tenant, so a
// password-only or an old sign-in is asked to step up.
func TestLoginDeviceAsksForTheTenantsSignInTerms(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.SetDeviceAnswers("ok")
	te := newTestEnv(t)
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true}); err != nil {
		t.Fatalf("login: %v\n%s", err, te.err)
	}
	forms := f.DeviceForms()
	if len(forms) != 1 || forms[0].Get("acr_values") != "urn:quisora:acr:mfa" || forms[0].Get("max_age") != "3600" {
		t.Errorf("device authorization request: %v", forms)
	}
}

// A poll that gets no answer, or a 5xx from a proxy, does not end the sign-in the user is in the middle of approving:
// the code is still good, so it is asked again, further apart each time, and the wait starts over once the server
// answers.
func TestLoginDeviceRetriesTransientErrors(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.SetDeviceAnswers("server_error", "hangup", "authorization_pending", "server_error", "ok")
	te := newTestEnv(t)
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true}); err != nil {
		t.Fatalf("login: %v\n%s", err, te.err)
	}
	s := time.Second
	if got, want := te.slept(), []time.Duration{5 * s, 10 * s, 20 * s, 5 * s, 10 * s}; !slices.Equal(got, want) {
		t.Errorf("poll waits %v, want %v", got, want)
	}
	if n := strings.Count(te.err.String(), "did not answer"); n != 2 {
		t.Errorf("%d warnings, want one for each run of failures:\n%s", n, te.err)
	}
}

// What never ends is bounded by the code's lifetime; the answers about the code do end the sign-in at once.
func TestLoginDeviceTransientErrorsEndWithTheCode(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.Fail["token"] = http.StatusServiceUnavailable
	te := newTestEnv(t)
	start := time.Now()
	te.Now = func() time.Time {
		var total time.Duration
		for _, d := range te.slept() {
			total += d
		}
		return start.Add(total)
	}
	err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true})
	if err == nil || !strings.Contains(err.Error(), "expired before it was approved") {
		t.Fatalf("got %v", err)
	}
	polls := 0
	for _, p := range f.Paths() {
		if p == "POST /token" {
			polls++
		}
	}
	if polls < 5 || polls > 20 {
		t.Errorf("%d polls before the code (600 s) expired", polls)
	}
	for _, d := range te.slept() {
		if d > time.Minute {
			t.Errorf("a wait of %v: the backoff is capped at a minute", d)
		}
	}

	f.Fail = map[string]int{}
	f.SetDeviceAnswers("bogus_error")
	te = newTestEnv(t)
	if err := te.Login(context.Background(), LoginOptions{URL: f.URL, Device: true}); err == nil || !strings.Contains(err.Error(), "bogus_error") {
		t.Errorf("an error answer about the code went on: %v", err)
	}
	if n := len(te.slept()); n != 1 {
		t.Errorf("%d polls after an answer that is not transient", n)
	}
}
