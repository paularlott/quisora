package sshe2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/sshcli"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

const (
	hostName    = "sshd.e2e.test" // the name the host certificate is for, and the client connects as (HostKeyAlias)
	hostPattern = "*.e2e.test"    // the tenant's host patterns
)

// What sshd logs when the certificate is fine (its authority is trusted, it is not revoked, it is in date) and the
// account does not list a principal of it, and when the key revocation list has it.
const noPrincipal = "Certificate does not contain an authorized principal"

// mfaAMR is how the test's browser signs in: a password, a one-time code and the second factor they make.
var mfaAMR = []string{"pwd", "otp", "mfa"}

func ptr[T any](v T) *T { return &v }

// fixture is a Quisora with SSH on for a tenant, a real sshd that trusts it, and a client's files.
type fixture struct {
	t     *testing.T
	env   *webtest.Env
	p     *oidc.Provider
	admin *service.Actor
	tn    *model.Tenant
	httpc *http.Client // the client the CLI code uses: trusts the test server's certificate

	alice, bob *model.User
	ops        *model.Group

	discovery  string // the tenant's discovery URL, which `quisora ssh` is given
	clientDir  string // keys and certificates of the test's user
	trustDir   string // what `quisora ssh fetch` writes: the server's trust files
	caFile     string
	krlFile    string
	knownHosts string // the client's known_hosts: only the @cert-authority line
	keys       int

	sshd *sshd
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{t: t}

	// Quisora: the OIDC provider (the SSH application's sign-in) and the management API (host certificates).
	var mod *admin.Module
	f.env = webtest.New(t, webtest.Options{Modules: func(s *web.Server) []web.Module {
		f.p = oidc.New(s)
		mod = admin.New()
		return []web.Module{f.p, mod}
	}})
	env := f.env
	f.httpc = &http.Client{Timeout: 30 * time.Second, Transport: env.HTTP.Client().Transport}
	// the management API takes the access token of a service account (what app.bearer does)
	env.Server.Bearer = func(ctx context.Context, r *http.Request, tok string) (*service.Actor, error) {
		cl, err := f.p.VerifyRequestToken(r, "Bearer", tok)
		if err != nil {
			return nil, err
		}
		if cl.ClientID == "" || cl.Sub != cl.ClientID {
			return nil, service.ErrBadToken
		}
		c, err := env.Svc.Clients.Get(ctx, cl.ClientID)
		if err != nil || !c.Enabled || !c.ServiceAccount {
			return nil, service.ErrBadToken
		}
		return service.ActorForServiceAccount(c, strings.Fields(cl.Scope), web.ClientIP(r)), nil
	}
	f.admin = service.ActorForUser(env.Admin, "")

	mkUser := func(name string) *model.User {
		pw := "correct horse battery"
		u, err := env.Svc.CreateUser(ctx, service.System, env.Primary.ID, service.UserInput{Username: ptr(name),
			Email: ptr(name + "@example.com"), Password: &pw, GivenName: ptr(name), FamilyName: ptr("T"), Verified: ptr(true)})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	f.alice, f.bob = mkUser("alice"), mkUser("bob")
	var err error
	if f.ops, err = env.Svc.CreateGroupWithMembers(ctx, f.admin, env.Primary.ID, service.GroupInput{DisplayName: ptr("ops")},
		[]string{f.alice.ID}); err != nil {
		t.Fatal(err)
	}

	// The tenant, open to everyone, with SSH on: principals are the username and "group:<name>" for each group; host
	// certificates for *.e2e.test.
	tn, err := env.Svc.CreateTenant(ctx, f.admin, env.Primary.ID, service.TenantInput{Name: ptr("prod"),
		Settings: &model.TenantSettings{PasswordLogin: true, PasskeyLogin: true, AllProviders: true}})
	if err != nil {
		t.Fatal(err)
	}
	if f.tn, err = env.Svc.UpdateTenantSSH(ctx, f.admin, tn.ID, service.SSHSettingsInput{Enabled: ptr(true),
		PrincipalUsername: ptr(true), PrincipalGroups: ptr(true),
		HostCerts: ptr(true), HostPatterns: &[]string{hostPattern}}); err != nil {
		t.Fatal(err)
	}
	f.discovery = env.URL + web.OrgPath(env.Primary.ID, "/ssh/"+f.tn.ID)

	root := t.TempDir()
	f.clientDir, f.trustDir = filepath.Join(root, "client"), filepath.Join(root, "trust")
	for _, d := range []string{f.clientDir, f.trustDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.caFile, f.krlFile = filepath.Join(f.trustDir, "quisora_user_ca.pub"), filepath.Join(f.trustDir, "quisora.krl")
	f.knownHosts = filepath.Join(f.trustDir, "known_hosts")

	// What a server's timer runs: `quisora ssh fetch`.
	out := f.fetch()
	for _, p := range []string{f.caFile, f.krlFile, f.knownHosts} {
		if !strings.Contains(out, "updated "+p) {
			t.Fatalf("the first fetch did not write %s:\n%s", p, out)
		}
	}
	if again := f.fetch(); again != "" {
		t.Fatalf("a second fetch changed files that were current:\n%s", again)
	}

	// The host's key, certified the way `quisora ssh host-sign` does it: the client credentials of a service account
	// with the ssh:host scope (made as the guide's, with the default authentication method, client_secret_post, which the
	// command tries first), then the management API.
	hostKey := filepath.Join(root, "ssh_host_ed25519_key")
	f.keygen(hostKey)
	sa, secret, err := env.Svc.CreateServiceAccount(ctx, service.System, env.Primary.ID, service.ServiceAccountInput{
		Name: ptr("e2e-host"), Scopes: &[]string{service.ScopeSSHHost}})
	if err != nil {
		t.Fatal(err)
	}
	cli, cliOut := f.cli(nil)
	if err := cli.HostSign(ctx, sshcli.HostSignOptions{URL: f.discovery, KeyFile: hostKey + ".pub",
		Principals: []string{hostName}, ClientID: sa.ID, Secret: secret}); err != nil {
		t.Fatalf("host-sign: %v\n%s", err, cliOut)
	}
	if !strings.Contains(cliOut.String(), "HostCertificate "+hostKey+"-cert.pub") {
		t.Fatalf("host-sign did not print the HostCertificate line:\n%s", cliOut)
	}

	files := map[string]string{
		"ssh_host_ed25519_key":          readFile(t, hostKey),
		"ssh_host_ed25519_key-cert.pub": readFile(t, hostKey+"-cert.pub"),
		"quisora_user_ca.pub":           readFile(t, f.caFile),
		"quisora.krl":                   readFile(t, f.krlFile),
	}
	f.sshd = startSSHD(t, filepath.Join(root, "build"), files)
	return f
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// cli is the environment of the `quisora ssh` code for a user's browser: it opens no real browser but signs the user
// in at the authorization URL (a session with a password, a code and the second factor) and takes the redirect to the
// loopback listener of the command, as a browser does. A nil user gets none. Its output is the second result.
func (f *fixture) cli(u *model.User) (*sshcli.Env, *bytes.Buffer) {
	var out bytes.Buffer
	env := &sshcli.Env{Out: &out, Err: &out, HTTP: f.httpc, Timeout: 30 * time.Second}
	if u != nil {
		env.OpenBrowser = func(authURL string) error { return f.browse(u, authURL) }
	}
	return env, &out
}

// browse is the user's browser at the authorization URL of the command's sign-in.
func (f *fixture) browse(u *model.User, authURL string) error {
	c, _ := f.env.SessionAMR(u, mfaAMR)
	resp, err := c.Get(authURL)
	if err != nil {
		return err
	}
	resp.Body.Close()
	to := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(to, "http://127.0.0.1:") {
		return fmt.Errorf("the authorization endpoint answered %d, not a redirect to the command's loopback listener: %q", resp.StatusCode, to)
	}
	back, err := http.Get(to) // the redirect: the command's listener takes the code
	if err != nil {
		return err
	}
	back.Body.Close()
	return nil
}

func (f *fixture) fetch() string {
	f.t.Helper()
	env, out := f.cli(nil)
	if err := env.Fetch(context.Background(), sshcli.FetchOptions{URL: f.discovery, CAFile: f.caFile, KRLFile: f.krlFile,
		KnownHostsFile: f.knownHosts}); err != nil {
		f.t.Fatalf("fetch: %v\n%s", err, out)
	}
	return out.String()
}

// rewriteKRL is a transport that has the revocation list changed on its way from the server: a proxy that mangles it.
type rewriteKRL struct {
	base http.RoundTripper
	fn   func([]byte) []byte
}

func (rt rewriteKRL) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(r)
	if err != nil || !strings.HasSuffix(r.URL.Path, "/krl") {
		return resp, err
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	b = rt.fn(b)
	resp.Body, resp.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
	resp.Header.Del("Content-Length")
	return resp, nil
}

// fetchMangled is `quisora ssh fetch` against a server whose revocation list is changed by fn on the way.
func (f *fixture) fetchMangled(fn func([]byte) []byte) (string, error) {
	env, out := f.cli(nil)
	env.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: rewriteKRL{f.httpc.Transport, fn}}
	err := env.Fetch(context.Background(), sshcli.FetchOptions{URL: f.discovery, CAFile: f.caFile, KRLFile: f.krlFile,
		KnownHostsFile: f.knownHosts})
	return out.String(), err
}

// refresh is the server's timer firing: fetch, then the files that changed go to the container. The KRL must have
// changed (every call is after something that changes it).
func (f *fixture) refresh(t *testing.T) {
	t.Helper()
	f.env.Svc.InvalidateSSHKRL() // the KRL is cached 30 s a node; the test does not wait
	if out := f.fetch(); !strings.Contains(out, "updated "+f.krlFile) {
		t.Fatalf("fetch did not find a new revocation list:\n%s", out)
	}
	f.sshd.copyIn(t, f.caFile, "/etc/ssh/quisora_user_ca.pub")
	f.sshd.copyIn(t, f.krlFile, "/etc/ssh/quisora.krl")
}

// changed drops what the server's caches hold of a user, as a cluster does on a change of the user's records.
func (f *fixture) changed(u *model.User) {
	f.p.InvalidateUser(u.ID)
	f.p.InvalidateMembership("")
}

func (f *fixture) keygen(path string) {
	f.t.Helper()
	if out, err := run(30*time.Second, "", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path); err != nil {
		f.t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
}

// tryLogin is `quisora ssh login --key` for user u (a fresh key each time) and returns the key's path.
func (f *fixture) tryLogin(u *model.User, ttl time.Duration, principals ...string) (key, out string, err error) {
	f.keys++
	key = filepath.Join(f.clientDir, "key"+strconv.Itoa(f.keys))
	f.keygen(key)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	env, buf := f.cli(u)
	var browseErr error
	env.OpenBrowser = func(authURL string) error {
		if browseErr = f.browse(u, authURL); browseErr != nil {
			cancel() // there is no sign-in to wait for
		}
		return browseErr
	}
	err = env.Login(ctx, sshcli.LoginOptions{URL: f.discovery, Key: key, Principals: principals, TTL: ttl})
	if err != nil && browseErr != nil {
		err = fmt.Errorf("%w: %v", err, browseErr)
	}
	return key, buf.String(), err
}

// login is tryLogin that must work; it returns the key and the certificate it got.
func (f *fixture) login(t *testing.T, u *model.User, principals ...string) (string, *ssh.Certificate) {
	t.Helper()
	key, out, err := f.tryLogin(u, 0, principals...)
	if err != nil {
		t.Fatalf("login of %s: %v\n%s", u.Username, err, out)
	}
	cert := certOf(t, key)
	if !strings.Contains(out, "Principals: "+strings.Join(cert.ValidPrincipals, ", ")) {
		t.Errorf("login did not say its principals:\n%s", out)
	}
	return key, cert
}

// certOf reads the certificate the login wrote next to key, and checks that the system's ssh-keygen reads it too.
func certOf(t *testing.T, key string) *ssh.Certificate {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(readFile(t, key+"-cert.pub")))
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert {
		t.Fatalf("%s-cert.pub is not a user certificate", key)
	}
	if out, err := run(20*time.Second, "", "ssh-keygen", "-L", "-f", key+"-cert.pub"); err != nil || !strings.Contains(out, "Type: ssh-ed25519-cert-v01@openssh.com user certificate") {
		t.Fatalf("ssh-keygen -L: %v\n%s", err, out)
	}
	return cert
}

type result struct {
	out, errOut string
	err         error
}

// ssh runs the system's ssh to log in as account with the key and its certificate, and runs `id -un`.
// knownHosts and alias are the host key checks; extra options come first, so they win.
func (f *fixture) ssh(account, key, knownHosts, alias string, extra ...string) result {
	args := append([]string{}, extra...)
	args = append(args, "-F", "/dev/null", "-p", f.sshd.port,
		"-o", "UserKnownHostsFile="+knownHosts, "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias="+alias, "-o", "CheckHostIP=no", "-o", "VerifyHostKeyDNS=no",
		"-o", "ConnectTimeout=5", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
		"-i", key, "-o", "CertificateFile="+key+"-cert.pub", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		account+"@127.0.0.1", "id", "-un")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return result{out.String(), errOut.String(), err}
}

// allowed asserts that account accepts the certificate (sshd says which certificate it was).
func (f *fixture) allowed(t *testing.T, account, key string, cert *ssh.Certificate) {
	t.Helper()
	from := f.sshd.logLen()
	r := f.ssh(account, key, f.knownHosts, hostName)
	if r.err != nil || strings.TrimSpace(r.out) != account {
		t.Errorf("login as %s with serial %d: %v, %q\n%s", account, cert.Serial, r.err, r.out, r.errOut)
		return
	}
	f.sshd.expectLog(t, from, "Accepted publickey for "+account)
	f.sshd.expectLog(t, from, fmt.Sprintf("ID %s (serial %d)", cert.KeyId, cert.Serial))
}

// denied asserts that account refuses the certificate at authentication (not before: the host is verified and sshd
// is reached), and that sshd says why with logged.
func (f *fixture) denied(t *testing.T, account, key, logged string) {
	t.Helper()
	from := f.sshd.logLen()
	r := f.ssh(account, key, f.knownHosts, hostName)
	if r.err == nil {
		t.Errorf("login as %s worked; it must not (%q)", account, r.out)
		return
	}
	if !strings.Contains(r.errOut, "Permission denied (publickey)") {
		t.Errorf("login as %s failed, but not at authentication:\n%s", account, r.errOut)
		return
	}
	if logged != "" {
		f.sshd.expectLog(t, from, logged)
	}
}

// The test: users get certificates from Quisora the way the CLI does, and a real sshd decides.
func TestE2ESSHCertificateAuthority(t *testing.T) {
	requireE2E(t)
	f := newFixture(t)
	ctx := context.Background()
	svc := f.env.Svc

	// A certificate that lives 60 seconds, for the last step: bob is in no group, nothing but time ends it.
	bobKey, out, err := f.tryLogin(f.bob, time.Minute)
	if err != nil {
		t.Fatalf("login of bob: %v\n%s", err, out)
	}
	bobCert := certOf(t, bobKey)
	f.allowed(t, "bob", bobKey, bobCert)

	// alice's first certificate, from a sign-in in the browser the test plays: principals alice and group:ops.
	aliceKey, aliceCert := f.login(t, f.alice)
	t.Run("the certificate", func(t *testing.T) {
		if got := strings.Join(aliceCert.ValidPrincipals, ","); got != "alice,group:ops" {
			t.Errorf("principals %q, want alice,group:ops", got)
		}
		if aliceCert.KeyId != fmt.Sprintf("alice@%s/%s", f.env.Primary.Name, f.alice.ID) {
			t.Errorf("key id %q", aliceCert.KeyId)
		}
		if ttl := time.Until(time.Unix(int64(aliceCert.ValidBefore), 0)); ttl < 7*time.Hour || ttl > 8*time.Hour+time.Minute {
			t.Errorf("valid for %v, want the tenant's 8 hours", ttl)
		}
	})

	t.Run("the host is verified by its certificate", func(t *testing.T) {
		kh := readFile(t, f.knownHosts)
		if lines := strings.Split(strings.TrimSpace(kh), "\n"); len(lines) != 1 || !strings.HasPrefix(lines[0], "@cert-authority "+hostPattern+" ssh-ed25519 ") {
			t.Fatalf("known_hosts from Quisora: %q", kh)
		}
		// the client knows no host key, only the CA: the certificate of the host proves its name
		f.allowed(t, "alice", aliceKey, aliceCert)

		empty := filepath.Join(t.TempDir(), "empty_known_hosts")
		if err := os.WriteFile(empty, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		r := f.ssh("alice", aliceKey, empty, hostName)
		if r.err == nil || !strings.Contains(r.errOut, "Host key verification failed") {
			t.Errorf("an unknown host key was accepted: %v\n%s", r.err, r.errOut)
		}
		// a name the certificate is not for (the pattern allows it, the certificate does not name it), and one
		// the pattern does not cover
		for _, alias := range []string{"other.e2e.test", "sshd.example.org"} {
			r := f.ssh("alice", aliceKey, f.knownHosts, alias)
			if r.err == nil || !strings.Contains(r.errOut, "Host key verification failed") {
				t.Errorf("connecting as %s: %v\n%s", alias, r.err, r.errOut)
			}
		}
	})

	t.Run("principals decide who may log in as whom", func(t *testing.T) {
		f.allowed(t, "ubuntu", aliceKey, aliceCert) // group:ops, in /etc/ssh/principals/ubuntu
		f.allowed(t, "alice", aliceKey, aliceCert)  // alice, in /etc/ssh/principals/alice
		f.denied(t, "root", aliceKey, noPrincipal)  // no principals file for root
		f.denied(t, "bob", aliceKey, noPrincipal)   // alice's certificate has no principal bob

		// asking for fewer principals gets a certificate with those only
		opsKey, opsCert := f.login(t, f.alice, "group:ops")
		if got := strings.Join(opsCert.ValidPrincipals, ","); got != "group:ops" {
			t.Fatalf("principals %q, want group:ops", got)
		}
		f.allowed(t, "ubuntu", opsKey, opsCert)
		f.denied(t, "alice", opsKey, noPrincipal)
	})

	t.Run("a certificate of another authority is refused", func(t *testing.T) {
		other := filepath.Join(t.TempDir(), "other_ca")
		f.keygen(other)
		key := filepath.Join(t.TempDir(), "key")
		f.keygen(key)
		if out, err := run(20*time.Second, "", "ssh-keygen", "-q", "-s", other, "-I", "rogue", "-n", "alice,group:ops", "-V", "-5m:+1h", key+".pub"); err != nil {
			t.Fatalf("ssh-keygen -s: %v\n%s", err, out)
		}
		f.denied(t, "ubuntu", key, "ID rogue (serial 0)") // sshd looked at it and did not trust its authority
		f.denied(t, "alice", key, "ID rogue (serial 0)")
	})

	t.Run("a certificate revoked by hand", func(t *testing.T) {
		key, cert := f.login(t, f.alice)
		f.allowed(t, "alice", key, cert)
		views, err := svc.ListSSHCerts(ctx, f.admin, f.tn.ID, service.SSHCertFilter{UserID: f.alice.ID})
		if err != nil {
			t.Fatal(err)
		}
		var id string
		for _, v := range views {
			if v.Serial == cert.Serial {
				id = v.ID
			}
		}
		if id == "" {
			t.Fatalf("the certificate (serial %d) is not listed: %d certificates", cert.Serial, len(views))
		}
		if err := svc.RevokeSSHCert(ctx, f.admin, f.env.Primary.ID, id); err != nil {
			t.Fatal(err)
		}
		f.refresh(t)
		f.denied(t, "alice", key, "revoked")
		f.denied(t, "ubuntu", key, "revoked")
		// the list names that certificate only
		f.allowed(t, "alice", aliceKey, aliceCert)
	})

	t.Run("a user removed from a group", func(t *testing.T) {
		key, cert := f.login(t, f.alice)
		f.allowed(t, "ubuntu", key, cert)

		if _, err := svc.ChangeGroup(ctx, f.admin, f.ops, service.GroupInput{}, nil, []string{f.alice.ID}); err != nil {
			t.Fatal(err)
		}
		f.changed(f.alice)
		f.refresh(t)
		// the certificates were issued for principals alice and group:ops; alice would not get group:ops now: revoked, wholly
		f.denied(t, "ubuntu", key, "revoked")
		f.denied(t, "alice", key, "revoked")
		f.denied(t, "alice", aliceKey, "revoked")

		// a new certificate has her username only: alice yes, ubuntu no
		newKey, newCert := f.login(t, f.alice)
		if got := strings.Join(newCert.ValidPrincipals, ","); got != "alice" {
			t.Fatalf("principals %q, want alice", got)
		}
		f.allowed(t, "alice", newKey, newCert)
		f.denied(t, "ubuntu", newKey, noPrincipal)
	})

	t.Run("SSH turned off and on", func(t *testing.T) {
		key, cert := f.login(t, f.alice)
		f.allowed(t, "alice", key, cert)
		off := false
		if _, err := svc.UpdateTenantSSH(ctx, f.admin, f.tn.ID, service.SSHSettingsInput{Enabled: &off}); err != nil {
			t.Fatal(err)
		}
		f.refresh(t) // fetch goes on working while SSH is off: that is how the servers hear of it
		f.denied(t, "alice", key, "revoked")
		f.denied(t, "alice", aliceKey, "revoked")
		if _, out, err := f.tryLogin(f.alice, 0); err == nil {
			t.Errorf("a certificate was signed while SSH is off:\n%s", out)
		} else if !strings.Contains(err.Error()+out, "turned off") {
			t.Errorf("login while off does not say SSH is turned off: %v\n%s", err, out)
		}
		on := true
		if _, err := svc.UpdateTenantSSH(ctx, f.admin, f.tn.ID, service.SSHSettingsInput{Enabled: &on}); err != nil {
			t.Fatal(err)
		}
		f.refresh(t)
		f.allowed(t, "alice", key, cert) // not revoked otherwise: valid again
	})

	t.Run("sessions revoked and a user disabled", func(t *testing.T) {
		key, cert := f.login(t, f.alice)
		f.allowed(t, "alice", key, cert)
		if err := svc.RevokeSessions(ctx, f.admin, f.alice.ID); err != nil {
			t.Fatal(err)
		}
		f.changed(f.alice)
		f.refresh(t)
		f.denied(t, "alice", key, "revoked") // signed out everywhere: its certificates go with the sessions

		key, cert = f.login(t, f.alice) // signing in again works, and gets a new certificate
		f.allowed(t, "alice", key, cert)
		if _, err := svc.UpdateUser(ctx, service.System, f.alice.ID, service.UserInput{Active: ptr(false)}); err != nil {
			t.Fatal(err)
		}
		f.changed(f.alice)
		f.refresh(t)
		f.denied(t, "alice", key, "revoked")
		if _, out, err := f.tryLogin(f.alice, 0); err == nil {
			t.Errorf("a disabled user got a certificate:\n%s", out)
		} else {
			t.Logf("a disabled user's login is refused: %v", err)
		}
	})

	t.Run("a corrupt revocation list is refused and the one in place kept", func(t *testing.T) {
		f.env.Svc.InvalidateSSHKRL()
		krl, ca, hosts := readFile(t, f.krlFile), readFile(t, f.caFile), readFile(t, f.knownHosts)
		for name, mangle := range map[string]func([]byte) []byte{
			"an error page":        func([]byte) []byte { return []byte("<html><body>502 Bad Gateway</body></html>") },
			"cut short":            func(b []byte) []byte { return b[:len(b)-3] },
			"cut after its header": func(b []byte) []byte { return b[:20] },
			"another magic":        func(b []byte) []byte { return append([]byte("NOTAKRL\n"), b[8:]...) },
		} {
			out, err := f.fetchMangled(mangle)
			if err == nil || !strings.Contains(err.Error(), "revocation list") {
				t.Errorf("%s: fetch: %v\n%s", name, err, out)
			}
			if got := (readFile(t, f.krlFile) + readFile(t, f.caFile) + readFile(t, f.knownHosts)); got != krl+ca+hosts {
				t.Errorf("%s: the trust files changed", name)
			}
		}
		// still the list sshd reads
		if out, err := run(20*time.Second, "", "ssh-keygen", "-Q", "-l", "-f", f.krlFile); err != nil {
			t.Errorf("the kept list does not read: %v\n%s", err, out)
		}
		entries, _ := os.ReadDir(f.trustDir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				t.Errorf("a temporary file was left: %s", e.Name())
			}
		}
	})

	t.Run("a revocation list for another tenant's CA key is refused", func(t *testing.T) {
		before := readFile(t, f.krlFile)
		other := filepath.Join(t.TempDir(), "other_ca")
		f.keygen(other)
		stranger, _, _, _, err := ssh.ParseAuthorizedKey([]byte(readFile(t, other+".pub")))
		if err != nil {
			t.Fatal(err)
		}
		krl := sshca.NewKRL(uint64(time.Now().Unix())+3600, time.Now(), "")
		krl.Add(stranger, 1, 2, 3)
		out, err := f.fetchMangled(func([]byte) []byte { return krl.Marshal() })
		if err == nil || !strings.Contains(err.Error(), "no section for any of the CA keys") {
			t.Errorf("fetch: %v\n%s", err, out)
		}
		if readFile(t, f.krlFile) != before {
			t.Error("the list was replaced")
		}
	})

	t.Run("an expired certificate", func(t *testing.T) {
		if testing.Short() {
			t.Skip("waits for a 60 second certificate to expire")
		}
		// the certificate was issued first and is not revoked; sshd must have accepted it while it lasted
		time.Sleep(time.Until(time.Unix(int64(bobCert.ValidBefore), 0)) + 2*time.Second)
		f.denied(t, "bob", bobKey, "Certificate invalid: expired")
	})

	// Last: it replaces the CA key, which the certificates above were signed by.
	t.Run("a certificate of a removed CA key", func(t *testing.T) {
		oldFile := readFile(t, f.caFile)
		key, cert := f.login(t, f.bob)
		f.allowed(t, "bob", key, cert)

		keys, err := svc.SSHKeys(ctx, f.tn.ID, model.SSHPurposeUser)
		if err != nil || len(keys) != 1 {
			t.Fatalf("user CA keys: %v, %v", keys, err)
		}
		// the key is compromised: rotate with immediate effect, then remove it
		if _, err := svc.RotateSSHKey(ctx, f.admin, f.tn.ID, model.SSHPurposeUser, true); err != nil {
			t.Fatal(err)
		}
		if err := svc.RemoveSSHKey(ctx, f.admin, f.tn.ID, keys[0].ID); err != nil {
			t.Fatal(err)
		}
		f.env.Svc.InvalidateSSHKRL()
		f.fetch()
		newFile := readFile(t, f.caFile)
		if strings.Contains(newFile, strings.Fields(keys[0].PublicKey)[1]) || strings.Count(strings.TrimSpace(newFile), "\n") != 0 {
			t.Fatalf("the removed key is still published, or the new one is not alone:\n%s", newFile)
		}

		// A server that still trusts the old key (it has not fetched ca.pub, or has an old copy back) is told by the
		// list: it names the key itself as revoked. The new key is trusted too, so a new certificate shows the list
		// does not refuse everything.
		both := filepath.Join(t.TempDir(), "both_ca.pub")
		if err := os.WriteFile(both, []byte(oldFile+newFile), 0o644); err != nil {
			t.Fatal(err)
		}
		f.sshd.copyIn(t, both, "/etc/ssh/quisora_user_ca.pub")
		f.sshd.copyIn(t, f.krlFile, "/etc/ssh/quisora.krl")
		f.denied(t, "bob", key, "revoked")
		newKey, newCert := f.login(t, f.bob)
		f.allowed(t, "bob", newKey, newCert)

		// and the server with the current files refuses the old certificate as signed by an authority it does not trust
		f.sshd.copyIn(t, f.caFile, "/etc/ssh/quisora_user_ca.pub")
		f.denied(t, "bob", key, fmt.Sprintf("ID %s (serial %d)", cert.KeyId, cert.Serial))
		f.allowed(t, "bob", newKey, newCert)
	})
}
