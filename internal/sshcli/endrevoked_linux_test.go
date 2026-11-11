package sshcli

import (
	"cmp"
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// End to end against a real sshd and journald: run as root, with QUISORA_SSHD_E2E set to a directory holding a user
// CA (ca, ca.pub) that an sshd trusts, with journald collecting sshd's log; QUISORA_SSHD_E2E_TO is where to log in
// (an ssh:// destination, ssh://root@127.0.0.1 if unset; the certificate's principal is its user). Each
// connection is made with a certificate of its own key id and serial, found in sshd's log by its key id, then ended:
// once by a revocation list that revokes its serial, once by a lifetime shorter than it has been open. For example:
//
//	GOOS=linux go test -c -o sshcli.test ./internal/sshcli/
//	docker run --rm --user root -v $PWD:/t ubuntu sh -c '<start systemd-journald and sshd, make the CA> &&
//	    QUISORA_SSHD_E2E=/e2e /t/sshcli.test -test.run RealSSHD -test.v'
func TestEndRevokedRealSSHD(t *testing.T) {
	dir := os.Getenv("QUISORA_SSHD_E2E")
	if dir == "" {
		t.Skip("QUISORA_SSHD_E2E is not set")
	}
	caBytes, err := os.ReadFile(filepath.Join(dir, "ca.pub"))
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey(caBytes)
	if err != nil {
		t.Fatal(err)
	}
	to := cmp.Or(os.Getenv("QUISORA_SSHD_E2E_TO"), "ssh://root@127.0.0.1")
	u, err := url.Parse(to)
	if err != nil || u.User == nil {
		t.Fatalf("QUISORA_SSHD_E2E_TO %q: an ssh:// destination with a user", to)
	}
	// start opens a connection with a certificate of keyID and serial, which stays open until something ends it.
	start := func(keyID, serial string) *exec.Cmd {
		t.Helper()
		key := filepath.Join(t.TempDir(), "key")
		for _, args := range [][]string{
			{"-q", "-t", "ed25519", "-N", "", "-f", key},
			{"-q", "-s", filepath.Join(dir, "ca"), "-I", keyID, "-n", u.User.Username(), "-z", serial, "-V", "+1h", key + ".pub"},
		} {
			if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen %v: %v %s", args, err, out)
			}
		}
		c := exec.Command("ssh", "-i", key, "-o", "CertificateFile="+key+"-cert.pub", "-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", to, "sleep", "600")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Process.Kill() })
		return c
	}
	// logged waits for sshd's log to have the login of keyID.
	logged := func(keyID string) SSHDLogin {
		t.Helper()
		for range 100 {
			list, err := journalLogins(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range list {
				if l.KeyID == keyID {
					if !isSSHD(l) {
						t.Fatalf("the login's process is not taken for sshd's: %+v", l)
					}
					return l
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no login of %s in sshd's log", keyID)
		return SSHDLogin{}
	}
	// gone waits for the client of a connection to exit.
	gone := func(c *exec.Cmd) bool {
		done := make(chan struct{})
		go func() { c.Wait(); close(done) }()
		select {
		case <-done:
			return true
		case <-time.After(10 * time.Second):
			return false
		}
	}
	krl := func(serials ...uint64) *sshca.KRL {
		k, err := sshca.ParseKRL(krlOf(uint64(time.Now().Unix()), serials, ca))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	env := func() (*Env, *syncBuffer) {
		out := &syncBuffer{}
		return &Env{Out: out, Err: out, GOOS: "linux"}, out
	}

	// revoked
	c1 := start("e2e-revoked", "71")
	l1 := logged("e2e-revoked")
	e, out := env()
	if n, err := e.endRevoked(context.Background(), krl(), []ssh.PublicKey{ca}, time.Hour); err != nil || n != 0 {
		t.Fatalf("nothing revoked, within the lifetime: ended %d, %v", n, err)
	}
	if n, err := e.endRevoked(context.Background(), krl(71), []ssh.PublicKey{ca}, time.Hour); err != nil || n != 1 {
		t.Fatalf("revoked: ended %d, %v (%s)", n, err, out)
	}
	if !gone(c1) {
		t.Fatal("the connection of a revoked certificate is still open")
	}
	t.Logf("%s (logged at %s since boot)", strings.TrimSpace(out.String()), l1.Logged)

	// open longer than the lifetime
	c2 := start("e2e-expired", "72")
	logged("e2e-expired")
	time.Sleep(2 * time.Second)
	e, out = env()
	if n, err := e.endRevoked(context.Background(), krl(), []ssh.PublicKey{ca}, time.Second); err != nil || n != 1 {
		t.Fatalf("past the lifetime: ended %d, %v (%s)", n, err, out)
	}
	if !gone(c2) {
		t.Fatal("a connection past the certificate lifetime is still open")
	}
	t.Log(strings.TrimSpace(out.String()))
}
