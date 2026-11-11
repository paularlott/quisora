package sshcli

import (
	"bufio"
	"cmp"
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// End to end against a real sshd and journald: run as root, with QUISORA_SSHD_E2E set to a directory holding a user
// CA (ca, ca.pub) that an sshd trusts, with journald collecting sshd's log; QUISORA_SSHD_E2E_TO is where to log in
// (an ssh:// destination, ssh://root@127.0.0.1 if unset; the certificate's principal is its user). Each
// connection is made with a certificate of its own key id and serial, found in sshd's log by its key id, then ended:
// once by a revocation list that revokes its serial, once by a lifetime shorter than it has been open. Each session
// leaves a process running on its own (setsid nohup, as tmux's server is): where the connection has a logind session
// (sshd with UsePAM), it is ended with the connection; where it has none, it is left running. For example:
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
	// start opens a connection with a certificate of keyID and serial, which stays open until something ends it, and
	// returns the process its session left running on its own.
	start := func(keyID, serial string) (*exec.Cmd, int) {
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
			"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", to,
			"setsid nohup sleep 600 >/dev/null 2>&1 </dev/null & echo $!; exec sleep 600")
		stdout, err := c.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Process.Kill() })
		line, err := bufio.NewReader(stdout).ReadString('\n')
		left, aerr := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || aerr != nil {
			t.Fatalf("the session's own process: %q %v", line, err)
		}
		t.Cleanup(func() { syscall.Kill(left, syscall.SIGKILL) })
		return c, left
	}
	// leftAlone checks what became of the process the session of login l left running: ended with a logind session,
	// running on without one. (Its number cannot have been taken since: it is checked within seconds.)
	leftAlone := func(l SSHDLogin, session string, left int) {
		t.Helper()
		time.Sleep(time.Second) // logind ends the scope's processes as it stops it
		alive := syscall.Kill(left, 0) == nil
		if session != "" && alive {
			t.Errorf("login session %s was ended, but the process it left running (%d) is alive", session, left)
		}
		if session == "" && !alive {
			t.Errorf("no login session, yet the process the session left running (%d) is gone", left)
		}
		t.Logf("login session %q: the process left running is alive: %v", session, alive)
	}
	// logged waits for sshd's log to have the login of keyID.
	logged := func(keyID string) SSHDLogin {
		t.Helper()
		for range 100 {
			r, err := journalLogins(context.Background(), "", "")
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range r.Logins {
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
	run := strconv.FormatInt(time.Now().UnixNano(), 36) // key ids of this run: the journal keeps earlier runs' logins
	krl := func(serials ...uint64) *sshca.KRL {
		k, err := sshca.ParseKRL(krlOf(uint64(time.Now().Unix()), serials, ca))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	state := filepath.Join(t.TempDir(), "end-revoked.json") // the open logins, kept between the runs below
	env := func() (*Env, *syncBuffer) {
		out := &syncBuffer{}
		return &Env{Out: out, Err: out, GOOS: "linux"}, out
	}

	// revoked
	c1, left1 := start("e2e-revoked-"+run, "71")
	l1 := logged("e2e-revoked-" + run)
	s1 := loginSession(l1.PID)
	e, out := env()
	if n, err := e.endRevoked(context.Background(), krl(), []ssh.PublicKey{ca}, time.Hour, state); err != nil || n != 0 {
		t.Fatalf("nothing revoked, within the lifetime: ended %d, %v", n, err)
	}
	if n, err := e.endRevoked(context.Background(), krl(71), []ssh.PublicKey{ca}, time.Hour, state); err != nil || n != 1 {
		t.Fatalf("revoked: ended %d, %v (%s)", n, err, out)
	}
	if !gone(c1) {
		t.Fatal("the connection of a revoked certificate is still open")
	}
	t.Logf("%s (logged at %s since boot)", strings.TrimSpace(out.String()), l1.Logged)
	leftAlone(l1, s1, left1)

	// open longer than the lifetime
	c2, left2 := start("e2e-expired-"+run, "72")
	l2 := logged("e2e-expired-" + run)
	s2 := loginSession(l2.PID)
	time.Sleep(2 * time.Second)
	e, out = env()
	if n, err := e.endRevoked(context.Background(), krl(), []ssh.PublicKey{ca}, time.Second, state); err != nil || n != 1 {
		t.Fatalf("past the lifetime: ended %d, %v (%s)", n, err, out)
	}
	if !gone(c2) {
		t.Fatal("a connection past the certificate lifetime is still open")
	}
	t.Log(strings.TrimSpace(out.String()))
	leftAlone(l2, s2, left2)
}

// The login session of a process is read from its cgroup: the scope logind made for it (cgroup v2, or v1's systemd
// hierarchy); a process outside one has none.
func TestLoginSession(t *testing.T) {
	dir := t.TempDir()
	defer func(was string) { procDir = was }(procDir)
	procDir = dir
	for pid, c := range map[string]string{
		"10": "0::/user.slice/user-1000.slice/session-785.scope\n",
		"11": "12:pids:/user.slice\n1:name=systemd:/user.slice/user-0.slice/session-c3.scope\n0::/\n",
		"12": "0::/system.slice/ssh.service\n",
		"13": "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-u5.service\n",
	} {
		if err := os.MkdirAll(filepath.Join(dir, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, pid, "cgroup"), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for pid, want := range map[int]string{10: "785", 11: "c3", 12: "", 13: "", 14: ""} {
		if got := loginSession(pid); got != want {
			t.Errorf("process %d: session %q, want %q", pid, got, want)
		}
	}
}
