package sshcli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/sshcli/sshclitest"
)

// sshd's log lines for certificate logins, as OpenSSH writes them; a plain key login and other lines are not logins.
func TestParseAccepted(t *testing.T) {
	line := "Accepted publickey for ubuntu from 192.0.2.7 port 51234 ssh2: ED25519-CERT SHA256:abcDEF ID alice@acme/u1 (serial 1234567) CA ED25519 SHA256:caFP123"
	l, ok := parseAccepted(42, line)
	if !ok || l != (SSHDLogin{PID: 42, KeyID: "alice@acme/u1", Serial: 1234567, CA: "SHA256:caFP123"}) {
		t.Fatalf("parsed %+v %v", l, ok)
	}
	for _, s := range []string{
		"Accepted publickey for ubuntu from 192.0.2.7 port 51234 ssh2: ED25519 SHA256:abcDEF",
		"Failed publickey for ubuntu from 192.0.2.7 port 51234 ssh2: ED25519-CERT SHA256:abc ID x (serial 1) CA ED25519 SHA256:y",
		"pam_unix(sshd:session): session opened for user ubuntu",
	} {
		if _, ok := parseAccepted(1, s); ok {
			t.Errorf("taken for a certificate login: %s", s)
		}
	}
}

// fetch --end-revoked ends the connections whose certificate the list in place revokes, once each, and only those of
// a known CA whose process is still sshd's.
func TestFetchEndsRevokedConnections(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	ca := f.UserCA.PublicKey()
	f.Body["krl"] = krlOf(uint64(time.Now().Unix()), []uint64{7}, ca)
	te := newTestEnv(t)
	te.GOOS = "linux"
	fp := sshca.Fingerprint(ca)
	te.SSHDLogins = func(context.Context) ([]SSHDLogin, error) {
		return []SSHDLogin{
			{PID: 100, KeyID: "alice", Serial: 7, CA: fp},          // revoked: ended
			{PID: 100, KeyID: "alice", Serial: 7, CA: fp},          // the same connection again: once
			{PID: 101, KeyID: "bob", Serial: 8, CA: fp},            // not revoked
			{PID: 102, KeyID: "carol", Serial: 7, CA: "SHA256:xx"}, // another CA's serial 7
			{PID: 103, KeyID: "alice", Serial: 7, CA: fp},          // gone (its number since taken by another program)
		}, nil
	}
	te.IsSSHD = func(l SSHDLogin) bool { return l.PID != 103 }
	var ended []int
	te.Terminate = func(l SSHDLogin) error { ended = append(ended, l.PID); return nil }

	tf := newTrustFiles(t)
	o := tf.opts(f.URL)
	if err := te.Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(ended) != 0 {
		t.Fatalf("ended without --end-revoked: %v", ended)
	}
	o.EndRevoked = true
	if err := te.Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ended, []int{100}) {
		t.Fatalf("ended %v, want [100]", ended)
	}
	mustContain(t, "output", te.out.String(), "ended the SSH connection of alice (serial 7, process 100)")

	// where sshd's log cannot be read, fetch says so (exit 1, the timer's alert) after writing the files
	te.SSHDLogins = func(context.Context) ([]SSHDLogin, error) { return nil, errors.New("no journal") }
	if err := te.Fetch(context.Background(), o); err == nil {
		t.Fatal("an unreadable log was not reported")
	}
	te.GOOS = "darwin"
	if err := te.Fetch(context.Background(), o); err == nil {
		t.Fatal("--end-revoked off Linux was not refused")
	}
}

// sshd's log is read from root's lines only: anyone can log a line that reads like sshd's from a program named sshd,
// but journald takes the user id from the socket. Each login carries when it was logged on the monotonic clock, and
// lines from an earlier boot are left out.
func TestJournalLoginsAreRootsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a shell script stands in for journalctl")
	}
	dir := t.TempDir()
	defer func(was string) { procDir = was }(procDir)
	procDir = dir
	if err := os.MkdirAll(filepath.Join(dir, "sys/kernel/random"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sys/kernel/random/boot_id"), []byte("0f3c6e7a-1b2d-4e5f-8a9b-0c1d2e3f4a5b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := filepath.Join(dir, "args")
	const msg = `"MESSAGE":"Accepted publickey for ubuntu from 192.0.2.7 port 51234 ssh2: ED25519-CERT SHA256:abc ID alice (serial 7) CA ED25519 SHA256:ca"`
	lines := `{` + msg + `,"_PID":"100","_BOOT_ID":"0f3c6e7a1b2d4e5f8a9b0c1d2e3f4a5b","__MONOTONIC_TIMESTAMP":"90123456","__REALTIME_TIMESTAMP":"1700000000123456"}` + "\n" +
		`{` + msg + `,"_PID":"200","_BOOT_ID":"99999999999999999999999999999999","__MONOTONIC_TIMESTAMP":"5000000","__REALTIME_TIMESTAMP":"1690000000000000"}`
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + args + "\ncat <<'EOF'\n" + lines + "\nEOF\n"
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	got, err := journalLogins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := SSHDLogin{PID: 100, KeyID: "alice", Serial: 7, CA: "SHA256:ca", Logged: 90123456 * time.Microsecond}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("logins %+v, want [%+v]", got, want)
	}
	b, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(strings.Fields(string(b)), "_UID=0") {
		t.Fatalf("journalctl was not asked for root's lines only: %s", b)
	}
}

// A logged login's process is ended only while it is still the one that logged it: sshd's, run as root, and started
// no later than the line was logged (not a number taken since), on the boot clock less the time spent asleep. Its
// parent does not matter: a connection that outlived a restart of sshd, or one under socket activation, is init's.
func TestIsSSHDChecksTheProcess(t *testing.T) {
	dir := t.TempDir()
	defer func(was string, wasAsleep func() time.Duration) { procDir, asleep = was, wasAsleep }(procDir, asleep)
	procDir = dir
	asleep = func() time.Duration { return 0 }
	// proc makes process pid: its program, real user id, parent and start (seconds after boot, on the boot clock).
	proc := func(pid, comm, uid, ppid string, started int) {
		t.Helper()
		d := filepath.Join(dir, pid)
		stat := pid + " (" + comm + ") S " + ppid + " 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 " +
			strconv.Itoa(started*100) + " 0 0\n"
		for name, body := range map[string]string{
			"comm":   comm + "\n",
			"status": "Name:\t" + comm + "\nUid:\t" + uid + "\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
			"stat":   stat,
		} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	proc("1", "systemd", "0", "0", 0)
	proc("10", "sshd", "0", "1", 100)          // the listener, restarted after the line was logged
	proc("100", "sshd-session", "0", "10", 60) // a connection
	proc("103", "sshd", "0", "1", 60)          // a connection that outlived a restart of sshd, or socket-activated
	proc("101", "sshd", "1000", "10", 60)      // run as a user (real uid)
	proc("102", "sshd", "0", "10", 120)        // started after the line was logged
	proc("104", "logger", "0", "10", 60)       // not sshd
	logged := 90 * time.Second
	for pid, want := range map[int]bool{100: true, 103: true, 10: false, 101: false, 102: false, 104: false, 105: false} {
		if got := isSSHD(SSHDLogin{PID: pid, Logged: logged}); got != want {
			t.Errorf("process %d: %v, want %v", pid, got, want)
		}
	}
	// A minute asleep before the connection started puts its start on the boot clock a minute later than on journald's.
	asleep = func() time.Duration { return time.Minute }
	if !isSSHD(SSHDLogin{PID: 102, Logged: logged}) {
		t.Error("a connection started after a suspend was not taken for the one that logged it")
	}
}
