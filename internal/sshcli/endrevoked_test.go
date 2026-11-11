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
	defer func(was func() time.Duration) { monoNow = was }(monoNow)
	monoNow = func() time.Duration { return time.Hour } // every login an hour old, within the lifetime (8 hours)
	fp := sshca.Fingerprint(ca)
	te.SSHDLogins = logins("boot1", "c1", []SSHDLogin{
		{PID: 100, KeyID: "alice", Serial: 7, CA: fp},          // revoked: ended
		{PID: 100, KeyID: "alice", Serial: 7, CA: fp},          // the same connection again: once
		{PID: 101, KeyID: "bob", Serial: 8, CA: fp},            // not revoked
		{PID: 102, KeyID: "carol", Serial: 7, CA: "SHA256:xx"}, // another CA's serial 7
		{PID: 103, KeyID: "alice", Serial: 7, CA: fp},          // gone (its number since taken by another program)
	})
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
	te.SSHDLogins = func(context.Context, string, string) (journalRead, error) {
		return journalRead{}, errors.New("no journal")
	}
	if err := te.Fetch(context.Background(), o); err == nil {
		t.Fatal("an unreadable log was not reported")
	}
	te.GOOS = "darwin"
	if err := te.Fetch(context.Background(), o); err == nil {
		t.Fatal("--end-revoked off Linux was not refused")
	}
}

// fetch --end-revoked also ends the connections logged in longer ago than the tenant's certificate lifetime (8 hours
// here): their certificate has expired, and one that expired before its access was removed is never on the list.
// The age is counted on journald's monotonic clock; another CA's connections and those gone are left alone.
func TestFetchEndsConnectionsPastTheLifetime(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	ca := f.UserCA.PublicKey()
	f.Body["krl"] = krlOf(uint64(time.Now().Unix()), nil, ca)
	te := newTestEnv(t)
	te.GOOS = "linux"
	defer func(was func() time.Duration) { monoNow = was }(monoNow)
	now := 30 * time.Hour
	monoNow = func() time.Duration { return now }
	life := 8 * time.Hour
	fp := sshca.Fingerprint(ca)
	te.SSHDLogins = logins("boot1", "c1", []SSHDLogin{
		{PID: 200, KeyID: "alice", Serial: 1, CA: fp, Logged: now - life - time.Second},    // past it: ended
		{PID: 201, KeyID: "bob", Serial: 2, CA: fp, Logged: now - life},                    // just within it
		{PID: 202, KeyID: "carol", Serial: 3, CA: "SHA256:xx", Logged: now - 20*time.Hour}, // another CA's
		{PID: 203, KeyID: "dave", Serial: 4, CA: fp, Logged: now - 20*time.Hour},           // gone
	})
	te.IsSSHD = func(l SSHDLogin) bool { return l.PID != 203 }
	var ended []int
	te.Terminate = func(l SSHDLogin) error { ended = append(ended, l.PID); return nil }
	o := newTrustFiles(t).opts(f.URL)
	o.EndRevoked = true
	if err := te.Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ended, []int{200}) {
		t.Fatalf("ended %v, want [200]", ended)
	}
	mustContain(t, "output", te.out.String(), "ended the SSH connection of alice (serial 1, process 200): open longer than the certificate lifetime (8h0m0s)")
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
	lines := `{` + msg + `,"_PID":"100","_BOOT_ID":"0f3c6e7a1b2d4e5f8a9b0c1d2e3f4a5b","__MONOTONIC_TIMESTAMP":"90123456","__REALTIME_TIMESTAMP":"1700000000123456","__CURSOR":"s=1"}` + "\n" +
		`{` + msg + `,"_PID":"200","_BOOT_ID":"99999999999999999999999999999999","__MONOTONIC_TIMESTAMP":"5000000","__REALTIME_TIMESTAMP":"1690000000000000","__CURSOR":"s=2"}`
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + args + "\ncat <<'EOF'\n" + lines + "\nEOF\n"
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	r, err := journalLogins(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	got := r.Logins
	want := SSHDLogin{PID: 100, KeyID: "alice", Serial: 7, CA: "SHA256:ca", Logged: 90123456 * time.Microsecond}
	if len(got) != 1 || got[0] != want || r.Boot != "0f3c6e7a1b2d4e5f8a9b0c1d2e3f4a5b" || r.Cursor != "s=2" {
		t.Fatalf("read %+v, want [%+v] of this boot, up to cursor s=2", r, want)
	}
	b, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	if f := strings.Fields(string(b)); !slices.Contains(f, "_UID=0") || !slices.Contains(f, "--boot") || slices.ContainsFunc(f, func(a string) bool { return strings.HasPrefix(a, "--after-cursor") }) {
		t.Fatalf("journalctl was not asked for root's lines of this whole boot: %s", b)
	}
	// From where the last read stopped, in the same boot; a cursor of another boot is not used.
	for boot, want := range map[string]bool{"0f3c6e7a1b2d4e5f8a9b0c1d2e3f4a5b": true, "an earlier boot": false} {
		if _, err := journalLogins(context.Background(), boot, "s=1"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(args)
		if got := slices.Contains(strings.Fields(string(b)), "--after-cursor=s=1"); got != want {
			t.Errorf("boot %s: read after the cursor %v, want %v (%s)", boot, got, want, b)
		}
	}
}

// logins is a reading of sshd's log that finds list, in boot, up to cursor, whatever it was asked to read after.
func logins(boot, cursor string, list []SSHDLogin) func(context.Context, string, string) (journalRead, error) {
	return func(context.Context, string, string) (journalRead, error) {
		return journalRead{Boot: boot, Cursor: cursor, Logins: list}, nil
	}
}

// fetch --end-revoked keeps the logins it has read whose connection is open, and reads only what was logged after
// the last run: a connection made long ago (past any window of the log) is still known, and ended once its
// certificate is revoked. A login whose process is gone is dropped; a reboot starts over.
func TestEndRevokedTracksOpenLogins(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	ca := f.UserCA.PublicKey()
	fp := sshca.Fingerprint(ca)
	f.Body["krl"] = krlOf(uint64(time.Now().Unix()), nil, ca)
	te := newTestEnv(t)
	te.GOOS = "linux"
	defer func(was func() time.Duration) { monoNow = was }(monoNow)
	monoNow = func() time.Duration { return time.Hour }
	open := map[int]bool{300: true, 301: true}
	te.IsSSHD = func(l SSHDLogin) bool { return open[l.PID] }
	var ended []int
	te.Terminate = func(l SSHDLogin) error { ended = append(ended, l.PID); return nil }
	var asked [][2]string
	reader := func(boot, cursor string, list []SSHDLogin) func(context.Context, string, string) (journalRead, error) {
		return func(_ context.Context, b, after string) (journalRead, error) {
			asked = append(asked, [2]string{b, after})
			return journalRead{Boot: boot, Cursor: cursor, Logins: list}, nil
		}
	}
	o := newTrustFiles(t).opts(f.URL)
	o.EndRevoked = true

	// The first run reads the whole boot and keeps both open logins.
	te.SSHDLogins = reader("b1", "c1", []SSHDLogin{{PID: 300, KeyID: "alice", Serial: 1, CA: fp}, {PID: 301, KeyID: "bob", Serial: 2, CA: fp}})
	if err := te.Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	// Later runs read from where the last stopped; nothing new, and bob's connection ends by itself.
	delete(open, 301)
	te.SSHDLogins = reader("b1", "", nil)
	if err := te.Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	// alice's certificate is revoked: her connection, read three runs ago, is ended.
	f.Body["krl"] = krlOf(uint64(time.Now().Unix())+1, []uint64{1, 2}, ca)
	if err := te.Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ended, []int{300}) {
		t.Fatalf("ended %v, want [300] (bob's connection had gone)", ended)
	}
	if want := [][2]string{{"", ""}, {"b1", "c1"}, {"b1", "c1"}}; !slices.Equal(asked, want) {
		t.Fatalf("reads %v, want %v", asked, want)
	}
	// After a reboot what was kept is dropped: the same process number is someone else's.
	ended, asked = nil, nil
	te.SSHDLogins = reader("b2", "d1", nil)
	if err := te.Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(ended) != 0 {
		t.Fatalf("ended %v after a reboot", ended)
	}
	if st := read(t, o.StateFile); !strings.Contains(st, `"boot":"b2"`) || strings.Contains(st, "alice") {
		t.Fatalf("state after a reboot: %s", st)
	}
	// Without a state file it is refused.
	o.StateFile = ""
	if err := te.Fetch(context.Background(), o); err == nil {
		t.Fatal("--end-revoked without a state file")
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
