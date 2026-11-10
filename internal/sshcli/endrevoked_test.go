package sshcli

import (
	"context"
	"errors"
	"slices"
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
	te.IsSSHD = func(pid int) bool { return pid != 103 }
	var ended []int
	te.Terminate = func(pid int) error { ended = append(ended, pid); return nil }

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
