package sshcli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/paularlott/quisora/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// SSHDLogin is a certificate login sshd logged: the process that serves the connection (the privileged one, which
// the user cannot touch) and the certificate it accepted.
type SSHDLogin struct {
	PID    int
	KeyID  string
	Serial uint64
	CA     string // SHA256:… fingerprint of the CA key that signed it
}

// sshdLoginsSince is how far back the log is read: the longest certificate lifetime (24 hours) and some.
const sshdLoginsSince = "-25h"

// acceptedCert matches the line sshd logs for a certificate login (auth.c auth_log, with the certificate's
// description from auth2-pubkey.c): "Accepted publickey for <user> from <addr> port <n> ssh2: <type>-CERT <fp> ID
// <key id> (serial <n>) CA <type> <ca fp>".
var acceptedCert = regexp.MustCompile(`^Accepted publickey for \S+ from \S+ port \d+ ssh2: \S+-CERT \S+ ID (\S+) \(serial (\d+)\) CA \S+ (SHA256:\S+)`)

// parseAccepted reads a certificate login from a line of sshd's log.
func parseAccepted(pid int, msg string) (SSHDLogin, bool) {
	m := acceptedCert.FindStringSubmatch(msg)
	if m == nil {
		return SSHDLogin{}, false
	}
	serial, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil {
		return SSHDLogin{}, false
	}
	return SSHDLogin{PID: pid, KeyID: m[1], Serial: serial, CA: m[3]}, true
}

// journalLogins reads the certificate logins sshd logged to journald in the last 25 hours (sshd, or sshd-session
// from OpenSSH 9.8).
func journalLogins(ctx context.Context) ([]SSHDLogin, error) {
	cmd := exec.CommandContext(ctx, "journalctl", "--no-pager", "--quiet", "--output=json", "--output-fields=MESSAGE,_PID",
		"--since="+sshdLoginsSince, "_COMM=sshd", "_COMM=sshd-session")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("reading sshd's log with journalctl: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	var logins []SSHDLogin
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var entry struct {
			Message any    `json:"MESSAGE"` // a string, or an array of bytes when it is not UTF-8
			PID     string `json:"_PID"`
		}
		if json.Unmarshal(sc.Bytes(), &entry) != nil {
			continue
		}
		msg, _ := entry.Message.(string)
		pid, err := strconv.Atoi(entry.PID)
		if err != nil || msg == "" {
			continue
		}
		if l, ok := parseAccepted(pid, msg); ok {
			logins = append(logins, l)
		}
	}
	return logins, sc.Err()
}

// isSSHD reports whether process pid is still sshd's (the connection it served may have ended, and its number been
// taken by another process since).
func isSSHD(pid int) bool {
	comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(comm)), "sshd")
}

func terminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }

// endRevoked ends the SSH connections whose certificate krl revokes: those sshd logged as accepted (SSHDLogins), whose
// process is still sshd's, signed by a CA key in cas or in the list. Ending the connection's privileged process closes
// it and ends its session. Processes the session left running on their own (under tmux, screen or nohup) are not
// ended. It reports how many connections it ended.
func (e *Env) endRevoked(ctx context.Context, krl *sshca.KRL, cas []ssh.PublicKey) (int, error) {
	if e.goos() != "linux" {
		return 0, errors.New("--end-revoked works on Linux only: it reads sshd's log from journald")
	}
	logins := e.SSHDLogins
	if logins == nil {
		logins = journalLogins
	}
	alive, end := e.IsSSHD, e.Terminate
	if alive == nil {
		alive = isSSHD
	}
	if end == nil {
		end = terminate
	}
	byFP := map[string]ssh.PublicKey{}
	add := func(k ssh.PublicKey) { byFP[sshca.Fingerprint(k)] = k }
	for _, k := range cas {
		add(k)
	}
	for _, c := range krl.CAs {
		if k, err := ssh.ParsePublicKey(c.Key); err == nil {
			add(k)
		}
	}
	for _, b := range krl.Keys {
		if k, err := ssh.ParsePublicKey(b); err == nil {
			add(k)
		}
	}
	list, err := logins(ctx)
	if err != nil {
		return 0, err
	}
	ended := map[int]bool{}
	var errs []error
	for _, l := range list {
		ca := byFP[l.CA]
		if ca == nil || ended[l.PID] || !krl.Revoked(ca, l.Serial, l.KeyID) || !alive(l.PID) {
			continue // another CA's, ended already, not revoked, or the connection is gone
		}
		if err := end(l.PID); err != nil {
			if !errors.Is(err, syscall.ESRCH) {
				errs = append(errs, fmt.Errorf("ending the connection of %s (serial %d, process %d): %w", l.KeyID, l.Serial, l.PID, err))
			}
			continue
		}
		ended[l.PID] = true
		fmt.Fprintf(e.out(), "ended the SSH connection of %s (serial %d, process %d): its certificate is revoked\n", l.KeyID, l.Serial, l.PID)
	}
	return len(ended), errors.Join(errs...)
}
