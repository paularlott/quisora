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
	"time"

	"github.com/paularlott/quisora/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// SSHDLogin is a certificate login sshd logged: the process that serves the connection (the privileged one, which
// the user cannot touch), the certificate it accepted, and when the line was logged.
type SSHDLogin struct {
	PID    int
	KeyID  string
	Serial uint64
	CA     string        // SHA256:… fingerprint of the CA key that signed it
	Logged time.Duration // when journald received the line, since this boot: the process serving it had started by then
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
// from OpenSSH 9.8), as root, since this boot. Any local user can log a line that reads like sshd's, even from a
// program named sshd (_COMM is only the program's name); the user id is not theirs to choose: journald takes _UID from
// the credentials of the socket the line came in on. Matches on one field are ORed and on different fields ANDed:
// (sshd or sshd-session) and root. Each login carries when it was logged on the monotonic clock
// (__MONOTONIC_TIMESTAMP, which the JSON output always has, as it has _BOOT_ID), not the wall clock: a clock stepped
// forward after the login (a resumed VM, a first NTP sync) would make the connection seem to have started after it.
// Lines from an earlier boot are left out: their monotonic times count from that boot, and their connections are gone.
func journalLogins(ctx context.Context) ([]SSHDLogin, error) {
	b, err := os.ReadFile(procDir + "/sys/kernel/random/boot_id")
	if err != nil {
		return nil, fmt.Errorf("reading this boot's id: %w", err)
	}
	boot := strings.ReplaceAll(strings.TrimSpace(string(b)), "-", "") // journald writes it without the dashes
	cmd := exec.CommandContext(ctx, "journalctl", "--no-pager", "--quiet", "--output=json", "--output-fields=MESSAGE,_PID",
		"--since="+sshdLoginsSince, "_COMM=sshd", "_COMM=sshd-session", "_UID=0")
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
			Boot    string `json:"_BOOT_ID"`
			Logged  string `json:"__MONOTONIC_TIMESTAMP"` // microseconds since that boot
		}
		if json.Unmarshal(sc.Bytes(), &entry) != nil || entry.Boot != boot {
			continue
		}
		msg, _ := entry.Message.(string)
		pid, err := strconv.Atoi(entry.PID)
		logged, terr := strconv.ParseInt(entry.Logged, 10, 64)
		if err != nil || terr != nil || msg == "" {
			continue
		}
		if l, ok := parseAccepted(pid, msg); ok {
			l.Logged = time.Duration(logged) * time.Microsecond
			logins = append(logins, l)
		}
	}
	return logins, sc.Err()
}

// procDir is where the processes are read from (tests make one of their own).
var procDir = "/proc"

// asleep is how long this boot has spent suspended (tests set their own).
var asleep = timeAsleep

// isSSHD reports whether process l.PID is still the one that served login l: the connection may have ended, and its
// number been taken by another process since. It must be sshd's, run as root (the real user id), and have started no
// later than the line was logged (a process started after it is not the one that logged it). Its parent is not
// checked: connections that outlive a restart of sshd are the init process's children, and under socket activation
// (sshd -i) they all are. The listener needs no test of its own: it does not log logins, so a line can name its number
// only from an earlier holder of that number, logged before the listener started.
func isSSHD(l SSHDLogin) bool {
	pid := strconv.Itoa(l.PID)
	if !commSSHD(pid) || !rootProcess(pid) {
		return false
	}
	start, ok := procStart(pid)
	return ok && start <= l.Logged+asleep()
}

// commSSHD reports whether process pid's program is sshd (or sshd-session).
func commSSHD(pid string) bool {
	comm, err := os.ReadFile(procDir + "/" + pid + "/comm")
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(comm)), "sshd")
}

// rootProcess reports whether process pid runs as root: the real user id, the first of the Uid line of its status.
func rootProcess(pid string) bool {
	b, err := os.ReadFile(procDir + "/" + pid + "/status")
	if err != nil {
		return false
	}
	for line := range strings.Lines(string(b)) {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(rest)
			return len(f) > 0 && f[0] == "0"
		}
	}
	return false
}

// procStart returns when process pid started, since boot: /proc/<pid>/stat's field 22, in clock ticks at USER_HZ (100
// a second on Linux). The fields are counted after the program's name, which is in parentheses and may hold spaces and
// parentheses itself. The kernel counts it on the boot clock, which, unlike journald's monotonic one, runs on while
// the machine is suspended: isSSHD allows for the time spent asleep.
func procStart(pid string) (time.Duration, bool) {
	b, err := os.ReadFile(procDir + "/" + pid + "/stat")
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:])) // from field 3 (the state) on
	if len(f) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return 0, false
	}
	const userHZ = 100
	return time.Duration(ticks) * time.Second / userHZ, true
}

// monoNow is the monotonic clock now, the one journald stamps lines with (tests set their own).
var monoNow = monotonicNow

// endRevoked ends the SSH connections whose certificate krl revokes, and, with maxAge set (the tenant's certificate
// lifetime), those whose login was logged longer ago than that: those sshd logged as accepted (SSHDLogins), whose
// process is still the one that logged it (IsSSHD), signed by a CA key in cas or in the list. A certificate is signed
// before the login it is used for and lasts at most maxAge, so a connection logged in longer ago than maxAge has a
// certificate that has expired: one that expired before its access was removed is never on the list, and would
// otherwise stay open. Its age is counted on the monotonic clock, which stops while the machine is suspended, so it
// is never ended before its certificate expires (later by the time spent suspended). Ending the connection's privileged
// process closes it and ends its session. Processes the session left running on their own (under tmux, screen or
// nohup) are not ended. It reports how many connections it ended.
func (e *Env) endRevoked(ctx context.Context, krl *sshca.KRL, cas []ssh.PublicKey, maxAge time.Duration) (int, error) {
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
	now := monoNow()
	ended := map[int]bool{}
	var errs []error
	for _, l := range list {
		ca := byFP[l.CA]
		if ca == nil || ended[l.PID] {
			continue // another CA's, or ended already
		}
		why := "its certificate is revoked"
		if !krl.Revoked(ca, l.Serial, l.KeyID) {
			if maxAge <= 0 || now-l.Logged <= maxAge {
				continue
			}
			why = fmt.Sprintf("open longer than the certificate lifetime (%s), its certificate has expired", maxAge)
		}
		if !alive(l) {
			continue // the connection is gone
		}
		if err := end(l); err != nil {
			if !errors.Is(err, syscall.ESRCH) {
				errs = append(errs, fmt.Errorf("ending the connection of %s (serial %d, process %d): %w", l.KeyID, l.Serial, l.PID, err))
			}
			continue
		}
		ended[l.PID] = true
		fmt.Fprintf(e.out(), "ended the SSH connection of %s (serial %d, process %d): %s\n", l.KeyID, l.Serial, l.PID, why)
	}
	return len(ended), errors.Join(errs...)
}
