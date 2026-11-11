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
	"path/filepath"
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

// journalRead is what a reading of sshd's log found: this boot's id, the certificate logins logged after the cursor
// it was asked to read from (every one of this boot when that cursor was of another boot, or none), and the cursor of
// the last line it read ("": none).
type journalRead struct {
	Boot   string
	Cursor string
	Logins []SSHDLogin
}

// journalLogins reads the certificate logins sshd logged to journald (sshd, or sshd-session from OpenSSH 9.8), as
// root, in this boot: those after cursor after when boot is this boot's id, else all of this boot's. Any local user
// can log a line that reads like sshd's, even from a program named sshd (_COMM is only the program's name); the user
// id is not theirs to choose: journald takes _UID from the credentials of the socket the line came in on. Matches on
// one field are ORed and on different fields ANDed: (sshd or sshd-session) and root. Each login carries when it was
// logged on the monotonic clock (__MONOTONIC_TIMESTAMP, which the JSON output always has, as it has _BOOT_ID and
// __CURSOR), not the wall clock: a clock stepped forward after the login (a resumed VM, a first NTP sync) would make
// the connection seem to have started after it. Lines from an earlier boot are left out: their monotonic times count
// from that boot, and their connections are gone.
func journalLogins(ctx context.Context, boot, after string) (journalRead, error) {
	b, err := os.ReadFile(procDir + "/sys/kernel/random/boot_id")
	if err != nil {
		return journalRead{}, fmt.Errorf("reading this boot's id: %w", err)
	}
	r := journalRead{Boot: strings.ReplaceAll(strings.TrimSpace(string(b)), "-", "")} // journald writes it without the dashes
	args := []string{"--no-pager", "--quiet", "--output=json", "--output-fields=MESSAGE,_PID", "--boot"}
	if boot == r.Boot && after != "" {
		args = append(args, "--after-cursor="+after)
	}
	cmd := exec.CommandContext(ctx, "journalctl", append(args, "_COMM=sshd", "_COMM=sshd-session", "_UID=0")...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return journalRead{}, fmt.Errorf("reading sshd's log with journalctl: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var entry struct {
			Message any    `json:"MESSAGE"` // a string, or an array of bytes when it is not UTF-8
			PID     string `json:"_PID"`
			Boot    string `json:"_BOOT_ID"`
			Logged  string `json:"__MONOTONIC_TIMESTAMP"` // microseconds since that boot
			Cursor  string `json:"__CURSOR"`
		}
		if json.Unmarshal(sc.Bytes(), &entry) != nil {
			continue
		}
		if entry.Cursor != "" {
			r.Cursor = entry.Cursor
		}
		msg, _ := entry.Message.(string)
		pid, err := strconv.Atoi(entry.PID)
		logged, terr := strconv.ParseInt(entry.Logged, 10, 64)
		if entry.Boot != r.Boot || err != nil || terr != nil || msg == "" {
			continue
		}
		if l, ok := parseAccepted(pid, msg); ok {
			l.Logged = time.Duration(logged) * time.Microsecond
			r.Logins = append(r.Logins, l)
		}
	}
	return r, sc.Err()
}

// loginState is what fetch --end-revoked keeps between runs (FetchOptions.StateFile): where it stopped reading sshd's
// log, and the certificate logins it has read whose connection is still open. So a connection is known for as long as
// it lasts, however long ago it was made, and each run reads only the lines logged since the last.
type loginState struct {
	Boot   string      `json:"boot"`
	Cursor string      `json:"cursor"`
	Logins []SSHDLogin `json:"logins"`
}

// trackedLogins returns the certificate logins whose connection is still open (alive): those kept in the state file
// at path, and those logged since. It writes the state back. The first run, and the first after a reboot or with a
// state file that cannot be read, reads the whole boot's log. A log that cannot be read is an error; a state that
// cannot be written is too, but the logins are still returned (the next run reads the same lines again).
func (e *Env) trackedLogins(ctx context.Context, path string, alive func(SSHDLogin) bool) ([]SSHDLogin, error) {
	read := e.SSHDLogins
	if read == nil {
		read = journalLogins
	}
	var st loginState
	if b, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(b, &st) != nil {
			st = loginState{} // unreadable: start over
		}
	}
	r, err := read(ctx, st.Boot, st.Cursor)
	if err != nil {
		return nil, err
	}
	if r.Boot != st.Boot {
		st = loginState{Boot: r.Boot} // another boot: its connections are gone
	}
	if r.Cursor != "" {
		st.Cursor = r.Cursor
	}
	type key struct {
		pid    int
		logged time.Duration
	}
	seen := map[key]bool{}
	var open []SSHDLogin
	for _, l := range append(st.Logins, r.Logins...) {
		k := key{l.PID, l.Logged}
		if seen[k] || !alive(l) {
			continue
		}
		seen[k] = true
		open = append(open, l)
	}
	st.Logins = open
	data, _ := json.Marshal(st)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return open, fmt.Errorf("keeping track of open logins in %s: %w", path, err)
	}
	if err := writeAtomic(path, data, 0o600); err != nil {
		return open, fmt.Errorf("keeping track of open logins in %s: %w", path, err)
	}
	return open, nil
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
// is never ended before its certificate expires (later by the time spent suspended). The connection is ended with its
// login session where it has one (terminate: what the session left running, under tmux or nohup, goes too), else by
// ending its privileged process. It reports how many connections it ended.
func (e *Env) endRevoked(ctx context.Context, krl *sshca.KRL, cas []ssh.PublicKey, maxAge time.Duration, state string) (int, error) {
	if e.goos() != "linux" {
		return 0, errors.New("--end-revoked works on Linux only: it reads sshd's log from journald")
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
	list, err := e.trackedLogins(ctx, state, alive)
	if list == nil && err != nil {
		return 0, err
	}
	now := monoNow()
	ended := map[int]bool{}
	errs := []error{err}
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
