package sshcli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// terminate ends the connection of login l. The process is held by a pidfd before it is checked again (isSSHD), and
// signalled through it: if the number was taken by another process between the check and the signal, the pidfd still
// names the process checked, and the signal fails (ESRCH) instead of reaching the newcomer. A kernel without pidfds
// (before 5.3) gets a plain kill, after the check endRevoked has just made.
//
// Where the connection has a login session of its own (systemd-logind, through sshd's PAM: the process is the leader
// of a session-<id>.scope), the whole session is ended (loginctl terminate-session), which ends what the session left
// running in it too: tmux, screen, nohup. Otherwise, or if that fails, only the process is signalled, which closes the
// connection and its shell.
func terminate(l SSHDLogin) error {
	fd, err := unix.PidfdOpen(l.PID, 0)
	if errors.Is(err, syscall.ENOSYS) {
		return syscall.Kill(l.PID, syscall.SIGTERM)
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if !isSSHD(l) {
		return syscall.ESRCH
	}
	if id := loginSession(l.PID); id != "" && endLoginSession(id, l.PID) == nil {
		return nil
	}
	return unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0)
}

// loginSession returns the id of the logind session whose scope process pid is in ("" when none):
// 0::/user.slice/user-1000.slice/session-785.scope is session 785.
func loginSession(pid int) string {
	b, err := os.ReadFile(procDir + "/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(b)) {
		path := strings.TrimSpace(line[strings.LastIndexByte(line, ':')+1:])
		if id, ok := strings.CutPrefix(path[strings.LastIndexByte(path, '/')+1:], "session-"); ok {
			if id, ok = strings.CutSuffix(id, ".scope"); ok && id != "" && !strings.ContainsAny(id, "./ ") {
				return id
			}
		}
	}
	return ""
}

// endLoginSession ends logind session id, only while process pid is its leader: a connection made without PAM is
// in the scope of whoever started sshd, a session that is not the connection's.
func endLoginSession(id string, pid int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "loginctl", "show-session", id, "--property=Leader", "--value").Output()
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != strconv.Itoa(pid) {
		return errors.New("the connection does not lead its login session")
	}
	return exec.CommandContext(ctx, "loginctl", "terminate-session", id).Run()
}

// timeAsleep is how long this boot has spent suspended: the boot clock, which runs on through a suspend, less the
// monotonic one, which stops. Zero if either cannot be read.
func timeAsleep() time.Duration {
	var boot, mono unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil || unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono) != nil {
		return 0
	}
	return max(time.Duration(boot.Nano()-mono.Nano()), 0)
}

// monotonicNow is the monotonic clock (CLOCK_MONOTONIC, journald's __MONOTONIC_TIMESTAMP), or zero if it cannot be read.
func monotonicNow() time.Duration {
	var mono unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono) != nil {
		return 0
	}
	return time.Duration(mono.Nano())
}
