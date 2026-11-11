package sshcli

import (
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// terminate ends the connection of login l (SIGTERM to its process). The process is held by a pidfd before it is
// checked again (isSSHD), and signalled through it: if the number was taken by another process between the check and
// the signal, the pidfd still names the process checked, and the signal fails (ESRCH) instead of reaching the newcomer.
// A kernel without pidfds (before 5.3) gets a plain kill, after the check endRevoked has just made.
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
	return unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0)
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
