//go:build !linux

package sshcli

import (
	"errors"
	"time"
)

// terminate is Linux only, as --end-revoked is (endRevoked refuses elsewhere before it gets here).
func terminate(SSHDLogin) error { return errors.ErrUnsupported }

// timeAsleep is Linux only too.
func timeAsleep() time.Duration { return 0 }

// monotonicNow is Linux only too.
func monotonicNow() time.Duration { return 0 }
