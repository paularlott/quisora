package service

import (
	"context"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// SweepAll runs the orphan sweep (SweepOrphans) once over every kind, judging records of any age: what a deletion
// left behind is gone when it returns. Owners come before what they own in sweepKinds, so one pass is enough.
func (s *Service) SweepAll(ctx context.Context) (int, error) {
	saved := sweepMinAge
	sweepMinAge = -time.Hour
	defer func() { sweepMinAge = saved }()
	var sw Sweep
	total := 0
	for {
		n, err := s.SweepOrphans(ctx, &sw, 1000)
		total += n
		if err != nil || (sw.kind == 0 && sw.after == "") {
			return total, err
		}
	}
}

// SelfRegRedirect reports whether a self-registered application may use uri as a redirect URI.
var SelfRegRedirect = selfRegRedirect

// WeakPassword is passwordcheck's test of a password against what it must not contain.
var WeakPassword = weakPassword

// RotateSSHScheduled is the scheduled rotation of tenant t's user CA key (EnsureSSHKeys makes it for a tenant that is
// due), without the check that the tenant has a key.
func (s *Service) RotateSSHScheduled(ctx context.Context, t *model.Tenant) (*model.SSHKey, error) {
	return s.rotateSSH(ctx, System, t, model.SSHPurposeUser, false, true)
}

// EnsureSSHKeysNow is EnsureSSHKeys that treats every leftover SSH application as old enough to remove.
func (s *Service) EnsureSSHKeysNow(ctx context.Context) error {
	saved := sweepMinAge
	sweepMinAge = -time.Hour
	defer func() { sweepMinAge = saved }()
	return s.EnsureSSHKeys(ctx)
}

// ForgetLegacyMarked makes the store look like one from before SetUpBy was recorded, whose old accounts have not all
// been marked yet (MarkLegacySetUpBy).
func (s *Service) ForgetLegacyMarked(ctx context.Context) error {
	return s.Locks.Delete(ctx, legacySetUpByID)
}
