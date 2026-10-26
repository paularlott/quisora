package service

import (
	"context"
	"time"
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

// SetPrimaryChoiceTTL sets how long PrimaryOrg remembers its choice, until the test ends.
func SetPrimaryChoiceTTL(t interface{ Cleanup(func()) }, d time.Duration) {
	old := primaryChoiceTTL
	primaryChoiceTTL = d
	t.Cleanup(func() { primaryChoiceTTL = old })
}
