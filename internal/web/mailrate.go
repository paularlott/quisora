package web

import (
	"context"
	"time"
)

// Test emails (POST /api/orgs/{org}/email-templates/test) carry text an administrator wrote to an address they chose,
// from the server's own mail identity: a few a minute and some dozens an hour per administrator are plenty to check a
// template, and keep the endpoint from being used to relay mail. Counted in the OAuth counters' namespace, like the
// SSH limits; a counter that cannot be read is an error, not a verdict.
const (
	TestEmailsPerMinute = 5
	TestEmailsPerHour   = 30
)

// TestEmailAllowed counts a test email by user userID and reports whether it is within the limits.
func (s *Server) TestEmailAllowed(ctx context.Context, userID string) (bool, error) {
	if s.Eph == nil {
		return true, nil
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, "mail-test|m|"+userID, 1, time.Minute)
	if err != nil {
		return false, err
	}
	nh, err := s.Eph.Incr(ctx, sshRateNS, "mail-test|h|"+userID, 1, time.Hour)
	if err != nil {
		return false, err
	}
	return n <= TestEmailsPerMinute && nh <= TestEmailsPerHour, nil
}
