package web

import (
	"context"
	"time"
)

// Caller verification (service.StartCallVerification) codes are six digits: a person signed in to the account could
// guess one by trying codes, so wrong codes are limited per account, and an agent's starts per hour (each start puts a
// code out). Counted as the test emails are; a counter that cannot be read is an error, not a verdict.
const (
	VerifyWrongCodesPer10Min = 5
	VerifyStartsPerHour      = 60
)

// VerifyCodeTriesLeft reports whether user userID may enter another caller verification code: fewer than
// VerifyWrongCodesPer10Min wrong ones in the last ten minutes or so.
func (s *Server) VerifyCodeTriesLeft(ctx context.Context, userID string) (bool, error) {
	if s.Eph == nil {
		return true, nil
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, "verify-code|"+userID, 0, 10*time.Minute)
	if err != nil {
		return false, err
	}
	return n < VerifyWrongCodesPer10Min, nil
}

// VerifyCodeWrong counts a wrong caller verification code entered by user userID.
func (s *Server) VerifyCodeWrong(ctx context.Context, userID string) {
	if s.Eph != nil {
		_, _ = s.Eph.Incr(ctx, sshRateNS, "verify-code|"+userID, 1, 10*time.Minute)
	}
}

// VerifyStartAllowed counts a caller verification started by agent userID and reports whether it is within the limit.
func (s *Server) VerifyStartAllowed(ctx context.Context, userID string) (bool, error) {
	if s.Eph == nil {
		return true, nil
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, "verify-start|"+userID, 1, time.Hour)
	if err != nil {
		return false, err
	}
	return n <= VerifyStartsPerHour, nil
}
