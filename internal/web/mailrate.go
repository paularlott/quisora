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

// Invitations and verification links sent by an administrator, a manager or a service account go to any address they
// enter, from the organization's own templates (which its administrators write), from the server's mail identity:
// without a limit the user endpoints would relay mail as the test email would. A budget per organization, generous
// enough to invite a whole team in an afternoon, bounds it. Counted as the test emails are.
const AdminEmailsPerHour = 300

// AdminEmailAllowed reports whether organization orgID's administration may send another email within its budget. It
// only reads the count: AdminEmailSent counts an email once it is sent, so a request refused before or after this
// check (a bad address, mail switched off) spends nothing.
func (s *Server) AdminEmailAllowed(ctx context.Context, orgID string) (bool, error) {
	if s.Eph == nil {
		return true, nil
	}
	n, err := s.Eph.Incr(ctx, sshRateNS, adminEmailKey(orgID), 0, time.Hour)
	if err != nil {
		return false, err
	}
	return n < AdminEmailsPerHour, nil
}

// AdminEmailSent counts an email sent on behalf of organization orgID's administration. The email is gone: a count
// that cannot be written now does not undo it. Requests at the same moment can each pass AdminEmailAllowed, so the
// budget can be overrun by as many as arrive together.
func (s *Server) AdminEmailSent(ctx context.Context, orgID string) {
	if s.Eph != nil {
		_, _ = s.Eph.Incr(ctx, sshRateNS, adminEmailKey(orgID), 1, time.Hour)
	}
}

func adminEmailKey(orgID string) string { return "mail-admin|h|" + orgID }
