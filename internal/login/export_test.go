package login

import (
	"context"
	"encoding/json"
)

// MarkReauth records a fresh re-authentication for a session, at its user's current security generation, as one with a
// second factor (tests in package login_test cannot reach the ephemeral namespace).
func (m *Module) MarkReauth(sessionID string) { m.markReauthWith(sessionID, true) }

// MarkReauthPasswordOnly is MarkReauth for an account without a second factor of its own: its re-authentication
// is the password alone.
func (m *Module) MarkReauthPasswordOnly(sessionID string) { m.markReauthWith(sessionID, false) }

func (m *Module) markReauthWith(sessionID string, secondFactor bool) {
	ctx := context.Background()
	sess, err := m.s.Svc.Sessions.Get(ctx, sessionID)
	if err != nil {
		return
	}
	u, err := m.s.Svc.Users.Get(ctx, sess.UserID)
	if err != nil {
		return
	}
	m.markReauth(ctx, sessionID, u.SecurityGen, secondFactor)
}

// PutEnrolTicket creates a sign-in ticket at the enrol step for a user (as a verified password would), bound to the
// account as it is now.
func (m *Module) PutEnrolTicket(userID string) (string, error) {
	ctx := context.Background()
	u, err := m.s.Svc.Users.Get(ctx, userID)
	if err != nil {
		return "", err
	}
	t := &ticket{Step: "enrol", AMR: []string{"pwd"}}
	if err := m.bind(ctx, t, u); err != nil {
		return "", err
	}
	return m.putTicket(ctx, t, enrolTTL)
}

// ClearReauth forgets a session's re-authentication (as if its window had passed).
func (m *Module) ClearReauth(sessionID string) {
	_ = m.s.Eph.Delete(context.Background(), nsReauth, sessionID)
}

// AgeEmailCode makes the last code sent for a sign-in older than the resend interval, so another may be sent.
func (m *Module) AgeEmailCode(ticketID string) {
	ctx := context.Background()
	b, err := m.s.Eph.Get(ctx, nsEmailCode, ticketID)
	if err != nil {
		return
	}
	var st emailCode
	_ = json.Unmarshal(b, &st)
	st.Last = st.Last.Add(-emailResendEvery)
	b, _ = json.Marshal(st)
	_ = m.s.Eph.Set(ctx, nsEmailCode, ticketID, b, emailCodeTTL)
}

// EmailCodesPerHour is emailCodesPerHour, for the tests.
const EmailCodesPerHour = emailCodesPerHour
