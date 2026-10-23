package login

import (
	"context"
	"encoding/json"
)

// MarkReauth records a fresh re-authentication for a session (tests in package login_test cannot reach the
// ephemeral namespace).
func (m *Module) MarkReauth(sessionID string) {
	_ = m.s.Eph.Set(context.Background(), nsReauth, sessionID, []byte("1"), reauthTTL)
}

// PutEnrolTicket creates a sign-in ticket at the enrol step for a user (as a verified password would).
func (m *Module) PutEnrolTicket(userID string) (string, error) {
	return m.putTicket(context.Background(), &ticket{Step: "enrol", UserID: userID, AMR: []string{"pwd"}}, enrolTTL)
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
