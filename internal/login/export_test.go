package login

import "context"

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
