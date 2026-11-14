package login

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// AgeSpray makes the last minute over the failure limit of an organization's password spray d earlier (spray.go).
func (m *Module) AgeSpray(orgID string, d time.Duration) {
	ctx := context.Background()
	st, err := readSpray(m.s.Eph.Get(ctx, nsSpray, orgID))
	if err != nil {
		return
	}
	st.Start, st.Last = st.Start.Add(-d), st.Last.Add(-d)
	b, _ := json.Marshal(st)
	_ = m.s.Eph.Set(ctx, nsSpray, orgID, b, sprayRecordTTL)
}

// NewSprayMinute starts a new minute of an organization's failed passwords (its counter for limits.org_failures_per_minute).
func (m *Module) NewSprayMinute(orgID string) {
	_ = m.s.Eph.Delete(context.Background(), nsSpray, "n|"+orgID)
}

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
	r, _ := http.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "192.0.2.250:1"
	return m.putTicket(r, t, enrolTTL, 0)
}

// ReadReauthStored stores raw as a session's re-authentication mark and reads it back as the account page does.
func (m *Module) ReadReauthStored(sessionID, raw string) (gen uint64, at time.Time, secondFactor, ok bool) {
	ctx := context.Background()
	_ = m.s.Eph.Set(ctx, nsReauth, sessionID, []byte(raw), time.Minute)
	return m.readReauth(ctx, sessionID)
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

// SpendUpstreamFailures counts n failed token exchanges of provider id at organization orgID, from every address
// together (upstreamReserve).
func (m *Module) SpendUpstreamFailures(orgID, id string, n int64) {
	_, _ = m.s.Eph.Incr(context.Background(), nsRate, "upstream-fail|"+orgID+"|"+id, n, time.Minute)
}

// The limits on failed token exchanges (upstreamReserve), for the tests.
const UpstreamFailPerProviderMin, UpstreamFailPerIPMin, UpstreamFailPerNetMin = upstreamFailPerProviderMin,
	upstreamFailPerIPMin, upstreamFailPerNetMin
