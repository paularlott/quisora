package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/web"
)

// Email codes: a second factor by email, for organizations that turn it on (OrgSettings.EmailCodes). A six-digit
// code goes to the user's verified address and finishes the sign-in it was sent for: it is bound to that sign-in's
// ticket (stored as a hash under it), works once, and lasts emailCodeTTL. It is offered to people without an
// authenticator app or passkey when a second factor is required (instead of setting one up), and under "Try another
// way" to those with one. Managers and above never use it: their second factor is their own app or passkey. A wrong
// code counts towards the lockout like a wrong authenticator code, and a sign-in can have a new code sent at most
// every emailResendEvery and emailSendsPerSignIn times.
const (
	nsEmailCode         = "login.emailcode"
	emailCodeTTL        = 10 * time.Minute
	emailResendEvery    = 30 * time.Second
	emailSendsPerSignIn = 5
)

// emailCode is the code sent for one sign-in (ephemeral, ns login.emailcode, keyed by the ticket).
type emailCode struct {
	Hash  []byte    `json:"h"`
	Sends int       `json:"n"`
	Last  time.Time `json:"t"`
}

// emailOK reports whether u may give the second factor by email: the organization allows it (on), email is set
// up, the address is verified, and u is not a manager or above.
func (m *Module) emailOK(u *model.User, on bool) bool {
	return on && m.Mail != nil && u.Email != "" && u.EmailVerified && !u.Role.Privileged()
}

// maskEmail shows enough of an address to recognise it: a•••@example.com.
func maskEmail(addr string) string {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" {
		return "your email address"
	}
	return string([]rune(local)[:1]) + "•••@" + domain
}

func codeHash(ticketID, code string) []byte {
	sum := sha256.Sum256([]byte("quisora email code\x00" + ticketID + "\x00" + code))
	return sum[:]
}

var (
	errCodeTooSoon  = errors.New("a code was sent moments ago: wait a little before asking for another")
	errCodeTooMany  = errors.New("too many codes were sent for this sign-in: start again")
	errCodeNotReady = errors.New("no code was sent for this sign-in")
)

// sendEmailCode emails u a new code for the sign-in ticketID (the previous one stops working).
func (m *Module) sendEmailCode(ctx context.Context, ticketID string, u *model.User, org *model.Org) error {
	var st emailCode
	if b, err := m.s.Eph.Get(ctx, nsEmailCode, ticketID); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	switch {
	case st.Sends >= emailSendsPerSignIn:
		return errCodeTooMany
	case !st.Last.IsZero() && time.Since(st.Last) < emailResendEvery:
		return errCodeTooSoon
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	st = emailCode{Hash: codeHash(ticketID, code), Sends: st.Sends + 1, Last: time.Now()}
	b, _ := json.Marshal(st)
	if err := m.s.Eph.Set(ctx, nsEmailCode, ticketID, b, emailCodeTTL); err != nil {
		return err
	}
	return m.Mail.SendSignInCode(ctx, u, org, code, emailCodeTTL)
}

// checkEmailCode reports whether code is the one sent for ticketID, and uses it up when it is.
func (m *Module) checkEmailCode(ctx context.Context, ticketID, code string) (bool, error) {
	b, err := m.s.Eph.Get(ctx, nsEmailCode, ticketID)
	if err != nil {
		return false, errCodeNotReady
	}
	var st emailCode
	if json.Unmarshal(b, &st) != nil {
		return false, errCodeNotReady
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 || subtle.ConstantTimeCompare(codeHash(ticketID, code), st.Hash) != 1 {
		return false, nil
	}
	_ = m.s.Eph.Delete(ctx, nsEmailCode, ticketID)
	return true, nil
}

// emailStep loads the sign-in a request continues: its ticket (a second-factor step), user and organization, with
// email codes allowed for them. It writes the error answer itself.
func (m *Module) emailStep(w http.ResponseWriter, r *http.Request, ticketID string) (*ticket, *model.User, *model.Org, bool) {
	ctx := r.Context()
	expired := func() { writeErr(w, http.StatusUnauthorized, "Your sign-in has expired. Start again.", "") }
	t, ok := m.getTicket(ctx, ticketID, "email_code", "totp", "passkey")
	if !ok {
		expired()
		return nil, nil, nil, false
	}
	u, err := m.s.Svc.Users.Get(ctx, t.UserID)
	if err != nil || !u.Enabled(time.Now()) {
		expired()
		return nil, nil, nil, false
	}
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if err != nil {
		expired()
		return nil, nil, nil, false
	}
	if !m.emailOK(u, org.Settings.EmailCodes) {
		writeErr(w, http.StatusForbidden, "Signing in with an emailed code is not available for this account.", "")
		return nil, nil, nil, false
	}
	return t, u, org, true
}

type emailSendReq struct {
	Ticket string `json:"ticket"`
}

// emailSend handles POST /api-internal/login/email/send: {ticket} -> {email}. It sends a code for the sign-in (a new
// one when asked again).
func (m *Module) emailSend(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in emailSendReq
	if !decode(w, r, &in) {
		return
	}
	_, u, org, ok := m.emailStep(w, r, in.Ticket)
	if !ok || !m.rateLimit(w, r, org.Name, known{userID: u.ID}) {
		return
	}
	if err := m.sendEmailCode(r.Context(), in.Ticket, u, org); err != nil {
		switch {
		case errors.Is(err, errCodeTooSoon):
			writeErr(w, http.StatusTooManyRequests, "A code was sent moments ago. Wait a little before asking for another.", "")
		case errors.Is(err, errCodeTooMany):
			writeErr(w, http.StatusTooManyRequests, "Too many codes were sent for this sign-in. Start again.", "")
		default:
			m.internalError(w, r, "send email code", err)
		}
		return
	}
	m.audit(r, "login.email_code.sent", org, u, u.Username, nil)
	web.WriteJSON(w, http.StatusOK, map[string]string{"email": maskEmail(u.Email)})
}

type emailVerifyReq struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// emailVerify handles POST /api-internal/login/email: {ticket, code} -> {next}.
func (m *Module) emailVerify(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in emailVerifyReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	t, u, org, ok := m.emailStep(w, r, in.Ticket)
	if !ok || !m.rateLimit(w, r, org.Name, known{userID: u.ID}) {
		return
	}
	key := m.lockKeyFor(r, u, u.ID)
	if m.locked(ctx, key) {
		m.audit(r, "login.failure", org, u, u.Username, map[string]string{"reason": "locked"})
		m.lockedResponse(w)
		return
	}
	if !m.attempt(ctx, in.Ticket) {
		writeErr(w, http.StatusUnauthorized, "Too many incorrect codes. Start again.", "")
		return
	}
	good, err := m.checkEmailCode(ctx, in.Ticket, in.Code)
	if errors.Is(err, errCodeNotReady) {
		writeErr(w, http.StatusConflict, "No code has been sent for this sign-in. Ask for one first.", "")
		return
	}
	if !good {
		m.failed(w, r, key, org, u, u.Username, "email_code")
		return
	}
	if !m.useTicket(ctx, in.Ticket) {
		writeErr(w, http.StatusUnauthorized, "Your sign-in has expired. Start again.", "")
		return
	}
	// A one-time code as the second factor (RFC 8176 "otp"), as an authenticator code is.
	amr := append(append([]string{}, t.AMR...), "otp", "mfa")
	dest, err := m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr, Provider: t.Provider}, t.Next)
	if err != nil {
		m.internalError(w, r, "create session", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
}
