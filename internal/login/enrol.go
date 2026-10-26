package login

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// Organizations that require MFA hold a password-verified user without a second factor at the "enrol" step until
// they register an authenticator app or a passkey; the session is created only when that succeeds.

type enrolBeginReq struct {
	Ticket string `json:"ticket"`
}

type totpBeginResp struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QR     string `json:"qr"`
}

func (m *Module) totpDetails(u *model.User, secret string) (totpBeginResp, error) {
	account := u.Email
	if account == "" {
		account = u.Username
	}
	uri := secure.TOTPURI(m.s.Cfg.UI.SiteName, account, secret)
	qr, err := qrDataURL(uri)
	return totpBeginResp{Secret: secret, URI: uri, QR: qr}, err
}

// enrolTicket validates a ticket at the enrol step and loads its user and org (step: the ticket still bound to the
// account as it is now, so a password changed or a factor set up since the ticket was issued ends it). The step
// exists only for an account with no second factor at all, and that is checked again here against the account as it
// is now, not as it was when the ticket was issued: whoever holds a first factor may choose the second only for an
// account that never had one. An account that has one meanwhile (its owner set it up from another browser) sends
// this browser back to sign in and use it; the first-factor-only ticket must never replace it.
func (m *Module) enrolTicket(w http.ResponseWriter, r *http.Request, id string) (*ticket, *model.User, *model.Org, bool) {
	t, u, org, ok := m.step(w, r, id, "enrol")
	if !ok {
		return nil, nil, nil, false
	}
	established := u.HasTOTP()
	if !established {
		n, err := m.s.Svc.HeldPasskeys(r.Context(), u) // any passkey of the account, usable or not (see secondFactor)
		if err != nil {
			m.internalError(w, r, "count passkeys", err)
			return nil, nil, nil, false
		}
		established = n > 0
	}
	if established {
		writeErr(w, http.StatusConflict, "A second factor is already set up on this account. Sign in again and use it.", "")
		return nil, nil, nil, false
	}
	return t, u, org, true
}

// msgChanged answers a step whose commit found the account changed under it (a stale compare-and-swap): another
// completion of the sign-in, or its owner, got there first.
const msgChanged = "Your account changed while you were signing in. Start again."

// enrolTOTPBegin handles POST /api-internal/login/enrol/totp/begin: {ticket} -> {secret, uri, qr}.
func (m *Module) enrolTOTPBegin(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in enrolBeginReq
	if !decode(w, r, &in) {
		return
	}
	t, u, _, ok := m.enrolTicket(w, r, in.Ticket)
	if !ok {
		return
	}
	secret := secure.NewTOTPSecret()
	t.Pending = m.s.Svc.Sealer.SealFor(pendingTOTPBinding("ticket", in.Ticket), []byte(secret))
	b, _ := json.Marshal(t)
	if err := m.s.Eph.Set(r.Context(), nsTicket, in.Ticket, b, enrolTTL); err != nil {
		m.internalError(w, r, "ticket", err)
		return
	}
	resp, err := m.totpDetails(u, secret)
	if err != nil {
		m.internalError(w, r, "qr", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, resp)
}

type enrolConfirmReq struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// enrolTOTPConfirm handles POST /api-internal/login/enrol/totp/confirm: {ticket, code} -> {next}.
func (m *Module) enrolTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in enrolConfirmReq
	if !decode(w, r, &in) {
		return
	}
	t, u, org, ok := m.enrolTicket(w, r, in.Ticket)
	if !ok {
		return
	}
	ctx := r.Context()
	if t.Pending == "" {
		writeErr(w, http.StatusConflict, "Start the Authenticator App set-up first.", "")
		return
	}
	if !m.attempt(ctx, in.Ticket) {
		writeErr(w, http.StatusUnauthorized, "Too many incorrect codes. Start again.", "")
		return
	}
	secret, err := m.s.Svc.Sealer.OpenFor(pendingTOTPBinding("ticket", in.Ticket), t.Pending)
	if err != nil {
		m.internalError(w, r, "open pending secret", err)
		return
	}
	step, good := secure.VerifyTOTP(string(secret), in.Code, time.Now(), 0)
	if !good {
		writeErr(w, http.StatusUnauthorized, "That code is incorrect. Check the time on your device and try again.", "code")
		return
	}
	if !m.useTicket(ctx, in.Ticket) {
		writeErr(w, http.StatusUnauthorized, msgExpired, "")
		return
	}
	// The commit: a compare-and-swap on the version of the user enrolTicket read and validated this request (no
	// factor, same generation as the ticket), moving the security generation on. Two completions for the same
	// account — this ticket twice, or two tickets issued from the same password — both read the same version, and
	// the store lets exactly one write it (the owner of the record's partition decides which); the other finds it stale and
	// sends its browser back to sign in, where the factor that won now stands between it and a session.
	if err := m.s.Svc.SetTOTP(ctx, u, secret, step); err != nil {
		if errors.Is(err, store.ErrStale) {
			writeErr(w, http.StatusConflict, msgChanged, "")
			return
		}
		m.internalError(w, r, "save totp", err)
		return
	}
	m.audit(r, "account.totp.enable", org, u, u.Username, map[string]string{"during": "sign-in"})
	amr := append(append([]string{}, t.AMR...), "otp", "mfa")
	dest, err := m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr, Provider: t.Provider}, t.Next)
	if err != nil {
		m.internalError(w, r, "create session", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
}

// enrolPasskeyBegin handles POST /api-internal/login/enrol/passkey/begin: {ticket} -> {challenge, options}.
func (m *Module) enrolPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) || !m.passkeysOK(w) {
		return
	}
	var in enrolBeginReq
	if !decode(w, r, &in) {
		return
	}
	_, u, _, ok := m.enrolTicket(w, r, in.Ticket)
	if !ok {
		return
	}
	id, opts, err := m.Passkeys.BeginRegistration(r.Context(), u, map[string]string{passkey.PurposeKey: purposeEnrol})
	if err != nil {
		m.internalError(w, r, "passkey registration", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, passkeyBeginResp{Challenge: id, Options: opts})
}

type enrolPasskeyFinishReq struct {
	Ticket     string          `json:"ticket"`
	Challenge  string          `json:"challenge"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

// enrolPasskeyFinish handles POST /api-internal/login/enrol/passkey/finish -> {next}.
func (m *Module) enrolPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) || !m.passkeysOK(w) {
		return
	}
	var in enrolPasskeyFinishReq
	if !decode(w, r, &in) {
		return
	}
	t, u, org, ok := m.enrolTicket(w, r, in.Ticket)
	if !ok {
		return
	}
	ctx := r.Context()
	if !m.attempt(ctx, in.Ticket) {
		writeErr(w, http.StatusUnauthorized, "Too many failed attempts. Start again.", "")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "Passkey"
	}
	// Verify first (a response that does not verify leaves the ticket for another try), then use the ticket up, then
	// commit: StoreRegistration moves the account's security generation on with a compare-and-swap on the version
	// enrolTicket read this request — a concurrent completion, or the owner's own set-up, makes this one stale and
	// nothing is stored — and then writes the passkey (as the authenticator-app commit above).
	reg, err := m.Passkeys.VerifyRegistrationAs(ctx, purposeEnrol, u, in.Challenge, in.Credential, name)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "The passkey could not be registered. Try again.", "")
		return
	}
	if !m.useTicket(ctx, in.Ticket) {
		writeErr(w, http.StatusUnauthorized, msgExpired, "")
		return
	}
	pk, err := m.Passkeys.StoreRegistration(ctx, u, reg)
	if errors.Is(err, store.ErrStale) {
		writeErr(w, http.StatusConflict, msgChanged, "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "The passkey could not be registered. Try again.", "")
		return
	}
	m.audit(r, "account.passkey.add", org, u, u.Username, map[string]string{"during": "sign-in", "name": pk.Name})
	k := "hwk"
	if pk.BackupEligible {
		k = "swk"
	}
	amr := append(append([]string{}, t.AMR...), k)
	if pk.UserVerified {
		amr = append(amr, "user")
	}
	amr = append(amr, "mfa")
	dest, err := m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr, Passkey: pk.ID, Provider: t.Provider}, t.Next)
	if err != nil {
		m.internalError(w, r, "create session", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
}

// pendingTOTPBinding binds an authenticator-app secret being set up to the sign-in step (ticket) or session it was
// made for: a sealed secret copied into another one's pending slot does not open there.
func pendingTOTPBinding(kind, id string) string { return "pending totp|" + kind + "|" + id }
