package login

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

type passwordReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Next     string `json:"next"`
	Tenant   string `json:"tenant"`
}

type stepResp struct {
	Step    string   `json:"step,omitempty"`
	Ticket  string   `json:"ticket,omitempty"`
	Next    string   `json:"next,omitempty"`
	Methods []string `json:"methods,omitempty"`
	// Alternatives are the other ways this account can give its second factor at a totp or passkey step ("passkey",
	// "email_code", "recovery"): the page's "Try another way" offers only these.
	Alternatives []string `json:"alternatives,omitempty"`
	// Email is the address an email code goes to, masked (a step "email_code").
	Email string `json:"email,omitempty"`
}

// alternatives lists the other ways u can give the second factor at step (see stepResp.Alternatives): a passkey
// instead of the authenticator code, and recovery codes when some are left. Never an emailed code: an account with an
// authenticator app or a passkey keeps it as its second factor (a code by email is weaker, and offering it would let
// whoever reads the mailbox and knows the password past the stronger factor); a lost device is what recovery codes
// are for.
func (m *Module) alternatives(ctx context.Context, u *model.User, step string) []string {
	var out []string
	if step == "totp" && m.Passkeys != nil {
		if n, err := m.s.Svc.UsablePasskeys(ctx, u, ""); err == nil && n > 0 {
			out = append(out, "passkey")
		}
	}
	if step == "totp" || step == "passkey" {
		if left, _ := m.s.Svc.RecoveryCodesLeft(ctx, u); left > 0 {
			out = append(out, "recovery")
		}
	}
	return out
}

// password handles POST /o/{org}/api-internal/login/password: {email, password[, next, tenant]} -> {next} or
// {step, ticket}.
func (m *Module) password(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in passwordReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	org := web.Org(r)
	if !m.rateLimit(w, r, org.ID, m.knownLogin(org, in.Email)) {
		return
	}
	login := strings.TrimSpace(in.Email) // the email address; the username never signs in
	if login == "" || in.Password == "" || len(login) > 256 || len(in.Password) > 1024 {
		writeErr(w, http.StatusUnprocessableEntity, "Enter your email address and password.", "email")
		return
	}
	eff, tenant, err := m.methods(ctx, org, in.Tenant, in.Next)
	if err != nil {
		m.internalError(w, r, "sign-in methods", err)
		return
	}
	var u *model.User
	if eff.Password {
		u, err = m.s.Svc.FindUserByEmail(ctx, org.ID, login)
		if err != nil && !errors.Is(err, service.ErrNotFound) {
			// The store could not say whether the account exists: that is no wrong password, so no failure is
			// audited and no lockout is charged to a person who may well have typed the right one.
			unavailableResponse(w)
			return
		}
	} // else: treated like an unknown user (generic failure after a dummy hash), so a switched-off org or tenant looks the same
	key := m.lockKeyFor(r, u, lockKey(u, org, login))
	n, open, err := m.charge(ctx, org, key)
	if err != nil { // the counter failed: refused, but not a lockout
		unavailableResponse(w)
		return
	}
	if !open {
		m.audit(r, "login.failure", org, u, login, map[string]string{"reason": "locked"})
		m.lockedResponse(w, org)
		return
	}
	wrong := false
	defer m.settle(ctx, org, key, &wrong)

	// Always spend one password hash, whatever is wrong, so timing does not reveal which accounts exist.
	check := u
	if u != nil && !u.Enabled(time.Now()) {
		check = nil
	}
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ok, err := m.s.Svc.VerifyPassword(vctx, org.ID, check, in.Password)
	cancel()
	if errors.Is(err, secure.ErrBusy) {
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, "The server is busy. Please try again in a moment.", "")
		return
	}
	if err != nil {
		m.internalError(w, r, "password verify", err)
		return
	}
	if !ok || u == nil || !u.Enabled(time.Now()) {
		reason := "bad password"
		switch {
		case u == nil:
			reason = "unknown user"
		case !u.Enabled(time.Now()):
			reason = "inactive"
		}
		wrong = true
		m.failed(w, r, n, org, u, login, reason)
		return
	}

	m.afterPassword(w, r, u, org, eff, tenant, safeNext(org, in.Next))
}

// secondFactor decides what follows a first factor (a password, or a sign-in at an upstream provider): the user's
// TOTP code when they have one; when the org or tenant requires MFA, or the user is a manager or above, their
// passkey (if they have one) or enrolment;
// otherwise nothing (""). It stores the step's ticket. A provider's own claims about MFA are never trusted: a
// federated sign-in is a first factor like a password.
func (m *Module) secondFactor(r *http.Request, u *model.User, eff *service.SignInMethods, t ticket) (stepResp, error) {
	ctx := r.Context()
	if err := m.bind(ctx, &t, u); err != nil {
		return stepResp{}, err
	}
	ttl := ticketTTL
	switch {
	case u.HasTOTP():
		t.Step = "totp"
	case eff.RequireMFA || u.Role.Privileged(): // managers and above always use a second factor
		t.Step, ttl = "enrol", enrolTTL
		usable, err := m.s.Svc.UsablePasskeys(ctx, u, "")
		if err != nil {
			return stepResp{}, err
		}
		if usable > 0 && m.Passkeys != nil {
			t.Step = "passkey" // has a passkey as the second factor: the first factor alone is not enough
			break
		}
		// Enrolment here lets whoever holds the first factor choose the second, which is only right for an account
		// that never had one (passkeys of an earlier credential epoch, made inert by a reset, do not count). An
		// account whose passkeys can no longer sign in (disabled after a suspected clone, or registered without user
		// verification) keeps them as evidence that it had a second factor: it gets a new one through an invitation
		// from an administrator, not from the password.
		if held, err := m.s.Svc.HeldPasskeys(ctx, u); err != nil {
			return stepResp{}, err
		} else if held > 0 {
			return stepResp{}, errFactorLost
		}
		// No factor of their own, and the organization takes a code by email: emailed now, instead of setting one up.
		if m.emailOK(u, eff.EmailCodes) {
			t.Step, ttl = "email_code", emailCodeTTL
		}
	default:
		return stepResp{}, nil
	}
	id, err := m.putTicket(ctx, &t, ttl)
	if err != nil {
		return stepResp{}, err
	}
	resp := stepResp{Step: t.Step, Ticket: id, Alternatives: m.alternatives(ctx, u, t.Step)}
	if t.Step == "email_code" {
		resp.Email = maskEmail(u.Email)
		org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
		if err != nil {
			return stepResp{}, err
		}
		// An account sent its hourly allowance of codes still gets the step: asking for a code there says why none came.
		switch err := m.sendEmailCode(ctx, id, u, org); {
		case err == nil:
			m.audit(r, "login.email_code.sent", org, u, u.Username, nil)
		case !errors.Is(err, errCodeHourly):
			return stepResp{}, err
		}
	}
	if t.Step == "enrol" {
		resp.Methods = []string{"totp"}
		if m.Passkeys != nil {
			resp.Methods = append(resp.Methods, "passkey")
		}
	}
	return resp, nil
}

// afterPassword continues a sign-in whose password step has succeeded: a second factor when one is due
// (secondFactor), otherwise the session.
func (m *Module) afterPassword(w http.ResponseWriter, r *http.Request, u *model.User, org *model.Org, eff *service.SignInMethods, tenant, next string) {
	step, err := m.secondFactor(r, u, eff, ticket{Next: next, AMR: []string{"pwd"}, Tenant: tenant})
	if errors.Is(err, errFactorLost) {
		m.audit(r, "login.failure", org, u, "", map[string]string{"reason": "second factor unusable"})
		writeErr(w, http.StatusForbidden, msgFactorLost, "")
		return
	}
	if err != nil {
		m.internalError(w, r, "ticket", err)
		return
	}
	if step.Step != "" {
		web.WriteJSON(w, http.StatusOK, step)
		return
	}
	dest, err := m.complete(w, r, u, org, []string{"pwd"}, next)
	if err != nil {
		m.internalError(w, r, "create session", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
}

// failed records the n-th failed attempt (charge: audit, lockout event) and answers with the generic message.
func (m *Module) failed(w http.ResponseWriter, r *http.Request, n int64, org *model.Org, u *model.User, login, reason string) {
	m.audit(r, "login.failure", org, u, login, map[string]string{"reason": reason})
	if m.tripped(org, n) && u != nil {
		m.audit(r, "login.lockout", org, u, login, map[string]string{"minutes": strconv.Itoa(int(m.lockWindow(org).Minutes()))})
	}
	field := ""
	msg := msgBadLogin
	switch reason {
	case "totp":
		msg, field = "That code is incorrect or has already been used.", "code"
	case "recovery_code":
		msg, field = "That recovery code is incorrect or has already been used.", "rcode"
	case "email_code":
		msg, field = "That code is incorrect, or a newer one was sent.", "mcode"
	}
	writeErr(w, http.StatusUnauthorized, msg, field)
}

type totpReq struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// totp handles POST /o/{org}/api-internal/login/totp: {ticket, code} -> {next}.
func (m *Module) totp(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in totpReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	t, u, org, ok := m.step(w, r, in.Ticket, "totp")
	if !ok {
		return
	}
	if !u.HasTOTP() { // (unreachable while the ticket is current: removing the app moves the generation on)
		writeErr(w, http.StatusUnauthorized, msgExpired, "")
		return
	}
	key := m.lockKeyFor(r, u, u.ID)
	n, open, err := m.charge(ctx, org, key)
	if err != nil { // the counter failed: refused, but not a lockout
		unavailableResponse(w)
		return
	}
	if !open {
		m.audit(r, "login.failure", org, u, u.Username, map[string]string{"reason": "locked"})
		m.lockedResponse(w, org)
		return
	}
	wrong := false
	defer m.settle(ctx, org, key, &wrong)
	within, err := m.attempt(ctx, in.Ticket)
	if err != nil { // the counter failed: refused, but not as too many tries
		unavailableResponse(w)
		return
	}
	if !within {
		writeErr(w, http.StatusUnauthorized, "Too many incorrect codes. Start again.", "")
		return
	}
	secret, err := m.s.Svc.Sealer.OpenFor(service.TOTPBinding(u.ID), u.TOTPSecret)
	if err != nil {
		m.internalError(w, r, "open totp secret", err)
		return
	}
	good, err := m.consumeTOTP(ctx, u, string(secret), in.Code)
	if err != nil { // the step could not be recorded (or may have been): try again, not a wrong code, no failure counted
		m.internalError(w, r, "record totp step", err)
		return
	}
	if !good {
		wrong = true
		m.failed(w, r, n, org, u, u.Username, "totp")
		return
	}
	if err := m.useTicket(ctx, in.Ticket); err != nil {
		ticketFailed(w, err)
		return
	}
	amr := append(append([]string{}, t.AMR...), "otp", "mfa")
	dest, err := m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr, Provider: t.Provider, UpstreamAMR: t.UpstreamAMR, Upstream: t.Upstream}, t.Next)
	if err != nil {
		m.internalError(w, r, "create session", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
}

type recoveryReq struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// recovery handles POST /o/{org}/api-internal/login/recovery: {ticket, code} -> {next}. A recovery code stands in for the
// second factor a sign-in asks for after the first (an authenticator code, or a passkey), once. It counts towards
// the lockout like a wrong authenticator code, and its owner is emailed when one is used.
func (m *Module) recovery(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in recoveryReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	t, u, org, ok := m.step(w, r, in.Ticket, "totp", "passkey")
	if !ok {
		return
	}
	key := m.lockKeyFor(r, u, u.ID)
	n, open, err := m.charge(ctx, org, key)
	if err != nil { // the counter failed: refused, but not a lockout
		unavailableResponse(w)
		return
	}
	if !open {
		m.audit(r, "login.failure", org, u, u.Username, map[string]string{"reason": "locked"})
		m.lockedResponse(w, org)
		return
	}
	wrong := false
	defer m.settle(ctx, org, key, &wrong)
	within, err := m.attempt(ctx, in.Ticket)
	if err != nil { // the counter failed: refused, but not as too many tries
		unavailableResponse(w)
		return
	}
	if !within {
		writeErr(w, http.StatusUnauthorized, "Too many incorrect codes. Start again.", "")
		return
	}
	used, left, err := m.s.Svc.ConsumeRecoveryCode(ctx, u, in.Code)
	if err != nil { // the use could not be recorded (or may have been): try again, not a wrong code, no failure counted
		m.internalError(w, r, "record recovery code", err)
		return
	}
	if !used {
		wrong = true
		m.failed(w, r, n, org, u, u.Username, "recovery_code")
		return
	}
	if err := m.useTicket(ctx, in.Ticket); err != nil {
		ticketFailed(w, err)
		return
	}
	m.audit(r, "login.recovery_code", org, u, u.Username, map[string]string{"left": strconv.Itoa(left)})
	if m.Mail != nil && u.Email != "" {
		if err := m.Mail.SendRecoveryUsed(ctx, u, org, left); err != nil {
			m.s.Log.Error("send recovery code notice", "error", err)
		}
	}
	// A one-time code as the second factor (RFC 8176 "otp"), as an authenticator code is.
	amr := append(append([]string{}, t.AMR...), "otp", "mfa")
	dest, err := m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr, Provider: t.Provider, UpstreamAMR: t.UpstreamAMR, Upstream: t.Upstream}, t.Next)
	if err != nil {
		m.internalError(w, r, "create session", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
}

// consumeTOTP verifies code and records the matched step so the same code cannot be used again, on any node
// (service.ConsumeTOTP: a cluster-wide compare-and-swap on the user's sign-in record).
func (m *Module) consumeTOTP(ctx context.Context, u *model.User, secret, code string) (bool, error) {
	return m.s.Svc.ConsumeTOTP(ctx, u, secret, code)
}

// ---------------------------------------------------------------------------------------------------------------
// Forgotten password

type forgotReq struct {
	Tenant string `json:"tenant"`
	Email  string `json:"email"`
}

// forgot handles POST /o/{org}/api-internal/password/forgot. It always answers 200 so it cannot be used to find accounts.
func (m *Module) forgot(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in forgotReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	org := web.Org(r)
	if !m.rateLimit(w, r, org.ID, m.knownLogin(org, in.Email)) {
		return
	}
	eff, _, err := m.methods(ctx, org, in.Tenant, "")
	if err == nil && eff.PasswordReset && m.Mail != nil && len(in.Email) <= 256 {
		u, err := m.s.Svc.FindUserByEmail(ctx, org.ID, in.Email)
		if err != nil && !errors.Is(err, service.ErrNotFound) {
			// "If the address has an account, a link is on its way" must not be said when the store could not look:
			// no link would come. (An outage is told the same way to every address, so it reveals nothing.)
			unavailableResponse(w)
			return
		}
		if err == nil && u.Enabled(time.Now()) && u.PasswordHash != "" {
			// (an account without a password is not sent a reset: its way in is a new invitation from an administrator)
			if m.forgotAllowed(ctx, r, u.ID) {
				// After the answer, not before: the link is a stored write and the mail a queued one, and the time
				// they take must not tell an existing account from an unknown address.
				m.audit(r, "password.forgot", org, u, u.Username, nil)
				m.s.Svc.Background(ctx, func(ctx context.Context) {
					if err := m.Mail.SendReset(ctx, u, org); err != nil {
						m.s.Log.Error("send reset mail", "error", err)
					}
				})
			}
		}
	}
	web.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Reset mails an account is sent an hour: forgotPerAddress for the requests of one address, forgotPerAccount for all
// of them together.
const (
	forgotPerAddress = 5
	forgotPerAccount = 20
)

// forgotAllowed spends a reset mail of account userID's hourly allowance for the request's address, then of the
// account's: anyone who knows the address can ask for resets, and must not use up the owner's own requests from
// another address, while the form still cannot flood the inbox. A request past its address's allowance does not
// spend the account's.
func (m *Module) forgotAllowed(ctx context.Context, r *http.Request, userID string) bool {
	n, err := m.s.Eph.Incr(ctx, nsForgot, userID+"|"+web.RateKeyIP(r), 1, time.Hour)
	if err != nil || n > forgotPerAddress {
		return false
	}
	n, err = m.s.Eph.Incr(ctx, nsForgot, userID, 1, time.Hour)
	return err == nil && n <= forgotPerAccount
}

type resetReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// msgResetUnknown answers a reset the cluster did not confirm: it may have been made.
const msgResetUnknown = "The server lost contact with its cluster before it answered, so your password may have been changed. " +
	"Try signing in with the new password; if that does not work, ask for a new reset link."

const msgBadLink = "This link is invalid or has expired."

// resettable reports whether the user of a reset link may still set a password this way: the org allows password
// sign-in and resets, and the account has a password (accounts without one use an invitation).
func resettable(org *model.Org, u *model.User) bool {
	return org.Settings.PasswordLogin && org.Settings.PasswordReset && u.PasswordHash != ""
}

// reset handles POST /o/{org}/api-internal/password/reset: {token, password} for a "forgot password" link of the
// organization (one of another is invalid here).
func (m *Module) reset(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in resetReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	if !m.rateLimit(w, r, web.Org(r).ID+"|reset", known{any: true}) {
		return
	}
	org := web.Org(r)
	u, ok := m.peekLink(ctx, org, in.Token, service.LinkReset)
	if !ok || !resettable(org, u) {
		writeErr(w, http.StatusGone, msgBadLink, "")
		return
	}
	// One commit sets the password and uses the link up (with any invitation of the account); a password the
	// policy refuses, or a failure, leaves the link usable. Every session and refresh grant of the account ends.
	resetting := u
	_, u, err := m.s.Svc.UseSignInLink(ctx, in.Token, service.LinkReset, in.Password, 0)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrLink):
			writeErr(w, http.StatusGone, msgBadLink, "")
		case errors.Is(err, service.ErrOutcomeUnknown):
			// The link is used up if the reset was made, and trying it again would only say it is invalid.
			m.auditUnknown(r, "password.reset", org, resetting, nil, err)
			writeErr(w, http.StatusServiceUnavailable, msgResetUnknown, "")
		default:
			web.WriteError(w, err)
		}
		return
	}
	m.clearLocks(ctx, u.ID)
	m.s.Sessions.Evict("", u.ID)
	m.audit(r, "password.reset", org, u, u.Username, nil)
	web.WriteJSON(w, http.StatusOK, stepResp{Next: web.OrgPath(org.ID, "/login")})
}

// errFactorLost: a second factor is required and the account's only ones (passkeys) can no longer sign in.
var errFactorLost = errors.New("login: the account's second factor can no longer be used")

const msgFactorLost = "Your passkey can no longer be used to sign in. Ask an administrator for a new invitation."
