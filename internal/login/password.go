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
	Org      string `json:"org"`
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
}

// password handles POST /api/login/password: {org, email, password[, next]} -> {next} or {step, ticket}.
func (m *Module) password(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in passwordReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	org, orgKey := m.resolveOrg(ctx, in.Org)
	if !m.rateLimit(w, r, orgKey, m.knownLogin(org, in.Email)) {
		return
	}
	login := strings.TrimSpace(in.Email) // the email address; the username never signs in
	if login == "" || in.Password == "" || len(login) > 256 || len(in.Password) > 1024 {
		writeErr(w, http.StatusUnprocessableEntity, "Enter your email address and password.", "email")
		return
	}
	if org == nil {
		// Org names are public (/login/<org> redirects when unknown), so this leaks nothing; answering without a
		// hash keeps random org names from being used to burn password workers.
		m.audit(r, "login.failure", nil, nil, login, map[string]string{"reason": "unknown org"})
		writeErr(w, http.StatusUnauthorized, msgBadLogin, "")
		return
	}
	eff, tenant, err := m.methods(ctx, org, in.Tenant, in.Next)
	if err != nil {
		m.internalError(w, r, "sign-in methods", err)
		return
	}
	var u *model.User
	if eff.Password {
		u, _ = m.s.Svc.FindUserByEmail(ctx, org.ID, login)
	} // else: treated like an unknown user (generic failure after a dummy hash), so a switched-off org or tenant looks the same
	key := lockKey(u, org, login)
	if m.locked(ctx, key) {
		m.audit(r, "login.failure", org, u, login, map[string]string{"reason": "locked"})
		m.lockedResponse(w)
		return
	}

	// Always spend one password hash, whatever is wrong, so timing does not reveal which accounts exist.
	hash := ""
	if u != nil && u.Enabled(time.Now()) {
		hash = u.PasswordHash
	}
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ok, err := m.s.Svc.Hasher.Verify(vctx, in.Password, hash)
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
		m.failed(w, r, key, org, u, login, reason)
		return
	}

	m.afterPassword(w, r, u, org, eff, tenant, safeNext(in.Next))
}

// secondFactor decides what follows a first factor (a password, or a sign-in at an upstream provider): the user's
// TOTP code when they have one; when the org or tenant requires MFA, or the user is a manager or above, their
// passkey (if they have one) or enrolment;
// otherwise nothing (""). It stores the step's ticket. A provider's own claims about MFA are never trusted: a
// federated sign-in is a first factor like a password.
func (m *Module) secondFactor(ctx context.Context, u *model.User, eff *service.SignInMethods, t ticket) (stepResp, error) {
	t.UserID = u.ID
	ttl := ticketTTL
	switch {
	case u.HasTOTP():
		t.Step = "totp"
	case eff.RequireMFA || u.Role.Privileged(): // managers and above always use a second factor
		t.Step, ttl = "enrol", enrolTTL
		usable, err := m.s.Svc.UsablePasskeys(ctx, u.ID, "")
		if err != nil {
			return stepResp{}, err
		}
		if usable > 0 && m.Passkeys != nil {
			t.Step = "passkey" // has a passkey as the second factor: the first factor alone is not enough
			break
		}
		// Enrolment here lets whoever holds the first factor choose the second, which is only right for an account
		// that never had one. An account whose passkeys can no longer sign in (disabled after a suspected clone,
		// or registered without user verification) keeps them as evidence that it had a second factor: it gets a
		// new one through an invitation from an administrator, not from the password.
		if all, err := m.s.Svc.Passkeys.Count(ctx, u.ID); err != nil {
			return stepResp{}, err
		} else if all > 0 {
			return stepResp{}, errFactorLost
		}
	default:
		return stepResp{}, nil
	}
	id, err := m.putTicket(ctx, &t, ttl)
	if err != nil {
		return stepResp{}, err
	}
	resp := stepResp{Step: t.Step, Ticket: id}
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
	ctx := r.Context()
	step, err := m.secondFactor(ctx, u, eff, ticket{Next: next, AMR: []string{"pwd"}, Tenant: tenant})
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

// failed records a failed attempt (counter, audit, lockout event) and answers with the generic message.
func (m *Module) failed(w http.ResponseWriter, r *http.Request, key string, org *model.Org, u *model.User, login, reason string) {
	ctx := r.Context()
	tripped := m.fail(ctx, key)
	m.audit(r, "login.failure", org, u, login, map[string]string{"reason": reason})
	if tripped && u != nil {
		m.audit(r, "login.lockout", org, u, login, map[string]string{"minutes": strconv.Itoa(int(m.lockWindow().Minutes()))})
	}
	field := ""
	msg := msgBadLogin
	if reason == "totp" {
		msg, field = "That code is incorrect or has already been used.", "code"
	}
	writeErr(w, http.StatusUnauthorized, msg, field)
}

type totpReq struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// totp handles POST /api/login/totp: {ticket, code} -> {next}.
func (m *Module) totp(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in totpReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	t, ok := m.getTicket(ctx, in.Ticket, "totp")
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Your sign-in has expired. Start again.", "")
		return
	}
	u, err := m.s.Svc.Users.Get(ctx, t.UserID)
	if err != nil || !u.Enabled(time.Now()) || !u.HasTOTP() {
		writeErr(w, http.StatusUnauthorized, "Your sign-in has expired. Start again.", "")
		return
	}
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Your sign-in has expired. Start again.", "")
		return
	}
	if !m.rateLimit(w, r, org.Name, known{userID: u.ID}) {
		return
	}
	key := u.ID
	if m.locked(ctx, key) {
		m.audit(r, "login.failure", org, u, u.Username, map[string]string{"reason": "locked"})
		m.lockedResponse(w)
		return
	}
	if !m.attempt(ctx, in.Ticket) {
		writeErr(w, http.StatusUnauthorized, "Too many incorrect codes. Start again.", "")
		return
	}
	secret, err := m.s.Svc.Sealer.OpenFor(service.TOTPBinding(u.ID), u.TOTPSecret)
	if err != nil {
		m.internalError(w, r, "open totp secret", err)
		return
	}
	if !m.consumeTOTP(ctx, u, string(secret), in.Code) {
		m.failed(w, r, key, org, u, u.Username, "totp")
		return
	}
	if !m.useTicket(ctx, in.Ticket) {
		writeErr(w, http.StatusUnauthorized, "Your sign-in has expired. Start again.", "")
		return
	}
	amr := append(append([]string{}, t.AMR...), "otp", "mfa")
	dest, err := m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr, Provider: t.Provider}, t.Next)
	if err != nil {
		m.internalError(w, r, "create session", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
}

// consumeTOTP verifies code and records the matched step so the same code cannot be used again, on any node
// (service.ConsumeTOTP: a cluster-wide compare-and-swap on the user's sign-in record).
func (m *Module) consumeTOTP(ctx context.Context, u *model.User, secret, code string) bool {
	return m.s.Svc.ConsumeTOTP(ctx, u, secret, code)
}

// ---------------------------------------------------------------------------------------------------------------
// Forgotten password

type forgotReq struct {
	Org   string `json:"org"`
	Email string `json:"email"`
}

// forgot handles POST /api/password/forgot. It always answers 200 so it cannot be used to find accounts.
func (m *Module) forgot(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in forgotReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	org, orgKey := m.resolveOrg(ctx, in.Org)
	if !m.rateLimit(w, r, orgKey, m.knownLogin(org, in.Email)) {
		return
	}
	if org != nil && org.Settings.PasswordLogin &&
		m.Mail != nil && len(in.Email) <= 256 {
		if u, err := m.s.Svc.FindUserByEmail(ctx, org.ID, in.Email); err == nil && u.Enabled(time.Now()) && u.PasswordHash != "" {
			// (an account without a password is not sent a reset: its way in is a new invitation from an administrator)
			// At most five reset mails an hour per account, so the form cannot be used to flood someone's inbox.
			if n, err := m.s.Eph.Incr(ctx, nsForgot, u.ID, 1, time.Hour); err == nil && n <= 5 {
				if err := m.Mail.SendReset(ctx, u, org); err != nil {
					m.s.Log.Error("send reset mail", "error", err)
				}
				m.audit(r, "password.forgot", org, u, u.Username, nil)
			}
		}
	}
	web.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type resetReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

const msgBadLink = "This link is invalid or has expired."

// resettable reports whether the user of a reset link may still set a password this way: the org allows password
// sign-in and the account has a password (accounts without one use an invitation).
func (m *Module) resettable(ctx context.Context, u *model.User) (*model.Org, bool) {
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if err != nil || !org.Settings.PasswordLogin || u.PasswordHash == "" {
		return org, false
	}
	return org, true
}

// reset handles POST /api/password/reset: {token, password} for a "forgot password" link.
func (m *Module) reset(w http.ResponseWriter, r *http.Request) {
	if !m.anonOK(w, r) {
		return
	}
	var in resetReq
	if !decode(w, r, &in) {
		return
	}
	if !m.rateLimit(w, r, "reset", known{any: true}) {
		return
	}
	ctx := r.Context()
	_, u, err := m.s.Svc.PeekLink(ctx, in.Token, service.LinkReset)
	if err != nil {
		writeErr(w, http.StatusGone, msgBadLink, "")
		return
	}
	org, ok := m.resettable(ctx, u)
	if !ok {
		writeErr(w, http.StatusGone, msgBadLink, "")
		return
	}
	// Validate before redeeming so a too-short password does not burn the link.
	if err := service.ValidatePassword(in.Password); err != nil {
		web.WriteError(w, err)
		return
	}
	l, u, err := m.s.Svc.RedeemLink(ctx, in.Token, service.LinkReset)
	if err != nil {
		writeErr(w, http.StatusGone, msgBadLink, "")
		return
	}
	in2 := service.UserInput{Password: &in.Password}
	if strings.EqualFold(l.Email, u.Email) { // the link went to the address on file, so it is now proven
		t := true
		in2.Verified = &t
	}
	// Acting as the system (not as the user) so every existing session and refresh grant is ended.
	if _, err := m.s.Svc.UpdateUser(ctx, service.System, u.ID, in2); err != nil {
		web.WriteError(w, err)
		return
	}
	m.clearLock(ctx, u.ID)
	m.s.Sessions.Evict("", u.ID)
	m.audit(r, "password.reset", org, u, u.Username, nil)
	web.WriteJSON(w, http.StatusOK, stepResp{Next: "/login/" + org.Name})
}

// errFactorLost: a second factor is required and the account's only ones (passkeys) can no longer sign in.
var errFactorLost = errors.New("login: the account's second factor can no longer be used")

const msgFactorLost = "Your passkey can no longer be used to sign in. Ask an administrator for a new invitation."
