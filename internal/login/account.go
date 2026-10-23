package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// The account API is the signed-in user's own self-service surface. Every handler is session-only (RequireAPI:
// cookie + CSRF header) and acts on the session's user; nothing here takes a user id from the client. The user held
// in the request context comes from a per-node cache and must never be modified: handlers that change the user
// re-read it first.

type acct struct {
	u     *model.User // cached, read-only
	sess  *model.Session
	actor *service.Actor
}

func (m *Module) registerAccount(s *web.Server) {
	h := func(pattern string, f func(http.ResponseWriter, *http.Request, acct)) {
		s.Mux.Handle(pattern, s.RequireAPI(func(w http.ResponseWriter, r *http.Request) {
			f(w, r, acct{u: web.User(r), sess: web.Session(r), actor: web.Actor(r)})
		}))
	}
	h("GET /api-internal/account", m.getAccount)
	h("GET /api-internal/account/profile-options", m.profileOptions)
	h("PATCH /api-internal/account", m.patchAccount)
	h("POST /api-internal/account/email/verify", m.sendVerify)
	h("POST /api-internal/account/password", m.changePassword)
	h("POST /api-internal/account/emails/{address}/verify", m.resendEmail)
	h("POST /api-internal/account/emails/{address}/primary", m.primaryEmail)

	h("GET /api-internal/account/passkeys", m.listPasskeys)
	h("PATCH /api-internal/account/passkeys/{id}", m.renamePasskey)
	h("DELETE /api-internal/account/passkeys/{id}", m.deletePasskey)
	h("POST /api-internal/account/passkeys/register/begin", m.registerPasskeyBegin)
	h("POST /api-internal/account/passkeys/register/finish", m.registerPasskeyFinish)

	h("POST /api-internal/account/totp/begin", m.totpBegin)
	h("POST /api-internal/account/totp/confirm", m.totpConfirm)
	h("DELETE /api-internal/account/totp", m.totpDisable)
	h("POST /api-internal/account/recovery-codes", m.createRecoveryCodes)

	h("GET /api-internal/account/reauth", m.reauthStatus)
	h("POST /api-internal/account/reauth", m.reauthPassword)
	h("POST /api-internal/account/reauth/passkey/begin", m.reauthPasskeyBegin)
	h("POST /api-internal/account/reauth/passkey/finish", m.reauthPasskeyFinish)

	h("GET /api-internal/account/sessions", m.listSessions)
	h("DELETE /api-internal/account/sessions/{id}", m.revokeSession)
	h("DELETE /api-internal/account/sessions", m.revokeOtherSessions)

	h("GET /api-internal/account/tokens", m.listTokens)
	h("POST /api-internal/account/tokens", m.createToken)
	h("DELETE /api-internal/account/tokens/{id}", m.deleteToken)
	h("POST /api-internal/account/tokens/{id}/regenerate", m.regenerateToken)
	h("PATCH /api-internal/account/tokens/{id}", m.updateToken)

	h("GET /api-internal/account/providers", m.listProviders)
	h("POST /api-internal/account/providers/{id}/connect", m.connectProvider)
	h("DELETE /api-internal/account/providers/{id}", m.disconnectProvider)

	h("GET /api-internal/account/apps", m.listApps)
	h("DELETE /api-internal/account/apps/{client}", m.revokeApp)
}

// accountPage handles GET /account.
func (m *Module) accountPage(w http.ResponseWriter, r *http.Request) {
	m.s.Render.Render(w, http.StatusOK, "account", m.s.Page(w, r, "My account", "account", map[string]any{
		"Passkeys": m.Passkeys != nil, "Mail": m.Mail != nil,
	}))
}

// fresh re-reads the user for modification and ends the per-node session cache entry after a change.
func (m *Module) fresh(ctx context.Context, a acct) (*model.User, error) {
	return m.s.Svc.Users.Get(ctx, a.u.ID)
}

func (m *Module) changed(a acct) { m.s.Sessions.Evict("", a.u.ID) }

func (m *Module) auditSelf(r *http.Request, a acct, action string, detail map[string]string) {
	org, _ := m.s.Svc.Orgs.Get(r.Context(), a.u.OrgID)
	m.audit(r, action, org, a.u, a.u.Username, detail)
}

// ---------------------------------------------------------------------------------------------------------------
// Profile

type profile struct {
	ID            string              `json:"id"`
	Username      string              `json:"username"`
	Email         string              `json:"email"`
	EmailVerified bool                `json:"email_verified"`
	Name          string              `json:"name"` // full name: given + family name, read-only
	GivenName     string              `json:"given_name"`
	FamilyName    string              `json:"family_name"`
	LinkedEmails  []model.LinkedEmail `json:"linked_emails"`
	Locale        string              `json:"locale"`
	ZoneInfo      string              `json:"zoneinfo"`
	PhoneNumber   string              `json:"phone_number"`
	PhoneVerified bool                `json:"phone_number_verified"`
	Role          string              `json:"role"`
	LastLogin     time.Time           `json:"last_login"`
	// Set by administrators or provisioning; shown, not edited, on the account page.
	UserType   string     `json:"user_type"`
	ValidUntil *time.Time `json:"valid_until"`
	Work       model.Work `json:"work"`
}

func (m *Module) profileOf(ctx context.Context, u *model.User) profile {
	m.s.Svc.WithSignIn(ctx, u)
	return toProfile(u)
}

func toProfile(u *model.User) profile {
	le := u.LinkedEmails
	if le == nil {
		le = []model.LinkedEmail{}
	}
	return profile{ID: u.ID, Username: u.Username, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.FullName(),
		GivenName: u.GivenName, FamilyName: u.FamilyName, LinkedEmails: le, Locale: u.Locale, ZoneInfo: u.ZoneInfo,
		PhoneNumber: u.PhoneNumber, PhoneVerified: u.PhoneVerified, Role: string(u.Role), LastLogin: u.LastLogin, UserType: u.UserType, ValidUntil: u.ValidUntil, Work: u.Work}
}

type accountResp struct {
	User profile `json:"user"`
	Org  struct {
		Name       string `json:"name"`
		Display    string `json:"display_name"`
		RequireMFA bool   `json:"require_mfa"`
	} `json:"org"`
	Security struct {
		HasPassword bool `json:"has_password"`
		TOTP        bool `json:"totp"`
		// Recovery codes: how many are left, when they were made (null: never), and whether the account has a
		// second factor for them to stand in for.
		RecoveryLeft      int        `json:"recovery_left"`
		RecoveryCreated   *time.Time `json:"recovery_created"`
		RecoveryAvailable bool       `json:"recovery_available"`
		Passkeys          int        `json:"passkeys"`
		PasskeysAvailable bool       `json:"passkeys_available"`
		PasswordsAllowed  bool       `json:"passwords_allowed"` // the organization signs people in with passwords
		MailAvailable     bool       `json:"mail_available"`
		Providers         []string   `json:"providers"`
	} `json:"security"`
}

func (m *Module) summary(ctx context.Context, u *model.User) (accountResp, error) {
	var out accountResp
	out.User = m.profileOf(ctx, u)
	if org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID); err == nil {
		out.Org.Name, out.Org.Display, out.Org.RequireMFA = org.Name, org.DisplayName, org.Settings.RequireMFA
	}
	n, err := m.s.Svc.UsablePasskeys(ctx, u.ID, "")
	if err != nil {
		return out, err
	}
	out.Security.HasPassword, out.Security.TOTP, out.Security.Passkeys = u.PasswordHash != "", u.HasTOTP(), n
	out.Security.RecoveryLeft, out.Security.RecoveryCreated = m.s.Svc.RecoveryCodesLeft(ctx, u)
	out.Security.RecoveryAvailable = u.HasTOTP() || n > 0
	out.Security.PasskeysAvailable, out.Security.MailAvailable = m.Passkeys != nil, m.Mail != nil
	out.Security.PasswordsAllowed = m.passwordsAllowed(ctx, u)
	out.Security.Providers = []string{}
	if ids, err := m.s.Svc.Identities.All(ctx, u.ID); err == nil {
		for _, id := range ids {
			if p, err := m.s.Svc.Providers.Get(ctx, id.ProviderID); err == nil {
				out.Security.Providers = append(out.Security.Providers, p.Name)
			}
		}
	}
	return out, nil
}

func (m *Module) getAccount(w http.ResponseWriter, r *http.Request, a acct) {
	u, err := m.fresh(r.Context(), a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	out, err := m.summary(r.Context(), u)
	if err != nil {
		m.internalError(w, r, "account summary", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, out)
}

type profileReq struct {
	GivenName  *string `json:"given_name"`
	FamilyName *string `json:"family_name"`
	Email      *string `json:"email"`
	Locale     *string `json:"locale"`
	ZoneInfo   *string `json:"zoneinfo"`
	Phone      *string `json:"phone_number"`
}

// patchAccount handles PATCH /api-internal/account. Only profile fields can be sent; role, username and the like are
// rejected by the strict decoder.
func (m *Module) patchAccount(w http.ResponseWriter, r *http.Request, a acct) {
	var in profileReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	before, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if in.Email != nil && !strings.EqualFold(strings.TrimSpace(*in.Email), before.Email) {
		// Nobody changes their own address (it redirects password resets and every application's email claim):
		// another manager or administrator does. Refused before asking to re-authenticate for nothing.
		writeErr(w, http.StatusUnprocessableEntity, "Your email address is changed by an administrator, not here.", "email")
		return
	}
	u, err := m.s.Svc.UpdateUser(service.SelfService(ctx), a.actor, a.u.ID, service.UserInput{GivenName: in.GivenName,
		FamilyName: in.FamilyName, Email: in.Email, Locale: in.Locale, ZoneInfo: in.ZoneInfo, Phone: in.Phone})
	if err != nil {
		web.WriteError(w, err)
		return
	}
	m.changed(a)
	web.WriteJSON(w, http.StatusOK, map[string]any{"user": toProfile(u)})
}

// sendVerify handles POST /api-internal/account/email/verify: mails a confirmation link for the address on file.
func (m *Module) sendVerify(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	u, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	switch {
	case m.Mail == nil:
		writeErr(w, http.StatusServiceUnavailable, "Email is not set up on this server.", "")
	case u.Email == "":
		writeErr(w, http.StatusUnprocessableEntity, "Add an email address first.", "email")
	case u.EmailVerified:
		writeErr(w, http.StatusConflict, "Your email address is already verified.", "")
	default:
		if n, err := m.s.Eph.Incr(ctx, nsVerify, u.ID, 1, time.Hour); err != nil || n > 5 {
			w.Header().Set("Retry-After", "3600")
			writeErr(w, http.StatusTooManyRequests, "Too many verification emails. Try again later.", "")
			return
		}
		org, _ := m.s.Svc.Orgs.Get(ctx, u.OrgID)
		if err := m.Mail.SendVerify(ctx, u, org); err != nil {
			m.internalError(w, r, "send verification", err)
			return
		}
		web.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Linked email addresses

// mailAddress sends the verification link for one of the user's addresses (at most 5 mails an hour per user, shared
// with sendVerify). It writes the error response itself and reports whether the mail went out.
func (m *Module) mailAddress(w http.ResponseWriter, r *http.Request, u *model.User, address string) bool {
	ctx := r.Context()
	if n, err := m.s.Eph.Incr(ctx, nsVerify, u.ID, 1, time.Hour); err != nil || n > 5 {
		w.Header().Set("Retry-After", "3600")
		writeErr(w, http.StatusTooManyRequests, "Too many verification emails. Try again later.", "")
		return false
	}
	org, _ := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if err := m.Mail.SendVerifyAddress(ctx, u, org, address); err != nil {
		if errors.Is(err, service.ErrNotFound) || errors.Is(err, service.ErrConflict) {
			web.WriteError(w, err)
		} else {
			m.internalError(w, r, "send verification", err)
		}
		return false
	}
	return true
}

// emailError maps a service error on an address to the field the form shows it under.
func (m *Module) emailError(w http.ResponseWriter, err error) {
	var fe *service.FieldError
	if errors.As(err, &fe) {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, service.ErrConflict) {
			status = http.StatusConflict
		}
		writeErr(w, status, "That "+fe.Msg+".", "address")
		return
	}
	web.WriteError(w, err)
}

// primaryEmail handles POST /api-internal/account/emails/{address}/primary. Needs a recent re-authentication.
func (m *Module) primaryEmail(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.needReauth(w, r, a) {
		return
	}
	u, err := m.s.Svc.MakePrimary(service.SelfService(r.Context()), a.actor, a.u.ID, r.PathValue("address"))
	if err != nil {
		m.emailError(w, err)
		return
	}
	m.changed(a)
	web.WriteJSON(w, http.StatusOK, map[string]any{"user": toProfile(u)})
}

// resendEmail handles POST /api-internal/account/emails/{address}/verify: mails the verification link again.
func (m *Module) resendEmail(w http.ResponseWriter, r *http.Request, a acct) {
	if m.Mail == nil {
		writeErr(w, http.StatusServiceUnavailable, "Email is not set up on this server.", "")
		return
	}
	u, err := m.fresh(r.Context(), a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if m.mailAddress(w, r, u, r.PathValue("address")) {
		web.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Password

type changePasswordReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// verifyPassword checks the user's password with lockout accounting; ok=false has already produced the response.
func (m *Module) verifyPassword(w http.ResponseWriter, r *http.Request, u *model.User, password, field string) bool {
	ctx := r.Context()
	key := m.lockKeyFor(r, u, u.ID) // as sign-in: a known browser has its own counter (device.go)
	if m.locked(ctx, key) {
		m.lockedResponse(w)
		return false
	}
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ok, err := m.s.Svc.VerifyPassword(vctx, u, password)
	if errors.Is(err, secure.ErrBusy) {
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, "The server is busy. Please try again in a moment.", "")
		return false
	}
	if err != nil {
		m.internalError(w, r, "password verify", err)
		return false
	}
	if !ok {
		if m.fail(ctx, key) {
			org, _ := m.s.Svc.Orgs.Get(ctx, u.OrgID)
			m.audit(r, "login.lockout", org, u, u.Username, nil)
		}
		writeErr(w, http.StatusUnprocessableEntity, "That password is incorrect.", field)
		return false
	}
	return true
}

// changePassword handles POST /api-internal/account/password: {current, new}. The current session survives; every other
// session of the user (and its refresh grants) is ended. An account without a password (set up with a passkey, an
// authenticator app or a sign-in provider) sets its first one here with {new} alone: setFirstPassword.
func (m *Module) changePassword(w http.ResponseWriter, r *http.Request, a acct) {
	var in changePasswordReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	u, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if u.PasswordHash == "" {
		m.setFirstPassword(w, r, a, u, in.New)
		return
	}
	if in.Current == "" {
		writeErr(w, http.StatusUnprocessableEntity, "Enter your current password.", "current")
		return
	}
	if !m.verifyPassword(w, r, u, in.Current, "current") {
		return
	}
	if err := m.s.Svc.CheckPassword(r.Context(), u, in.New); err != nil {
		var fe *service.FieldError
		if errors.As(err, &fe) {
			writeErr(w, http.StatusUnprocessableEntity, "Your new password "+fe.Msg+".", "new")
			return
		}
		web.WriteError(w, err)
		return
	}
	if in.New == in.Current {
		writeErr(w, http.StatusUnprocessableEntity, "Choose a password you have not used just now.", "new")
		return
	}
	if _, err := m.s.Svc.UpdateUser(service.SelfService(ctx), a.actor, u.ID, service.UserInput{Password: &in.New}); err != nil {
		web.WriteError(w, err)
		return
	}
	// UpdateUser leaves a user's own sessions alone; end the others here.
	n := m.endOtherSessions(ctx, a)
	m.changed(a)
	web.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "signed_out": n})
}

// setFirstPassword adds a password to an account that has none, when its organization signs people in with
// passwords. It adds a way into the account, so it needs a recent re-authentication with what the account already
// signs in with (needReauth: its passkey or authenticator code, or signing in again through its provider), as adding
// a passkey or an authenticator app does; a session alone, perhaps a stolen one, cannot add it. Nothing else changes:
// the other sessions stay.
func (m *Module) setFirstPassword(w http.ResponseWriter, r *http.Request, a acct, u *model.User, password string) {
	ctx := r.Context()
	if !m.passwordsAllowed(ctx, u) {
		writeErr(w, http.StatusConflict, "Your organization does not sign people in with passwords.", "")
		return
	}
	if !m.needReauth(w, r, a) {
		return
	}
	if err := m.s.Svc.CheckPassword(ctx, u, password); err != nil {
		var fe *service.FieldError
		if errors.As(err, &fe) {
			writeErr(w, http.StatusUnprocessableEntity, "Your password "+fe.Msg+".", "new")
			return
		}
		web.WriteError(w, err)
		return
	}
	if _, err := m.s.Svc.UpdateUser(service.SelfService(ctx), a.actor, u.ID, service.UserInput{Password: &password}); err != nil {
		web.WriteError(w, err)
		return
	}
	m.changed(a)
	web.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "signed_out": 0})
}

// passwordsAllowed reports whether u's organization signs people in with passwords (anywhere: as an invitation
// decides whether to offer one).
func (m *Module) passwordsAllowed(ctx context.Context, u *model.User) bool {
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if err != nil {
		return false
	}
	eff, err := m.s.Svc.EffectiveSignIn(ctx, org, nil)
	return err == nil && eff.Password
}

func (m *Module) endOtherSessions(ctx context.Context, a acct) int {
	list, err := m.s.Svc.Sessions.All(ctx, a.u.ID)
	if err != nil {
		return 0
	}
	n := 0
	for _, s := range list {
		if s.ID != a.sess.ID && m.s.Sessions.Delete(ctx, s.ID) == nil {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------------------------------------------
// Re-authentication (needed before turning off the authenticator app)

func (m *Module) markReauth(ctx context.Context, a acct) {
	_ = m.s.Eph.Set(ctx, nsReauth, a.sess.ID, []byte("1"), reauthTTL)
}

func (m *Module) reauthed(ctx context.Context, a acct) bool {
	_, err := m.s.Eph.Get(ctx, nsReauth, a.sess.ID)
	return err == nil
}

// needReauth answers 403 {"field":"reauth"} (the shape the account page turns into its re-authentication dialog)
// unless the session re-authenticated within reauthTTL, or signed in within it. It reports whether the caller may go
// on. Every change behind it adds, replaces or removes a way into the account (or reaches its credentials), so a
// fresh sign-in counts only when it used the account's own second factor, if it has one (an authenticator code or a
// passkey): a provider trusted to count as a second factor (TrustMFA) signs in without it, and must not be able to
// add ways in that skip it as well, or remove it. A re-authentication always asks for that factor. An account with
// nothing to re-enter (signed in through a provider only) confirms by signing in again.
func (m *Module) needReauth(w http.ResponseWriter, r *http.Request, a acct) bool {
	ctx := r.Context()
	if m.reauthed(ctx, a) {
		return true
	}
	if time.Since(a.sess.AuthTime) < reauthTTL {
		if slices.ContainsFunc(a.sess.AMR, func(v string) bool { return v == "otp" || v == "hwk" || v == "swk" }) {
			return true
		}
		pk, err := m.s.Svc.UsablePasskeys(ctx, a.u.ID, "")
		if err == nil && !a.u.HasTOTP() && pk == 0 {
			return true
		}
	}
	writeErr(w, http.StatusForbidden, "Confirm it is you with your password or a passkey first.", "reauth")
	return false
}

func (m *Module) reauthStatus(w http.ResponseWriter, r *http.Request, a acct) {
	web.WriteJSON(w, http.StatusOK, map[string]bool{"valid": m.reauthed(r.Context(), a)})
}

type reauthReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// reauthPassword handles POST /api-internal/account/reauth: {password, code}. Re-authentication asks for what the account
// signs in with, second factor included: the password alone only for an account without one; the password and the
// authenticator code for an account with the app (the code alone when it has no password); an account whose second
// factor is a passkey confirms with the passkey (reauthPasskeyBegin / Finish).
func (m *Module) reauthPassword(w http.ResponseWriter, r *http.Request, a acct) {
	var in reauthReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	u, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	lockKey := m.lockKeyFor(r, u, u.ID) // as sign-in: a known browser has its own counter (device.go)
	checkCode := func() bool {
		if m.locked(ctx, lockKey) {
			m.lockedResponse(w)
			return false
		}
		secret, err := m.s.Svc.Sealer.OpenFor(service.TOTPBinding(u.ID), u.TOTPSecret)
		if err != nil {
			m.internalError(w, r, "open totp secret", err)
			return false
		}
		if !m.consumeTOTP(ctx, u, string(secret), in.Code) {
			m.fail(ctx, lockKey)
			writeErr(w, http.StatusUnprocessableEntity, "That code is incorrect or has already been used.", "code")
			return false
		}
		return true
	}
	switch {
	case u.PasswordHash != "" && u.HasTOTP():
		if in.Password == "" {
			writeErr(w, http.StatusUnprocessableEntity, "Enter your password.", "password")
			return
		}
		if !m.verifyPassword(w, r, u, in.Password, "password") {
			return
		}
		if in.Code == "" {
			writeErr(w, http.StatusUnprocessableEntity, "Enter the code from your authenticator app as well.", "code")
			return
		}
		if !checkCode() {
			return
		}
	case u.PasswordHash != "":
		// A passkey as the account's second factor: the password alone is not enough.
		if n, err := m.s.Svc.UsablePasskeys(ctx, u.ID, ""); err != nil {
			m.internalError(w, r, "count passkeys", err)
			return
		} else if n > 0 && m.Passkeys != nil {
			writeErr(w, http.StatusUnprocessableEntity, "Confirm with your passkey: your account uses one as its second factor.", "passkey")
			return
		}
		if in.Password == "" {
			writeErr(w, http.StatusUnprocessableEntity, "Enter your password.", "password")
			return
		}
		if !m.verifyPassword(w, r, u, in.Password, "password") {
			return
		}
	case u.HasTOTP(): // no password: the code is the account's own factor
		if in.Code == "" {
			writeErr(w, http.StatusUnprocessableEntity, "Enter the code from your authenticator app.", "code")
			return
		}
		if !checkCode() {
			return
		}
	default:
		writeErr(w, http.StatusUnprocessableEntity, "Enter your password.", "password")
		return
	}
	m.markReauth(ctx, a)
	web.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "valid_for": int(reauthTTL.Seconds())})
}

func (m *Module) reauthPasskeyBegin(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.passkeysOK(w) {
		return
	}
	u, err := m.fresh(r.Context(), a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	id, opts, err := m.Passkeys.BeginLogin(r.Context(), u, map[string]string{"reauth": a.sess.ID, passkey.PurposeKey: purposeReauth})
	if errors.Is(err, passkey.ErrUnknownCredential) {
		writeErr(w, http.StatusUnprocessableEntity, "You have no passkeys.", "")
		return
	}
	if err != nil {
		m.internalError(w, r, "passkey reauth", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, passkeyBeginResp{Challenge: id, Options: opts})
}

func (m *Module) reauthPasskeyFinish(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.passkeysOK(w) {
		return
	}
	var in passkeyFinishReq
	if !decode(w, r, &in) {
		return
	}
	res, err := m.Passkeys.FinishLoginAs(r.Context(), in.Challenge, in.Credential, purposeReauth)
	if err != nil || res.User.ID != a.u.ID || res.Extra["reauth"] != a.sess.ID {
		writeErr(w, http.StatusUnprocessableEntity, msgBadPasskey, "")
		return
	}
	m.markReauth(r.Context(), a)
	web.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "valid_for": int(reauthTTL.Seconds())})
}

// ---------------------------------------------------------------------------------------------------------------
// Passkeys

type passkeyItem struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Created        time.Time `json:"created"`
	LastUsed       time.Time `json:"last_used"`
	Transports     []string  `json:"transports"`
	BackupEligible bool      `json:"backup_eligible"`
	BackupState    bool      `json:"backup_state"`
	// Problem says why the passkey cannot sign in: "disabled" (signs of a cloned authenticator) or "unverified"
	// (registered without user verification, which every sign-in now requires). Empty when it works.
	Problem string `json:"problem,omitempty"`
}

func toPasskeyItem(p *model.Passkey) passkeyItem {
	tr := p.Transports
	if tr == nil {
		tr = []string{}
	}
	return passkeyItem{ID: p.ID, Name: p.Name, Created: p.Created, LastUsed: p.LastUsed, Transports: tr,
		BackupEligible: p.BackupEligible, BackupState: p.BackupState, Problem: passkeyProblem(p)}
}

func passkeyProblem(p *model.Passkey) string {
	switch {
	case p.Disabled:
		return "disabled"
	case !p.UserVerified:
		return "unverified"
	}
	return ""
}

func (m *Module) listPasskeys(w http.ResponseWriter, r *http.Request, a acct) {
	list, err := m.s.Svc.Passkeys.All(r.Context(), a.u.ID)
	if err != nil {
		m.internalError(w, r, "list passkeys", err)
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
	items := make([]passkeyItem, 0, len(list))
	for _, p := range list {
		items = append(items, toPasskeyItem(p))
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "available": m.Passkeys != nil})
}

// ownPasskey loads a passkey that belongs to the session's user; anything else is "not found".
func (m *Module) ownPasskey(w http.ResponseWriter, r *http.Request, a acct) *model.Passkey {
	p, err := m.s.Svc.Passkeys.Get(r.Context(), r.PathValue("id"))
	if err != nil || p.UserID != a.u.ID {
		writeErr(w, http.StatusNotFound, "Not found.", "")
		return nil
	}
	return p
}

type renameReq struct {
	Name string `json:"name"`
}

func (m *Module) renamePasskey(w http.ResponseWriter, r *http.Request, a acct) {
	var in renameReq
	if !decode(w, r, &in) {
		return
	}
	p := m.ownPasskey(w, r, a)
	if p == nil {
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len([]rune(name)) > 100 {
		writeErr(w, http.StatusUnprocessableEntity, "Enter a name of up to 100 characters.", "name")
		return
	}
	p.Name = name
	if err := m.s.Svc.Passkeys.Update(r.Context(), p); err != nil {
		web.WriteError(w, mapStoreErr(err))
		return
	}
	web.WriteJSON(w, http.StatusOK, toPasskeyItem(p))
}

func mapStoreErr(err error) error {
	if errors.Is(err, store.ErrStale) {
		return service.ErrStale
	}
	return err
}

func (m *Module) deletePasskey(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	p := m.ownPasskey(w, r, a)
	if p == nil || !m.needReauth(w, r, a) {
		return
	}
	u, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if m.mfaRequired(ctx, u) && !u.HasTOTP() {
		if n, _ := m.s.Svc.UsablePasskeys(ctx, u.ID, p.ID); n == 0 && p.Usable() {
			writeErr(w, http.StatusConflict, "You need a second factor. Set up an Authenticator App first.", "")
			return
		}
	}
	if n, _ := m.s.Svc.UsablePasskeys(ctx, u.ID, p.ID); n == 0 && p.Usable() && u.PasswordHash == "" {
		if ids, _ := m.s.Svc.Identities.Count(ctx, u.ID); ids == 0 {
			writeErr(w, http.StatusConflict, "This is your only way to sign in. Ask an administrator for an invitation first.", "")
			return
		}
	}
	if err := m.s.Svc.Passkeys.Delete(service.Durable(ctx), p.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	// The sessions that signed in with it end (with their refresh tokens; applications are told by back-channel
	// logout), except the one deleting it, which has just confirmed it is the user.
	ended := 0
	if list, err := m.s.Svc.Sessions.All(ctx, u.ID); err == nil {
		for _, s := range list {
			if s.Passkey == p.ID && s.ID != a.sess.ID && m.s.Sessions.Delete(ctx, s.ID) == nil {
				ended++
			}
		}
	}
	if err := m.s.Svc.DropRecoveryCodes(ctx, a.u.ID); err != nil {
		m.s.Log.Warn("recovery codes not removed with the last second factor", "user", a.u.ID, "error", err)
	}
	m.auditSelf(r, a, "account.passkey.delete", map[string]string{"name": p.Name, "sessions_ended": strconv.Itoa(ended)})
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) registerPasskeyBegin(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.passkeysOK(w) || !m.needReauth(w, r, a) {
		return
	}
	u, err := m.fresh(r.Context(), a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if !m.passkeyRoom(w, r, u) {
		return
	}
	id, opts, err := m.Passkeys.BeginRegistration(r.Context(), u, map[string]string{passkey.PurposeKey: purposeRegister})
	if err != nil {
		m.internalError(w, r, "passkey registration", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, passkeyBeginResp{Challenge: id, Options: opts})
}

// passkeyRoom answers 409 when the user already has model.MaxPasskeys passkeys.
func (m *Module) passkeyRoom(w http.ResponseWriter, r *http.Request, u *model.User) bool {
	n, err := m.s.Svc.Passkeys.Count(r.Context(), u.ID)
	if err != nil {
		m.internalError(w, r, "count passkeys", err)
		return false
	}
	if n >= model.MaxPasskeys {
		writeErr(w, http.StatusConflict, fmt.Sprintf("You can have up to %d passkeys. Delete one you no longer use first.", model.MaxPasskeys), "")
		return false
	}
	return true
}

type registerFinishReq struct {
	Challenge  string          `json:"challenge"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func (m *Module) registerPasskeyFinish(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.passkeysOK(w) || !m.needReauth(w, r, a) {
		return
	}
	var in registerFinishReq
	if !decode(w, r, &in) {
		return
	}
	u, err := m.fresh(r.Context(), a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if !m.passkeyRoom(w, r, u) { // checked again: several ceremonies may have been begun at once
		return
	}
	p, _, err := m.Passkeys.FinishRegistrationAs(r.Context(), purposeRegister, u, in.Challenge, in.Credential, in.Name)
	if err != nil {
		msg := "The passkey could not be registered. Try again."
		if errors.Is(err, passkey.ErrChallenge) {
			msg = "That request expired. Try again."
		}
		writeErr(w, http.StatusUnprocessableEntity, msg, "")
		return
	}
	m.auditSelf(r, a, "account.passkey.add", map[string]string{"name": p.Name})
	web.WriteJSON(w, http.StatusCreated, toPasskeyItem(p))
}

// ---------------------------------------------------------------------------------------------------------------
// Authenticator app (TOTP)

func (m *Module) totpBegin(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	u, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	// A recent re-authentication first, also for the first one: a second factor chosen by whoever holds a stolen
	// session (or only the password) would let them past every later check. Setting it up again replaces the
	// current one, which is the same reason.
	if !m.needReauth(w, r, a) {
		return
	}
	secret := secure.NewTOTPSecret()
	if err := m.s.Eph.Set(ctx, nsPending, a.sess.ID, []byte(m.s.Svc.Sealer.Seal([]byte(secret))), 10*time.Minute); err != nil {
		m.internalError(w, r, "pending totp", err)
		return
	}
	resp, err := m.totpDetails(u, secret)
	if err != nil {
		m.internalError(w, r, "qr", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, resp)
}

type codeReq struct {
	Code string `json:"code"`
}

func (m *Module) totpConfirm(w http.ResponseWriter, r *http.Request, a acct) {
	var in codeReq
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	if n, err := m.s.Eph.Incr(ctx, nsTry, "totp:"+a.sess.ID, 1, 10*time.Minute); err != nil || n > 10 {
		w.Header().Set("Retry-After", "600")
		writeErr(w, http.StatusTooManyRequests, "Too many attempts. Start again in a few minutes.", "")
		return
	}
	sealed, err := m.s.Eph.Get(ctx, nsPending, a.sess.ID)
	if err != nil {
		writeErr(w, http.StatusConflict, "Start the Authenticator App set-up again.", "")
		return
	}
	secret, err := m.s.Svc.Sealer.Open(string(sealed))
	if err != nil {
		m.internalError(w, r, "open pending secret", err)
		return
	}
	step, ok := secure.VerifyTOTP(string(secret), in.Code, time.Now(), 0)
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "That code is incorrect. Check the time on your device and try again.", "code")
		return
	}
	u, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	replace := u.HasTOTP()
	if replace && !m.needReauth(w, r, a) {
		return
	}
	now := time.Now().UTC()
	u.TOTPSecret, u.MFAEnrolledAt = m.s.Svc.Sealer.SealFor(service.TOTPBinding(u.ID), secret), &now
	if err := m.s.Svc.Users.Update(service.Durable(ctx), u); err != nil {
		web.WriteError(w, mapStoreErr(err))
		return
	}
	if err := m.s.Svc.NoteTOTPStep(ctx, u, step); err != nil { // the code just used cannot sign in again
		web.WriteError(w, mapStoreErr(err))
		return
	}
	_ = m.s.Eph.Delete(ctx, nsPending, a.sess.ID)
	m.changed(a)
	if replace {
		m.auditSelf(r, a, "account.totp.replace", nil)
	} else {
		m.auditSelf(r, a, "account.totp.enable", nil)
	}
	web.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// totpDisable handles DELETE /api-internal/account/totp; it needs a re-authentication within the last five minutes.
// createRecoveryCodes handles POST /api-internal/account/recovery-codes: a new set of recovery codes (the old ones
// stop working), shown this once. After a recent re-authentication.
func (m *Module) createRecoveryCodes(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.needReauth(w, r, a) {
		return
	}
	u, err := m.fresh(r.Context(), a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	codes, err := m.s.Svc.CreateRecoveryCodes(r.Context(), a.actor, u)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	m.changed(a)
	w.Header().Set("Cache-Control", "no-store") // shown this once
	web.WriteJSON(w, http.StatusOK, map[string]any{"codes": codes})
}

func (m *Module) totpDisable(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	if !m.needReauth(w, r, a) {
		return
	}
	u, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if !u.HasTOTP() {
		writeErr(w, http.StatusConflict, "No Authenticator App is set up.", "")
		return
	}
	if m.mfaRequired(ctx, u) {
		if n, _ := m.s.Svc.UsablePasskeys(ctx, u.ID, ""); n == 0 {
			writeErr(w, http.StatusConflict, "You need a second factor. Add a passkey first.", "")
			return
		}
	}
	u.TOTPSecret, u.MFAEnrolledAt = "", nil
	if err := m.s.Svc.Users.Update(service.Durable(ctx), u); err != nil {
		web.WriteError(w, mapStoreErr(err))
		return
	}
	if err := m.s.Svc.DropRecoveryCodes(ctx, u.ID); err != nil {
		m.s.Log.Warn("recovery codes not removed with the last second factor", "user", u.ID, "error", err)
	}
	m.changed(a)
	m.auditSelf(r, a, "account.totp.disable", nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------------------------
// Sessions

type sessionItem struct {
	ID        string    `json:"id"` // an opaque handle, not the session id (which is the cookie secret)
	Current   bool      `json:"current"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"last_seen"`
	Expires   time.Time `json:"expires"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	AMR       []string  `json:"amr"`
}

func (m *Module) listSessions(w http.ResponseWriter, r *http.Request, a acct) {
	list, err := m.s.Svc.Sessions.All(r.Context(), a.u.ID)
	if err != nil {
		m.internalError(w, r, "list sessions", err)
		return
	}
	now := time.Now()
	items := make([]sessionItem, 0, len(list))
	for _, s := range list {
		if !s.Valid(now) {
			continue
		}
		amr := s.AMR
		if amr == nil {
			amr = []string{}
		}
		items = append(items, sessionItem{ID: web.SessionHandle(s.ID), Current: s.ID == a.sess.ID, Created: s.Created,
			LastSeen: s.LastSeen, Expires: s.Expires, IP: s.IP, UserAgent: s.UserAgent, AMR: amr})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Current != items[j].Current {
			return items[i].Current
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (m *Module) revokeSession(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	handle := r.PathValue("id")
	list, err := m.s.Svc.Sessions.All(ctx, a.u.ID)
	if err != nil {
		m.internalError(w, r, "list sessions", err)
		return
	}
	for _, s := range list {
		if web.SessionHandle(s.ID) != handle {
			continue
		}
		if s.ID == a.sess.ID {
			writeErr(w, http.StatusConflict, "That is the session you are using. Sign out instead.", "")
			return
		}
		if err := m.s.Sessions.Delete(ctx, s.ID); err != nil {
			web.WriteError(w, err)
			return
		}
		m.auditSelf(r, a, "account.session.revoke", map[string]string{"ip": s.IP})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeErr(w, http.StatusNotFound, "Not found.", "")
}

func (m *Module) revokeOtherSessions(w http.ResponseWriter, r *http.Request, a acct) {
	n := m.endOtherSessions(r.Context(), a)
	m.auditSelf(r, a, "account.session.revoke_others", map[string]string{"count": strconv.Itoa(n)})
	web.WriteJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// ---------------------------------------------------------------------------------------------------------------
// API tokens

type tokenItem struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	Audience  []string  `json:"audience"`
	AppScopes []string  `json:"app_scopes"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	LastUsed  time.Time `json:"last_used"`
}

func toTokenItem(t *model.APIToken) tokenItem {
	nn := func(l []string) []string {
		if l == nil {
			return []string{}
		}
		return l
	}
	return tokenItem{ID: t.ID, Name: t.Name, Scopes: t.Scopes, Audience: nn(t.Audience), AppScopes: nn(t.AppScopes),
		Created: t.Created, Expires: t.Expires, LastUsed: t.LastUsed}
}

func (m *Module) listTokens(w http.ResponseWriter, r *http.Request, a acct) {
	list, _, err := m.s.Svc.ListAPITokens(r.Context(), a.actor, store.ListQuery{Sort: "created", Desc: true})
	if err != nil {
		web.WriteError(w, err)
		return
	}
	items := make([]tokenItem, 0, len(list))
	for _, t := range list {
		items = append(items, toTokenItem(t))
	}
	scopes := []string{}
	for _, sc := range service.APITokenScopes {
		if (sc == service.ScopeSCIM || sc == service.ScopeAdmin) && a.actor.Role.Rank() < model.RoleManager.Rank() ||
			service.SuperOnlyScope(sc) && !a.actor.IsSuper() {
			continue
		}
		scopes = append(scopes, sc)
	}
	// the applications an api token can be for, with their own scopes (for the audience and scope choices)
	apps, err := m.s.Svc.TokenApps(r.Context(), a.actor)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "scopes": scopes,
		"max_days": m.s.Cfg.Tokens.APITokenMaxDays, "apps": apps})
}

// updateToken changes a token's name, applications or scopes. It can give a narrowed token its full access back, so
// it asks what making a token asks: a recent re-authentication, and a second factor for managers and up.
func (m *Module) updateToken(w http.ResponseWriter, r *http.Request, a acct) {
	var in service.APITokenUpdate
	if !decode(w, r, &in) || !m.needReauth(w, r, a) {
		return
	}
	if a.u.Role.Privileged() && !model.MFA(a.sess.AMR) {
		writeErr(w, http.StatusForbidden, "Sign in again with your second factor to change an API token.", "mfa")
		return
	}
	t, err := m.s.Svc.UpdateAPIToken(r.Context(), a.actor, r.PathValue("id"), in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"item": toTokenItem(t)})
}

func (m *Module) createToken(w http.ResponseWriter, r *http.Request, a acct) {
	var in service.APITokenInput
	if !decode(w, r, &in) || !m.needReauth(w, r, a) {
		return
	}
	// A manager's or administrator's token acts with their role and skips the console's second-factor check, so it
	// is only made from a session that used a second factor.
	if a.u.Role.Privileged() && !model.MFA(a.sess.AMR) {
		writeErr(w, http.StatusForbidden, "Sign in again with your second factor to create an API token.", "mfa")
		return
	}
	t, plain, err := m.s.Svc.CreateAPIToken(r.Context(), a.actor, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, map[string]any{"token": plain, "item": toTokenItem(t)})
}

// regenerateToken gives one of the user's tokens a new secret (shown once); the old one stops working. The same
// conditions as making a token: a recent re-authentication, and a second factor for managers and up.
func (m *Module) regenerateToken(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.needReauth(w, r, a) {
		return
	}
	if a.u.Role.Privileged() && !model.MFA(a.sess.AMR) {
		writeErr(w, http.StatusForbidden, "Sign in again with your second factor to make a new token secret.", "mfa")
		return
	}
	t, plain, err := m.s.Svc.RegenerateAPIToken(r.Context(), a.actor, r.PathValue("id"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"token": plain, "item": toTokenItem(t)})
}

func (m *Module) deleteToken(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	t, err := m.s.Svc.APITokens.Get(ctx, r.PathValue("id"))
	if err != nil || t.UserID != a.u.ID { // never a token of someone else, even for an admin (they use the management API)
		writeErr(w, http.StatusNotFound, "Not found.", "")
		return
	}
	if err := m.s.Svc.DeleteAPIToken(ctx, a.actor, t.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------------------------------------------
// Connected apps (refresh-token grants grouped by client)

func (m *Module) listApps(w http.ResponseWriter, r *http.Request, a acct) {
	items, err := m.s.Svc.ConnectedApps(r.Context(), a.u.ID)
	if err != nil {
		m.internalError(w, r, "list grants", err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (m *Module) revokeApp(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	client := r.PathValue("client")
	n, err := m.s.Svc.RevokeAppAccess(ctx, a.u.ID, client) // tells the application first (back-channel logout)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if n == 0 {
		writeErr(w, http.StatusNotFound, "Not found.", "")
		return
	}
	m.auditSelf(r, a, "account.app.revoke", map[string]string{"client": client})
	w.WriteHeader(http.StatusNoContent)
}

// mfaRequired reports whether u must keep a second factor: their organization requires one, or they are a manager
// or above.
func (m *Module) mfaRequired(ctx context.Context, u *model.User) bool {
	if u.Role.Privileged() {
		return true
	}
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	return err == nil && org.Settings.RequireMFA
}

// profileOptions handles GET /api-internal/account/profile-options: the languages, time zones and user types the
// autocompleters offer (the account page and the admin console). The same for everyone, so cacheable.
func (m *Module) profileOptions(w http.ResponseWriter, r *http.Request, a acct) {
	w.Header().Set("Cache-Control", "private, max-age=86400")
	web.WriteJSON(w, http.StatusOK, map[string]any{"locales": model.Locales, "time_zones": model.TimeZones,
		"user_types": model.UserTypes})
}
