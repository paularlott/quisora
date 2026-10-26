// Package login is the sign-in and self-service HTTP module: the landing page, per-organization sign-in (password
// with optional TOTP, passkeys, upstream providers), password reset and invitation pages, logout, and the account
// JSON API behind /account.
//
// Authentication method references (amr) recorded on sessions and surfaced in ID tokens:
//
//	pwd        password
//	otp        TOTP authenticator code
//	hwk        passkey on a hardware-bound key (not backup eligible)
//	swk        passkey on a synced/software key (backup eligible)
//	user       the authenticator verified the user (PIN or biometrics)
//	mfa        more than one factor was used (password+otp, password+passkey)
//	fed        signed in through an upstream provider (OIDC / GitHub)
//
// Organizations that require MFA (OrgSettings.RequireMFA) hold a password-verified user without a second factor at an
// enrolment step until they register an authenticator app or a passkey; a user with a passkey and no TOTP must use
// the passkey as the second factor; a passkey sign-in on its own satisfies the requirement. An upstream (federated)
// sign-in is a first factor like a password and gets the same second-factor step, unless its provider is trusted for
// the second factor (Provider.TrustMFA, plain users only: ["fed","mfa"]).
//
// So a password-only sign-in is ["pwd"], password+TOTP is ["pwd","otp","mfa"], a passkey is ["hwk","user"] or
// ["swk","user"], and a password followed by a passkey (an org that requires MFA) is ["pwd","swk","user","mfa"].
//
// Security properties implemented here: sign-in requests carry the anonymous double-submit CSRF token; failures
// look identical for unknown users, inactive users and wrong passwords and cost an argon2 hash either way; failed
// passwords and TOTP codes count toward a per-account lockout kept in ephemeral state (never database writes);
// every attempt is rate limited per organization and client IP; a TOTP code works once (TOTPLastStep); the "next"
// parameter is only ever honoured when it is a local path.
package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	netmail "net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/upstream"
	"github.com/paularlott/quisora/internal/web"
)

// Ephemeral namespaces used by this module (see also passkey, upstream and mail).
const (
	nsTicket  = "login"       // multi-step sign-in tickets
	nsTry     = "login.try"   // attempts per ticket
	nsLockout = "lockout"     // failed attempts per account
	nsRate    = "rl"          // per org+IP request counters
	nsForgot  = "forgot"      // password reset mails per user
	nsReauth  = "reauth"      // recent re-authentication of a session
	nsPending = "totp.pend"   // TOTP secret being enrolled for a session
	nsVerify  = "verify.mail" // verification mails per user
)

const (
	ticketTTL      = 5 * time.Minute
	enrolTTL       = 10 * time.Minute
	reauthTTL      = 5 * time.Minute
	ticketAttempts = 5
	defaultNext    = "/account"
	msgBadLogin    = "The email address or password is incorrect."
	msgBadCSRF     = "The request could not be verified. Reload the page and try again."
)

// Module implements web.Module.
type Module struct {
	// Passkeys is nil when the public URL cannot be a WebAuthn relying party (an IP address); passkey features are
	// then switched off.
	Passkeys *passkey.Service
	Upstream *upstream.Service
	Mail     *mail.Mailer

	stepUp func(ctx context.Context, next string) bool
	s      *web.Server
}

// Options configures New.
type Options struct {
	// Mail sends invitation, reset and verification emails; nil disables them (forgot-password then does nothing).
	Mail *mail.Mailer
	// StepUp reports whether the sign-in continuing at next asks for a second factor of its own (an OpenID
	// Connect request with acr_values for MFA); the sign-in then requires one as a tenant that requires it would.
	StepUp func(ctx context.Context, next string) bool
}

// New builds the module for s.
func New(s *web.Server, o Options) *Module {
	m := &Module{s: s, Mail: o.Mail, stepUp: o.StepUp}
	if pk, err := passkey.New(s.Cfg, s.Svc, s.Eph); err == nil {
		m.Passkeys = pk
	} else {
		s.Log.Warn("passkeys disabled", "error", err)
	}
	// Provider issuers are entered by organization administrators: the same address guard as back-channel logout
	// and client JWKS (allowed_networks or allow_private_networks lets an internal provider through), and the extra
	// CA roots.
	roots, _ := secure.RootPool(s.Cfg.Server.ExtraCAFile) // checked by config.Validate
	m.Upstream = upstream.New(s.Svc, s.Eph, s.Cfg.Server.PublicURL, secure.OutboundClient(s.Cfg.OutboundReach, roots, s.Log))
	if m.Mail != nil && m.Mail.Svc == nil {
		m.Mail.SetService(s.Svc)
	}
	return m
}

// Register adds the routes.
func (m *Module) Register(s *web.Server) {
	m.s = s
	s.Reauthed = func(r *http.Request) bool {
		sess := web.Session(r)
		if sess == nil {
			return false
		}
		return m.reauthed(r.Context(), acct{sess: sess}) || time.Since(sess.AuthTime) < reauthTTL
	}
	mux := s.Mux
	// pages
	mux.Handle("GET /{$}", s.WithSession(http.HandlerFunc(m.landing)))
	mux.Handle("GET /login/{org}", s.WithSession(http.HandlerFunc(m.loginPage)))
	mux.Handle("GET /login/{org}/provider/{id}", http.HandlerFunc(m.providerStart))
	mux.Handle("GET /login/callback/{provider}", http.HandlerFunc(m.providerCallback))
	mux.Handle("GET /invite", http.HandlerFunc(m.invitePage))
	mux.Handle("GET /reset", http.HandlerFunc(m.resetPage))
	mux.Handle("GET /verify-email", http.HandlerFunc(m.verifyEmailPage))
	mux.Handle("POST /verify-email", http.HandlerFunc(m.verifyEmail))
	mux.Handle("GET /logout", s.WithSession(http.HandlerFunc(m.logoutPage)))
	mux.Handle("POST /logout", s.WithSession(http.HandlerFunc(m.logout)))
	mux.Handle("GET /account", s.RequirePage(m.accountPage))

	// anonymous sign-in JSON
	mux.HandleFunc("POST /api-internal/login/password", m.password)
	mux.HandleFunc("POST /api-internal/login/totp", m.totp)
	mux.HandleFunc("POST /api-internal/login/recovery", m.recovery)
	mux.HandleFunc("POST /api-internal/login/email/send", m.emailSend)
	mux.HandleFunc("POST /api-internal/login/email", m.emailVerify)
	mux.HandleFunc("POST /api-internal/login/passkey/begin", m.passkeyBegin)
	mux.HandleFunc("POST /api-internal/login/passkey/finish", m.passkeyFinish)
	mux.HandleFunc("POST /api-internal/login/enrol/totp/begin", m.enrolTOTPBegin)
	mux.HandleFunc("POST /api-internal/login/enrol/totp/confirm", m.enrolTOTPConfirm)
	mux.HandleFunc("POST /api-internal/login/enrol/passkey/begin", m.enrolPasskeyBegin)
	mux.HandleFunc("POST /api-internal/login/enrol/passkey/finish", m.enrolPasskeyFinish)
	mux.HandleFunc("POST /api-internal/password/forgot", m.forgot)
	mux.HandleFunc("POST /api-internal/password/reset", m.reset)
	mux.HandleFunc("POST /api-internal/invite/passkey/begin", m.inviteBegin)
	mux.HandleFunc("POST /api-internal/invite/complete", m.inviteComplete)

	m.registerAccount(s)
}

// ---------------------------------------------------------------------------------------------------------------
// Helpers

func writeErr(w http.ResponseWriter, status int, msg, field string) {
	web.WriteJSON(w, status, web.ErrorBody{Error: msg, Field: field})
}

// anonOK checks the anonymous CSRF token of a sign-in request.
func (m *Module) anonOK(w http.ResponseWriter, r *http.Request) bool {
	if !m.s.CheckAnonCSRF(r) {
		writeErr(w, http.StatusForbidden, msgBadCSRF, "")
		return false
	}
	return true
}

// decode reads a JSON body; unknown fields are rejected.
func decode(w http.ResponseWriter, r *http.Request, v any) bool { return web.DecodeJSON(w, r, v) }

// safeNext returns next when it is a local path (starts with a single "/", no scheme, host, backslash or control
// character) and "" otherwise.
func safeNext(next string) string {
	if next == "" || len(next) > 2048 || next[0] != '/' || strings.HasPrefix(next, "//") {
		return ""
	}
	for i := 0; i < len(next); i++ {
		if c := next[i]; c < 0x20 || c == 0x7f || c == '\\' {
			return ""
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return ""
	}
	return next
}

func nextOrDefault(next string) string {
	if n := safeNext(next); n != "" {
		return n
	}
	return defaultNext
}

// WebAuthn ceremony purposes (passkey.PurposeKey): every finish handler accepts only its own.
const (
	purposeLogin        = "login"
	purposeSecondFactor = "second-factor"
	purposeReauth       = "reauth"
	purposeRegister     = "register"
	purposeEnrol        = "enrol"
	purposeInvite       = "invite"
)

// maxTenantName bounds the tenant parameter (a URL-safe slug of at most 63 characters).
const maxTenantName = 63

// methods returns the sign-in methods an org offers for the tenant named tenantName (resolved within the org). An
// empty or unknown tenant means the org's own methods; it is never an error. The returned name is the canonical
// name of the tenant that applied, or "" for none.
func (m *Module) methods(ctx context.Context, org *model.Org, tenantName, next string) (*service.SignInMethods, string, error) {
	var t *model.Tenant
	name := strings.ToLower(strings.TrimSpace(tenantName))
	if name != "" && len(name) <= maxTenantName {
		if tt, err := m.s.Svc.Tenants.GetByUnique(ctx, model.TenantNameKey(org.ID, name)); err == nil && tt.OrgID == org.ID {
			t = tt
		}
	}
	eff, err := m.s.Svc.EffectiveSignIn(ctx, org, t)
	if err != nil {
		return nil, "", err
	}
	if !eff.RequireMFA && next != "" && m.stepUp != nil && m.stepUp(ctx, next) {
		e := *eff
		e.RequireMFA = true
		eff = &e
	}
	if t == nil {
		return eff, "", nil
	}
	return eff, t.Name, nil
}

// unknownOrgKey is the shared rate-limit bucket for every organization name that does not exist, so random names
// cannot mint fresh buckets.
const unknownOrgKey = "unknown"

// resolveOrg normalises an organization name once (trim + lower case) and looks it up. The returned key is the
// canonical name for a real org and a single fixed pseudo-key otherwise; use it for rate limiting.
func (m *Module) resolveOrg(ctx context.Context, raw string) (*model.Org, string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return nil, unknownOrgKey, nil
	}
	org, err := m.s.Svc.OrgByName(ctx, name)
	if err != nil && !errors.Is(err, service.ErrNotFound) && !errors.Is(err, store.ErrNotFound) {
		return nil, unknownOrgKey, err // not "no such organization": the store cannot answer now
	}
	if err != nil || org == nil {
		return nil, unknownOrgKey, nil
	}
	return org, strings.ToLower(org.Name), nil
}

// allow counts a sign-in request for org+client IP in a one-minute window and reports whether it is within the
// configured limit (Limits.LoginPerIPMin). A request from a browser that has signed in to the account (or org) it is
// for, as k says, is counted against that account's own budget instead (see device.go), so a flood from the same
// address does not keep it out.
//
// tripped names the limit ("device", "address" or "organization") when this request is the first one it refuses in
// its minute, so the audit log gets one event per limit and minute, not one per refused request.
func (m *Module) allow(r *http.Request, orgKey string, k known) (ok bool, tripped string, uid string) {
	limit := int64(m.s.Cfg.Limits.LoginPerIPMin)
	if limit <= 0 {
		return true, "", ""
	}
	if uid, ok := m.knownDevice(r, k); ok {
		n, err := m.s.Eph.Incr(r.Context(), nsRate, "login-dev|"+uid, 1, time.Minute)
		return err == nil && n <= limit, tripIf(n == limit+1, "device"), uid
	}
	ip := web.RateKeyIP(r)
	// An IP-only ceiling (three times the per-org limit) bounds what one client can spend across organizations,
	// whatever names it sends.
	// Counters fail closed: a counter that cannot be read or updated refuses rather than allows.
	if n, err := m.s.Eph.Incr(r.Context(), nsRate, "login-ip|"+ip, 1, time.Minute); err != nil || n > 3*limit {
		return false, tripIf(n == 3*limit+1, "address"), ""
	}
	key := "login|" + strings.ToLower(orgKey) + "|" + ip
	n, err := m.s.Eph.Incr(r.Context(), nsRate, key, 1, time.Minute)
	return err == nil && n <= limit, tripIf(n == limit+1, "organization"), ""
}

// allowed is allow for a page that answers a refusal its own way (a link page shows the link as invalid).
func (m *Module) allowed(r *http.Request, orgKey string, k known) bool {
	ok, tripped, uid := m.allow(r, orgKey, k)
	if tripped != "" {
		m.auditLimited(r, orgKey, tripped, uid)
	}
	return ok
}

func tripIf(first bool, limit string) string {
	if first {
		return limit
	}
	return ""
}

// rateLimit is allow plus the 429 response (with Retry-After); it returns false when the request was rejected.
func (m *Module) rateLimit(w http.ResponseWriter, r *http.Request, orgKey string, k known) bool {
	ok, tripped, uid := m.allow(r, orgKey, k)
	if ok {
		return true
	}
	if tripped != "" {
		m.auditLimited(r, orgKey, tripped, uid)
	}
	w.Header().Set("Retry-After", "60")
	writeErr(w, http.StatusTooManyRequests, "Too many attempts. Please wait a minute and try again.", "")
	return false
}

// auditLimited records that a sign-in limit started refusing requests (login.limited): once per limit and minute.
func (m *Module) auditLimited(r *http.Request, orgKey, limit, uid string) {
	ctx := r.Context()
	org, err := m.s.Svc.OrgByName(ctx, strings.ToLower(orgKey))
	if err != nil {
		org, _ = m.s.Svc.PrimaryOrg(ctx) // not an organization (a link, a callback): the primary one's log
	}
	orgID := ""
	if org != nil {
		orgID = org.ID
	}
	target := web.ClientIP(r)
	if uid != "" {
		target = uid
	}
	m.s.Svc.Audit(ctx, &service.Actor{IP: web.ClientIP(r), Name: "anonymous"}, orgID, "login.limited", target,
		map[string]string{"limit": limit, "per_minute": strconv.Itoa(m.s.Cfg.Limits.LoginPerIPMin), "bucket": orgKey})
}

// ---- lockout -------------------------------------------------------------------------------------------------

func (m *Module) lockWindow() time.Duration {
	mins := m.s.Cfg.Limits.LockoutMinutes
	if mins <= 0 {
		mins = 15
	}
	return time.Duration(mins) * time.Minute
}

// lockKey identifies the account being attacked. Unknown logins get a pseudo key so that an attacker sees the same
// behaviour (including the lockout response) whether or not the account exists.
func lockKey(u *model.User, org *model.Org, login string) string {
	if u != nil {
		return u.ID
	}
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(login))))
	id := ""
	if org != nil {
		id = org.ID
	}
	return "x:" + id + ":" + base64.RawURLEncoding.EncodeToString(h[:12])
}

// charge counts an attempt against the lockout counter key before the attempt is checked, and reports false when
// the account has used up its attempts (or the counter cannot be reached: fail closed). Counting first is what makes
// the limit hold for attempts sent at once: had only finished failures counted, every attempt in a burst would pass
// the check before the first was charged. The charge is a failure unless it is given back: settle, deferred by the
// caller, refunds it for every outcome but a wrong credential (n is then this failure's number: tripped).
func (m *Module) charge(ctx context.Context, key string) (n int64, ok bool) {
	max := m.s.Cfg.Limits.LockoutAttempts
	if max <= 0 {
		return 0, true
	}
	n, err := m.s.Eph.Incr(ctx, nsLockout, key, 1, m.lockWindow())
	if err == nil && n > int64(max) { // refused while locked: not an attempt, so the counter stays at the limit
		_, _ = m.s.Eph.Incr(context.WithoutCancel(ctx), nsLockout, key, -1, m.lockWindow())
	}
	return n, err == nil && n <= int64(max)
}

// settle gives back a charge (charge) unless *wrong says the attempt was a wrong credential.
func (m *Module) settle(ctx context.Context, key string, wrong *bool) {
	if *wrong || m.s.Cfg.Limits.LockoutAttempts <= 0 {
		return
	}
	_, _ = m.s.Eph.Incr(context.WithoutCancel(ctx), nsLockout, key, -1, m.lockWindow())
}

// tripped reports whether the n-th failure (charge) is the one that locks the account.
func (m *Module) tripped(n int64) bool {
	max := m.s.Cfg.Limits.LockoutAttempts
	return max > 0 && n == int64(max)
}

func (m *Module) clearLock(ctx context.Context, key string) { _ = m.s.Eph.Delete(ctx, nsLockout, key) }

// clearLocks clears both of a user's lockout counters: the account's and its known browsers' (lockKeyFor).
func (m *Module) clearLocks(ctx context.Context, userID string) {
	m.clearLock(ctx, userID)
	m.clearLock(ctx, "dev:"+userID)
}

// unavailableResponse answers a step that could not read the account from its cluster (service.ErrUnavailable).
func unavailableResponse(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	writeErr(w, http.StatusServiceUnavailable, "The server cannot check your account right now. Please try again in a moment.", "")
}

func (m *Module) lockedResponse(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(int(m.lockWindow().Seconds())))
	writeErr(w, http.StatusTooManyRequests, "Too many failed attempts. Please try again later.", "")
}

// ---- audit ---------------------------------------------------------------------------------------------------

func (m *Module) audit(r *http.Request, action string, org *model.Org, u *model.User, login string, detail map[string]string) {
	login = auditLogin(login)
	a := &service.Actor{IP: web.ClientIP(r), Name: login}
	target := login
	orgID := ""
	if org != nil {
		orgID = org.ID
	}
	if u != nil {
		a.UserID, a.OrgID, a.Role, a.Name = u.ID, u.OrgID, u.Role, u.Username
		target, orgID = u.Username, u.OrgID
	}
	m.s.Svc.Audit(context.WithoutCancel(r.Context()), a, orgID, action, target, detail)
}

// auditLogin is what an audit event records of a login typed for an account that was not found: the address when it
// is one (evidence of which addresses are being tried), else a placeholder. People type their password into the
// address box, and the audit trail and the structured log must never hold one.
func auditLogin(login string) string {
	if login == "" {
		return ""
	}
	if a, err := netmail.ParseAddress(login); err == nil && a.Name == "" && a.Address == login && !strings.ContainsAny(login, " \t") {
		return login
	}
	return "(not an email address)"
}

// ---- tickets -------------------------------------------------------------------------------------------------

// ticket is the state between the steps of a sign-in (TOTP code, passkey as second factor, MFA enrolment).
type ticket struct {
	Step    string   `json:"s"` // totp, passkey, email_code, enrol
	UserID  string   `json:"u"`
	OrgID   string   `json:"o,omitempty"` // the user's organization: the account is read from its partition's owner
	Next    string   `json:"n,omitempty"`
	AMR     []string `json:"a"`
	Pending string   `json:"p,omitempty"` // sealed TOTP secret being enrolled
	Tenant  string   `json:"t,omitempty"` // tenant name the sign-in is for
	// Provider is the upstream provider of a federated first factor (recorded on the session it ends in).
	Provider string `json:"pv,omitempty"`
	// Gen is the account's security generation (model.User.SecurityGen) when the first factor was verified, and Stamp
	// the sign-out counters then (model.SignOutStamp). Every later step checks both against the account as it is now
	// (ticketCurrent): a ticket whose password has since been changed, whose account set up a second factor
	// meanwhile, was disabled, re-enabled or given another role, or whose organization pulled the emergency
	// sign-out lever, is dead, and the browser holding it starts again with the account's current credentials.
	Gen   uint64             `json:"g"`
	Stamp model.SignOutStamp `json:"st"`
}

// bind records on t the account state its first factor was verified against (see ticket.Gen).
func (m *Module) bind(ctx context.Context, t *ticket, u *model.User) error {
	st, err := m.s.Svc.SessionStamp(ctx, u.OrgID)
	if err != nil {
		return err
	}
	t.UserID, t.OrgID, t.Gen, t.Stamp = u.ID, u.OrgID, u.SecurityGen, st
	return nil
}

// ticketCurrent reports whether t still binds to u as the account is now: the one it was issued for, enabled, at the
// same security generation, and not signed out by the emergency lever since. u must be freshly read.
func (m *Module) ticketCurrent(ctx context.Context, t *ticket, u *model.User) bool {
	return t.UserID == u.ID && u.Enabled(time.Now()) && u.SecurityGen == t.Gen &&
		m.s.Svc.SessionCurrent(ctx, u.OrgID, t.Stamp)
}

// ticketUser loads the user and organization of a ticket's sign-in, as they are now, if the ticket still binds to
// them (ticketCurrent). The user is read afresh here, from the owners' copies (a step that only checks a code writes
// nothing to the user, so no compare-and-swap would catch a password change this node has not received yet), so a
// step that commits a change to it (setting a factor) does
// so with a compare-and-swap on this very version: a change made between this read and that write — another
// completion of the same sign-in, the owner setting up a factor — makes the write stale, and the step refuses.
func (m *Module) ticketUser(ctx context.Context, t *ticket) (*model.User, *model.Org, bool) {
	u, err := m.s.Svc.FreshUserIn(ctx, t.OrgID, t.UserID)
	if err != nil || !m.ticketCurrent(ctx, t, u) {
		return nil, nil, false
	}
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if err != nil {
		return nil, nil, false
	}
	return u, org, true
}

const msgExpired = "Your sign-in has expired. Start again."

// step loads the sign-in a request continues: a ticket at one of the steps, its user and organization (ticketUser),
// within the organization's rate limit for the account. On failure it has written the answer (401 for a dead ticket,
// 429 when limited) and the handler returns.
func (m *Module) step(w http.ResponseWriter, r *http.Request, id string, steps ...string) (*ticket, *model.User, *model.Org, bool) {
	ctx := r.Context()
	t, ok := m.getTicket(ctx, id, steps...)
	if !ok {
		writeErr(w, http.StatusUnauthorized, msgExpired, "")
		return nil, nil, nil, false
	}
	u, org, ok := m.ticketUser(ctx, t)
	if !ok {
		writeErr(w, http.StatusUnauthorized, msgExpired, "")
		return nil, nil, nil, false
	}
	if !m.rateLimit(w, r, org.Name, known{userID: u.ID}) {
		return nil, nil, nil, false
	}
	return t, u, org, true
}

func (m *Module) putTicket(ctx context.Context, t *ticket, ttl time.Duration) (string, error) {
	b, _ := json.Marshal(t)
	return m.s.Eph.New(ctx, nsTicket, b, ttl)
}

// getTicket reads a ticket and checks the step; it does not consume it.
func (m *Module) getTicket(ctx context.Context, id string, steps ...string) (*ticket, bool) {
	b, err := m.s.Eph.Get(ctx, nsTicket, id)
	if err != nil {
		return nil, false
	}
	var t ticket
	if json.Unmarshal(b, &t) != nil {
		return nil, false
	}
	for _, s := range steps {
		if t.Step == s {
			return &t, true
		}
	}
	return nil, false
}

// useTicket consumes the ticket; only one concurrent caller wins.
func (m *Module) useTicket(ctx context.Context, id string) bool {
	_, err := m.s.Eph.Take(ctx, nsTicket, id)
	return err == nil
}

// attempt counts tries against one ticket and drops it after too many.
func (m *Module) attempt(ctx context.Context, id string) bool {
	n, err := m.s.Eph.Incr(ctx, nsTry, id, 1, enrolTTL)
	if err != nil || n > ticketAttempts {
		_ = m.s.Eph.Delete(ctx, nsTicket, id)
		return false
	}
	return true
}

// ---- completing a sign-in ------------------------------------------------------------------------------------

// complete finishes a sign-in: upgrades the browser's session when it is the same user's (or replaces another user's
// session with a new one), records the login and returns where to send the browser.
func (m *Module) complete(w http.ResponseWriter, r *http.Request, u *model.User, org *model.Org, amr []string, next string) (string, error) {
	return m.completeWith(w, r, u, org, web.SessionOptions{AMR: amr}, next)
}

// completeWith is complete with session options (the upstream provider of a federated sign-in).
func (m *Module) completeWith(w http.ResponseWriter, r *http.Request, u *model.User, org *model.Org, opt web.SessionOptions, next string) (string, error) {
	ctx := r.Context()
	amr := opt.AMR
	upgraded := false
	if old, _ := m.s.Sessions.Current(r); old != nil {
		if old.UserID == u.ID {
			// The same user signing in again (prompt=login, max_age, a second factor asked for, or simply again):
			// the session is upgraded in place, keeping the refresh grants other applications hold on it, with a
			// new cookie value.
			if sess, err := m.s.Sessions.Upgrade(ctx, w, r, old, u, org, opt); err == nil {
				upgraded = true
				noteSession(ctx, sess)
			} else {
				m.s.Log.Warn("session upgrade failed; starting a new session", "error", err)
			}
		}
		if !upgraded { // another user (or no upgrade possible): the old session ends, or the sign-in fails
			if err := m.s.Sessions.Delete(ctx, old.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return "", err
			}
		}
	}
	if !upgraded {
		sess, err := m.s.Sessions.CreateWith(ctx, w, r, u, org, opt)
		if err != nil {
			return "", err
		}
		noteSession(ctx, sess)
	}
	// The last sign-in time is best effort and nothing below needs it: it is recorded in the background, so the sign-in
	// does not wait for one more write (in a gossip cluster, a round trip to the partition's owner and a majority).
	touched := *u
	m.s.Svc.Background(ctx, func(ctx context.Context) { m.s.Svc.TouchLogin(ctx, &touched) })
	// Only the counter this browser charges (lockKeyFor): the owner signing in from a known browser must not reset
	// the account-wide one, which only strangers' browsers charge (a reset or an accepted invitation clears both).
	m.clearLock(ctx, m.lockKeyFor(r, u, u.ID))
	m.rememberDevice(w, r, u)
	if m.s.Cfg.Audit.Logins {
		m.audit(r, "login.success", org, u, u.Username, map[string]string{"amr": strings.Join(amr, " ")})
	}
	return nextOrDefault(next), nil
}

// noteSession records the session a sign-in made for the rest of the request's audit events (login.success).
func noteSession(ctx context.Context, sess *model.Session) {
	if ri := service.RequestFrom(ctx); ri != nil && sess != nil {
		ri.SessionID = sess.ID
	}
}

func (m *Module) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	if errors.Is(err, store.ErrUnconfirmed) || errors.Is(err, store.ErrNotWritable) ||
		errors.Is(err, service.ErrOutcomeUnknown) || errors.Is(err, service.ErrUnavailable) {
		// the cluster could not confirm the change in time: trying again is safe, and the answer says so
		m.s.Log.Warn(what, "error", err, "path", r.URL.Path)
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "We could not complete this just now. Please try again in a moment.", "")
		return
	}
	m.s.Log.Error(what, "error", err, "path", r.URL.Path)
	writeErr(w, http.StatusInternalServerError, "Something went wrong. Please try again.", "")
}

// passkeysOK answers 404-style when passkeys are switched off.
func (m *Module) passkeysOK(w http.ResponseWriter) bool {
	if m.Passkeys == nil {
		writeErr(w, http.StatusServiceUnavailable, "Passkeys are not available on this server.", "")
		return false
	}
	return true
}
