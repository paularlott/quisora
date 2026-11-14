// Package login is the sign-in and self-service HTTP module: the landing page, per-organization sign-in (password
// with optional TOTP, passkeys, upstream providers), password reset and invitation pages, logout, and the account
// JSON API behind the account page. Every page and endpoint of it is in an organization's own address space,
// /o/{org}/... (web.Server.InOrg): the organization is the one the path names, the browser's session there is that
// organization's only, and nothing here takes the organization from anywhere else.
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
// the second factor (Provider.TrustMFA, plain users only, when its ID token's amr has "mfa" or there is none:
// ["fed","mfa"]).
//
// So a password-only sign-in is ["pwd"], password+TOTP is ["pwd","otp","mfa"], a passkey is ["hwk","user","mfa"] or
// ["swk","user","mfa"] (["hwk"] without user verification), and a password followed by a passkey (an org that
// requires MFA) is ["pwd","swk","user","mfa"]. A federated sign-in also keeps what the provider said about it
// (Session.UpstreamAMR) apart from these: tokens pass it on, nothing here decides on it.
//
// Security properties implemented here: sign-in requests carry the anonymous double-submit CSRF token; failures
// look identical for unknown users, inactive users and wrong passwords and cost an argon2 hash either way; failed
// passwords and TOTP codes count toward a per-account lockout kept in ephemeral state (never database writes), and
// failed passwords toward a per-address one as well while the organization is under a password spray (spray.go);
// every attempt is rate limited per organization and client IP; a TOTP code works once (TOTPLastStep); the "next"
// parameter is only ever honoured when it is a path in the organization's own address space (or the console).
package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	netmail "net/mail"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/paularlott/quisora/internal/ephemeral"
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
	// CA roots. The requests of an organization provider to its source organization are this server's own: it serves
	// them itself, not over the network (web.Server.SelfTransport).
	roots, _ := secure.RootPool(s.Cfg.Server.ExtraCAFile) // checked by config.Validate
	client := secure.OutboundClient(s.Cfg.OutboundReach, roots, s.Log)
	client.Transport = s.SelfTransport(client.Transport)
	m.Upstream = upstream.New(s.Svc, s.Eph, s.Cfg.Server.PublicURL, client)
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
		a := acct{sess: sess}
		if m.reauthed(r.Context(), a) {
			return true
		}
		ok, err := m.freshSignIn(r.Context(), a) // as the account page decides (needReauth)
		return err == nil && ok
	}
	mux := s.Mux
	// inOrg registers an organization's page or endpoint: the path names the organization (s.InOrg), and with it the
	// session the request may present.
	inOrg := func(pattern string, h http.Handler) {
		method, path, _ := strings.Cut(pattern, " ")
		mux.Handle(method+" /o/{org}"+path, s.InOrg(h))
	}
	// pages
	mux.Handle("GET /{$}", s.WithSession(http.HandlerFunc(m.landing)))
	inOrg("GET /login", s.WithSession(http.HandlerFunc(m.loginPage)))
	inOrg("GET /login/provider/{id}", http.HandlerFunc(m.providerStart))
	inOrg("GET /login/callback/{provider}", http.HandlerFunc(m.providerCallback))
	inOrg("GET /invite", http.HandlerFunc(m.invitePage))
	inOrg("GET /reset", http.HandlerFunc(m.resetPage))
	inOrg("GET /verify-email", http.HandlerFunc(m.verifyEmailPage))
	inOrg("POST /verify-email", http.HandlerFunc(m.verifyEmail))
	inOrg("GET /logout", s.WithSession(http.HandlerFunc(m.logoutPage)))
	inOrg("POST /logout", s.WithSession(http.HandlerFunc(m.logout)))
	inOrg("GET /account", s.RequirePage(m.accountPage))

	// anonymous sign-in JSON
	inOrg("POST /api-internal/login/password", http.HandlerFunc(m.password))
	inOrg("POST /api-internal/login/totp", http.HandlerFunc(m.totp))
	inOrg("POST /api-internal/login/recovery", http.HandlerFunc(m.recovery))
	inOrg("POST /api-internal/login/email/send", http.HandlerFunc(m.emailSend))
	inOrg("POST /api-internal/login/email", http.HandlerFunc(m.emailVerify))
	inOrg("POST /api-internal/login/passkey/begin", http.HandlerFunc(m.passkeyBegin))
	inOrg("POST /api-internal/login/passkey/finish", http.HandlerFunc(m.passkeyFinish))
	inOrg("POST /api-internal/login/enrol/totp/begin", http.HandlerFunc(m.enrolTOTPBegin))
	inOrg("POST /api-internal/login/enrol/totp/confirm", http.HandlerFunc(m.enrolTOTPConfirm))
	inOrg("POST /api-internal/login/enrol/passkey/begin", http.HandlerFunc(m.enrolPasskeyBegin))
	inOrg("POST /api-internal/login/enrol/passkey/finish", http.HandlerFunc(m.enrolPasskeyFinish))
	inOrg("POST /api-internal/password/forgot", http.HandlerFunc(m.forgot))
	inOrg("POST /api-internal/password/reset", http.HandlerFunc(m.reset))
	inOrg("POST /api-internal/invite/passkey/begin", http.HandlerFunc(m.inviteBegin))
	inOrg("POST /api-internal/invite/complete", http.HandlerFunc(m.inviteComplete))

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

// safeNext returns next when a browser sent there after signing in to org stays where that sign-in belongs, and ""
// otherwise: a local path (starts with a single "/", no scheme, host, backslash or control character) in the
// organization's own address space, /o/<org id> (or its name: the page a browser was sent from may have been opened
// by name), or in the console, /admin. Another organization's pages are not the place for this sign-in to lead, and a
// path with dot segments could climb out of either.
func safeNext(org *model.Org, next string) string {
	// It is kept with the sign-in it belongs to (a ticket, a provider's state, a passkey challenge), so it must be
	// text that takes there what it takes here: bytes that are not UTF-8 would each be kept as six.
	if next == "" || len(next) > 2048 || next[0] != '/' || strings.HasPrefix(next, "//") || !utf8.ValidString(next) {
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
	if slices.ContainsFunc(strings.Split(u.Path, "/"), func(seg string) bool { return seg == "." || seg == ".." }) {
		return ""
	}
	if !inOrgSpace(org, u.Path) && !inSpace(u.Path, "/admin") {
		return ""
	}
	return next
}

// inOrgSpace reports whether path is in org's space, /o/<ref> or below it, where ref names org as service.OrgByRef
// reads it: by its id, exactly, when ref is an id, else by its name in any case. Ids are case-sensitive: another
// organization's id, folded to lower case, may spell this one's name.
func inOrgSpace(org *model.Org, path string) bool {
	rest, ok := strings.CutPrefix(path, web.OrgPath("", ""))
	if !ok {
		return false
	}
	ref, _, _ := strings.Cut(rest, "/")
	if model.IsID(ref) {
		return ref == org.ID
	}
	return strings.ToLower(ref) == org.Name
}

// inSpace reports whether path is root or below it (root has no trailing slash).
func inSpace(path, root string) bool { return path == root || strings.HasPrefix(path, root+"/") }

// nextOrDefault is where a sign-in to org continues: next when it stays in the organization's space (safeNext), else
// the organization's account page.
func nextOrDefault(org *model.Org, next string) string {
	if n := safeNext(org, next); n != "" {
		return n
	}
	return web.OrgPath(org.ID, "/account")
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

// allow counts a sign-in request for a bucket (an organization's id, or its id and a kind of link or callback) and
// client IP in a one-minute window and reports whether it is within the configured limit (Limits.LoginPerIPMin). A request from a browser that has signed in to the account (or org) it is
// for, as k says, is counted against that account's own budget instead (see device.go), so a flood from the same
// address does not keep it out.
//
// tripped names the limit ("device", "address" or "organization") when this request is the first one it refuses in
// its minute, so the audit log gets one event per limit and minute, not one per refused request. Counters fail
// closed: a counter that cannot be read or updated refuses (ok is false) and err says so, so that the refusal is
// answered as "unavailable" and no limit is reported as tripped.
func (m *Module) allow(r *http.Request, bucket string, k known) (ok bool, tripped string, uid string, err error) {
	limit := int64(m.s.Cfg.LiveLimits().LoginPerIPMin)
	if limit <= 0 {
		return true, "", "", nil
	}
	if uid, ok := m.knownDevice(r, k); ok {
		n, err := m.s.Eph.Incr(r.Context(), nsRate, "login-dev|"+uid, 1, time.Minute)
		if err != nil {
			return false, "", uid, err
		}
		return n <= limit, tripIf(n == limit+1, "device"), uid, nil
	}
	ip := web.RateKeyIP(r)
	// An IP-only ceiling (three times the per-org limit) bounds what one client can spend across organizations,
	// whatever names it sends.
	n, err := m.s.Eph.Incr(r.Context(), nsRate, "login-ip|"+ip, 1, time.Minute)
	if err != nil {
		return false, "", "", err
	}
	if n > 3*limit {
		return false, tripIf(n == 3*limit+1, "address"), "", nil
	}
	key := "login|" + bucket + "|" + ip
	n, err = m.s.Eph.Incr(r.Context(), nsRate, key, 1, time.Minute)
	if err != nil {
		return false, "", "", err
	}
	return n <= limit, tripIf(n == limit+1, "organization"), "", nil
}

// allowed is allow for a page that answers a refusal its own way (a link page shows the link as invalid). A counter
// that fails refuses too, but is not audited as a limit that tripped.
func (m *Module) allowed(r *http.Request, bucket string, k known) bool {
	ok, tripped, uid, err := m.allow(r, bucket, k)
	if err != nil {
		return false
	}
	if tripped != "" {
		m.auditLimited(r, bucket, tripped, uid)
	}
	return ok
}

func tripIf(first bool, limit string) string {
	if first {
		return limit
	}
	return ""
}

// rateLimit is allow plus the 429 response (with Retry-After); it returns false when the request was rejected. A
// counter that fails is answered as unavailable, and nothing is audited.
func (m *Module) rateLimit(w http.ResponseWriter, r *http.Request, bucket string, k known) bool {
	ok, tripped, uid, err := m.allow(r, bucket, k)
	if err != nil {
		unavailableResponse(w)
		return false
	}
	if ok {
		return true
	}
	if tripped != "" {
		m.auditLimited(r, bucket, tripped, uid)
	}
	w.Header().Set("Retry-After", "60")
	writeErr(w, http.StatusTooManyRequests, "Too many attempts. Please wait a minute and try again.", "")
	return false
}

// auditLimited records that a sign-in limit started refusing requests (login.limited): once per limit and minute.
func (m *Module) auditLimited(r *http.Request, bucket, limit, uid string) {
	ctx := r.Context()
	orgID := web.Org(r).ID
	a := &service.Actor{IP: web.ClientIP(r), Name: "anonymous"}
	detail := map[string]string{"limit": limit, "per_minute": strconv.Itoa(m.s.Cfg.LiveLimits().LoginPerIPMin), "bucket": bucket}
	if uid != "" { // the budget of an account (a browser it signed in from): the account is the target
		m.s.Svc.AuditUser(ctx, a, m.s.Svc.AuditTargetUser(ctx, orgID, uid), "login.limited", detail)
		return
	}
	m.s.Svc.Audit(ctx, a, orgID, "login.limited", web.ClientIP(r), detail)
}

// ---- lockout -------------------------------------------------------------------------------------------------

// lockWindow is how long an account of org stays locked (service.Lockout).
func (m *Module) lockWindow(org *model.Org) time.Duration {
	_, w := m.s.Svc.Lockout(org)
	return w
}

// lockKey identifies the account being attacked. Unknown logins get a pseudo key so that an attacker sees the same
// behaviour (including the lockout response) whether or not the account exists.
func lockKey(u *model.User, org *model.Org, login string) string {
	if u != nil {
		return u.ID
	}
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(login))))
	return "x:" + org.ID + ":" + base64.RawURLEncoding.EncodeToString(h[:12])
}

// charge counts an attempt against the lockout counter key before the attempt is checked, and reports open false
// when the account has used up its attempts. A counter that cannot be reached is an error, not a lockout: the caller
// refuses the attempt (fail closed) but answers "unavailable" and audits no lockout. Counting first is what makes
// the limit hold for attempts sent at once: had only finished failures counted, every attempt in a burst would pass
// the check before the first was charged. The charge is a failure unless it is given back: settle, deferred by the
// caller, refunds it for every outcome but a wrong credential (n is then this failure's number: tripped).
// The lockout is org's (service.Lockout): the organization of the account, or of the sign-in page for an unknown one.
func (m *Module) charge(ctx context.Context, org *model.Org, key string) (n int64, open bool, err error) {
	max, window := m.s.Svc.Lockout(org)
	if max <= 0 {
		return 0, true, nil
	}
	n, err = m.s.Eph.Incr(ctx, nsLockout, key, 1, window)
	if err != nil {
		return 0, false, err
	}
	if n > int64(max) { // refused while locked: not an attempt, so the counter stays at the limit
		_, _ = m.s.Eph.Incr(context.WithoutCancel(ctx), nsLockout, key, -1, window)
	}
	return n, n <= int64(max), nil
}

// settle gives back a charge (charge) unless *wrong says the attempt was a wrong credential.
func (m *Module) settle(ctx context.Context, org *model.Org, key string, wrong *bool) {
	max, window := m.s.Svc.Lockout(org)
	if *wrong || max <= 0 {
		return
	}
	_, _ = m.s.Eph.Incr(context.WithoutCancel(ctx), nsLockout, key, -1, window)
}

// tripped reports whether the n-th failure (charge) is the one that locks an account of org.
func (m *Module) tripped(org *model.Org, n int64) bool {
	max, _ := m.s.Svc.Lockout(org)
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

func (m *Module) lockedResponse(w http.ResponseWriter, org *model.Org) {
	w.Header().Set("Retry-After", strconv.Itoa(int(m.lockWindow(org).Seconds())))
	writeErr(w, http.StatusTooManyRequests, "Too many failed attempts. Please try again later.", "")
}

// ---- audit ---------------------------------------------------------------------------------------------------

func (m *Module) audit(r *http.Request, action string, org *model.Org, u *model.User, login string, detail map[string]string) {
	a, orgID, target := auditActor(r, org, u, login)
	if u != nil { // the account is the target, named by its id as well
		m.s.Svc.AuditUser(context.WithoutCancel(r.Context()), a, u, action, detail)
		return
	}
	m.s.Svc.Audit(context.WithoutCancel(r.Context()), a, orgID, action, target, detail)
}

// auditLocked records a sign-in refused because its lockout key (an account, a browser of it, or an address under
// spray) is locked, through service.AuditLoginRefusal, so the refusals of a locked key, repeated at will, cannot fill
// the audit log, and every address that is refused is still named in it. An account's own lockout ("locked" with u
// found) is recorded at most once per account key, sign-in step (a fixed name, never the request's path, whose
// organization may be spelled in any case: each spelling would be a key of its own) and client address per minute
// on each node, the next saying how many were held back, and at most service.LoginRowsPerAddress a minute per
// address in the organization; it is kept apart from the refusals that name no account (a login that names none,
// an address under spray), which are recorded in the same way with an allowance of their own
// (service.LoginRowsPerAddressUnknown), so such a flood cannot crowd it out.
func (m *Module) auditLocked(r *http.Request, step string, org *model.Org, u *model.User, login, reason, key string) {
	account := u != nil && reason == "locked"
	m.s.Svc.AuditLoginRefusal(account, org.ID, web.RateKeyIP(r), key, reason+"|"+step, func(detail map[string]string) {
		detail["reason"] = reason
		m.audit(r, "login.failure", org, u, login, detail)
	})
}

// auditFailure records a sign-in that failed (login.failure, with detail) through service.AuditLoginFailure, so
// failures repeated at will (wrong passwords and codes, limits.lockout_attempts = 0 never locking; callbacks with a
// made-up state or code; passkeys nobody holds) cannot fill the audit log, and every address that sends one is still
// named in it. step is a fixed name of the step that failed, never anything of the request. key is the lockout key of
// a password step (lockKeyFor: the account, its known browsers, or a login that names no account, by its case-folded
// hash), else "": the account when u is known, and otherwise none, the step's one key at the organization. At most
// one event per key, step and client address (web.RateKeyIP) per minute on each node, the next saying how many were
// held back. The address is part of the key so that whoever fails cannot hide behind another address that failed
// first; nothing else the request can vary for the same account is (the organization by its id, the step a fixed
// name, as auditLocked's: never the request's path, the login as typed, a state, a provider or credential id it
// names, each of which would make keys of its own). What one address can have recorded across keys is bounded in
// turn: service.LoginRowsPerAddress events a minute in the organization for real accounts, and
// service.LoginRowsPerAddressUnknown for keys that name none (made up by whoever sends them: the events are a sample
// of what the address tries), then one that says so; an organization has at most
// service.LoginAddressRowsPerOrg events naming addresses a minute in each kind. An event that cannot name its address
// (its allowance spent, the organization's cap reached, the limiter full) is still recorded once a minute per account
// and step (per step, for keys that name none), naming the address that came first. A real account's failures (u known) are kept apart from those
// that name none, so a flood of made-up logins, states or credentials cannot crowd them out; and those of its known
// browsers apart from a stranger's, so its owner's own mistakes are still seen while a stranger is held back. A wrong
// second factor has a key apart from the wrong passwords': it says the password was right.
func (m *Module) auditFailure(r *http.Request, step string, org *model.Org, u *model.User, login, key string, detail map[string]string) {
	if key == "" && u != nil {
		key = u.ID
	}
	m.s.Svc.AuditLoginFailure(u != nil, org.ID, web.RateKeyIP(r), key, step, func(d map[string]string) {
		maps.Copy(d, detail)
		m.audit(r, "login.failure", org, u, login, d)
	})
}

// failureStep is the sign-in step whose credential reason (failed) says was wrong: the password's, or the second
// factor's own (totp, recovery_code, email_code).
func failureStep(reason string) string {
	switch reason {
	case "bad password", "unknown user", "inactive":
		return "password"
	}
	return reason
}

// auditUnknown records action as audit does, with outcome "unknown": the change ended with err, whose outcome is not
// known (it may have been made), and one that was made must not be missing from the audit log.
func (m *Module) auditUnknown(r *http.Request, action string, org *model.Org, u *model.User, detail map[string]string, err error) {
	a, _, _ := auditActor(r, org, u, u.Username)
	_ = m.s.Svc.AuditedUser(context.WithoutCancel(r.Context()), a, u, action, detail, func() error { return err })
}

// auditActor is who an audit event of the request names, in which organization, and its target.
func auditActor(r *http.Request, org *model.Org, u *model.User, login string) (*service.Actor, string, string) {
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
	return a, orgID, target
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
	Next    string   `json:"n,omitempty"`
	AMR     []string `json:"a"`
	Pending string   `json:"p,omitempty"` // sealed TOTP secret being enrolled
	Tenant  string   `json:"t,omitempty"` // tenant name the sign-in is for
	// Provider is the upstream provider of a federated first factor (recorded on the session it ends in),
	// UpstreamAMR how the provider said the person signed in to it and Upstream the account there (both passed on in
	// tokens, never decided on).
	Provider    string                 `json:"pv,omitempty"`
	UpstreamAMR []string               `json:"ua,omitempty"`
	Upstream    *model.UpstreamAccount `json:"up,omitempty"`
	// Sources are the accounts a guest's sign-in through an organization provider stands on (recorded on the session
	// it ends in: model.Session.Sources).
	Sources []model.GuestSource `json:"src,omitempty"`
	// Gen is the account's security generation (model.User.SecurityGen) when the first factor was verified, and Stamp
	// the sign-out counters then (model.SignOutStamp). Every later step checks both against the account as it is now
	// (ticketCurrent): a ticket whose password has since been changed, whose account set up a second factor
	// meanwhile, lost the provider link it signed in with (removed, or taken by a promotion), was disabled or
	// re-enabled, or whose organization pulled the emergency sign-out lever, is dead, and the browser holding it
	// starts again with the account's current credentials. (The role is not bound: each step judges it afresh.)
	Gen   uint64             `json:"g"`
	Stamp model.SignOutStamp `json:"st"`
	// Expires is when the ticket ends (unix nanos), set as it is made: a step that stores it again (enrolTOTPBegin)
	// keeps it until then and no longer, since its address was charged for that long (secondFactor).
	Expires int64 `json:"x,omitempty"`
	// Held is the charge for the ticket against what the address it was made for may hold (putTicket), given back
	// when the ticket is used (useTicket). Nil when that budget was off.
	Held *ephemeral.Held `json:"h,omitempty"`
}

// bind records on t the account state its first factor was verified against (see ticket.Gen).
func (m *Module) bind(ctx context.Context, t *ticket, u *model.User) error {
	st, err := m.s.Svc.SessionStamp(ctx, u.OrgID)
	if err != nil {
		return err
	}
	t.UserID, t.Gen, t.Stamp = u.ID, u.SecurityGen, st
	return nil
}

// errTicketGone says a sign-in's ticket is dead: expired, taken, at another step, or no longer bound to its account.
// Any other error from loading a ticket is a read that failed: no verdict, and the person must not be sent back to
// sign in again for a store that could not answer (ticketFailed).
var errTicketGone = errors.New("login: the sign-in has expired")

// ticketCurrent reports whether t still binds to u as the account is now (errTicketGone when it does not): the one it
// was issued for, enabled, at the same security generation, and not signed out by the emergency lever since. u must be
// freshly read. A sign-out counter that cannot be read is that error, not "signed out".
func (m *Module) ticketCurrent(ctx context.Context, t *ticket, u *model.User) error {
	if t.UserID != u.ID || !u.Enabled(time.Now()) || u.SecurityGen != t.Gen {
		return errTicketGone
	}
	want, err := m.s.Svc.SessionStamp(ctx, u.OrgID)
	if err != nil {
		return err
	}
	if !t.Stamp.Current(want) {
		return errTicketGone
	}
	return nil
}

// ticketUser loads the user and organization of a ticket's sign-in, as they are now, if the ticket still binds to
// them (ticketCurrent). The user is read afresh here, from the owners' copies (a step that only checks a code writes
// nothing to the user, so no compare-and-swap would catch a password change this node has not received yet), so a
// step that commits a change to it (setting a factor) does
// so with a compare-and-swap on this very version: a change made between this read and that write — another
// completion of the same sign-in, the owner setting up a factor — makes the write stale, and the step refuses.
func (m *Module) ticketUser(ctx context.Context, t *ticket) (*model.User, *model.Org, error) {
	u, err := m.s.Svc.UserByID(ctx, t.UserID)
	if errors.Is(err, service.ErrNotFound) {
		return nil, nil, errTicketGone
	}
	if err == nil {
		err = m.ticketCurrent(ctx, t, u)
	}
	if err != nil {
		return nil, nil, err
	}
	org, err := m.s.Svc.Orgs.Get(ctx, u.OrgID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, errTicketGone
	}
	if err != nil {
		return nil, nil, err
	}
	return u, org, nil
}

const msgExpired = "Your sign-in has expired. Start again."

// step loads the sign-in a request continues: a ticket at one of the steps, its user and organization (ticketUser),
// within the organization's rate limit for the account. A ticket of another organization than the path's is dead
// here, as an expired one is. On failure it has written the answer (401 for a dead ticket,
// 429 when limited) and the handler returns.
func (m *Module) step(w http.ResponseWriter, r *http.Request, id string, steps ...string) (*ticket, *model.User, *model.Org, bool) {
	ctx := r.Context()
	t, err := m.getTicket(ctx, id, steps...)
	var u *model.User
	var org *model.Org
	if err == nil {
		u, org, err = m.ticketUser(ctx, t)
	}
	if err == nil && org.ID != web.Org(r).ID {
		err = errTicketGone
	}
	if err != nil {
		ticketFailed(w, err)
		return nil, nil, nil, false
	}
	if !m.rateLimit(w, r, org.ID, known{userID: u.ID}) {
		return nil, nil, nil, false
	}
	return t, u, org, true
}

// putTicket stores the ticket of a sign-in's next step for ttl, charged to the address the sign-in comes from
// (limits.held_kb, with extra bytes for what the step keeps beside it): whoever holds an account's first factor can
// have as many made as the request limits allow, each carrying the path the sign-in is to end at, so what they hold
// together is bounded as a flow's is (ephemeral.ErrHeld past it: 429). Given back when the ticket is used
// (useTicket): an address many people share (an office, a provider's address translation) is then bounded by the
// sign-ins it has under way at once, not by how many second factors it finished in twenty minutes. One that is
// abandoned stays charged until its window turns, and that is the trade the budget makes for such an address: the
// people behind it share one budget, so whoever among them starts sign-ins and leaves them (a few thousand, at the
// rate the request limits allow) uses it up for the others for up to twenty minutes. Raise limits.held_kb where
// many people sign in from one address.
func (m *Module) putTicket(r *http.Request, t *ticket, ttl time.Duration, extra int) (string, error) {
	ctx := r.Context()
	t.Expires = time.Now().Add(ttl).UnixNano()
	held, err := m.s.Held.Charge(ctx, web.HolderIP(r), nsTicket, len(ephemeral.JSON(t))+extra, ttl)
	if err != nil {
		return "", err
	}
	t.Held = held
	id, err := m.s.Eph.New(ctx, nsTicket, ephemeral.JSON(t), ttl)
	if err != nil {
		held.Refund(ctx, m.s.Eph)
	}
	return id, err
}

// ticketEnded gives back what the ticket with stored value b, just taken, was charged to its address (putTicket).
func (m *Module) ticketEnded(ctx context.Context, b []byte) {
	var t ticket
	if json.Unmarshal(b, &t) == nil {
		t.Held.Refund(ctx, m.s.Eph)
	}
}

// heldByIP returns the request's context naming its client address as the one what the request stores is kept for
// (a provider's sign-in state, a passkey challenge: ephemeral.Charge), for requests nobody has signed in for;
// heldByUser names the signed-in user instead.
func (m *Module) heldByIP(r *http.Request) context.Context {
	return m.s.Held.With(r.Context(), web.HolderIP(r))
}

func (m *Module) heldByUser(r *http.Request, userID string) context.Context {
	return m.s.Held.With(r.Context(), web.HolderUser(userID))
}

// tooManyHeld answers a request refused because its requester already has this server hold as much short-lived
// state as it may (ephemeral.ErrHeld): 429, counted by the budget, never audited or logged per request.
func tooManyHeld(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeErr(w, http.StatusTooManyRequests, "Too many sign-ins are in progress from your network. Finish one, or wait a few minutes, then try again.", "")
}

// ticketFailed answers a step whose ticket could not be loaded: a dead one (errTicketGone) is 401, as the person has
// to start again; a read that failed is 503, since the sign-in may well be alive and starting again would not help.
func ticketFailed(w http.ResponseWriter, err error) {
	if errors.Is(err, errTicketGone) {
		writeErr(w, http.StatusUnauthorized, msgExpired, "")
		return
	}
	unavailableResponse(w)
}

// getTicket reads a ticket and checks the step; it does not consume it. A ticket that is not there, or not at one
// of the steps, is errTicketGone; any other error is the read failing.
func (m *Module) getTicket(ctx context.Context, id string, steps ...string) (*ticket, error) {
	b, err := m.s.Eph.Get(ctx, nsTicket, id)
	if errors.Is(err, ephemeral.ErrNotFound) {
		return nil, errTicketGone
	}
	if err != nil {
		return nil, err
	}
	var t ticket
	if json.Unmarshal(b, &t) != nil {
		return nil, errTicketGone
	}
	for _, s := range steps {
		if t.Step == s {
			return &t, nil
		}
	}
	return nil, errTicketGone
}

// useTicket consumes the ticket; only one concurrent caller wins, the others get errTicketGone. A store that cannot
// answer is its own error (the caller answers "unavailable"), not "expired". The caller that wins gives the
// ticket's charge back to its address (putTicket).
func (m *Module) useTicket(ctx context.Context, id string) error {
	b, err := m.s.Eph.Take(ctx, nsTicket, id)
	if errors.Is(err, ephemeral.ErrNotFound) {
		return errTicketGone // used already (a step replayed or raced) or expired
	}
	if err == nil {
		m.ticketEnded(ctx, b)
	}
	return err
}

// attempt counts tries against one ticket and drops it after too many. A counter that cannot be used is an error,
// not "too many": the caller refuses the try (fail closed) but answers "unavailable", and the ticket is kept so the
// person can try again once the counter answers.
func (m *Module) attempt(ctx context.Context, id string) (within bool, err error) {
	n, err := m.s.Eph.Incr(ctx, nsTry, id, 1, enrolTTL)
	if err != nil {
		return false, err
	}
	if n > ticketAttempts {
		if b, err := m.s.Eph.Take(ctx, nsTicket, id); err == nil {
			m.ticketEnded(ctx, b)
		}
		return false, nil
	}
	return true, nil
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
	if org.ID != web.Org(r).ID || u.OrgID != org.ID { // (every step has checked; this one must never sign in across organizations)
		return "", errors.New("login: a sign-in of another organization than the page's")
	}
	amr := opt.AMR
	upgraded := false
	// A session the store could not check is no reason to start another beside it: the one it may be (another user's)
	// would stay alive, and a same-user sign-in would lose the grants held on it. The sign-in is refused, to be retried.
	old, _, err := m.s.Sessions.Check(r)
	if err != nil {
		return "", err
	}
	if old != nil {
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
		if !upgraded { // another user (or no upgrade possible): the old session is signed out, or the sign-in fails
			if err := m.s.Sessions.SignOut(ctx, old.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
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
	// does not wait for one more write.
	touched := *u
	m.s.Svc.Background(ctx, service.BackgroundShort, func(ctx context.Context) { m.s.Svc.TouchLogin(ctx, &touched) })
	// Only the counter this browser charges (lockKeyFor): the owner signing in from a known browser must not reset
	// the account-wide one, which only strangers' browsers charge (a reset or an accepted invitation clears both).
	m.clearLock(ctx, m.lockKeyFor(r, u, u.ID))
	m.rememberDevice(w, r, u)
	if m.s.Cfg.Audit.Logins {
		m.audit(r, "login.success", org, u, u.Username, map[string]string{"amr": strings.Join(amr, " ")})
	}
	return nextOrDefault(org, next), nil
}

// noteSession records the session a sign-in made for the rest of the request's audit events (login.success).
func noteSession(ctx context.Context, sess *model.Session) {
	if ri := service.RequestFrom(ctx); ri != nil && sess != nil {
		ri.SessionID = sess.ID
	}
}

func (m *Module) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	if errors.Is(err, ephemeral.ErrHeld) {
		tooManyHeld(w)
		return
	}
	if errors.Is(err, ephemeral.ErrFull) {
		// this node's short-lived state is full: the store counts and logs that (once a minute), so this does not
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "This server is busy. Please try again in a moment.", "")
		return
	}
	if errors.Is(err, store.ErrUnconfirmed) || errors.Is(err, store.ErrUnavailable) ||
		errors.Is(err, service.ErrOutcomeUnknown) || errors.Is(err, service.ErrUnavailable) {
		// the cluster could not confirm the change in time: trying again is safe, and the answer says so. A request
		// whose client went away ends the same way and is not worth a warning: nobody is waiting for the answer.
		if r.Context().Err() == nil {
			m.s.Log.Warn(what, "error", err, "path", r.URL.Path)
		}
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
