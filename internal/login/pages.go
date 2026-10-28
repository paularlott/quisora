package login

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// anonPage builds page data for a page of the organization the path names; the anonymous CSRF token is always used
// (a signed-in user on a reauth page still posts to the anonymous sign-in endpoints). The page's organization is the
// path's, whoever is signed in: its templates build every link from it.
func (m *Module) anonPage(w http.ResponseWriter, r *http.Request, title string, data any) *web.Page {
	p := m.s.Page(w, r, title, "", data)
	p.CSRF = m.s.AnonCSRF(w, r)
	p.Org = web.Org(r)
	return p
}

func wantsReauth(r *http.Request) bool { return r.URL.Query().Get("reauth") == "1" }

// landing handles GET /: on to the primary organization's sign-in page, the one an installation's first visitor means.
// Every other organization has its own address (/o/<org>/login), which an application or the organization's own
// link leads to.
func (m *Module) landing(w http.ResponseWriter, r *http.Request) {
	org, err := m.s.Svc.PrimaryOrg(r.Context())
	if err != nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "This server cannot serve its sign-in page right now. Please try again shortly.", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, web.OrgPath(org.ID, "/login"), http.StatusSeeOther)
}

type providerButton struct {
	Name string
	Type string
	Href string
}

type loginData struct {
	OrgDisplay  string
	Tenant      string // canonical name of the tenant the page signs in for ("" = the org's own methods)
	Next        string
	Reauth      bool
	Password    bool
	Passkey     bool
	Providers   []providerButton
	Error       string
	CanReset    bool
	NoMethods   bool
	CurrentUser string // shown on reauth pages
	Hint        string // OIDC login_hint: an email address that pre-fills the sign-in form
	// A second-factor step after a provider sign-in (step totp, passkey or enrol, its ticket, enrolment methods).
	Step, Ticket, Methods string
	Alternatives          string // the other ways to give the second factor at that step (stepResp.Alternatives)
	Email                 string // where an email code goes, masked (stepResp.Email)
	Cancel                string // declines the authorization request next continues (empty for other sign-ins)
}

// cancelURL is where a sign-in that continues an authorization request (next is its resume URL) can be declined.
func cancelURL(org *model.Org, next string) string {
	if q, ok := strings.CutPrefix(next, web.OrgPath(org.ID, "/oauth/authorize/resume?")); ok {
		return web.OrgPath(org.ID, "/oauth/authorize/cancel?") + q
	}
	return ""
}

// loginPage handles GET /o/{org}/login.
func (m *Module) loginPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	org := web.Org(r)
	next := safeNext(org, q.Get("next"))
	reauth := wantsReauth(r)
	cur := web.User(r)
	if cur != nil && !reauth {
		http.Redirect(w, r, nextOrDefault(org, next), http.StatusSeeOther)
		return
	}
	eff, tenant, err := m.methods(ctx, org, q.Get("tenant"), next)
	if err != nil {
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return
	}
	d := loginData{OrgDisplay: org.DisplayName, Tenant: tenant, Next: next, Reauth: reauth,
		Password: eff.Password, Passkey: eff.Passkey && m.Passkeys != nil,
		Error: upstreamMessages[q.Get("error")], Cancel: cancelURL(org, next)}
	d.CanReset = eff.PasswordReset && m.Mail != nil
	if c, err := r.Cookie(stepCookie); err == nil && q.Get("step") == "1" && c.Value != "" && len(c.Value) < 200 {
		// only the step a provider sign-in left, for this org
		// (a ticket that cannot be read is no step to resume: the page is the sign-in form, and the person can start again)
		if t, err := m.getTicket(ctx, c.Value, "totp", "passkey", "email_code", "enrol"); err == nil && t.Provider != "" {
			if u, err := m.s.Svc.Users.Get(ctx, t.UserID); err == nil && u.OrgID == org.ID {
				d.Step, d.Ticket = t.Step, c.Value
				d.Alternatives = strings.Join(m.alternatives(ctx, u, t.Step), " ")
				if t.Step == "email_code" && m.emailOK(u, org.Settings.EmailCodes) {
					d.Email = maskEmail(u.Email)
				}
			}
			if d.Step == "enrol" {
				d.Methods = "totp"
				if m.Passkeys != nil {
					d.Methods += " passkey"
				}
			}
		}
	}
	if h := strings.TrimSpace(q.Get("login_hint")); len(h) <= 256 {
		d.Hint = h
	}
	if cur != nil {
		d.CurrentUser = cur.Email
	}
	for _, p := range eff.Providers {
		v := url.Values{}
		if next != "" {
			v.Set("next", next)
		}
		if tenant != "" {
			v.Set("tenant", tenant)
		}
		href := web.OrgPath(org.ID, "/login/provider/"+url.PathEscape(p.ID))
		if len(v) > 0 {
			href += "?" + v.Encode()
		}
		d.Providers = append(d.Providers, providerButton{Name: p.Name, Type: p.Type, Href: href})
	}
	d.NoMethods = !d.Password && !d.Passkey && len(d.Providers) == 0
	m.s.Render.Render(w, http.StatusOK, "login", m.anonPage(w, r, "Sign in to "+org.DisplayName, d))
}

// ---------------------------------------------------------------------------------------------------------------
// Invitation and reset pages

type linkData struct {
	Valid bool
	Token string
	Name  string
	Email string
	Org   string

	// Invitation page: what the organization allows the user to set up.
	Password  bool // may set a password
	Passkey   bool // may create a passkey (and this server supports them)
	NoMethods bool // neither: sign-in is through the organization's providers only
}

// peekLink is PeekLink for a link of org, the organization the path names: a link of another organization is as
// good as none (a link is only ever opened at the address its mail gave).
func (m *Module) peekLink(ctx context.Context, org *model.Org, token string, purposes ...string) (*model.User, bool) {
	_, u, err := m.s.Svc.PeekLink(ctx, token, purposes...)
	if err != nil || u.OrgID != org.ID {
		return nil, false
	}
	return u, true
}

func (m *Module) linkPage(w http.ResponseWriter, r *http.Request, page, title, purpose string) {
	ctx := r.Context()
	org := web.Org(r)
	d := linkData{}
	status := http.StatusOK
	token := r.URL.Query().Get("token")
	if token != "" && len(token) < 200 && m.allowed(r, org.ID+"|link", known{any: true}) {
		if u, ok := m.peekLink(ctx, org, token, purpose); ok {
			d.Org = org.DisplayName
			d.Valid = true
			switch purpose {
			case service.LinkInvite:
				if eff, err := m.s.Svc.EffectiveSignIn(ctx, org, nil); err == nil {
					d.Password = eff.Password
					d.Passkey = eff.Passkey && m.Passkeys != nil
					d.NoMethods = !d.Password && !d.Passkey
				}
			case service.LinkReset:
				d.Valid = resettable(org, u)
			}
			if d.Valid {
				d.Token, d.Name, d.Email = token, u.FullName(), u.Email
			}
		}
	}
	if !d.Valid {
		status = http.StatusGone
	}
	m.s.Render.Render(w, status, page, m.anonPage(w, r, title, d))
}

// invitePage handles GET /o/{org}/invite?token=.
func (m *Module) invitePage(w http.ResponseWriter, r *http.Request) {
	m.linkPage(w, r, "invite", "Accept your invitation", service.LinkInvite)
}

// resetPage handles GET /o/{org}/reset?token=.
func (m *Module) resetPage(w http.ResponseWriter, r *http.Request) {
	m.linkPage(w, r, "reset", "Choose a new password", service.LinkReset)
}

type verifyEmailData struct{ Token string }

// verifyEmailPage handles GET /o/{org}/verify-email?token=: a page with one button that confirms the address. Opening
// the link uses nothing up: mail scanners and link previews open links too, and would spend it before its owner does.
func (m *Module) verifyEmailPage(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" || len(tok) > 128 {
		http.Redirect(w, r, web.OrgPath(web.Org(r).ID, "/account?email=invalid#profile"), http.StatusSeeOther)
		return
	}
	m.s.Render.Render(w, http.StatusOK, "verify-email", m.anonPage(w, r, "Confirm your email address", verifyEmailData{Token: tok}))
}

// verifyEmail handles POST /o/{org}/verify-email (token, csrf: verifyEmailPage's form): marks the address verified and
// goes to the account page. A link of another organization is looked at first and left unused.
func (m *Module) verifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := web.Org(r)
	_ = r.ParseForm()
	r.Header.Set("X-CSRF-Token", r.PostForm.Get("csrf"))
	if !m.s.CheckAnonCSRF(r) {
		writeErr(w, http.StatusForbidden, msgBadCSRF, "")
		return
	}
	result, frag := "invalid", "profile"
	token := r.PostForm.Get("token")
	if m.allowed(r, org.ID+"|link", known{any: true}) {
		if _, ok := m.peekLink(ctx, org, token, service.LinkVerify); ok {
			if l, u, err := m.s.Svc.RedeemLink(ctx, token); err == nil {
				// The link names the address it was mailed to: the primary one, or a linked one (verified in place).
				// An address that has since been removed or replaced verifies nothing.
				if l.Email == "" {
					l.Email = u.Email // links issued before addresses were recorded
				}
				if err := m.s.Svc.VerifyEmailAddress(ctx, u.ID, l.Email); err == nil {
					m.s.Sessions.Evict("", u.ID)
					m.audit(r, "account.email.verify", org, u, u.Username, map[string]string{"email": l.Email})
					result = "verified"
					if !strings.EqualFold(u.Email, l.Email) {
						frag = "emails" // a linked address: back to the list it is in
					}
				}
			}
		}
	}
	http.Redirect(w, r, web.OrgPath(org.ID, "/account?email="+result+"#"+frag), http.StatusSeeOther)
}

// ---------------------------------------------------------------------------------------------------------------
// Logout

type logoutData struct{ Next string }

// logoutPage handles GET /o/{org}/logout: a confirmation page (never signs out by itself, so a link or image cannot).
func (m *Module) logoutPage(w http.ResponseWriter, r *http.Request) {
	org := web.Org(r)
	next := safeNext(org, r.URL.Query().Get("next"))
	if web.User(r) == nil {
		http.Redirect(w, r, withNext(web.OrgPath(org.ID, "/login"), next), http.StatusSeeOther)
		return
	}
	m.s.Render.Render(w, http.StatusOK, "logout", m.s.Page(w, r, "Sign out", "", logoutData{Next: next}))
}

// logout handles POST /o/{org}/logout: ends the organization's session. It accepts the CSRF token as the X-CSRF-Token
// header (fetch) or a "csrf" form field (plain form), and answers JSON {"next"} for fetch or a redirect for a form.
func (m *Module) logout(w http.ResponseWriter, r *http.Request) {
	org := web.Org(r)
	sess := web.Session(r)
	wantsJSON := strings.Contains(r.Header.Get("Accept"), "application/json") || r.Header.Get("X-CSRF-Token") != ""
	var next string
	if wantsJSON {
		next = safeNext(org, r.URL.Query().Get("next"))
	} else {
		_ = r.ParseForm()
		next = safeNext(org, r.PostForm.Get("next"))
		if r.Header.Get("X-CSRF-Token") == "" {
			r.Header.Set("X-CSRF-Token", r.PostForm.Get("csrf"))
		}
	}
	// Back to the organization's sign-in page, so signing in again needs no org picker.
	dest := orDefault(next, web.OrgPath(org.ID, "/login"))
	if web.SessionUnchecked(r) {
		// The store refused to say whether there is a session: that is not "already signed out", and answering so
		// would leave a live session behind a page that says it ended.
		if wantsJSON {
			web.WriteUnchecked(w)
		} else {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "This server cannot check your session right now. Please try again shortly.", http.StatusServiceUnavailable)
		}
		return
	}
	if sess == nil { // already signed out
		if wantsJSON {
			web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
			return
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	if !m.s.CheckCSRF(r, sess.CSRF) {
		writeErr(w, http.StatusForbidden, msgBadCSRF, "")
		return
	}
	u := web.User(r)
	if _, err := m.s.Sessions.End(r.Context(), w, r); err != nil {
		// The cookie is cleared, but the session (or a refresh grant of it) is still in the store, so whoever else
		// holds it is not signed out: say so, instead of "signed out" and a logout in the audit log.
		m.s.Log.Warn("logout: the session could not be ended", "user", u.ID, "error", err)
		m.audit(r, "logout", org, u, u.Username, map[string]string{"result": "incomplete", "error": err.Error()})
		writeErr(w, http.StatusServiceUnavailable, "You could not be fully signed out right now. Please try again shortly.", "")
		return
	}
	m.audit(r, "logout", org, u, u.Username, nil)
	if wantsJSON {
		web.WriteJSON(w, http.StatusOK, stepResp{Next: dest})
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
