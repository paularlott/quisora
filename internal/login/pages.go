package login

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// anonPage builds page data for a signed-out page; the anonymous CSRF token is always used (a signed-in user on a
// reauth page still posts to the anonymous sign-in endpoints).
func (m *Module) anonPage(w http.ResponseWriter, r *http.Request, title string, data any) *web.Page {
	p := m.s.Page(w, r, title, "", data)
	p.CSRF = m.s.AnonCSRF(w, r)
	return p
}

// LandingData is the help page: how to sign in (through an application, or the organization's sign-in link,
// /login/<org>). NotFound: it answers a page that does not exist, or that needs a signed-in user.
type LandingData struct {
	Error    string
	NotFound bool
}

// tenantParam returns the tenant query parameter when it is a plausible tenant name (a URL-safe slug), else "".
func tenantParam(r *http.Request) string {
	t := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tenant")))
	if len(t) > maxTenantName || !orgRe.MatchString(t) {
		return ""
	}
	return t
}

func wantsReauth(r *http.Request) bool { return r.URL.Query().Get("reauth") == "1" }

// landing handles GET /: signed in, on to next (or the account page); otherwise the help page. Sign-in itself is
// only ever at /login/<org>, which an application or the organization's link leads to.
func (m *Module) landing(w http.ResponseWriter, r *http.Request) {
	if web.User(r) != nil && !wantsReauth(r) {
		http.Redirect(w, r, nextOrDefault(safeNext(r.URL.Query().Get("next"))), http.StatusSeeOther)
		return
	}
	d := LandingData{Error: upstreamMessages[r.URL.Query().Get("error")]}
	m.s.Render.Render(w, http.StatusOK, "landing", m.anonPage(w, r, "Sign in", d))
}

// notFound answers with the help page and 404: an organization that does not exist.
func (m *Module) notFound(w http.ResponseWriter, r *http.Request) {
	m.s.Render.Render(w, http.StatusNotFound, "landing", m.anonPage(w, r, "Not found", LandingData{NotFound: true}))
}

var orgRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type providerButton struct {
	Name string
	Type string
	Href string
}

type loginData struct {
	OrgName     string
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
}

// loginPage handles GET /login/{org}.
func (m *Module) loginPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	next := safeNext(q.Get("next"))
	org, err := m.s.Svc.OrgByName(ctx, strings.ToLower(r.PathValue("org")))
	if err != nil {
		m.notFound(w, r)
		return
	}
	reauth := wantsReauth(r)
	cur := web.User(r)
	if cur != nil && !reauth {
		http.Redirect(w, r, nextOrDefault(next), http.StatusSeeOther)
		return
	}
	eff, tenant, err := m.methods(ctx, org, q.Get("tenant"), next)
	if err != nil {
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return
	}
	d := loginData{OrgName: org.Name, OrgDisplay: org.DisplayName, Tenant: tenant, Next: next, Reauth: reauth,
		Password: eff.Password, Passkey: eff.Passkey && m.Passkeys != nil,
		Error: upstreamMessages[q.Get("error")]}
	d.CanReset = eff.PasswordReset && m.Mail != nil
	if c, err := r.Cookie(stepCookie); err == nil && q.Get("step") == "1" && c.Value != "" && len(c.Value) < 200 {
		// only the step a provider sign-in left, for this org
		if t, ok := m.getTicket(ctx, c.Value, "totp", "passkey", "enrol"); ok && t.Provider != "" {
			if u, err := m.s.Svc.Users.Get(ctx, t.UserID); err == nil && u.OrgID == org.ID {
				d.Step, d.Ticket = t.Step, c.Value
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
		href := "/login/" + url.PathEscape(org.Name) + "/provider/" + url.PathEscape(p.ID)
		if len(v) > 0 {
			href += "?" + v.Encode()
		}
		d.Providers = append(d.Providers, providerButton{Name: p.Name, Type: p.Type, Href: href})
	}
	d.NoMethods = !d.Password && !d.Passkey && len(d.Providers) == 0
	p := m.anonPage(w, r, "Sign in to "+org.DisplayName, d)
	p.Org = org
	m.s.Render.Render(w, http.StatusOK, "login", p)
}

// ---------------------------------------------------------------------------------------------------------------
// Invitation and reset pages

type linkData struct {
	Valid   bool
	Token   string
	Name    string
	Email   string
	Org     string
	OrgName string

	// Invitation page: what the organization allows the user to set up.
	Password  bool // may set a password
	Passkey   bool // may create a passkey (and this server supports them)
	NoMethods bool // neither: sign-in is through the organization's providers only
}

func (m *Module) linkPage(w http.ResponseWriter, r *http.Request, page, title, purpose string) {
	ctx := r.Context()
	d := linkData{}
	status := http.StatusOK
	token := r.URL.Query().Get("token")
	if token != "" && len(token) < 200 && m.allowed(r, "link", known{any: true}) {
		if _, u, err := m.s.Svc.PeekLink(ctx, token, purpose); err == nil {
			if o, err := m.s.Svc.Orgs.Get(ctx, u.OrgID); err == nil {
				d.Org, d.OrgName = o.DisplayName, o.Name
				d.Valid = true
				switch purpose {
				case service.LinkInvite:
					if eff, err := m.s.Svc.EffectiveSignIn(ctx, o, nil); err == nil {
						d.Password = eff.Password
						d.Passkey = eff.Passkey && m.Passkeys != nil
						d.NoMethods = !d.Password && !d.Passkey
					}
				case service.LinkReset:
					_, d.Valid = m.resettable(ctx, u)
				}
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

// invitePage handles GET /invite?token=.
func (m *Module) invitePage(w http.ResponseWriter, r *http.Request) {
	m.linkPage(w, r, "invite", "Accept your invitation", service.LinkInvite)
}

// resetPage handles GET /reset?token=.
func (m *Module) resetPage(w http.ResponseWriter, r *http.Request) {
	m.linkPage(w, r, "reset", "Choose a new password", service.LinkReset)
}

// verifyEmail handles GET /verify-email?token=: marks the address verified and goes to the account page.
func (m *Module) verifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	result, frag := "invalid", "profile"
	if m.allowed(r, "link", known{any: true}) {
		if l, u, err := m.s.Svc.RedeemLink(ctx, r.URL.Query().Get("token"), service.LinkVerify); err == nil {
			// The link names the address it was mailed to: the primary one, or a linked one (verified in place).
			// An address that has since been removed or replaced verifies nothing.
			if l.Email == "" {
				l.Email = u.Email // links issued before addresses were recorded
			}
			if err := m.s.Svc.VerifyEmailAddress(ctx, u.ID, l.Email); err == nil {
				m.s.Sessions.Evict("", u.ID)
				org, _ := m.s.Svc.Orgs.Get(ctx, u.OrgID)
				m.audit(r, "account.email.verify", org, u, u.Username, map[string]string{"email": l.Email})
				result = "verified"
				if !strings.EqualFold(u.Email, l.Email) {
					frag = "emails" // a linked address: back to the list it is in
				}
			}
		}
	}
	http.Redirect(w, r, "/account?email="+result+"#"+frag, http.StatusSeeOther)
}

// ---------------------------------------------------------------------------------------------------------------
// Logout

type logoutData struct{ Next string }

// logoutPage handles GET /logout: a confirmation page (never signs out by itself, so a link or image cannot).
func (m *Module) logoutPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if web.User(r) == nil {
		http.Redirect(w, r, withNext("/", next), http.StatusSeeOther)
		return
	}
	m.s.Render.Render(w, http.StatusOK, "logout", m.s.Page(w, r, "Sign out", "", logoutData{Next: next}))
}

// logout handles POST /logout: ends the session. It accepts the CSRF token as the X-CSRF-Token header (fetch) or a
// "csrf" form field (plain form), and answers JSON {"next"} for fetch or a redirect for a form.
func (m *Module) logout(w http.ResponseWriter, r *http.Request) {
	sess := web.Session(r)
	wantsJSON := strings.Contains(r.Header.Get("Accept"), "application/json") || r.Header.Get("X-CSRF-Token") != ""
	var next string
	if wantsJSON {
		next = safeNext(r.URL.Query().Get("next"))
	} else {
		_ = r.ParseForm()
		next = safeNext(r.PostForm.Get("next"))
		if r.Header.Get("X-CSRF-Token") == "" {
			r.Header.Set("X-CSRF-Token", r.PostForm.Get("csrf"))
		}
	}
	if sess == nil { // already signed out
		if wantsJSON {
			web.WriteJSON(w, http.StatusOK, stepResp{Next: orDefault(next, "/")})
			return
		}
		http.Redirect(w, r, orDefault(next, "/"), http.StatusSeeOther)
		return
	}
	if !m.s.CheckCSRF(r, sess.CSRF) {
		writeErr(w, http.StatusForbidden, msgBadCSRF, "")
		return
	}
	u := web.User(r)
	m.s.Sessions.End(r.Context(), w, r)
	org, _ := m.s.Svc.Orgs.Get(r.Context(), u.OrgID)
	m.audit(r, "logout", org, u, u.Username, nil)
	// Back to the organization's sign-in page, so signing in again needs no org picker.
	dest := "/"
	if org != nil {
		dest = "/login/" + url.PathEscape(org.Name)
	}
	dest = orDefault(next, dest)
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
