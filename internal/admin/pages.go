package admin

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// RoleOption is one entry of a role <select>.
type RoleOption struct {
	Value string
	Label string
}

// View is the Data of every admin page.
type View struct {
	API        string // base URL of the management API for this page's scope
	Base       string // page URL of the administered organization, /admin/orgs/<name>
	OrgName    string
	OrgDisplay string
	IsPrimary  bool
	CanSCIM    bool // super admins only: the SCIM and first-party switches, and managing such clients
	UserID     string
	Self       bool // the user page is the viewer's own: read-only addresses, connections on the account page
	Roles      []RoleOption
	// FilterRoles are the roles the users list may be filtered by: the viewer's own and lower (super admins only for
	// super admins, on the primary organization: nobody else sees any).
	FilterRoles []RoleOption

	// Tenant page (/admin/orgs/{org}/tenants/{tenant}).
	TenantID      string
	TenantName    string
	TenantDisplay string

	// Error pages.
	Status  int
	Heading string
	Message string

	// AllOrgs: the audit page of every organization (super admins).
	AllOrgs bool

	// Organizations page: the server's session defaults (seconds), shown next to an organization's overrides.
	DefaultSessionTTL  int
	DefaultSessionIdle int

	// KeyRotationDays: the signing keys page (tokens.key_rotation_days; 0 = by hand only).
	KeyRotationDays int
}

var roleLabels = map[model.Role]string{
	model.RoleSuperAdmin: "Super administrator", model.RoleAdmin: "Administrator", model.RoleManager: "Manager",
	model.RoleUser: "User",
}

// filterRoles lists the roles a may filter org's users by: its own role and lower; super admin only for super admins on
// the primary organization (they are hidden from everyone else, and only the primary organization has any).
func filterRoles(a *service.Actor, org *model.Org) []RoleOption {
	var out []RoleOption
	for _, r := range []model.Role{model.RoleUser, model.RoleManager, model.RoleAdmin, model.RoleSuperAdmin} {
		if r.Rank() > a.Role.Rank() || (r == model.RoleSuperAdmin && !org.Primary) {
			continue
		}
		out = append(out, RoleOption{string(r), roleLabels[r]})
	}
	return out
}

// assignableRoles lists the roles the actor may give to users of org (mirrors the service rules for the UI only; the
// service still decides).
func assignableRoles(a *service.Actor, org *model.Org) []RoleOption {
	roles := []model.Role{model.RoleUser}
	switch {
	case a.IsSuper():
		roles = append(roles, model.RoleManager, model.RoleAdmin)
		if org.Primary {
			roles = append(roles, model.RoleSuperAdmin)
		}
	case a.Role == model.RoleAdmin:
		roles = append(roles, model.RoleManager, model.RoleAdmin)
	}
	out := make([]RoleOption, len(roles))
	for i, r := range roles {
		out[i] = RoleOption{string(r), roleLabels[r]}
	}
	return out
}

func (m *Module) registerPages(s *web.Server) {
	page := func(pattern string, h http.HandlerFunc) { s.Mux.Handle(pattern, s.RequirePage(m.consoleMFA(h))) }
	page("GET /admin", m.pageHome)
	page("GET /admin/orgs", m.pageOrgs)
	page("GET /admin/orgs/{org}", m.pageOrgHome)
	page("GET /admin/orgs/{org}/users", m.orgPage("admin-users", "Users", "users", false, nil))
	page("GET /admin/orgs/{org}/users/{id}", m.orgPage("admin-user", "User", "users", false,
		func(v *View, r *http.Request) { v.UserID = r.PathValue("id"); v.Self = v.UserID == web.Actor(r).UserID }))
	page("GET /admin/orgs/{org}/groups", m.orgPage("admin-groups", "Groups", "groups", true, nil))
	page("GET /admin/orgs/{org}/tenants", m.orgPage("admin-tenants", "Tenants", "tenants", true, nil))
	page("GET /admin/orgs/{org}/tenants/{tenant}", m.pageTenant)
	page("GET /admin/orgs/{org}/clients", m.pageClientsMoved)
	page("GET /admin/orgs/{org}/providers", m.orgPage("admin-providers", "Providers", "providers", true, nil))
	page("GET /admin/orgs/{org}/audit", m.orgPage("admin-audit", "Audit log", "audit", true, nil))
	page("GET /admin/audit", m.pageAllAudit)
	page("GET /admin/system", m.systemPage("admin-system", "System overview", "system"))
	page("GET /admin/system/master-key", m.systemPage("admin-master-key", "Master key rotation", "system"))
}

// adminOrgCookie remembers the organization last administered in this browser, so the system pages (which belong to
// none) keep its menu, one click back.
const adminOrgCookie = "__Host-quisora_admin_org"

// systemPage builds the handler of a page about the server as a whole (/admin/system/...): super admins only. The menu
// keeps the organization last administered.
func (m *Module) systemPage(name, title, nav string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !web.Actor(r).IsSuper() {
			m.errorPage(w, r, http.StatusNotFound)
			return
		}
		m.renderSystemPage(w, r, name, title, nav)
	}
}

func (m *Module) renderSystemPage(w http.ResponseWriter, r *http.Request, name, title, nav string) {
	p := m.s.Page(w, r, title, nav, &View{API: "/api", KeyRotationDays: m.s.Cfg.Tokens.KeyRotationDays})
	if c, err := r.Cookie(adminOrgCookie); err == nil {
		if org, err := m.s.Svc.OrgByName(r.Context(), c.Value); err == nil {
			p.Org = org // super admins administer every organization
		}
	}
	m.s.Render.Render(w, http.StatusOK, name, p)
}

// pageAllAudit is the audit log of every organization (super admins).
func (m *Module) pageAllAudit(w http.ResponseWriter, r *http.Request) {
	if a := web.Actor(r); !a.IsSuper() {
		m.errorPage(w, r, http.StatusForbidden)
		return
	}
	p := m.s.Page(w, r, "Audit log", "audit-all", &View{API: "/api", Base: "/admin/orgs", AllOrgs: true})
	m.s.Render.Render(w, http.StatusOK, "admin-audit", p)
}

// pageHome sends everyone to the most useful admin page for their role.
func (m *Module) pageHome(w http.ResponseWriter, r *http.Request) {
	u := web.User(r)
	switch {
	case u.Role == model.RoleSuperAdmin:
		http.Redirect(w, r, "/admin/system", http.StatusSeeOther)
	case u.Role == model.RoleAdmin:
		http.Redirect(w, r, "/admin/orgs/"+m.orgName(r, u.OrgID), http.StatusSeeOther)
	case u.Role.Rank() >= model.RoleManager.Rank():
		http.Redirect(w, r, "/admin/orgs/"+m.orgName(r, u.OrgID)+"/users", http.StatusSeeOther)
	default:
		m.errorPage(w, r, http.StatusForbidden)
	}
}

func (m *Module) orgName(r *http.Request, id string) string {
	if o, err := m.s.Svc.GetOrg(r.Context(), nil, id); err == nil {
		return url.PathEscape(o.Name)
	}
	return ""
}

// pageOrgHome is an organization's overview, with its emergency sign-out: its administrators and super admins.
// Managers, who administer users only, go to the users page.
func (m *Module) pageOrgHome(w http.ResponseWriter, r *http.Request) {
	if web.Actor(r).Role.Rank() < model.RoleAdmin.Rank() {
		http.Redirect(w, r, "/admin/orgs/"+url.PathEscape(r.PathValue("org"))+"/users", http.StatusSeeOther)
		return
	}
	org, v, ok := m.orgGate(w, r, true)
	if !ok {
		return
	}
	m.renderOrgPage(w, r, org, "admin-org", org.DisplayName, "overview", v)
}

func (m *Module) pageOrgs(w http.ResponseWriter, r *http.Request) {
	a := web.Actor(r)
	if !a.IsSuper() {
		m.errorPage(w, r, http.StatusForbidden)
		return
	}
	p := m.s.Page(w, r, "Organizations", "orgs", &View{API: "/api/orgs", Base: "/admin/orgs",
		DefaultSessionTTL: m.s.Cfg.Session.TTL, DefaultSessionIdle: m.s.Cfg.Session.Idle})
	m.s.Render.Render(w, http.StatusOK, "admin-orgs", p)
}

// orgPage builds the handler of a page scoped to the {org} path value. adminOnly pages need the org admin role,
// the others manager+.
func (m *Module) orgPage(name, title, nav string, adminOnly bool, extra func(*View, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org, v, ok := m.orgGate(w, r, adminOnly)
		if !ok {
			return
		}
		if extra != nil {
			extra(v, r)
		}
		m.renderOrgPage(w, r, org, name, title, nav, v)
	}
}

// orgGate resolves {org} for the signed-in user and checks the role; on failure it has already written the error
// page.
func (m *Module) orgGate(w http.ResponseWriter, r *http.Request, adminOnly bool) (*model.Org, *View, bool) {
	a := web.Actor(r)
	org, err := m.s.Svc.OrgByName(r.Context(), r.PathValue("org"))
	if err != nil || (!a.IsSuper() && org.ID != a.OrgID) {
		m.errorPage(w, r, http.StatusNotFound)
		return nil, nil, false
	}
	allowed := m.s.Svc.CanManageUsers(a, org.ID)
	if adminOnly {
		allowed = m.s.Svc.CanAdminOrg(a, org.ID)
	}
	if !allowed {
		m.errorPage(w, r, http.StatusForbidden)
		return nil, nil, false
	}
	esc := url.PathEscape(org.Name)
	v := &View{API: "/api/orgs/" + esc, Base: "/admin/orgs/" + esc, OrgName: org.Name, OrgDisplay: org.DisplayName,
		IsPrimary: org.Primary, CanSCIM: a.IsSuper(),
		Roles: assignableRoles(a, org), FilterRoles: filterRoles(a, org)}
	return org, v, true
}

func (m *Module) renderOrgPage(w http.ResponseWriter, r *http.Request, org *model.Org, name, title, nav string, v *View) {
	p := m.s.Page(w, r, title, nav, v)
	p.Org = org // on admin pages Org is the organization being administered
	if p.IsSuper {
		http.SetCookie(w, &http.Cookie{Name: adminOrgCookie, Value: org.Name, Path: "/", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode})
	}
	m.s.Render.Render(w, http.StatusOK, name, p)
}

// pageTenant is the page of one tenant: its sign-in rules and its clients. Unknown tenants and tenants of other
// organizations are a 404; the role rules are those of the tenants list (org admins and super admins).
func (m *Module) pageTenant(w http.ResponseWriter, r *http.Request) {
	org, v, ok := m.orgGate(w, r, true)
	if !ok {
		return
	}
	name := r.PathValue("tenant")
	t, err := m.s.Svc.Tenants.GetByUnique(r.Context(), model.TenantNameKey(org.ID, name))
	if err != nil && strings.EqualFold(name, model.DefaultTenantName) {
		t, err = m.s.Svc.DefaultTenant(r.Context(), org.ID)
	}
	if err != nil || t.OrgID != org.ID {
		m.errorPage(w, r, http.StatusNotFound)
		return
	}
	v.TenantID, v.TenantName, v.TenantDisplay = t.ID, t.Name, t.DisplayName
	m.renderOrgPage(w, r, org, "admin-tenant", "Tenant: "+t.DisplayName, "tenants", v)
}

// pageClientsMoved keeps old /clients links working: clients live under tenants.
func (m *Module) pageClientsMoved(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/orgs/"+url.PathEscape(r.PathValue("org"))+"/tenants", http.StatusFound)
}

var errorText = map[int][2]string{
	http.StatusForbidden:           {"Not allowed", "You do not have permission to view this page."},
	http.StatusNotFound:            {"Page not found", "The page you are looking for does not exist or has moved."},
	http.StatusInternalServerError: {"Something went wrong", "An unexpected error occurred. Please try again."},
}

func (m *Module) errorPage(w http.ResponseWriter, r *http.Request, status int) {
	renderError(m.s, w, r, status)
}

func renderError(s *web.Server, w http.ResponseWriter, r *http.Request, status int) {
	t, ok := errorText[status]
	if !ok {
		t = errorText[http.StatusInternalServerError]
	}
	p := s.Page(w, r, t[0], "", &View{Status: status, Heading: t[0], Message: t[1]})
	s.Render.Render(w, status, "error", p)
}

// landingHelp is the data of the sign-in help page ("landing", the login module's LandingData).
type landingHelp struct {
	Error    string
	NotFound bool
}

// NotFound returns the handler for unknown routes: JSON for /api/ and /api-internal/, the styled 404 page otherwise. Mount it on the
// catch-all pattern "/" (it is more general than every real route, so it only sees unmatched requests).
func NotFound(s *web.Server) http.Handler {
	return s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if web.APIPath(r.URL.Path) {
			web.WriteJSON(w, http.StatusNotFound, web.ErrorBody{Error: "Not found."})
			return
		}
		if web.User(r) == nil { // signed out: how to sign in, as a 404
			p := s.Page(w, r, "Not found", "", landingHelp{NotFound: true})
			s.Render.Render(w, http.StatusNotFound, "landing", p)
			return
		}
		renderError(s, w, r, http.StatusNotFound)
	}))
}

// consoleMFA refuses console pages to managers and administrators whose session did not use a second factor
// (web.ConsoleMFA), with the way forward.
func (m *Module) consoleMFA(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !web.ConsoleMFA(r) {
			m.messagePage(w, r, http.StatusForbidden, "Sign in with a second factor", web.MsgConsoleMFA)
			return
		}
		next(w, r)
	}
}

// messagePage renders the error page with a heading and message of its own.
func (m *Module) messagePage(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	p := m.s.Page(w, r, heading, "", &View{Status: status, Heading: heading, Message: message})
	m.s.Render.Render(w, status, "error", p)
}
