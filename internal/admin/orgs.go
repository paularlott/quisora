package admin

import (
	"net/http"
	"slices"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// orgView adds to an organization whether it is the primary one (derived: model.Org.Primary) and the user count (shown
// to super admins).
type orgView struct {
	*model.Org
	Primary  bool         `json:"primary"`
	Users    *int         `json:"users,omitempty"`
	Branding brandingView `json:"branding"`
}

// brandingView is an organization's branding with the URLs of its logo (none: omitted).
type brandingView struct {
	PrimaryColor string `json:"primary_color"`
	LogoLight    string `json:"logo_light,omitempty"`
	LogoDark     string `json:"logo_dark,omitempty"`
	Footer       string `json:"footer"`
	Skin         string `json:"skin"`
}

// viewOf is o as a sees it: the last emergency sign-out (who pulled it, and why) is for those who manage the
// organization's users, not for everyone in it.
func (m *Module) viewOf(a *service.Actor, o *model.Org) orgView {
	if o.LastSignOut != nil && !m.s.Svc.CanManageUsers(a, o.ID) {
		cp := *o
		cp.LastSignOut = nil
		o = &cp
	}
	return orgView{Org: o, Primary: o.Primary, Branding: brandingView{PrimaryColor: o.Branding.PrimaryColor,
		LogoLight: web.OrgLogoURL(o, false), LogoDark: web.OrgLogoURL(o, true), Footer: o.Branding.Footer, Skin: o.Branding.Skin}}
}

func (m *Module) listOrgs(w http.ResponseWriter, r *http.Request) {
	a := web.Actor(r)
	items, total, err := m.s.Svc.ListOrgs(r.Context(), a, listQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	out := make([]orgView, len(items))
	for i, o := range items {
		out[i] = m.viewOf(a, o)
		if a.IsSuper() {
			if n, err := m.s.Svc.Users.Count(r.Context(), o.ID); err == nil {
				out[i].Users = &n
			}
		}
	}
	writeList(w, out, total)
}

// createOrg creates an organization, with its first service account when the request names one (returned with its
// secret, which is never retrievable again).
func (m *Module) createOrg(w http.ResponseWriter, r *http.Request) {
	var in service.OrgInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	// Its first service account is made as any other is (serviceaccounts.go): by a person only after a recent
	// re-authentication, never by a personal API token (stepUp lets a service account through).
	if in.ServiceAccount != nil && !m.stepUp(w, r) {
		return
	}
	o, sa, secret, err := m.s.Svc.CreateOrgWithServiceAccount(r.Context(), web.Actor(r), in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	zero := 0
	out := struct {
		orgView
		ServiceAccount *createdServiceAccount `json:"service_account,omitempty"`
	}{orgView: m.viewOf(web.Actor(r), o)}
	out.Users = &zero
	if sa != nil {
		out.ServiceAccount = &createdServiceAccount{m.serviceAccountViewOf(sa), secret}
	}
	web.WriteJSON(w, http.StatusCreated, out)
}

func (m *Module) updateOrg(w http.ResponseWriter, r *http.Request) {
	o, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	// settings is decoded over a copy of the current ones: a PATCH that names some settings leaves the others as
	// they are (an omitted switch must not read as "off"). The group list is copied: decoding reuses the memory of the
	// slice it is given, and the organization read is shared.
	set := o.Settings
	set.APITokenGroups = slices.Clone(set.APITokenGroups)
	in := service.OrgInput{Settings: &set}
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if in.Settings != nil && in.Settings.Equal(o.Settings) {
		in.Settings = nil
	}
	// The primary organization's sign-in policy covers the super admins themselves.
	if o.Primary && in.Settings != nil && a.IsSuper() && !m.stepUp(w, r) {
		return
	}
	upd, err := m.s.Svc.UpdateOrg(r.Context(), a, o.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.viewOf(a, upd))
}

// updateBranding changes the organization's logo and primary colour (its admins; never a service account).
func (m *Module) updateBranding(w http.ResponseWriter, r *http.Request) {
	o, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.BrandingInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	upd, err := m.s.Svc.UpdateBranding(r.Context(), a, o.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.viewOf(a, upd))
}

// deleteOrg deletes an organization; ?cascade=1 allows one with users (they, its groups, clients and providers stop
// counting at once and the orphan sweep removes them). A service account (orgs:delete) names an organization it
// created, not its own: the service decides which it may delete.
func (m *Module) deleteOrg(w http.ResponseWriter, r *http.Request) {
	a := web.Actor(r)
	var o *model.Org
	if a.ClientID != "" {
		var err error
		if o, err = m.s.Svc.OrgByRef(r.Context(), r.PathValue("org")); err != nil {
			web.WriteError(w, err)
			return
		}
	} else {
		var found bool
		if o, a, found = m.orgFor(w, r); !found {
			return
		}
	}
	cascade := r.URL.Query().Get("cascade") == "1"
	if a.IsSuper() && !m.stepUp(w, r) {
		return
	}
	if err := m.s.Svc.DeleteOrg(r.Context(), a, o.ID, cascade); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

func (m *Module) getOrg(w http.ResponseWriter, r *http.Request) {
	o, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	v := m.viewOf(a, o)
	if a.IsSuper() {
		if n, err := m.s.Svc.Users.Count(r.Context(), o.ID); err == nil {
			v.Users = &n
		}
	}
	web.WriteJSON(w, http.StatusOK, v)
}
