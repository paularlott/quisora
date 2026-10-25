package admin

import (
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// orgView adds the user count (shown to super admins) to an organization.
type orgView struct {
	*model.Org
	Users *int `json:"users,omitempty"`
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
		out[i] = orgView{Org: o}
		if a.IsSuper() {
			if n, err := m.s.Svc.Users.Count(r.Context(), o.ID); err == nil {
				out[i].Users = &n
			}
		}
	}
	writeList(w, out, total)
}

func (m *Module) createOrg(w http.ResponseWriter, r *http.Request) {
	var in service.OrgInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	o, err := m.s.Svc.CreateOrg(r.Context(), web.Actor(r), in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	zero := 0
	web.WriteJSON(w, http.StatusCreated, orgView{Org: o, Users: &zero})
}

func (m *Module) updateOrg(w http.ResponseWriter, r *http.Request) {
	o, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.OrgInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	// The primary organization's sign-in policy covers the super admins themselves.
	if o.Primary && in.Settings != nil && *in.Settings != o.Settings && a.IsSuper() && !m.stepUp(w, r) {
		return
	}
	upd, err := m.s.Svc.UpdateOrg(r.Context(), a, o.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, orgView{Org: upd})
}

// deleteOrg deletes an organization; ?cascade=1 allows one with users (they, its groups, clients and providers stop
// counting at once and the orphan sweep removes them).
func (m *Module) deleteOrg(w http.ResponseWriter, r *http.Request) {
	o, a, found := m.orgFor(w, r)
	if !found {
		return
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
	v := orgView{Org: o}
	if a.IsSuper() {
		if n, err := m.s.Svc.Users.Count(r.Context(), o.ID); err == nil {
			v.Users = &n
		}
	}
	web.WriteJSON(w, http.StatusOK, v)
}
