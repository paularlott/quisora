package admin

import (
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/upstream"
	"github.com/paularlott/quisora/internal/web"
)

// providerView never carries the client secret; HasSecret says whether one is stored. CallbackURL is the provider's
// own redirect URI, to register with it.
type providerView struct {
	*model.Provider
	HasSecret   bool   `json:"has_secret"`
	CallbackURL string `json:"callback_url"`
}

func (m *Module) providerViewOf(p *model.Provider) providerView {
	return providerView{p, p.ClientSecret != "", m.s.Cfg.Server.PublicURL + upstream.CallbackPath(p.ID)}
}

func (m *Module) providerViews(ps []*model.Provider) []providerView {
	out := make([]providerView, len(ps))
	for i, p := range ps {
		out[i] = m.providerViewOf(p)
	}
	return out
}

func (m *Module) providerFor(w http.ResponseWriter, r *http.Request, org *model.Org, a *service.Actor) (*model.Provider, bool) {
	p, err := m.s.Svc.GetProvider(r.Context(), a, r.PathValue("id"))
	if err != nil || p.OrgID != org.ID {
		web.WriteError(w, service.ErrNotFound)
		return nil, false
	}
	return p, true
}

func (m *Module) getProvider(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	if p, found := m.providerFor(w, r, org, a); found {
		web.WriteJSON(w, http.StatusOK, m.providerViewOf(p))
	}
}

func (m *Module) listProviders(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	items, total, err := m.s.Svc.ListProviders(r.Context(), a, org.ID, listQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	writeList(w, m.providerViews(items), total)
}

func (m *Module) createProvider(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.ProviderInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	p, err := m.s.Svc.CreateProvider(r.Context(), a, org.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, m.providerViewOf(p))
}

func (m *Module) updateProvider(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	p, found := m.providerFor(w, r, org, a)
	if !found {
		return
	}
	var in service.ProviderInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	in.ClientSecret = emptyToNil(in.ClientSecret) // blank keeps the stored secret
	upd, err := m.s.Svc.UpdateProvider(r.Context(), a, p.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.providerViewOf(upd))
}

func (m *Module) deleteProvider(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	p, found := m.providerFor(w, r, org, a)
	if !found {
		return
	}
	if err := m.s.Svc.DeleteProvider(r.Context(), a, p.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}
