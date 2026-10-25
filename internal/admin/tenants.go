package admin

import (
	"context"
	"net/http"
	"slices"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// tenantView adds the number of clients to a tenant.
type tenantView struct {
	*model.Tenant
	Clients int `json:"clients"`
}

func (m *Module) tenantView(ctx context.Context, a *service.Actor, t *model.Tenant) tenantView {
	v := tenantView{Tenant: t}
	if t.Settings.Providers == nil {
		cp := *t
		cp.Settings.Providers = []string{}
		v.Tenant = &cp
	}
	_, n, err := m.s.Svc.ListClients(ctx, a, t.OrgID, store.ListQuery{Limit: 1,
		Filters: []store.Filter{{Field: "tenant_id", Value: t.ID}}})
	if err == nil {
		v.Clients = n
	}
	return v
}

func (m *Module) tenantFor(w http.ResponseWriter, r *http.Request, org *model.Org, a *service.Actor) (*model.Tenant, bool) {
	// {id} is the tenant's id or its name (the name the console shows and puts in its address)
	ref := r.PathValue("id")
	t, err := m.s.Svc.GetTenant(r.Context(), a, ref)
	if err != nil {
		if byName, nerr := m.s.Svc.Tenants.GetByUnique(r.Context(), model.TenantNameKey(org.ID, ref)); nerr == nil {
			t, err = m.s.Svc.GetTenant(r.Context(), a, byName.ID)
		}
	}
	if err != nil || t.OrgID != org.ID {
		web.WriteError(w, service.ErrNotFound)
		return nil, false
	}
	return t, true
}

func (m *Module) listTenants(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	items, total, err := m.s.Svc.ListTenants(r.Context(), a, org.ID, listQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	out := make([]tenantView, len(items))
	for i, t := range items {
		out[i] = m.tenantView(r.Context(), a, t)
	}
	writeList(w, out, total)
}

func (m *Module) createTenant(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.TenantInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	t, err := m.s.Svc.CreateTenant(r.Context(), a, org.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, m.tenantView(r.Context(), a, t))
}

func (m *Module) getTenant(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	t, found := m.tenantFor(w, r, org, a)
	if !found {
		return
	}
	web.WriteJSON(w, http.StatusOK, m.tenantView(r.Context(), a, t))
}

func (m *Module) updateTenant(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	t, found := m.tenantFor(w, r, org, a)
	if !found {
		return
	}
	// settings is decoded over a copy of the current ones: a PATCH that names some settings leaves the others as
	// they are (an omitted members_only must not open the tenant).
	set := t.Settings
	set.Providers = slices.Clone(t.Settings.Providers)
	in := service.TenantInput{Settings: &set}
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if in.Settings != nil && in.Settings.Equal(t.Settings) {
		in.Settings = nil
	}
	upd, err := m.s.Svc.UpdateTenant(r.Context(), a, t.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.tenantView(r.Context(), a, upd))
}

func (m *Module) deleteTenant(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	t, found := m.tenantFor(w, r, org, a)
	if !found {
		return
	}
	if err := m.s.Svc.DeleteTenant(r.Context(), a, t.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// ---- Tenant access (who may sign in to the tenant's applications, and their roles and tags there) -------------

func (m *Module) accessTenant(w http.ResponseWriter, r *http.Request) (*model.Tenant, *service.Actor, bool) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return nil, nil, false
	}
	t, found := m.tenantFor(w, r, org, a)
	return t, a, found
}

func (m *Module) listAccess(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.accessTenant(w, r)
	if !found {
		return
	}
	items, total, err := m.s.Svc.ListAccess(r.Context(), a, t.ID, listQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	writeList(w, items, total)
}

func (m *Module) addAccess(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.accessTenant(w, r)
	if !found {
		return
	}
	var in service.AccessInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	e, err := m.s.Svc.AddAccess(r.Context(), a, t.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, e)
}

func (m *Module) getAccess(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.accessTenant(w, r)
	if !found {
		return
	}
	e, err := m.s.Svc.GetAccess(r.Context(), a, t.ID, r.PathValue("aid"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, e)
}

func (m *Module) updateAccess(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.accessTenant(w, r)
	if !found {
		return
	}
	var in service.AccessInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	e, err := m.s.Svc.UpdateAccess(r.Context(), a, t.ID, r.PathValue("aid"), in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, e)
}

func (m *Module) removeAccess(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.accessTenant(w, r)
	if !found {
		return
	}
	if err := m.s.Svc.RemoveAccess(r.Context(), a, t.ID, r.PathValue("aid")); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// listSelfRegistered handles GET /tenants/{id}/self-registered: the self-registered applications authorized in it.
func (m *Module) listSelfRegistered(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.accessTenant(w, r)
	if !found {
		return
	}
	items, err := m.s.Svc.SelfRegisteredApps(r.Context(), a, t.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	writeList(w, items, len(items))
}

// revokeSelfRegistered handles DELETE /tenants/{id}/self-registered/{client}.
func (m *Module) revokeSelfRegistered(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.accessTenant(w, r)
	if !found {
		return
	}
	if err := m.s.Svc.RevokeSelfRegisteredApp(r.Context(), a, t.ID, r.PathValue("client")); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}
