package admin

import (
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

func (m *Module) clientFor(w http.ResponseWriter, r *http.Request, org *model.Org, a *service.Actor) (*model.Client, bool) {
	c, err := m.s.Svc.GetClient(r.Context(), a, r.PathValue("id"))
	if err != nil || c.OrgID != org.ID {
		web.WriteError(w, service.ErrNotFound)
		return nil, false
	}
	return c, true
}

// clientView is a client as the management API shows it: with require_pkce (stored as its opt-out).
type clientView struct {
	*model.Client
	RequirePKCE bool `json:"require_pkce"`
}

func clientViewOf(c *model.Client) clientView {
	return clientView{Client: c, RequirePKCE: c.RequirePKCE()}
}

func (m *Module) listClients(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	q := listQuery(r)
	if t := r.URL.Query().Get("tenant"); t != "" {
		q.Filters = append(q.Filters, store.Filter{Field: "tenant_id", Value: t})
	}
	items, total, err := m.s.Svc.ListClients(r.Context(), a, org.ID, q)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	views := make([]clientView, len(items))
	for i, c := range items {
		views[i] = clientViewOf(c)
	}
	writeList(w, views, total)
}

func (m *Module) getClient(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	if c, found := m.clientFor(w, r, org, a); found {
		web.WriteJSON(w, http.StatusOK, clientViewOf(c))
	}
}

// createClient returns the client with its secret, which is never retrievable again.
func (m *Module) createClient(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.ClientInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	c, secret, err := m.s.Svc.CreateClient(r.Context(), a, org.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, struct {
		clientView
		Secret string `json:"secret"`
	}{clientViewOf(c), secret})
}

func (m *Module) updateClient(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	c, found := m.clientFor(w, r, org, a)
	if !found {
		return
	}
	var in service.ClientInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	upd, err := m.s.Svc.UpdateClient(r.Context(), a, c.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, clientViewOf(upd))
}

func (m *Module) deleteClient(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	c, found := m.clientFor(w, r, org, a)
	if !found {
		return
	}
	if err := m.s.Svc.DeleteClient(r.Context(), a, c.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// rotateSecret issues a new secret (shown once).
func (m *Module) rotateSecret(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	c, found := m.clientFor(w, r, org, a)
	if !found {
		return
	}
	if c.Public() {
		web.WriteError(w, service.Invalid("token_endpoint_auth_method", "public clients have no secret"))
		return
	}
	secret, err := m.s.Svc.RotateClientSecret(r.Context(), a, c.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]string{"client_id": c.ID, "secret": secret})
}
