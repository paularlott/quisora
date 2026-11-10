package admin

import (
	"net/http"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// serviceAccountView is a service account as the management API shows it, with where it gets its tokens: its id is
// the client_id it authenticates with there.
type serviceAccountView struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Scopes        []string  `json:"scopes"`
	AuthMethod    string    `json:"token_endpoint_auth_method"`
	JWKS          string    `json:"jwks,omitempty"`
	JWKSURI       string    `json:"jwks_uri,omitempty"`
	FAPI          bool      `json:"fapi2_security_profile"`
	Enabled       bool      `json:"enabled"`
	TokenEndpoint string    `json:"token_endpoint"`
	Created       time.Time `json:"created"`
	Updated       time.Time `json:"updated"`
}

func (m *Module) serviceAccountViewOf(c *model.Client) serviceAccountView {
	return serviceAccountView{ID: c.ID, Name: c.Name, Description: c.Description, Scopes: c.Scopes, AuthMethod: c.AuthMethod,
		JWKS: c.JWKS, JWKSURI: c.JWKSURI, FAPI: c.FAPI, Enabled: c.Enabled, TokenEndpoint: m.s.Cfg.OrgEndpoints(c.OrgID).Token,
		Created: c.Created, Updated: c.Updated}
}

// createdServiceAccount is a new service account with its secret, which is never retrievable again (none for
// private_key_jwt).
type createdServiceAccount struct {
	serviceAccountView
	Secret string `json:"secret,omitempty"`
}

func (m *Module) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	items, total, err := m.s.Svc.ListServiceAccounts(r.Context(), a, org.ID, listQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	views := make([]serviceAccountView, len(items))
	for i, c := range items {
		views[i] = m.serviceAccountViewOf(c)
	}
	writeList(w, views, total)
}

func (m *Module) getServiceAccount(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	c, err := m.s.Svc.GetServiceAccount(r.Context(), a, org.ID, r.PathValue("id"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.serviceAccountViewOf(c))
}

func (m *Module) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.ServiceAccountInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if !m.stepUp(w, r) { // a service account holds its scopes for good: given only after a recent re-authentication, never by an API token
		return
	}
	c, secret, err := m.s.Svc.CreateServiceAccount(r.Context(), a, org.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, createdServiceAccount{m.serviceAccountViewOf(c), secret})
}

func (m *Module) updateServiceAccount(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.ServiceAccountInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if !m.stepUp(w, r) { // a service account holds its scopes for good: given only after a recent re-authentication, never by an API token
		return
	}
	c, err := m.s.Svc.UpdateServiceAccount(r.Context(), a, org.ID, r.PathValue("id"), in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.serviceAccountViewOf(c))
}

func (m *Module) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	if err := m.s.Svc.DeleteServiceAccount(r.Context(), a, org.ID, r.PathValue("id")); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// rotateServiceAccountSecret issues a new secret (shown once); the old one stops working at once.
func (m *Module) rotateServiceAccountSecret(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	if !m.stepUp(w, r) { // a service account holds its scopes for good: its secret issued only after a recent re-authentication, never by an API token
		return
	}
	id := r.PathValue("id")
	secret, err := m.s.Svc.RotateServiceAccountSecret(r.Context(), a, org.ID, id)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]string{"id": id, "secret": secret})
}
