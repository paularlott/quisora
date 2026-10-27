// Package admin is the administration UI: the JSON API under /api/admin and the HTML pages under /admin. Every
// permission decision is made by the service layer; this package resolves which organization is being administered
// (path /admin/orgs/{org}/..., org = URL name; non-super users reach only their own), decodes requests and shapes
// responses.
package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// ErrMailerDisabled is returned by a Mailer that cannot send (no SMTP configured).
var ErrMailerDisabled = errors.New("email is not configured")

// Mailer sends the emails the admin UI can trigger. The application wires a real implementation; the default does
// nothing and reports ErrMailerDisabled.
type Mailer interface {
	// SendInviteLink emails u an invitation: url is the single-use link and expires its end of life.
	SendInviteLink(ctx context.Context, org *model.Org, u *model.User, url string, expires time.Time) error
	// SendVerifyAddress emails a verification link to one of u's addresses.
	SendVerifyAddress(ctx context.Context, org *model.Org, u *model.User, address string) error
}

type noopMailer struct{}

func (noopMailer) SendInviteLink(context.Context, *model.Org, *model.User, string, time.Time) error {
	return ErrMailerDisabled
}

func (noopMailer) SendVerifyAddress(context.Context, *model.Org, *model.User, string) error {
	return ErrMailerDisabled
}

// Module registers the admin routes.
type Module struct {
	Mailer Mailer
	// RotateKeys mints a new signing key (wired to the OAuth provider by the app).
	RotateKeys func(ctx context.Context) error
	// RemoveKey removes a signing key that no longer signs, at once (wired to the OAuth provider by the app).
	RemoveKey func(ctx context.Context, id string) error
	// ClusterStatus reports this node's cluster status (wired to cluster.Node.Status by the app).
	ClusterStatus func() any
	// ReloadCluster has every node re-read its configuration (wired to cluster.Node.ReloadCluster by the app): the
	// nodes' reports, and an error when nothing or not everything was applied.
	ReloadCluster func(ctx context.Context) (any, error)
	s             *web.Server
}

// New returns the admin module with a no-op mailer.
func New() *Module { return &Module{Mailer: noopMailer{}} }

// Register implements web.Module.
func (m *Module) Register(s *web.Server) {
	m.s = s
	if m.Mailer == nil {
		m.Mailer = noopMailer{}
	}
	for _, rt := range m.routes() {
		s.Mux.Handle(rt.Method+" "+rt.Path, s.RequireManagement(rt.Handler))
	}
	m.registerPages(s)
}

// Route is one management API operation.
type Route struct {
	Method  string
	Path    string // OpenAPI-style template, e.g. /api/orgs/{org}
	Handler http.HandlerFunc
}

// Routes lists every /api operation this module serves. The OpenAPI document (web/openapi/openapi.yaml, served at
// /api/openapi.json) must describe each one (tested).
func (m *Module) Routes() []Route { return m.routes() }

func (m *Module) routes() []Route {
	const o = "/api/orgs/{org}"
	return []Route{
		{"GET", "/api/orgs", m.listOrgs},
		{"POST", "/api/orgs", m.createOrg},
		{"GET", o, m.getOrg},
		{"PATCH", o, m.updateOrg},
		{"DELETE", o, m.deleteOrg},
		{"POST", o + "/sign-out", m.signOutOrg},

		{"GET", o + "/users", m.listUsers},
		{"POST", o + "/users", m.createUser},
		{"GET", o + "/users/{id}", m.getUser},
		{"PATCH", o + "/users/{id}", m.updateUser},
		{"DELETE", o + "/users/{id}", m.deleteUser},
		{"DELETE", o + "/users/{id}/password", m.removePassword},
		{"POST", o + "/users/{id}/lock-out", m.lockOutUser},
		{"POST", o + "/users/{id}/invite", m.inviteUser},
		{"POST", o + "/users/{id}/emails", m.addEmail},
		{"DELETE", o + "/users/{id}/emails/{address}", m.removeEmail},
		{"POST", o + "/users/{id}/emails/{address}/primary", m.primaryEmail},
		{"POST", o + "/users/{id}/emails/{address}/verify", m.resendEmail},
		{"POST", o + "/users/{id}/emails/{address}/mark-verified", m.markEmailVerified},
		{"GET", o + "/users/{id}/apps", m.listUserApps},
		{"DELETE", o + "/users/{id}/apps/{client}", m.removeUserApp},
		{"GET", o + "/users/{id}/providers", m.listUserProviders},
		{"GET", o + "/users/{id}/sessions", m.listUserSessions},
		{"DELETE", o + "/users/{id}/sessions/{session}", m.revokeUserSession},
		{"DELETE", o + "/users/{id}/providers/{provider}", m.disconnectUserProvider},
		{"GET", o + "/users/{id}/passkeys", m.listUserPasskeys},
		{"DELETE", o + "/users/{id}/passkeys/{passkey}", m.removeUserPasskey},
		{"DELETE", o + "/users/{id}/sessions", m.revokeSessions},
		{"GET", o + "/users/{id}/tokens", m.listUserTokens},
		{"DELETE", o + "/users/{id}/tokens/{token}", m.revokeUserToken},

		{"GET", o + "/groups", m.listGroups},
		{"POST", o + "/groups", m.createGroup},
		{"GET", o + "/groups/{id}", m.getGroup},
		{"PATCH", o + "/groups/{id}", m.updateGroup},
		{"DELETE", o + "/groups/{id}", m.deleteGroup},
		{"GET", o + "/groups/{id}/members", m.listMembers},
		{"PUT", o + "/groups/{id}/members/{user}", m.addMember},
		{"DELETE", o + "/groups/{id}/members/{user}", m.removeMember},

		{"GET", o + "/tenants", m.listTenants},
		{"POST", o + "/tenants", m.createTenant},
		{"GET", o + "/tenants/{id}", m.getTenant},
		{"PATCH", o + "/tenants/{id}", m.updateTenant},
		{"DELETE", o + "/tenants/{id}", m.deleteTenant},
		{"GET", o + "/tenants/{id}/self-registered", m.listSelfRegistered},
		{"DELETE", o + "/tenants/{id}/self-registered/{client}", m.revokeSelfRegistered},
		{"GET", o + "/tenants/{id}/access", m.listAccess},
		{"POST", o + "/tenants/{id}/access", m.addAccess},
		{"GET", o + "/tenants/{id}/access/{aid}", m.getAccess},
		{"PATCH", o + "/tenants/{id}/access/{aid}", m.updateAccess},
		{"DELETE", o + "/tenants/{id}/access/{aid}", m.removeAccess},

		{"GET", o + "/clients", m.listClients},
		{"POST", o + "/clients", m.createClient},
		{"GET", o + "/clients/{id}", m.getClient},
		{"PATCH", o + "/clients/{id}", m.updateClient},
		{"DELETE", o + "/clients/{id}", m.deleteClient},
		{"POST", o + "/clients/{id}/secret", m.rotateSecret},

		{"GET", o + "/providers", m.listProviders},
		{"POST", o + "/providers", m.createProvider},
		{"GET", o + "/providers/{id}", m.getProvider},
		{"PATCH", o + "/providers/{id}", m.updateProvider},
		{"DELETE", o + "/providers/{id}", m.deleteProvider},

		{"GET", o + "/audit", m.listAudit},

		{"GET", "/api/audit", m.listAllAudit},
		{"GET", "/api/keys", m.listKeys},
		{"POST", "/api/keys/rotate", m.rotateKeys},
		{"DELETE", "/api/keys/{id}", m.removeKey},
		{"GET", "/api/backup", m.downloadBackup},
		{"GET", "/api/master-key", m.masterKeyStatus},
		{"GET", "/api/cluster", m.clusterStatus},
		{"POST", "/api/cluster/reload", m.reloadCluster},
		{"POST", "/api/sign-out", m.signOutServer},
		{"GET", "/api/system", m.systemStatus},
	}
}

// orgFor resolves the {org} path value for the signed-in actor. Unknown orgs and orgs the actor may not see are
// both reported as not found.
// unanswered answers a lookup that ended with an error other than "not found" (the store could not answer: 503) as
// that error, and reports whether it did: the caller answers "not found" only for what was looked up and is not there.
func unanswered(w http.ResponseWriter, err error) bool {
	if err == nil || errors.Is(err, service.ErrNotFound) || errors.Is(err, store.ErrNotFound) {
		return false
	}
	web.WriteError(w, err)
	return true
}

func (m *Module) orgFor(w http.ResponseWriter, r *http.Request) (*model.Org, *service.Actor, bool) {
	a := web.Actor(r)
	o, err := m.s.Svc.OrgByName(r.Context(), r.PathValue("org"))
	if unanswered(w, err) {
		return nil, nil, false
	}
	if err != nil || (!a.IsSuper() && o.ID != a.OrgID) {
		web.WriteError(w, service.ErrNotFound)
		return nil, nil, false
	}
	return o, a, true
}

const (
	defaultLimit = 25
	maxLimit     = 100
)

// listQuery parses ?q=&sort=&desc=1&offset=&limit=.
func listQuery(r *http.Request) store.ListQuery {
	v := r.URL.Query()
	q := store.ListQuery{Search: strings.TrimSpace(v.Get("q")), Sort: v.Get("sort"), Limit: defaultLimit}
	switch v.Get("desc") {
	case "1", "true":
		q.Desc = true
	}
	if n, err := strconv.Atoi(v.Get("offset")); err == nil && n > 0 {
		q.Offset = n
	}
	if n, err := strconv.Atoi(v.Get("limit")); err == nil && n > 0 {
		q.Limit = min(n, maxLimit)
	}
	return q
}

// listResponse is the list envelope: {"items": [...], "total": n}.
type listResponse[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

func writeList[T any](w http.ResponseWriter, items []T, total int) {
	if items == nil {
		items = []T{}
	}
	web.WriteJSON(w, http.StatusOK, listResponse[T]{Items: items, Total: total})
}

func ok(w http.ResponseWriter) { web.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true}) }

// emptyToNil turns a pointer to a blank string into nil (meaning "leave unchanged").
func emptyToNil(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}
