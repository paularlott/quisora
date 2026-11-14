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

	"github.com/paularlott/quisora/internal/mailtpl"
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
	// SendTest emails msg, rendered from organization orgID's templates, to the address to: a test email.
	SendTest(ctx context.Context, orgID, to string, msg mailtpl.Message) error
}

type noopMailer struct{}

func (noopMailer) SendInviteLink(context.Context, *model.Org, *model.User, string, time.Time) error {
	return ErrMailerDisabled
}

func (noopMailer) SendVerifyAddress(context.Context, *model.Org, *model.User, string) error {
	return ErrMailerDisabled
}

func (noopMailer) SendTest(context.Context, string, string, mailtpl.Message) error {
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
	audits        auditGate // the audit pages read at once on this node (auditBudget)
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
		s.Mux.Handle(rt.Method+" "+rt.Path, s.RequireManagement(rt.Scope, rt.Handler))
	}
	m.registerPages(s)
}

// Route is one management API operation.
type Route struct {
	Method  string
	Path    string // OpenAPI-style template, e.g. /api/orgs/{org}
	Handler http.HandlerFunc
	// Scope is the scope a service account needs to call it (web.AnyScope: any service account; "": none may).
	Scope string
}

// Routes lists every /api operation this module serves. The OpenAPI document (web/openapi/openapi.yaml, served at
// /api/openapi.json) must describe each one (tested).
func (m *Module) Routes() []Route { return m.routes() }

func (m *Module) routes() []Route {
	const o = "/api/orgs/{org}"
	return []Route{
		{"GET", "/api/orgs", m.listOrgs, ""},
		{"POST", "/api/orgs", m.createOrg, service.ScopeOrgsCreate},
		{"GET", o, m.getOrg, web.AnyScope},
		{"PATCH", o, m.updateOrg, ""},
		{"PATCH", o + "/branding", m.updateBranding, ""},
		{"GET", o + "/email-templates", m.getEmailTemplates, ""},
		{"PUT", o + "/email-templates", m.putEmailTemplates, ""},
		{"POST", o + "/email-templates/preview", m.previewEmailTemplate, ""},
		{"POST", o + "/email-templates/test", m.testEmailTemplate, ""},
		{"DELETE", o, m.deleteOrg, service.ScopeOrgsDelete},
		{"GET", "/api/skins", m.listSkins, ""},
		{"POST", "/api/skins", m.createSkin, ""},
		{"GET", "/api/skins/{name}", m.getSkin, ""},
		{"PATCH", "/api/skins/{name}", m.updateSkin, ""},
		{"DELETE", "/api/skins/{name}", m.deleteSkin, ""},
		{"POST", o + "/sign-out", m.signOutOrg, ""},

		{"GET", o + "/users", m.listUsers, service.ScopeUsers},
		{"POST", o + "/users", m.createUser, service.ScopeUsers},
		{"GET", o + "/users/{id}", m.getUser, service.ScopeUsers},
		{"PATCH", o + "/users/{id}", m.updateUser, service.ScopeUsers},
		{"DELETE", o + "/users/{id}", m.deleteUser, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/password", m.removePassword, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/totp", m.removeUserTOTP, service.ScopeUsers},
		{"PUT", o + "/users/{id}/picture", m.setUserPicture, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/picture", m.removeUserPicture, service.ScopeUsers},
		{"POST", o + "/users/{id}/lock-out", m.lockOutUser, service.ScopeUsers},
		{"POST", o + "/users/{id}/invite", m.inviteUser, service.ScopeUsers},
		{"POST", o + "/users/{id}/emails", m.addEmail, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/emails/{address}", m.removeEmail, service.ScopeUsers},
		{"POST", o + "/users/{id}/emails/{address}/primary", m.primaryEmail, service.ScopeUsers},
		{"POST", o + "/users/{id}/emails/{address}/verify", m.resendEmail, service.ScopeUsers},
		{"POST", o + "/users/{id}/emails/{address}/mark-verified", m.markEmailVerified, service.ScopeUsers},
		{"GET", o + "/users/{id}/apps", m.listUserApps, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/apps/{client}", m.removeUserApp, service.ScopeUsers},
		{"GET", o + "/users/{id}/providers", m.listUserProviders, service.ScopeUsers},
		{"GET", o + "/users/{id}/sessions", m.listUserSessions, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/sessions/{session}", m.revokeUserSession, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/providers/{provider}", m.disconnectUserProvider, service.ScopeUsers},
		{"GET", o + "/users/{id}/passkeys", m.listUserPasskeys, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/passkeys/{passkey}", m.removeUserPasskey, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/sessions", m.revokeSessions, service.ScopeUsers},
		{"GET", o + "/users/{id}/tokens", m.listUserTokens, service.ScopeUsers},
		{"DELETE", o + "/users/{id}/tokens/{token}", m.revokeUserToken, service.ScopeUsers},
		{"GET", o + "/users/{id}/ssh-certificates", m.listUserSSHCerts, service.ScopeSSH},

		{"GET", o + "/groups", m.listGroups, service.ScopeGroups},
		{"POST", o + "/groups", m.createGroup, service.ScopeGroups},
		{"GET", o + "/groups/{id}", m.getGroup, service.ScopeGroups},
		{"PATCH", o + "/groups/{id}", m.updateGroup, service.ScopeGroups},
		{"DELETE", o + "/groups/{id}", m.deleteGroup, service.ScopeGroups},
		{"GET", o + "/groups/{id}/members", m.listMembers, service.ScopeGroups},
		{"PUT", o + "/groups/{id}/members/{user}", m.addMember, service.ScopeGroups},
		{"DELETE", o + "/groups/{id}/members/{user}", m.removeMember, service.ScopeGroups},

		{"GET", o + "/tenants", m.listTenants, web.AnyScope},
		{"POST", o + "/tenants", m.createTenant, service.ScopeTenants},
		{"GET", o + "/tenants/{id}", m.getTenant, web.AnyScope},
		{"PATCH", o + "/tenants/{id}", m.updateTenant, service.ScopeTenants},
		{"DELETE", o + "/tenants/{id}", m.deleteTenant, service.ScopeTenants},
		{"GET", o + "/self-registered", m.listSelfRegistered, service.ScopeClients},
		{"DELETE", o + "/self-registered/{client...}", m.revokeSelfRegistered, service.ScopeClients},
		{"GET", o + "/tenants/{id}/access", m.listAccess, service.ScopeAccess},
		{"POST", o + "/tenants/{id}/access", m.addAccess, service.ScopeAccess},
		{"GET", o + "/tenants/{id}/access/{aid}", m.getAccess, service.ScopeAccess},
		{"PATCH", o + "/tenants/{id}/access/{aid}", m.updateAccess, service.ScopeAccess},
		{"DELETE", o + "/tenants/{id}/access/{aid}", m.removeAccess, service.ScopeAccess},

		{"GET", o + "/tenants/{id}/ssh", m.getSSH, service.ScopeSSH},
		{"PATCH", o + "/tenants/{id}/ssh", m.updateSSH, service.ScopeSSH},
		{"POST", o + "/tenants/{id}/ssh/rotate", m.rotateSSH, service.ScopeSSH},
		{"DELETE", o + "/tenants/{id}/ssh/keys/{key}", m.removeSSHKey, service.ScopeSSH},
		{"GET", o + "/tenants/{id}/ssh/certificates", m.listSSHCerts, service.ScopeSSH},
		{"POST", o + "/tenants/{id}/ssh/certificates/{cert}/revoke", m.revokeSSHCert, service.ScopeSSH},
		{"POST", o + "/tenants/{id}/ssh/host-certificates", m.signHostSSH, service.ScopeSSHHost},

		{"GET", o + "/clients", m.listClients, web.AnyScope},
		{"POST", o + "/clients", m.createClient, service.ScopeClients},
		{"GET", o + "/clients/{id}", m.getClient, web.AnyScope},
		{"PATCH", o + "/clients/{id}", m.updateClient, service.ScopeClients},
		{"DELETE", o + "/clients/{id}", m.deleteClient, service.ScopeClients},
		{"POST", o + "/clients/{id}/secret", m.rotateSecret, service.ScopeClients},

		{"GET", o + "/providers", m.listProviders, service.ScopeProviders},
		{"POST", o + "/providers", m.createProvider, service.ScopeProviders},
		{"GET", o + "/providers/{id}", m.getProvider, service.ScopeProviders},
		{"PATCH", o + "/providers/{id}", m.updateProvider, service.ScopeProviders},
		{"DELETE", o + "/providers/{id}", m.deleteProvider, service.ScopeProviders},

		{"GET", o + "/service-accounts", m.listServiceAccounts, service.ScopeServiceAccounts},
		{"POST", o + "/service-accounts", m.createServiceAccount, service.ScopeServiceAccounts},
		{"GET", o + "/service-accounts/{id}", m.getServiceAccount, service.ScopeServiceAccounts},
		{"PATCH", o + "/service-accounts/{id}", m.updateServiceAccount, service.ScopeServiceAccounts},
		{"DELETE", o + "/service-accounts/{id}", m.deleteServiceAccount, service.ScopeServiceAccounts},
		{"POST", o + "/service-accounts/{id}/secret", m.rotateServiceAccountSecret, service.ScopeServiceAccounts},

		{"GET", o + "/audit", m.listAudit, ""},

		{"GET", "/api/audit", m.listAllAudit, ""},
		{"GET", "/api/keys", m.listKeys, ""},
		{"POST", "/api/keys/rotate", m.rotateKeys, ""},
		{"DELETE", "/api/keys/{id}", m.removeKey, ""},
		{"GET", "/api/backup", m.downloadBackup, ""},
		{"GET", "/api/master-key", m.masterKeyStatus, ""},
		{"GET", "/api/cluster", m.clusterStatus, ""},
		{"POST", "/api/cluster/reload", m.reloadCluster, ""},
		{"POST", "/api/sign-out", m.signOutServer, ""},
		{"GET", "/api/system", m.systemStatus, ""},
	}
}

// unanswered answers a lookup that ended with an error other than "not found" (the store could not answer: 503) as
// that error, and reports whether it did: the caller answers "not found" only for what was looked up and is not there.
func unanswered(w http.ResponseWriter, err error) bool {
	if err == nil || errors.Is(err, service.ErrNotFound) || errors.Is(err, store.ErrNotFound) {
		return false
	}
	web.WriteError(w, err)
	return true
}

// orgFor resolves the {org} path value, the organization's id or name (service.OrgByRef), for the signed-in actor.
// Unknown orgs and orgs the actor may not see are both reported as not found.
func (m *Module) orgFor(w http.ResponseWriter, r *http.Request) (*model.Org, *service.Actor, bool) {
	a := web.Actor(r)
	o, err := m.s.Svc.OrgByRef(r.Context(), r.PathValue("org"))
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
