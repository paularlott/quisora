package admin

import (
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

type settingsView struct {
	*model.Org
	// Server defaults shown next to the session lifetime overrides (seconds).
	DefaultSessionTTL  int `json:"default_session_ttl"`
	DefaultSessionIdle int `json:"default_session_idle"`
}

func (m *Module) settingsView(o *model.Org) settingsView {
	return settingsView{Org: o, DefaultSessionTTL: m.s.Cfg.Session.TTL, DefaultSessionIdle: m.s.Cfg.Session.Idle}
}

func (m *Module) getSettings(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	if !m.s.Svc.CanAdminOrg(a, org.ID) {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.settingsView(org))
}

func (m *Module) putSettings(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.OrgInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	// The primary organization's sign-in policy covers the super admins themselves.
	if org.Primary && in.Settings != nil && *in.Settings != org.Settings && a.IsSuper() && !m.stepUp(w, r) {
		return
	}
	upd, err := m.s.Svc.UpdateOrg(r.Context(), a, org.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.settingsView(upd))
}

// auditItem is one audit event in a listing; OrgName is filled in the listing of every organization.
type auditItem struct {
	*model.Audit
	OrgName string `json:"org_name,omitempty"`
}

// auditList is an audit page: the list envelope plus where the events come from. A gossip cluster asks every node
// (nodes, nodes_answered: a node that did not answer in time is missing); source is "store", "cluster" or
// "victorialogs".
type auditList struct {
	Items         []auditItem `json:"items"`
	Total         int         `json:"total"`
	Nodes         int         `json:"nodes"`
	NodesAnswered int         `json:"nodes_answered"`
	Source        string      `json:"source"`
}

func auditQuery(r *http.Request) service.AuditQuery {
	q := listQuery(r)
	return service.AuditQuery{Search: q.Search, Sort: q.Sort, Desc: q.Desc, Offset: q.Offset, Limit: q.Limit}
}

func (m *Module) writeAudit(w http.ResponseWriter, r *http.Request, p service.AuditPage, names bool) {
	out := auditList{Items: make([]auditItem, 0, len(p.Items)), Total: p.Total, Nodes: p.Nodes,
		NodesAnswered: p.Answered, Source: p.Source}
	orgs := map[string]string{}
	for _, e := range p.Items {
		it := auditItem{Audit: e}
		if names && e.OrgID != "" {
			name, ok := orgs[e.OrgID]
			if !ok {
				if o, err := m.s.Svc.GetOrg(r.Context(), nil, e.OrgID); err == nil {
					name = o.DisplayName
				}
				orgs[e.OrgID] = name
			}
			it.OrgName = name
		}
		out.Items = append(out.Items, it)
	}
	web.WriteJSON(w, http.StatusOK, out)
}

// listAudit pages the organization's audit log, newest first unless sorted otherwise.
func (m *Module) listAudit(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	p, err := m.s.Svc.ListAudit(r.Context(), a, org.ID, auditQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	m.writeAudit(w, r, p, false)
}

// listAllAudit pages the audit log of every organization (super admins), or of one (?org=name).
func (m *Module) listAllAudit(w http.ResponseWriter, r *http.Request) {
	a := web.Actor(r)
	if !a.IsSuper() {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	orgID := ""
	if name := r.URL.Query().Get("org"); name != "" {
		o, err := m.s.Svc.OrgByName(r.Context(), name)
		if err != nil {
			web.WriteError(w, service.ErrNotFound)
			return
		}
		orgID = o.ID
	}
	p, err := m.s.Svc.ListAudit(r.Context(), a, orgID, auditQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	m.writeAudit(w, r, p, true)
}
