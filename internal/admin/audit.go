package admin

import (
	"net/http"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// auditItem is one audit event in a listing; OrgName is filled in the listing of every organization.
type auditItem struct {
	*model.Audit
	OrgName string `json:"org_name,omitempty"`
}

// auditList is an audit page: the list envelope plus where the events come from. total counts the matching events
// up to a bound (10,000, or the end of the page past it), and total_more says there are more than that. A gossip
// cluster asks every node (nodes, nodes_answered: a node that did not answer in time is missing); source is "store",
// "cluster" or "victorialogs".
type auditList struct {
	Items         []auditItem `json:"items"`
	Total         int         `json:"total"`
	TotalMore     bool        `json:"total_more"`
	Nodes         int         `json:"nodes"`
	NodesAnswered int         `json:"nodes_answered"`
	Source        string      `json:"source"`
}

// auditQuery reads an audit page's parameters: the list ones (q, sort, desc, offset, limit), and the filters from and
// to (RFC 3339 times), action_group (a family of actions, such as "user."), action and outcome.
func auditQuery(r *http.Request) (service.AuditQuery, error) {
	q := listQuery(r)
	v := r.URL.Query()
	aq := service.AuditQuery{Search: q.Search, Sort: q.Sort, Desc: q.Desc, Offset: q.Offset, Limit: q.Limit,
		ActionPrefix: v.Get("action_group"), Action: v.Get("action"), Outcome: v.Get("outcome")}
	for _, t := range []struct {
		name string
		to   *time.Time
	}{{"from", &aq.From}, {"to", &aq.To}} {
		if s := v.Get(t.name); s != "" {
			at, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return aq, service.Invalid(t.name, "must be a time such as 2026-10-21T09:00:00Z")
			}
			*t.to = at
		}
	}
	return aq, nil
}

func (m *Module) writeAudit(w http.ResponseWriter, r *http.Request, p service.AuditPage, names bool) {
	out := auditList{Items: make([]auditItem, 0, len(p.Items)), Total: p.Total, TotalMore: p.More,
		Nodes: p.Nodes, NodesAnswered: p.Answered, Source: p.Source}
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
	aq, err := auditQuery(r)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	p, err := m.s.Svc.ListAudit(r.Context(), a, org.ID, aq)
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
		if unanswered(w, err) {
			return
		}
		if err != nil {
			web.WriteError(w, service.ErrNotFound)
			return
		}
		orgID = o.ID
	}
	aq, err := auditQuery(r)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	p, err := m.s.Svc.ListAudit(r.Context(), a, orgID, aq)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	m.writeAudit(w, r, p, true)
}
