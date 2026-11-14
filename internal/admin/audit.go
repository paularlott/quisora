package admin

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// auditGate bounds the audit pages this node reads at once: web.AuditReadsInFlight in all, and
// web.AuditReadsInFlightPerBudget of one budget (web.AuditBudgetOrg, web.AuditBudgetSuper), so one organization's
// slow searches leave room for everyone else's. web.AuditReadsInFlightSuper of the places are kept for the super
// admins' budgets: the organizations' pages together take the others at most, so however many organizations search
// slowly at once, the operators can still read any log (theirs take any place that is free). A page that finds no
// room is refused at once, not queued: a queue would hold the request (and the client's patience) for a log that is
// already busy. The zero value is ready.
type auditGate struct {
	mu    sync.Mutex
	total int // places taken
	orgs  int // ... by the organizations' budgets
	per   map[string]int
}

// enter takes a place for a page of budget (super: a super admin's), and the function that gives it back; ok is
// false when there is none.
func (g *auditGate) enter(budget string, super bool) (leave func(), ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.total >= web.AuditReadsInFlight || g.per[budget] >= web.AuditReadsInFlightPerBudget ||
		(!super && g.orgs >= web.AuditReadsInFlight-web.AuditReadsInFlightSuper) {
		return nil, false
	}
	if g.per == nil {
		g.per = map[string]int{}
	}
	g.total++
	g.per[budget]++
	if !super {
		g.orgs++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.total--
			if !super {
				g.orgs--
			}
			if g.per[budget]--; g.per[budget] == 0 {
				delete(g.per, budget)
			}
		})
	}, true
}

// auditBudget admits an audit page read by a against budget (auditBudgetOf), or writes the refusal: a 429 while the
// node already reads as many pages as it may at once, of that budget or in all (Retry-After: 2), or once the pages
// for the minute are spent, the reader's own allowance of an organization's budget (web.AuditReadsPerMinuteActor) or
// the budget (web.AuditReadsPerMinute; Retry-After: 60), and a 503 when the count cannot be read. The place is taken
// before the page is counted: a page refused for want of one spends nothing, so a client that retries while the
// node is busy (the console does, every Retry-After) does not spend its organization's minute on refusals. Call it
// only for a reader ListAudit will let read the log, so that nobody else can spend an organization's budget. The
// caller runs leave once the page is read.
func (m *Module) auditBudget(w http.ResponseWriter, r *http.Request, a *service.Actor, budget string) (leave func(), ok bool) {
	if leave, ok = m.audits.enter(budget, a.IsSuper()); !ok {
		w.Header().Set("Retry-After", "2")
		web.WriteJSON(w, http.StatusTooManyRequests, web.ErrorBody{Error: "Too many audit log searches are running at " +
			"once. Try again in a moment."})
		return nil, false
	}
	// The count is bounded as the read is (web.AuditReadTimeout): in a gossip cluster it is a round trip to the
	// counter's owner, and a place must not be held for as long as that takes when the owner does not answer.
	ctx, cancel := context.WithTimeout(r.Context(), web.AuditReadTimeout)
	verdict, err := m.s.AuditReadAllowed(ctx, budget, auditReader(a))
	cancel()
	if err == nil && verdict == web.AuditReadOK {
		return leave, true
	}
	leave()
	switch {
	case err != nil:
		web.WriteError(w, fmt.Errorf("%w: %v", service.ErrUnavailable, err))
	case verdict == web.AuditReadActorSpent:
		w.Header().Set("Retry-After", "60")
		web.WriteJSON(w, http.StatusTooManyRequests, web.ErrorBody{Error: "You searched the audit log " +
			strconv.Itoa(web.AuditReadsPerMinuteActor) + " times in the last minute. Wait a minute and try again."})
	default:
		w.Header().Set("Retry-After", "60")
		web.WriteJSON(w, http.StatusTooManyRequests, web.ErrorBody{Error: "The audit log was searched " +
			strconv.Itoa(web.AuditReadsPerMinute) + " times in the last minute. Wait a minute and try again."})
	}
	return nil, false
}

// auditReader names a among the readers who share an organization's budget (web.AuditReadAllowed): the user, through
// the console or any token of theirs, or the service account; "" for a super admin, whose budget is their own.
func auditReader(a *service.Actor) string {
	switch {
	case a.IsSuper():
		return ""
	case a.UserID != "":
		return "user|" + a.UserID
	}
	return "client|" + a.ClientID
}

// readAudit reads an audit page as ListAudit does, within web.AuditReadTimeout whichever log it is read from, or
// writes the error: a page that takes longer is given up with a 503 (Retry-After), so that the place it holds
// (auditBudget) is held for so long at most (the database trail ends its read when the database notices the
// deadline).
func (m *Module) readAudit(w http.ResponseWriter, r *http.Request, a *service.Actor, orgID string, aq service.AuditQuery) (service.AuditPage, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), web.AuditReadTimeout)
	defer cancel()
	p, err := m.s.Svc.ListAudit(ctx, a, orgID, aq)
	switch {
	case err == nil:
		return p, true
	case ctx.Err() != nil && r.Context().Err() == nil: // the deadline, not the client going away
		w.Header().Set("Retry-After", "5")
		web.WriteJSON(w, http.StatusServiceUnavailable, web.ErrorBody{Error: "The audit log took too long to answer. " +
			"Try a shorter time range or a narrower search."})
	default:
		web.WriteError(w, err)
	}
	return p, false
}

// auditBudgetOf is the budget an audit page of organization orgID ("" for every organization) read by a counts
// against: a super admin's own, or the organization's; "" when a may not read it (ListAudit refuses it, uncounted).
func (m *Module) auditBudgetOf(a *service.Actor, orgID string) string {
	switch {
	case a != nil && a.IsSuper():
		return web.AuditBudgetSuper(a.UserID)
	case a != nil && orgID != "" && m.s.Svc.CanAdminOrg(a, orgID):
		return web.AuditBudgetOrg(orgID)
	}
	return ""
}

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
	if budget := m.auditBudgetOf(a, org.ID); budget != "" {
		leave, ok := m.auditBudget(w, r, a, budget)
		if !ok {
			return
		}
		defer leave()
	}
	p, ok := m.readAudit(w, r, a, org.ID, aq)
	if !ok {
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
	leave, ok := m.auditBudget(w, r, a, m.auditBudgetOf(a, orgID)) // a super admin: their own budget
	if !ok {
		return
	}
	defer leave()
	p, ok := m.readAudit(w, r, a, orgID, aq)
	if !ok {
		return
	}
	m.writeAudit(w, r, p, true)
}
