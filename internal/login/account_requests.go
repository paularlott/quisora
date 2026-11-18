package login

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// The account pages for access requests (docs/ACCESS-REQUESTS.md): Request access, for the members of groups
// whose members may ask, and Approvals, for the members of approver groups. Both are reached from the account menu,
// which shows each only to whom it concerns.

func (m *Module) registerAccessRequests(h func(string, func(http.ResponseWriter, *http.Request, acct))) {
	h("GET /api-internal/account/access-requests", m.ownRequests)
	h("GET /api-internal/account/access-requests/options", m.requestChoices)
	h("GET /api-internal/account/access-requests/tenants", m.requestableTenants)
	h("POST /api-internal/account/access-requests", m.askAccess)
	h("POST /api-internal/account/access-requests/{id}/cancel", m.cancelOwnRequest)
	h("POST /api-internal/account/access-requests/{id}/end", m.endOwnAccess)
	h("GET /api-internal/account/approvals/pending", m.approvalsWaiting)
	h("GET /api-internal/account/approvals/decisions", m.approvalsDecided)
	h("POST /api-internal/account/approvals/{id}/approve", m.decide(true))
	h("POST /api-internal/account/approvals/{id}/deny", m.decide(false))
	h("POST /api-internal/account/approvals/{id}/end", m.endApproved)
}

// requestsPage handles GET /o/{org}/account/requests.
func (m *Module) requestsPage(w http.ResponseWriter, r *http.Request) {
	m.s.Render.Render(w, http.StatusOK, "account-requests", m.s.Page(w, r, "Request access", "requests", nil))
}

// approvalsPage handles GET /o/{org}/account/approvals.
func (m *Module) approvalsPage(w http.ResponseWriter, r *http.Request) {
	m.s.Render.Render(w, http.StatusOK, "account-approvals", m.s.Page(w, r, "Approvals", "approvals", nil))
}

// requestError answers err of an access request call: a field error, a refusal, or a server error.
func (m *Module) requestError(w http.ResponseWriter, r *http.Request, err error) {
	var fe *service.FieldError
	switch {
	case errors.As(err, &fe):
		writeErr(w, http.StatusUnprocessableEntity, fe.Msg, fe.Field)
	case errors.Is(err, service.ErrForbidden):
		writeErr(w, http.StatusForbidden, "You cannot do this.", "")
	case errors.Is(err, service.ErrNotFound):
		writeErr(w, http.StatusNotFound, "There is no such request.", "")
	case errors.Is(err, service.ErrStale):
		writeErr(w, http.StatusConflict, "Someone else changed this request just now: look again.", "")
	default:
		web.WriteError(w, err)
	}
}

// pageOf reads a list call's ?offset= and ?limit= (at most 100).
func pageOf(r *http.Request) store.ListQuery {
	q := store.ListQuery{Limit: 10}
	if n, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && n > 0 {
		q.Offset = n
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		q.Limit = min(n, 100)
	}
	return q
}

// requestList answers a page of requests: {"items": [...], "total": n}.
func (m *Module) requestList(w http.ResponseWriter, r *http.Request, l []*model.AccessRequest, n int, mark func(*service.AccessRequestView)) {
	views := m.s.Svc.AccessRequestViews(r.Context(), l)
	if mark != nil {
		for i := range views {
			mark(&views[i])
		}
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": views, "total": n})
}

// requestChoices answers GET /api-internal/account/access-requests/options: who may approve the person's requests
// (with the lengths each offers), and whether they are a guest (who asks in their own organization).
func (m *Module) requestChoices(w http.ResponseWriter, r *http.Request, a acct) {
	approvers, err := m.s.Svc.RequestApproversFor(r.Context(), a.u)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	if approvers == nil {
		approvers = []service.RequestApprovers{}
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"approvers": approvers, "guest": len(a.actor.Sources) > 0})
}

// ownRequests answers GET /api-internal/account/access-requests: a page of the person's requests, newest first.
func (m *Module) ownRequests(w http.ResponseWriter, r *http.Request, a acct) {
	l, n, err := m.s.Svc.OwnAccessRequests(r.Context(), a.actor, pageOf(r))
	if errors.Is(err, service.ErrForbidden) || err != nil && len(a.actor.Sources) > 0 {
		l, n, err = nil, 0, nil // a guest asks nothing here
	}
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	m.requestList(w, r, l, n, nil)
}

// requestableTenants answers GET /api-internal/account/access-requests/tenants?q=.
func (m *Module) requestableTenants(w http.ResponseWriter, r *http.Request, a acct) {
	l, err := m.s.Svc.RequestableTenants(r.Context(), a.actor, r.URL.Query().Get("q"), 8)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": l})
}

// askAccess answers POST /api-internal/account/access-requests.
func (m *Module) askAccess(w http.ResponseWriter, r *http.Request, a acct) {
	var in service.AccessRequestInput
	if !decode(w, r, &in) {
		return
	}
	req, err := m.s.Svc.CreateAccessRequest(r.Context(), a.actor, in)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
}

// cancelOwnRequest answers POST /api-internal/account/access-requests/{id}/cancel.
func (m *Module) cancelOwnRequest(w http.ResponseWriter, r *http.Request, a acct) {
	req, err := m.s.Svc.CancelAccessRequest(r.Context(), a.actor, r.PathValue("id"))
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
}

// endOwnAccess answers POST /api-internal/account/access-requests/{id}/end: the person ending the access their own
// request gave.
func (m *Module) endOwnAccess(w http.ResponseWriter, r *http.Request, a acct) {
	req, err := m.s.Svc.Requests.Get(r.Context(), r.PathValue("id"))
	if err != nil || req.UserID != a.u.ID {
		writeErr(w, http.StatusNotFound, "There is no such request.", "")
		return
	}
	req, err = m.s.Svc.EndAccessRequest(r.Context(), a.actor, req.ID, false)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
}

// approvalsWaiting answers GET /api-internal/account/approvals/pending: a page of the requests waiting for the
// person's approver groups, oldest first; their own among them is marked (someone else decides it).
func (m *Module) approvalsWaiting(w http.ResponseWriter, r *http.Request, a acct) {
	l, n, err := m.s.Svc.ApprovalQueue(r.Context(), a.actor, pageOf(r))
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	m.requestList(w, r, l, n, func(v *service.AccessRequestView) { v.Yours = v.UserID == a.u.ID })
}

// approvalsDecided answers GET /api-internal/account/approvals/decisions?show=&q=: a page of the decisions of the
// person's approver groups, newest first: show active (the default: access that runs), ended, denied or all; q finds
// those whose requester's name or email, tenant or reason starts with it.
func (m *Module) approvalsDecided(w http.ResponseWriter, r *http.Request, a acct) {
	q := pageOf(r)
	q.Search = r.URL.Query().Get("q")
	l, n, err := m.s.Svc.GroupDecisions(r.Context(), a.actor, r.URL.Query().Get("show"), q)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	m.requestList(w, r, l, n, func(v *service.AccessRequestView) { v.Yours = v.UserID == a.u.ID })
}

// decide answers POST /api-internal/account/approvals/{id}/approve and …/deny, with an optional {"note": "..."}:
// after the person confirmed it is them (needReauth).
func (m *Module) decide(approve bool) func(http.ResponseWriter, *http.Request, acct) {
	return func(w http.ResponseWriter, r *http.Request, a acct) {
		var in struct {
			Note string `json:"note"`
		}
		if !decode(w, r, &in) {
			return
		}
		if !m.needReauth(w, r, a) {
			return
		}
		req, err := m.s.Svc.DecideAccessRequest(r.Context(), a.actor, r.PathValue("id"), approve, in.Note, true)
		if err != nil {
			m.requestError(w, r, err)
			return
		}
		web.WriteJSON(w, http.StatusOK, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
	}
}

// endApproved answers POST /api-internal/account/approvals/{id}/end: an approver ending access early, after
// confirming it is them.
func (m *Module) endApproved(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.needReauth(w, r, a) {
		return
	}
	req, err := m.s.Svc.EndAccessRequest(r.Context(), a.actor, r.PathValue("id"), true)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
}
