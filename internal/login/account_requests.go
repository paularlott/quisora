package login

import (
	"errors"
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// The account pages for access requests (docs/design/access-requests.md): Request access, for the members of groups
// whose members may ask, and Approvals, for the members of approver groups. Both are reached from the account menu,
// which shows each only to whom it concerns.

func (m *Module) registerAccessRequests(h func(string, func(http.ResponseWriter, *http.Request, acct))) {
	h("GET /api-internal/account/access-requests", m.ownRequests)
	h("GET /api-internal/account/access-requests/tenants", m.requestableTenants)
	h("POST /api-internal/account/access-requests", m.askAccess)
	h("POST /api-internal/account/access-requests/{id}/cancel", m.cancelOwnRequest)
	h("POST /api-internal/account/access-requests/{id}/end", m.endOwnAccess)
	h("GET /api-internal/account/approvals", m.approvals)
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

// ownRequests answers GET /api-internal/account/access-requests: the person's requests, and who may approve them
// (with the lengths each offers).
func (m *Module) ownRequests(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	approvers, err := m.s.Svc.RequestApproversFor(ctx, a.u)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	l, err := m.s.Svc.OwnAccessRequests(ctx, a.actor)
	if err != nil && !errors.Is(err, service.ErrForbidden) {
		m.requestError(w, r, err)
		return
	}
	if approvers == nil {
		approvers = []service.RequestApprovers{}
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"approvers": approvers, "items": m.s.Svc.AccessRequestViews(ctx, l),
		"guest": len(a.actor.Sources) > 0})
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

// approvals answers GET /api-internal/account/approvals: the requests waiting for the person's decision, and the
// access their approver groups gave that still lasts.
func (m *Module) approvals(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	pending, err := m.s.Svc.ApprovalQueue(ctx, a.actor)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	active, err := m.s.Svc.ApprovedByGroups(ctx, a.actor)
	if err != nil {
		m.requestError(w, r, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"pending": m.s.Svc.AccessRequestViews(ctx, pending),
		"active": m.s.Svc.AccessRequestViews(ctx, active)})
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
