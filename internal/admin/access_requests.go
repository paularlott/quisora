package admin

import (
	"errors"
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// Access requests through the management API (docs/design/access-requests.md): a person's own requests with a
// personal API token holding access_requests; deciding with a service account holding access_requests:approve; and
// every request of the organization for its administrators.

func writeRequestError(w http.ResponseWriter, err error) {
	if errors.Is(err, service.ErrReauth) {
		web.WriteReauth(w)
		return
	}
	web.WriteError(w, err)
}

// listAllRequests answers GET /api/orgs/{org}/access-requests/all: every request of the organization, newest first,
// for its administrators (?state= narrows it).
func (m *Module) listAllRequests(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	l, n, err := m.s.Svc.AccessRequestsOf(r.Context(), a, org.ID, r.URL.Query().Get("state"), listQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	writeList(w, m.s.Svc.AccessRequestViews(r.Context(), l), n)
}

// listOwnRequests answers GET /api/orgs/{org}/access-requests: a page of the caller's own requests, newest first.
func (m *Module) listOwnRequests(w http.ResponseWriter, r *http.Request) {
	_, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	ctx := r.Context()
	l, n, err := m.s.Svc.OwnAccessRequests(ctx, a, listQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	writeList(w, m.s.Svc.AccessRequestViews(ctx, l), n)
}

// createRequest answers POST /api/orgs/{org}/access-requests.
func (m *Module) createRequest(w http.ResponseWriter, r *http.Request) {
	_, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.AccessRequestInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	req, err := m.s.Svc.CreateAccessRequest(r.Context(), a, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
}

// requestOptions answers GET /api/orgs/{org}/access-requests/options: who may approve the caller's requests (with
// the lengths each offers), and the tenants matching ?q= they may ask for.
func (m *Module) requestOptions(w http.ResponseWriter, r *http.Request) {
	_, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	ctx := r.Context()
	u, err := m.s.Svc.Users.Get(ctx, a.UserID)
	if err != nil || a.ClientID != "" {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	approvers, err := m.s.Svc.RequestApproversFor(ctx, u)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	tenants, err := m.s.Svc.RequestableTenants(ctx, a, r.URL.Query().Get("q"), 20)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if approvers == nil {
		approvers = []service.RequestApprovers{}
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"approvers": approvers, "tenants": tenants})
}

// pendingRequests answers GET /api/orgs/{org}/access-requests/pending: a page of the requests the caller may decide,
// oldest first.
func (m *Module) pendingRequests(w http.ResponseWriter, r *http.Request) {
	_, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	l, n, err := m.s.Svc.ApprovalQueue(r.Context(), a, listQuery(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	views := m.s.Svc.AccessRequestViews(r.Context(), l)
	for i := range views {
		views[i].Yours = a.ClientID == "" && views[i].UserID == a.UserID
	}
	writeList(w, views, n)
}

// decideRequest answers POST /api/orgs/{org}/access-requests/{id}/approve and …/deny, with an optional
// {"note": "..."}.
func (m *Module) decideRequest(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, a, found := m.orgFor(w, r)
		if !found {
			return
		}
		var in struct {
			Note string `json:"note"`
		}
		if r.ContentLength != 0 && !web.DecodeJSON(w, r, &in) {
			return
		}
		req, err := m.s.Svc.DecideAccessRequest(r.Context(), a, r.PathValue("id"), approve, in.Note, m.s.Reauthed(r))
		if err != nil {
			writeRequestError(w, err)
			return
		}
		web.WriteJSON(w, http.StatusOK, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
	}
}

// cancelRequest answers POST /api/orgs/{org}/access-requests/{id}/cancel.
func (m *Module) cancelRequest(w http.ResponseWriter, r *http.Request) {
	_, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	req, err := m.s.Svc.CancelAccessRequest(r.Context(), a, r.PathValue("id"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
}

// endRequest answers POST /api/orgs/{org}/access-requests/{id}/end.
func (m *Module) endRequest(w http.ResponseWriter, r *http.Request) {
	_, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	req, err := m.s.Svc.EndAccessRequest(r.Context(), a, r.PathValue("id"), m.s.Reauthed(r))
	if err != nil {
		writeRequestError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.s.Svc.AccessRequestViews(r.Context(), []*model.AccessRequest{req})[0])
}
