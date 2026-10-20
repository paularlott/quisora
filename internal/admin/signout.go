package admin

import (
	"context"
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// signOutRequest is the body of an emergency sign-out.
type signOutRequest struct {
	Reason    string `json:"reason"`
	APITokens bool   `json:"api_tokens"`
}

// signOutOrg handles POST /api/orgs/{org}/sign-out: ends every session and refresh grant of the organization at once
// (and its personal API tokens with api_tokens), except the caller's own session. Its administrators and super
// admins, after a recent re-authentication in the console.
func (m *Module) signOutOrg(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	m.pullSignOut(w, r, func(opt service.SignOutOptions) (*model.SignOutEvent, error) {
		return m.s.Svc.SignOutOrg(r.Context(), a, org.ID, opt)
	}, a, org.ID)
}

// signOutServer handles POST /api/sign-out: the same for every organization. Super admins only.
func (m *Module) signOutServer(w http.ResponseWriter, r *http.Request) {
	a := web.Actor(r)
	if !a.IsSuper() {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	m.pullSignOut(w, r, func(opt service.SignOutOptions) (*model.SignOutEvent, error) {
		return m.s.Svc.SignOutServer(r.Context(), a, opt)
	}, a, "")
}

func (m *Module) pullSignOut(w http.ResponseWriter, r *http.Request, pull func(service.SignOutOptions) (*model.SignOutEvent, error),
	a *service.Actor, sweepOrg string) {
	var in signOutRequest
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if !m.stepUp(w, r) {
		return
	}
	ev, err := pull(service.SignOutOptions{Reason: in.Reason, APITokens: in.APITokens, KeepSession: web.Session(r).ID})
	if err != nil {
		web.WriteError(w, err)
		return
	}
	// Everything stamped before has stopped working already; deleting it and telling applications can take a while.
	m.s.Svc.Background(r.Context(), func(ctx context.Context) {
		_, _ = m.s.Svc.SweepSignOut(ctx, a, sweepOrg, in.APITokens)
	})
	web.WriteJSON(w, http.StatusOK, ev)
}
