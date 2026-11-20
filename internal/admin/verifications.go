package admin

import (
	"net/http"
	"slices"
	"strings"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// Caller verification through the management API (docs/CALLER-VERIFICATION.md): a CRM or helpdesk verifies a caller
// as the agent on the call, never as itself: the customer is shown the agent's own name. It calls with the agent's
// personal API token (scope call_verify), or with the access token the agent's sign-in through Quisora gave it for the
// organization's caller verification API (its resource: config.Config.OrgVerifyAPI). Service accounts cannot.

// verifyRoutes are the caller verification operations: a personal API token may call them with call_verify.
var verifyRoutes = []string{"GET /verifications", "POST /verifications", "GET /verifications/orgs", "GET /verifications/users",
	"GET /verifications/{id}", "POST /verifications/{id}/cancel"}

func init() {
	for _, p := range verifyRoutes {
		method, path, _ := strings.Cut(p, " ")
		tokenScopes[method+" /api/orgs/{org}"+path] = service.ScopeCallVerify
	}
}

// isVerifyRoute reports whether pattern (method and path) is one of verifyRoutes.
func isVerifyRoute(pattern string) bool {
	method, path, _ := strings.Cut(pattern, " ")
	return slices.Contains(verifyRoutes, method+" "+strings.TrimPrefix(path, "/api/orgs/{org}"))
}

// verifyAuth lets a caller verification route (its handler h) take an agent's access token issued for the
// organization's caller verification API (an application they signed in to through Quisora): checked for that address,
// its user still active and still allowed the application, the request runs as that user acting through the
// application. Any other credential goes to next (the management API's own check of the route: a session, or a
// personal API token with call_verify).
func (m *Module) verifyAuth(h http.HandlerFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := web.BearerToken(r)
		if !ok || service.IsAPIToken(tok) || m.ResourceToken == nil {
			next.ServeHTTP(w, r)
			return
		}
		org, err := m.s.Svc.OrgByRef(r.Context(), r.PathValue("org"))
		if err != nil {
			next.ServeHTTP(w, r) // answered as any unknown organization is
			return
		}
		a, err := m.ResourceToken(r, tok, m.s.Cfg.OrgVerifyAPI(org.ID))
		if err != nil || a == nil {
			next.ServeHTTP(w, r) // not one: a service account's token (refused there) or a bad one
			return
		}
		v := r.Header.Get(web.APIVersionHeader)
		if v == "" {
			v = web.APIVersions[0]
		}
		if !slices.Contains(web.APIVersions, v) {
			w.Header().Set(web.APIVersionHeader, web.APIVersionLatest)
			web.WriteJSON(w, http.StatusBadRequest, web.ErrorBody{Error: "Unsupported Api-Version " + v + "."})
			return
		}
		w.Header().Set(web.APIVersionHeader, v)
		h(w, web.WithActor(r, a))
	})
}

// listVerifications answers GET /api/orgs/{org}/verifications: the agent's verifications of today and yesterday,
// newest first.
func (m *Module) listVerifications(w http.ResponseWriter, r *http.Request) {
	if _, a, found := m.orgFor(w, r); found {
		l, err := m.s.Svc.AgentVerifications(r.Context(), a)
		if err != nil {
			web.WriteError(w, err)
			return
		}
		if l == nil {
			l = []*service.CallVerificationView{}
		}
		writeList(w, l, len(l))
	}
}

// verifyOrgsAPI answers GET /api/orgs/{org}/verifications/orgs?q=: the organizations the agent may verify the people
// of.
func (m *Module) verifyOrgsAPI(w http.ResponseWriter, r *http.Request) {
	if _, a, found := m.orgFor(w, r); found {
		l, err := m.s.Svc.VerifyOrgs(r.Context(), a, r.URL.Query().Get("q"), 20)
		if err != nil {
			web.WriteError(w, err)
			return
		}
		writeList(w, l, len(l))
	}
}

// verifyUsersAPI answers GET /api/orgs/{org}/verifications/users?org=&q=: the people of an organization the agent
// may verify whose name, family name, username or email starts with q.
func (m *Module) verifyUsersAPI(w http.ResponseWriter, r *http.Request) {
	if _, a, found := m.orgFor(w, r); found {
		l, err := m.s.Svc.VerifyUsers(r.Context(), a, r.URL.Query().Get("org"), r.URL.Query().Get("q"), 20)
		if err != nil {
			web.WriteError(w, err)
			return
		}
		writeList(w, l, len(l))
	}
}

// startVerificationAPI answers POST /api/orgs/{org}/verifications {org, user_id, direction, reason}: the
// verification and its code, this once.
func (m *Module) startVerificationAPI(w http.ResponseWriter, r *http.Request) {
	_, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	var in service.VerifyCallInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if a.UserID != "" {
		if ok, err := m.s.VerifyStartAllowed(r.Context(), a.UserID); err != nil {
			web.WriteError(w, service.ErrUnavailable)
			return
		} else if !ok {
			web.WriteJSON(w, http.StatusTooManyRequests, web.ErrorBody{Error: "Too many verifications started in the last hour: wait a while."})
			return
		}
	}
	v, code, err := m.s.Svc.StartCallVerification(r.Context(), a, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, map[string]any{"verification": v, "code": code})
}

// getVerificationAPI answers GET /api/orgs/{org}/verifications/{id}: how it stands (a CRM asks while it waits).
func (m *Module) getVerificationAPI(w http.ResponseWriter, r *http.Request) {
	if _, a, found := m.orgFor(w, r); found {
		v, err := m.s.Svc.AgentVerification(r.Context(), a, r.PathValue("id"))
		if err != nil {
			web.WriteError(w, err)
			return
		}
		web.WriteJSON(w, http.StatusOK, v)
	}
}

// cancelVerificationAPI answers POST /api/orgs/{org}/verifications/{id}/cancel.
func (m *Module) cancelVerificationAPI(w http.ResponseWriter, r *http.Request) {
	if _, a, found := m.orgFor(w, r); found {
		v, err := m.s.Svc.CancelCallVerification(r.Context(), a, r.PathValue("id"))
		if err != nil {
			web.WriteError(w, err)
			return
		}
		web.WriteJSON(w, http.StatusOK, v)
	}
}
