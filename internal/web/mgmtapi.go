package web

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Management API versioning: callers send "Api-Version: <date>"; responses echo the version served. A version is
// the date (YYYY-MM-DD) of the release that introduced it; a new one is added only for a change that would break
// existing callers. A request without the header gets the oldest supported version, so integrations written against
// it never break silently.
const (
	APIVersionHeader = "Api-Version"
	APIVersionLatest = "2026-10-20"
)

// APIVersions lists the supported versions, oldest first (tested: dates, in order, ending with APIVersionLatest).
// web/src/js/lib/api.js and web/openapi/openapi.yaml name them too (tested).
var APIVersions = []string{APIVersionLatest}

// APIVersion returns the version negotiated for the request (set by RequireManagement).
func APIVersion(r *http.Request) string {
	if v, _ := r.Context().Value(ctxAPIVersion).(string); v != "" {
		return v
	}
	return APIVersions[0]
}

const ctxAPIVersion ctxKey = 100

// BearerFunc resolves a bearer token to an actor. The app sets Server.Bearer to accept personal API tokens and
// OAuth access tokens.
type BearerFunc func(ctx context.Context, r *http.Request, token string) (*service.Actor, error)

// RequireManagement guards the management API (/api/...): either a browser session (with the CSRF header on
// unsafe methods) or "Authorization: Bearer <token>" whose actor holds the admin scope. It also negotiates the API
// version. Handlers must use Actor(r) — User(r) is nil for bearer requests.
func (s *Server) RequireManagement(next http.HandlerFunc) http.Handler {
	return s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get(APIVersionHeader)
		if v == "" {
			v = APIVersions[0]
		}
		if !slices.Contains(APIVersions, v) {
			w.Header().Set(APIVersionHeader, APIVersionLatest)
			WriteJSON(w, http.StatusBadRequest, ErrorBody{Error: "Unsupported Api-Version " + v + "; supported: " +
				strings.Join(APIVersions, ", ") + "."})
			return
		}
		w.Header().Set(APIVersionHeader, v)
		r = r.WithContext(context.WithValue(r.Context(), ctxAPIVersion, v))

		if tok, ok := BearerToken(r); ok {
			if s.Bearer == nil {
				WriteJSON(w, http.StatusUnauthorized, ErrorBody{Error: "Bearer tokens are not accepted."})
				return
			}
			a, err := s.Bearer(r.Context(), r, tok)
			if err != nil || a == nil {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				WriteJSON(w, http.StatusUnauthorized, ErrorBody{Error: "The access token is invalid or has expired."})
				return
			}
			// The backup download takes its own scope (and only that one does: admin is not enough for it).
			backup := r.URL.Path == "/api/backup"
			if backup && !a.HasScope(service.ScopeBackup) || !backup && !a.HasScope(service.ScopeAdmin) {
				scope := service.ScopeAdmin
				if backup {
					scope = service.ScopeBackup
				}
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
				WriteJSON(w, http.StatusForbidden, ErrorBody{Error: "The token does not have the " + scope + " scope."})
				return
			}
			next(w, WithActor(r, a))
			return
		}
		if User(r) == nil {
			WriteJSON(w, http.StatusUnauthorized, ErrorBody{Error: "Your session has ended. Please sign in again."})
			return
		}
		if !s.CheckCSRF(r, Session(r).CSRF) {
			WriteJSON(w, http.StatusForbidden, ErrorBody{Error: "The request could not be verified. Reload the page."})
			return
		}
		if !ConsoleMFA(r) {
			WriteJSON(w, http.StatusForbidden, ErrorBody{Error: MsgConsoleMFA, Field: "mfa"})
			return
		}
		next(w, r)
	}))
}

// BearerToken returns the credentials of an "Authorization: Bearer <token>" header. The scheme name is matched
// case-insensitively (RFC 9110 §11.1); ok is false when the header uses another scheme or is absent.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	return strings.TrimSpace(h[7:]), true
}

// MsgConsoleMFA explains why a console session without a second factor is refused.
const MsgConsoleMFA = "Administration needs a sign-in with a second factor. Set up an Authenticator App or a passkey on your account page, then sign out and sign in again with it."

// ConsoleMFA reports whether r's session may use the administration console: managers and administrators (the only
// ones who can) need a sign-in that used a second factor, whatever their organization requires (an administrator
// could switch that off, then sign in as someone else through a provider).
func ConsoleMFA(r *http.Request) bool {
	sess, u := Session(r), User(r)
	if sess == nil || u == nil || !u.Role.Privileged() {
		return true
	}
	return model.MFA(sess.AMR)
}
