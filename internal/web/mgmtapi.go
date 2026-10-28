package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

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

// BearerFailuresPerIPMin bounds failed bearer-token authentications (management API and SCIM together) per IP
// address and minute. Tokens cannot be guessed, but every attempt costs store reads: past the limit every bearer
// request from the address is refused (429) for the rest of the minute, before its token is looked at, the right
// one too. Only a failure counts, so a busy integration with a valid token is never slowed. Behind a proxy set
// server.trust_proxy, or every caller shares the proxy's address.
const BearerFailuresPerIPMin = 60

const nsBearer = "web.bearer" // failed bearer authentications per IP address

// BearerLimited reports whether r's address has used up its failed bearer authentications for this minute. A counter
// that cannot be read is an error, not "limited": the caller refuses the request (fail closed) but answers
// "unavailable", since no limit was reached.
func (s *Server) BearerLimited(r *http.Request) (bool, error) {
	if s.Eph == nil {
		return false, nil
	}
	n, err := s.Eph.Incr(r.Context(), nsBearer, RateKeyIP(r), 0, time.Minute)
	return n >= BearerFailuresPerIPMin, err
}

// BearerFailed counts a failed bearer authentication from r's address.
func (s *Server) BearerFailed(r *http.Request) {
	if s.Eph == nil {
		return
	}
	n, err := s.Eph.Incr(r.Context(), nsBearer, RateKeyIP(r), 1, time.Minute)
	if err == nil && n == BearerFailuresPerIPMin && s.Log != nil {
		s.Log.Warn("too many failed bearer-token authentications: refusing the address for a minute", "ip", ClientIP(r),
			"failures_per_minute", BearerFailuresPerIPMin)
	}
}

// WriteBearerLimited answers a bearer request refused by BearerLimited.
func WriteBearerLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(60))
	WriteJSON(w, http.StatusTooManyRequests, ErrorBody{Error: "Too many failed authentications from this address; try again in a minute."})
}

// auditRefused records a management API request refused for an authenticated actor (a token without the scope, a
// request without the CSRF header, a console session without a second factor): the attempt is an access-control
// event (SOC 2 CC6.1). Requests nobody can be named for (no session, an unknown token) are counted, not audited.
func (s *Server) auditRefused(r *http.Request, a *service.Actor, reason string) {
	if s.Svc == nil || a == nil {
		return
	}
	s.Svc.AuditRefused(r.Context(), a, r.Method, r.URL.Path, reason)
}

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

		if tok, ok := BearerToken(r); ok {
			if s.Bearer == nil {
				WriteJSON(w, http.StatusUnauthorized, ErrorBody{Error: "Bearer tokens are not accepted."})
				return
			}
			limited, err := s.BearerLimited(r)
			if err != nil {
				w.Header().Set("Retry-After", "5")
				WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "The token could not be checked right now; try again shortly."})
				return
			}
			if limited {
				WriteBearerLimited(w)
				return
			}
			a, err := s.Bearer(r.Context(), r, tok)
			if errors.Is(err, service.ErrUnavailable) { // the store failed, not the caller: not counted
				WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "The token could not be checked right now; try again shortly."})
				return
			}
			if err != nil || a == nil {
				s.BearerFailed(r)
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
				s.auditRefused(r, a, "the token does not have the "+scope+" scope")
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
				WriteJSON(w, http.StatusForbidden, ErrorBody{Error: "The token does not have the " + scope + " scope."})
				return
			}
			s.auditDenied(w, WithActor(r, a), a, next)
			return
		}
		if SessionUnchecked(r) {
			WriteUnchecked(w)
			return
		}
		if User(r) == nil {
			WriteJSON(w, http.StatusUnauthorized, ErrorBody{Error: "Your session has ended. Please sign in again."})
			return
		}
		if !s.CheckCSRF(r, Session(r).CSRF) {
			s.auditRefused(r, service.ActorForUser(User(r), ClientIP(r)), "missing or wrong CSRF header")
			WriteJSON(w, http.StatusForbidden, ErrorBody{Error: "The request could not be verified. Reload the page."})
			return
		}
		if !ConsoleMFA(r) {
			s.auditRefused(r, service.ActorForUser(User(r), ClientIP(r)), "console session without a second factor")
			WriteJSON(w, http.StatusForbidden, ErrorBody{Error: MsgConsoleMFA, Field: "mfa"})
			return
		}
		s.auditDenied(w, r, service.ActorForUser(User(r), ClientIP(r)), next)
	}))
}

// auditDenied runs next, and records the request as refused when next refused it for want of permission
// (WriteError with service.ErrForbidden): an access-control event, like the refusals RequireManagement makes itself.
func (s *Server) auditDenied(w http.ResponseWriter, r *http.Request, a *service.Actor, next http.HandlerFunc) {
	dw := &deniedWriter{ResponseWriter: w}
	next(dw, r)
	if dw.denied {
		s.auditRefused(r, a, "not permitted")
	}
}

// deniedWriter notes that a handler answered "not permitted" (noteDenied).
type deniedWriter struct {
	http.ResponseWriter
	denied bool
}

func (w *deniedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *deniedWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// noteDenied marks the deniedWriter w is, or wraps, if any.
func noteDenied(w http.ResponseWriter) {
	for w != nil {
		if d, ok := w.(*deniedWriter); ok {
			d.denied = true
			return
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
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
