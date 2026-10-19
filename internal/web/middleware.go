package web

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"sync/atomic"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxUser
	ctxActor
)

// trustedProxies are the networks whose X-Forwarded-For is honoured (set once at start-up).
var trustedProxies []netip.Prefix

// SetTrustedProxies configures which peers may set X-Forwarded-For (CIDRs or single IPs).
func SetTrustedProxies(list []string) {
	trustedProxies = nil
	for _, s := range list {
		if p, err := config.ParseProxy(s); err == nil { // config.Validate reports the bad ones
			trustedProxies = append(trustedProxies, p)
		}
	}
}

// ClientIP returns the caller's address, honouring X-Forwarded-For only from trusted proxies.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if !trusted(addr) {
		return addr.String()
	}
	// Walk X-Forwarded-For from the right, skipping our own proxies: the first untrusted hop is the client.
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		addr = hop
		if !trusted(hop) {
			break
		}
	}
	return addr.String()
}

func trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range trustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// contentSecurityPolicy forbids inline scripts and eval; Alpine runs as its CSP build.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; " +
	"font-src 'self'; connect-src 'self'; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'; " +
	"object-src 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Shared, read-only value slices (len == cap, so a later Add copies rather than writing into them): no
		// allocation per response for headers that never change.
		for _, sh := range staticSecurityHeaders {
			h[sh.key] = sh.val
		}
		if _, ok := h["Content-Security-Policy"]; !ok {
			h["Content-Security-Policy"] = cspValue
		}
		next.ServeHTTP(w, r)
	})
}

type staticHeader struct {
	key string
	val []string
}

// one returns a read-only header value slice (cap 1).
func one(v string) []string { return []string{v}[:1:1] }

var (
	staticSecurityHeaders = []staticHeader{
		{"Strict-Transport-Security", one("max-age=63072000; includeSubDomains")},
		{"X-Content-Type-Options", one("nosniff")},
		{"Referrer-Policy", one("strict-origin-when-cross-origin")},
		{"X-Frame-Options", one("DENY")},
		{"Cross-Origin-Opener-Policy", one("same-origin")},
		{"Permissions-Policy", one("camera=(), microphone=(), geolocation=(), interest-cohort=()")},
	}
	cspValue = one(contentSecurityPolicy)
)

func recoverer(log logger.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Error("panic", "path", r.URL.Path, "error", v, "stack", string(debug.Stack()))
				WriteJSON(w, http.StatusInternalServerError, ErrorBody{Error: "Something went wrong."})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// shed rejects requests with 503 once max are in flight on this node.
func shed(max int, next http.Handler) http.Handler {
	if max <= 0 {
		return next
	}
	// An atomic counter rather than a channel semaphore: every request passes here, and a channel's lock taken
	// twice per request by every core is itself a bottleneck under load.
	var inFlight atomic.Int64
	limit := int64(max)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unshed(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if inFlight.Add(1) > limit {
			inFlight.Add(-1)
			w.Header().Set("Retry-After", "1")
			WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "The server is busy. Please try again."})
			return
		}
		defer inFlight.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// unshed reports whether a path is exempt from load shedding: the liveness and readiness probes (a busy node must
// not look dead or unready to its orchestrator and be restarted or drained for it), discovery and the signing keys
// (cheap, cached, and every relying party's token validation depends on them), and the event stream (long-lived
// streams have their own per-node limit, see internal/events).
func unshed(p string) bool {
	switch p {
	case EventsPath, "/healthz", "/readyz", "/oauth/jwks", "/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server":
		return true
	}
	return false
}

// EventsPath is the Server-Sent Events stream of the management API.
const EventsPath = "/api/v1/events"

// Session returns the request's session (set by WithSession / RequireUser).
func Session(r *http.Request) *model.Session {
	s, _ := r.Context().Value(ctxSession).(*model.Session)
	return s
}

// User returns the signed-in user, if any.
func User(r *http.Request) *model.User { u, _ := r.Context().Value(ctxUser).(*model.User); return u }

// Actor returns the actor for the request (session user or API token).
func Actor(r *http.Request) *service.Actor {
	a, _ := r.Context().Value(ctxActor).(*service.Actor)
	return a
}

// WithActor stores an actor in the request context (used by bearer-token authenticated APIs).
func WithActor(r *http.Request, a *service.Actor) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxActor, a))
}

// WithSession loads the session (if any) into the request context.
func (s *Server) WithSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, u := s.Sessions.Current(r)
		if sess != nil {
			ctx := context.WithValue(r.Context(), ctxSession, sess)
			ctx = context.WithValue(ctx, ctxUser, u)
			ctx = context.WithValue(ctx, ctxActor, service.ActorForUser(u, ClientIP(r)))
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePage requires a signed-in user for an HTML page, redirecting to the sign-in page otherwise.
func (s *Server) RequirePage(next http.HandlerFunc) http.Handler {
	return s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if User(r) == nil {
			http.Redirect(w, r, signInFor(r), http.StatusSeeOther)
			return
		}
		next(w, r)
	}))
}

// signInFor is where a signed-out visitor of a page goes: an organization's admin page to that organization's
// sign-in page, back here afterwards; anything else to the help page (sign-in needs the organization).
func signInFor(r *http.Request) string {
	if rest, ok := strings.CutPrefix(r.URL.Path, "/admin/orgs/"); ok {
		if org, _, _ := strings.Cut(rest, "/"); org != "" && orgName.MatchString(org) {
			return "/login/" + org + "?next=" + urlQueryEscape(r.URL.RequestURI())
		}
	}
	return "/"
}

var orgName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// RequireAPI requires a signed-in user for a JSON endpoint and, for unsafe methods, a matching CSRF header
// (X-CSRF-Token) and same-origin request.
func (s *Server) RequireAPI(next http.HandlerFunc) http.Handler {
	return s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if User(r) == nil {
			WriteJSON(w, http.StatusUnauthorized, ErrorBody{Error: "Your session has ended. Please sign in again."})
			return
		}
		if !s.CheckCSRF(r, Session(r).CSRF) {
			WriteJSON(w, http.StatusForbidden, ErrorBody{Error: "The request could not be verified. Reload the page."})
			return
		}
		next(w, r)
	}))
}

// CheckCSRF verifies unsafe requests carry the expected token in X-CSRF-Token and come from this origin.
func (s *Server) CheckCSRF(r *http.Request, token string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if o := r.Header.Get("Origin"); o != "" && !sameOrigin(o, s.Cfg.Server.PublicURL) {
		return false
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" {
		return false
	}
	got := r.Header.Get("X-CSRF-Token")
	return token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// sameOrigin compares two origins after normalising case and default ports.
func sameOrigin(a, b string) bool {
	norm := func(v string) string {
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			return v
		}
		host, port := strings.ToLower(u.Hostname()), u.Port()
		if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
			port = ""
		}
		if port != "" {
			host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		return strings.ToLower(u.Scheme) + "://" + host
	}
	return norm(a) == norm(b)
}
