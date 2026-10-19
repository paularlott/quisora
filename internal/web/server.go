// Package web is the HTTPS server: middleware, sessions, page rendering and the shared plumbing every HTTP module
// (UI, login, OAuth, SCIM) registers its routes on.
package web

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io/fs"
	stdlog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	webassets "github.com/paularlott/quisora/web"
)

// Module is a group of routes (login, admin UI, OAuth, SCIM, ...).
type Module interface {
	Register(s *Server)
}

// Health reports readiness (set by the cluster layer: false while a node cannot reach a majority).
type Health interface {
	Ready() (bool, string)
}

// Server is the HTTPS server and the shared dependencies of every module.
type Server struct {
	Cfg      *config.Config
	Svc      *service.Service
	Log      logger.Logger
	Eph      ephemeral.Store
	Sessions *Sessions
	Render   *Renderer
	Site     Site
	Mux      *http.ServeMux
	Health   Health
	Bearer   BearerFunc // resolves bearer tokens for the management API (set by the app)
	// ServesTokens reports whether the token, userinfo and introspection endpoints may answer while this node is not
	// writable (a grace period on the minority side of a partition). Nil: always.
	ServesTokens func() bool
	// Writable reports whether this node may accept writes (false on the minority side of a partition).
	Writable func() bool
	// Reauthed reports whether the request's session signed in or re-authenticated recently (set by the login module,
	// which owns re-authentication); false without a session (API tokens). Changes to your own account made from the
	// admin pages ask for it, as the account page does.
	Reauthed func(r *http.Request) bool
	// Status is the cluster summary /readyz reports (counts only: /readyz is unauthenticated). Nil: none.
	Status func() any

	httpSrv *http.Server
	addr    string
}

// New builds the server; modules are added with Use before Start.
func New(cfg *config.Config, svc *service.Service, eph ephemeral.Store, log logger.Logger) (*Server, error) {
	r, err := NewRenderer(webassets.Templates, webassets.Dist)
	if err != nil {
		return nil, err
	}
	r.Log = log
	SetTrustedProxies(cfg.Server.TrustProxy)
	s := &Server{Cfg: cfg, Svc: svc, Log: log, Eph: eph, Sessions: NewSessions(svc), Render: r,
		Site: SiteFromConfig(cfg), Mux: http.NewServeMux()}
	s.baseRoutes()
	return s, nil
}

// Use registers modules.
func (s *Server) Use(mods ...Module) {
	for _, m := range mods {
		m.Register(s)
	}
}

// Handler returns the full middleware chain around the mux.
func (s *Server) Handler() http.Handler {
	return recoverer(s.Log, requestInfo(observe(s.Log, s.Cfg.Log.Access,
		securityHeaders(shed(s.Cfg.Limits.MaxInFlight, s.serveGate(s.writeGuard(s.Mux)))))))
}

// alwaysServed reports whether a path answers whatever the node's state: the probes and static files, which hold
// no data.
func alwaysServed(p string) bool {
	return p == "/healthz" || p == "/readyz" || p == "/metrics" || strings.HasPrefix(p, "/assets/") || strings.HasPrefix(p, "/branding/") ||
		p == "/favicon.ico"
}

// tokenPaths keep answering on a node cut off from the majority for cluster.minority_grace (ServesTokens).
func tokenPath(p string) bool {
	return p == "/oauth/token" || p == "/oauth/userinfo" || p == "/oauth/introspect"
}

// serveGate answers 503 (Retry-After: 5) to everything but the probes and static files while this node is not
// ready (Health): a node that is starting, catching up, copying its first data, out of date, misconfigured or cut
// off from the majority must not hand data it cannot vouch for — partial, stale or since deleted — to a caller that
// bypasses the load balancer (admin and management API reads, SCIM, the authorization pages, discovery, JWKS). The
// token, userinfo and introspection endpoints keep answering on a node that was serving and got cut off, for the
// grace of cluster.minority_grace (ServesTokens): only what needs no write succeeds there (a write is refused
// without a quorum).
func (s *Server) serveGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if s.Health == nil || alwaysServed(p) {
			next.ServeHTTP(w, r)
			return
		}
		if ok, _ := s.Health.Ready(); ok {
			next.ServeHTTP(w, r)
			return
		}
		if tokenPath(p) && s.ServesTokens != nil && s.ServesTokens() {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case strings.HasPrefix(p, "/oauth/") || strings.HasPrefix(p, "/.well-known/"):
			WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable",
				"error_description": "this server is not ready to serve; try again shortly"})
		case strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/scim/"):
			WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "This server is not ready to serve. Please try again shortly."})
		default:
			http.Error(w, "This server is not ready to serve. Please try again shortly.", http.StatusServiceUnavailable)
		}
	})
}

// writeGuard refuses state-changing requests while this node cannot reach a majority of the cluster, so a
// partitioned minority never diverges (admin and SCIM writes, sign-ins, including a provider's sign-in callback,
// which is a GET). The token endpoint (refresh, code exchange), userinfo and introspection keep working for a grace
// period (ServesTokens), so applications ride out a short partition: what they write is new records, not edits that
// could conflict, and refresh token reuse detection still holds once the partition heals. After it they refuse
// too: revocations made on the majority side cannot reach this node. Signing out and revocation keep working.
func (s *Server) writeGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Writable != nil && !s.Writable() {
			switch r.URL.Path {
			case "/oauth/token", "/oauth/userinfo", "/oauth/introspect":
				if s.ServesTokens != nil && !s.ServesTokens() {
					w.Header().Set("Retry-After", "5")
					WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable",
						"error_description": "this server cannot reach the rest of the cluster"})
					return
				}
			}
			// GET routes that write (a provider's sign-in callback, an email verification link); HEAD reaches GET
			// routes too
			if (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
				(strings.HasPrefix(r.URL.Path, "/login/callback/") || r.URL.Path == "/verify-email") {
				w.Header().Set("Retry-After", "5")
				http.Error(w, "This server cannot reach the rest of the cluster. Go back and try again shortly.",
					http.StatusServiceUnavailable)
				return
			}
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				p := r.URL.Path
				if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/scim/") {
					w.Header().Set("Retry-After", "5")
					WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{
						Error: "This server cannot reach the rest of the cluster. Please try again shortly."})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) baseRoutes() {
	dist, _ := fs.Sub(webassets.Dist, "dist")
	static := http.FileServerFS(dist)
	s.Mux.Handle("GET /assets/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r) // no directory listings
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		static.ServeHTTP(w, r)
	}))
	s.Mux.HandleFunc("GET /branding/{name}", s.branding)
	s.Mux.HandleFunc("GET /metrics", s.metrics)
	s.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.Mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"status": "ready"}
		if s.Status != nil {
			body["cluster"] = s.Status() // counts only; the reasons stay in the log: /readyz is unauthenticated
		}
		w.Header().Set("Cache-Control", "no-store")
		if s.Health != nil {
			if ok, why := s.Health.Ready(); !ok {
				s.Log.Debug("not ready", "reason", why)
				body["status"] = "unavailable"
				WriteJSON(w, http.StatusServiceUnavailable, body)
				return
			}
		}
		WriteJSON(w, http.StatusOK, body)
	})
}

// branding serves the configured logos (local files or redirects to https URLs), else the built-in one.
func (s *Server) branding(w http.ResponseWriter, r *http.Request) {
	var src string
	switch r.PathValue("name") {
	case "logo-light":
		src = s.Cfg.UI.LogoLight
	case "logo-dark":
		src = s.Cfg.UI.LogoDark
		if src == "" {
			src = s.Cfg.UI.LogoLight
		}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	switch {
	case src == "":
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		file := "dist/logo.svg"
		if r.PathValue("name") == "logo-dark" {
			file = "dist/logo-dark.svg"
		}
		b, err := fs.ReadFile(webassets.Dist, file)
		if err != nil {
			b = []byte(defaultLogo)
		}
		_, _ = w.Write(b)
	case strings.HasPrefix(src, "https://"):
		http.Redirect(w, r, src, http.StatusFound)
	default:
		if strings.HasSuffix(strings.ToLower(src), ".svg") {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		}
		http.ServeFile(w, r, src)
	}
}

const defaultLogo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#4f46e5"/><path d="M32 13 50 48H14Z" fill="none" stroke="#e0e7ff" stroke-width="4.5" stroke-linejoin="round"/><circle cx="32" cy="13" r="5.5" fill="#fff"/><circle cx="14" cy="48" r="5.5" fill="#fff"/><circle cx="50" cy="48" r="5.5" fill="#fff"/></svg>`

// Page builds the common page data for r.
func (s *Server) Page(w http.ResponseWriter, r *http.Request, title, nav string, data any) *Page {
	p := &Page{Site: s.Site, Title: title, Nav: nav, Data: data}
	if u := User(r); u != nil {
		p.User = u
		p.CSRF = Session(r).CSRF
		if org, err := s.Svc.GetOrg(r.Context(), nil, u.OrgID); err == nil {
			p.Org, p.HomeOrg = org, org.Name
		}
		p.Path = r.URL.RequestURI()
		p.IsSuper = u.Role == model.RoleSuperAdmin
		p.IsAdmin = u.Role.Rank() >= model.RoleAdmin.Rank()
		p.IsMgr = u.Role.Rank() >= model.RoleManager.Rank()
		p.KeyRotation = p.IsSuper && s.Svc.Sealer.Previous()
	} else {
		p.CSRF = s.AnonCSRF(w, r)
	}
	return p
}

// anonCSRFCookie carries the double-submit token for requests made before sign-in.
const anonCSRFCookie = "__Host-quisora_csrf"

// AnonCSRF returns (setting if needed) the anonymous double-submit CSRF token.
func (s *Server) AnonCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(anonCSRFCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok := secure.RandomToken(24)
	http.SetCookie(w, &http.Cookie{Name: anonCSRFCookie, Value: tok, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode})
	return tok
}

// CheckAnonCSRF verifies an anonymous unsafe request (sign-in endpoints).
func (s *Server) CheckAnonCSRF(r *http.Request) bool {
	c, err := r.Cookie(anonCSRFCookie)
	if err != nil {
		return false
	}
	return s.CheckCSRF(r, c.Value) && subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.Header.Get("X-CSRF-Token"))) == 1
}

// Start listens on the configured address with TLS (self-signed when no certificate is configured) and serves until
// ctx is done. It returns once the listener is up; errors after that are logged.
func (s *Server) Start(ctx context.Context) error {
	u, _ := url.Parse(s.Cfg.Server.PublicURL)
	cert, err := LoadOrCreateCert(s.Cfg.Server.TLSCert, s.Cfg.Server.TLSKey, s.Cfg.Server.DataDir+string(os.PathSeparator)+"tls", u.Hostname())
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.Cfg.Server.Listen)
	if err != nil {
		return err
	}
	s.httpSrv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
			NextProtos: []string{"h2", "http/1.1"}},
		ErrorLog: stdlog.New(debugWriter{s.Log}, "", 0),
	}
	go func() {
		if err := s.httpSrv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Log.Error("https server", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(sctx)
	}()
	s.addr = ln.Addr().String()
	s.Log.Info("listening", "addr", ln.Addr().String(), "url", s.Cfg.Server.PublicURL)
	return nil
}

// Addr returns the listening address (after Start).
func (s *Server) Addr() string { return s.addr }

func urlQueryEscape(v string) string { return url.QueryEscape(v) }

// debugWriter sends net/http's internal error log (TLS handshake failures and the like) to debug level.
type debugWriter struct{ log logger.Logger }

func (d debugWriter) Write(p []byte) (int, error) {
	d.log.Debug(strings.TrimSpace(string(p)))
	return len(p), nil
}

// metrics serves the Prometheus metrics (metrics.token as a bearer token; without one there is no such endpoint).
// It answers whatever the node's state, so a node that is not ready can be watched too.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	tok := s.Cfg.Metrics.Token
	if tok == "" {
		http.NotFound(w, r)
		return
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = metrics.Default.Write(w)
}
