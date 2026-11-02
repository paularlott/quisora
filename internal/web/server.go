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
	"strings"
	"sync"
	"sync/atomic"
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

// Health reports readiness (set by the app: false while the store is not ready to serve, or the server is not set up).
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
	// Reauthed reports whether the request's session signed in or re-authenticated recently (set by the login module,
	// which owns re-authentication); false without a session (API tokens). Changes to your own account made from the
	// admin pages ask for it, as the account page does.
	Reauthed func(r *http.Request) bool
	// Status is the cluster summary /readyz reports (counts only: /readyz is unauthenticated). Nil: none.
	Status func() any

	skin    *Skin // ui.skin, or nil
	httpSrv *http.Server
	addr    string
	certs   *certSource

	lastProbe atomic.Int64 // unix nanos of the last GET /readyz: something is routing traffic by it
	draining  atomic.Bool  // shutting down: /readyz answers 503
	stopOnce  sync.Once
	stopping  chan struct{} // closed when the listener closes (Stopping)
	closeOnce sync.Once
}

// Stopping is closed when the server stops taking requests. Handlers that hold a response open (the live-update
// streams) return on it: shutdown waits for every request in flight, and the clients reconnect by themselves.
func (s *Server) Stopping() <-chan struct{} { return s.stopping }

// probeSeen is how recent a /readyz probe must be for Stop to drain first: something is routing traffic by it.
const probeSeen = 2 * time.Minute

// drainUnit is the unit of server.shutdown_drain (tests shorten it).
var drainUnit = time.Second

// TLS12CipherSuites are the only cipher suites offered over TLS 1.2: forward-secret AEAD suites, the ones RFC 9325
// §4.2 recommends (as FAPI 2.0 §5.2.2 requires; Go implements no DHE). TLS 1.3 suites are not configurable and are
// all acceptable.
var TLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// New builds the server; modules are added with Use before Start.
func New(cfg *config.Config, svc *service.Service, eph ephemeral.Store, log logger.Logger) (*Server, error) {
	r, err := NewRenderer(webassets.Templates, webassets.Dist)
	if err != nil {
		return nil, err
	}
	r.Log = log
	if len(r.manifest) == 0 {
		// A binary built without "task webassets" (npm run build) serves its pages without their scripts and styles:
		// the admin console and the sign-in pages do not work. Said at start, not found out by the first user.
		log.Warn("this binary was built without its web assets (run \"task webassets\" before go build): the sign-in " +
			"pages and the admin console will not work")
	}
	skin, err := LoadSkin(cfg.UI.Skin)
	if err != nil {
		return nil, err
	}
	SetTrustedProxies(cfg.Server.TrustProxy)
	s := &Server{Cfg: cfg, Svc: svc, Log: log, Eph: eph, Sessions: NewSessions(svc), Render: r, stopping: make(chan struct{}),
		Site: SiteFromConfig(cfg), Mux: http.NewServeMux(), skin: skin}
	if skin != nil {
		s.Site.Skin, s.Site.SkinCSS = skin.Name, "/branding/skin.css?v="+skin.Version
	}
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
	// recoverer inside observe: a request that panics is answered 500 and is still logged and counted as one.
	return requestInfo(observe(s.Log, s.Cfg.Log.Access, recoverer(s.Log,
		securityHeaders(one(contentSecurityPolicy(s.Cfg.UI.LogoLight, s.Cfg.UI.LogoDark)), shed(s.Cfg.Limits.MaxInFlight, limitBody(s.serveGate(s.Mux)))))))
}

// alwaysServed reports whether a path answers whatever the node's state: the probes and static files, which hold
// no data.
func alwaysServed(p string) bool {
	return p == "/healthz" || p == "/readyz" || p == "/metrics" || strings.HasPrefix(p, "/assets/") || strings.HasPrefix(p, "/branding/") ||
		p == "/favicon.ico"
}

// serveGate answers 503 (Retry-After: 5) to everything but the probes and static files while this node is not
// ready (Health): a store that is not ready to serve (starting, misconfigured, out of date) must not hand out data —
// partial, stale or since deleted — to a caller that bypasses the load balancer (admin and management API reads,
// SCIM, the authorization pages, discovery, JWKS, the token endpoints), as a database node that is not ready refuses
// queries.
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
		writeUnavailable(w, p, "This server is not ready to serve. Please try again shortly.")
	})
}

// writeUnavailable answers 503 "try again" (Retry-After) in the form the path's clients read: an OAuth error for the
// OAuth endpoints and metadata (temporarily_unavailable), JSON for the APIs and SCIM, text otherwise.
func writeUnavailable(w http.ResponseWriter, p, msg string) {
	w.Header().Set("Retry-After", "5")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case strings.HasPrefix(InOrgPath(p), "/oauth/") || strings.HasPrefix(InOrgPath(p), "/.well-known/") ||
		strings.HasPrefix(p, "/.well-known/"):
		WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": msg})
	case APIPath(p) || strings.HasPrefix(p, "/scim/"):
		WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: msg})
	default:
		http.Error(w, msg, http.StatusServiceUnavailable)
	}
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
	s.Mux.Handle("GET /o/{org}/branding/{name}", s.InOrg(http.HandlerFunc(s.orgBranding)))
	s.Mux.HandleFunc("GET /api-docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api-docs/", http.StatusMovedPermanently)
	})
	s.Mux.HandleFunc("GET /api-docs/{$}", apiDocs)
	s.Mux.HandleFunc("GET /api/openapi.json", openAPIDocument)
	s.Mux.HandleFunc("GET /metrics", s.metrics)
	s.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.Mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		s.lastProbe.Store(time.Now().UnixNano())
		body := map[string]any{"status": "ready"}
		if s.Status != nil {
			body["cluster"] = s.Status() // counts only; the reasons stay in the log: /readyz is unauthenticated
		}
		w.Header().Set("Cache-Control", "no-store")
		if s.draining.Load() {
			body["status"] = "draining"
			WriteJSON(w, http.StatusServiceUnavailable, body)
			return
		}
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

// apiDocsCSP lets Redoc run from this server only: its script is a built asset, it styles itself with inline styles,
// and it fetches nothing but /api/openapi.json (no telemetry, fonts or icons from elsewhere).
const apiDocsCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// apiDocs serves the API reference page (web/api-docs/index.html, built into dist by Vite).
func apiDocs(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webassets.Dist, "dist/api-docs/index.html")
	if err != nil {
		http.Error(w, "The API reference was not built into this binary.", http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache") // it names the current hashed assets
	h.Set("Content-Security-Policy", apiDocsCSP)
	_, _ = w.Write(b)
}

// openAPIDocument serves the OpenAPI description of the management API: web/openapi/openapi.yaml, bundled into
// dist/openapi.json by the web build.
func openAPIDocument(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webassets.Dist, "dist/openapi.json")
	if err != nil {
		WriteJSON(w, http.StatusNotFound, ErrorBody{Error: "The OpenAPI document was not built into this binary."})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

// branding serves the configured logos (local files or redirects to https URLs), else the skin's, else the built-in
// one, and the skin's stylesheet.
func (s *Server) branding(w http.ResponseWriter, r *http.Request) {
	var src string
	var skinLogo *SkinFile
	switch r.PathValue("name") {
	case "logo-light":
		src = s.Cfg.UI.LogoLight
		if s.skin != nil {
			skinLogo = s.skin.LogoLight
		}
	case "logo-dark":
		src = s.Cfg.UI.LogoDark
		if src == "" {
			src = s.Cfg.UI.LogoLight
		}
		if s.skin != nil {
			skinLogo = s.skin.LogoDark
		}
	case "skin.css":
		if s.skin == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		// the pages name it with ?v=<content hash>, so a changed skin is a new URL
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write(s.skin.CSS)
		return
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	switch {
	case src == "" && skinLogo != nil:
		w.Header().Set("Content-Type", skinLogo.Type)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		_, _ = w.Write(skinLogo.Body)
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
			p.Org = org
		}
		p.Path = r.URL.RequestURI()
		p.IsSuper = u.Role == model.RoleSuperAdmin
		p.IsAdmin = u.Role.Rank() >= model.RoleAdmin.Rank()
		p.IsMgr = u.Role.Privileged()
		p.KeyRotation = p.IsSuper && s.Svc.Sealer.Previous()
	} else {
		p.CSRF = s.AnonCSRF(w, r)
		p.Org = Org(r) // an organization's own pages (sign-in, device, sign-out) name it signed out too
	}
	p.Site = p.Site.For(p.Org) // its branding (an admin page then names the organization it administers: p.Org)
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
// ctx is done or Stop. It returns once the listener is up; errors after that are logged. The certificate is replaced
// without a restart when it is renewed (certSource).
func (s *Server) Start(ctx context.Context) error {
	u, _ := url.Parse(s.Cfg.Server.PublicURL)
	certs, err := newCertSource(s.Cfg.Server.TLSCert, s.Cfg.Server.TLSKey, s.Cfg.DataPath(config.DirTLS),
		u.Hostname(), s.Log)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.Cfg.Server.Listen)
	if err != nil {
		return err
	}
	s.certs = certs
	go certs.watch()
	s.httpSrv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate,
			CipherSuites: TLS12CipherSuites, NextProtos: []string{"h2", "http/1.1"}},
		ErrorLog: stdlog.New(debugWriter{s.Log}, "", 0),
	}
	go func() {
		if err := s.httpSrv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Log.Error("https server", "error", err)
		}
	}()
	s.httpSrv.RegisterOnShutdown(func() { s.closeOnce.Do(func() { close(s.stopping) }) })
	go func() {
		<-ctx.Done()
		s.Stop()
	}()
	s.addr = ln.Addr().String()
	s.Log.Info("listening", "addr", ln.Addr().String(), "url", s.Cfg.Server.PublicURL)
	return nil
}

// ReloadCertificate loads the TLS certificate again now (SIGHUP); a renewal is also picked up by itself within an
// hour. A certificate that does not load leaves the current one in place.
func (s *Server) ReloadCertificate() error {
	if s.certs == nil {
		return nil
	}
	return s.certs.Reload()
}

// Stop stops serving, once (later calls wait for the first). When something has been polling /readyz (a load
// balancer, an orchestrator), /readyz first answers 503 for server.shutdown_drain seconds, so traffic moves to other
// nodes before the listener closes; then requests in flight get server.shutdown_timeout seconds to finish.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		if s.httpSrv == nil {
			return
		}
		s.draining.Store(true)
		drain := time.Duration(s.Cfg.Server.ShutdownDrain) * drainUnit
		if drain > 0 && time.Since(time.Unix(0, s.lastProbe.Load())) < probeSeen {
			s.Log.Info("draining before shutdown: /readyz answers 503", "for", drain)
			time.Sleep(drain)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.Cfg.Server.ShutdownTimeout)*time.Second)
		defer cancel()
		if err := s.httpSrv.Shutdown(ctx); err != nil {
			s.Log.Warn("requests still running at shutdown were cut off", "error", err)
		}
		s.certs.Close()
	})
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
