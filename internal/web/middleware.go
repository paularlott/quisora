package web

import (
	"context"
	"crypto/subtle"
	"hash/maphash"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strconv"
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
)

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxUser
	ctxActor
	ctxUnchecked
)

// trustedProxies are the networks whose X-Forwarded-For is honoured (set at start-up; atomic because every server
// created in one process sets it, as tests do side by side).
var trustedProxies atomic.Pointer[[]netip.Prefix]

// SetTrustedProxies configures which peers may set X-Forwarded-For (CIDRs or single IPs).
func SetTrustedProxies(list []string) {
	var proxies []netip.Prefix
	for _, s := range list {
		if p, err := config.ParseProxy(s); err == nil { // config.Validate reports the bad ones
			proxies = append(proxies, p)
		}
	}
	trustedProxies.Store(&proxies)
}

// ClientIP returns the caller's address, honouring X-Forwarded-For only from trusted proxies.
// RateKeyIP is the client address as rate limits count it: an IPv4 address, or an IPv6 address's /64 prefix. One
// IPv6 client is usually given a whole /64 and can send from any address in it: counted one by one, it would get a
// fresh budget (and a fresh counter in memory) for every address. Audit records keep the full ClientIP.
func RateKeyIP(r *http.Request) string {
	key, _ := rateKeys(r)
	return key
}

// RateNetIP is the network the request's client address is counted in beside its own key (RateKeyIP): an IPv6
// address's /48, or "" for an IPv4 address (counted as itself alone). A share limited per address counts the /48 as
// well, at NetShareFactor times the address's share: a provider hands a customer a /48 or a /56 as readily as a /64,
// and counted by /64 alone one such allocation would bring as many shares as it has /64s (65,536 in a /48), enough
// to spend whatever every address shares.
func RateNetIP(r *http.Request) string {
	_, wide := rateKeys(r)
	return wide
}

// NetShareFactor is how many times an address's share of a limit (counted by RateKeyIP) its network (RateNetIP) may
// take in all: a few customers of one /48, each with a /64 of their own, are not refused for one another, and one
// customer holding the whole /48 gets this many shares rather than 65,536. It is for limits of what is rare or costly
// per address (registrations, documents fetched, device sign-ins and pushed requests that hold state, wrong codes):
// a /48 is often a whole organization's network (a university, a company) whose people share it, and these are
// limits such a site does not come near.
const NetShareFactor = 4

// NetBusyFactor is NetShareFactor for limits of request rates already high per address that hold nothing by
// themselves (authorization requests, failed requests to the token endpoint): a /48 that is a whole organization's
// network makes many times one address's ordinary traffic, and four addresses' worth would throttle a busy site's
// users for one another. Sixty-four, as the widest key of the held budgets (ephemeral.WidestFactor), still bounds
// what one allocation's 65,536 /64s get to that many shares.
const NetBusyFactor = 64

// rateKeys returns RateKeyIP and RateNetIP from one reading of the client address.
func rateKeys(r *http.Request) (key, wide string) {
	ip := ClientIP(r)
	if a, err := netip.ParseAddr(ip); err == nil && a.Is6() && !a.Is4In6() {
		p64, err64 := a.Prefix(64)
		p48, err48 := a.Prefix(48)
		if err64 == nil && err48 == nil {
			return p64.String(), p48.String()
		}
	}
	return ip, ""
}

// HolderIP names the request's client address as the one short-lived state is kept for (ephemeral.Budget): the
// address as rate limits count it (RateKeyIP), and for an IPv6 address its /48 as the wider key, which may hold
// ephemeral.WideFactor times as much, and its /32 as the widest, which may hold ephemeral.WidestFactor times as
// much. A provider hands a customer a /48 or a /56 as readily as a /64, and counted by /64 alone one such allocation
// would bring 65,536 budgets; a /32 is what a provider itself is allocated, and holds 65,536 /48s, each of which
// would otherwise bring sixteen. The price is the provider's other customers: everyone behind one /32 shares
// sixty-four budgets of unfinished sign-ins, which an attacker inside it can use up for them (and for nobody else).
func HolderIP(r *http.Request) ephemeral.Holder {
	h := ephemeral.Holder{Key: "ip|" + RateKeyIP(r)}
	if a, err := netip.ParseAddr(ClientIP(r)); err == nil && a.Is6() && !a.Is4In6() {
		if p, err := a.Prefix(48); err == nil {
			h.Wide = "net|" + p.String()
		}
		if p, err := a.Prefix(32); err == nil {
			h.Widest = "net|" + p.String()
		}
	}
	return h
}

// HolderUser names a signed-in user as the one short-lived state is kept for (ephemeral.Budget): what an account
// stores is the account's to answer for, from whatever addresses it is used.
func HolderUser(userID string) ephemeral.Holder { return ephemeral.Holder{Key: "user|" + userID} }

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
	proxies := trustedProxies.Load()
	if proxies == nil {
		return false
	}
	for _, p := range *proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// contentSecurityPolicy forbids inline scripts and eval; Alpine runs as its CSP build. Images come from this server
// and data: URIs (QR codes), plus the origin of a logo configured as an https URL (/branding/ redirects to it):
// nothing else, so markup that ever renders an outside URL as an image cannot send data anywhere with it.
func contentSecurityPolicy(logos ...string) string {
	img := "'self' data:"
	seen := map[string]bool{}
	for _, l := range logos {
		if u, err := url.Parse(l); err == nil && u.Scheme == "https" && u.Host != "" && !seen[u.Host] {
			seen[u.Host] = true
			img += " https://" + u.Host
		}
	}
	return "default-src 'self'; script-src 'self'; style-src 'self'; img-src " + img + "; font-src 'self'; " +
		"connect-src 'self'; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
}

// securityHeaders sets the headers every response carries; csp is the Content-Security-Policy of a response that
// sets none of its own (one(contentSecurityPolicy(...)), made once). A skin preview (a GET with ?skin=, shown in the
// console's preview dialog) may be framed by this site's own pages, and only by them.
func securityHeaders(csp []string, next http.Handler) http.Handler {
	preview := one(strings.Replace(csp[0], "frame-ancestors 'none'", "frame-ancestors 'self'", 1))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Shared, read-only value slices (len == cap, so a later Add copies rather than writing into them): no
		// allocation per response for headers that never change.
		for _, sh := range staticSecurityHeaders {
			h[sh.key] = sh.val
		}
		pageCSP := csp
		if r.Method == http.MethodGet && r.URL.Query().Has("skin") {
			h["X-Frame-Options"] = frameSameOrigin
			pageCSP = preview
		}
		if _, ok := h["Content-Security-Policy"]; !ok {
			h["Content-Security-Policy"] = pageCSP
		}
		next.ServeHTTP(w, r)
	})
}

var frameSameOrigin = one("SAMEORIGIN")

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

// maxFormBody limits what a form (application/x-www-form-urlencoded) request may send. Every form of this server is a
// few fields; net/http's own limit for reading one (10 MB) would let each anonymous POST hold that much memory until
// ReadTimeout.
const maxFormBody = 64 << 10

// limitBody caps every request body, in one place for all handlers: forms at maxFormBody, anything else (JSON,
// SCIM) at MaxJSONBody, but for the setting of a profile picture (MaxPictureBody), the one upload the server takes. A
// body over the cap fails the handler's read with *http.MaxBytesError.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := int64(MaxJSONBody)
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt == "application/x-www-form-urlencoded" {
			limit = maxFormBody
		} else if isPictureUpload(r) {
			limit = MaxPictureBody
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// shed rejects requests with 503 once max() are in flight on this node, and with 429 a request whose client address
// (RateKeyIP: an IPv6 /64 counts as one) has its share of them in flight already (limits.max_in_flight_per_ip), or
// whose IPv6 /48 (RateNetIP) has NetShareFactor times that share in flight. Both are read at each request, so a
// configuration reload changes them (limits.max_in_flight) and the requests in flight stay counted.
//
// A request holds its place from here, before its body is read: the handlers read it before their own limits by
// address (the token endpoint, pushed authorization, logout, the sign-in pages' JSON), and the server waits for it up
// to its read timeout (30 s). Without the share, one address sending requests whose bodies come a byte at a time
// could hold every place, and every other client would get 503 for as long as it went on. The address's own requests
// are refused first, at its share, and a handful of addresses are needed to fill the node. The /48's share keeps that
// handful from being the /64s of one allocation: counted by /64 alone, 16 of the 65,536 /64s of one /48 held every
// place at the default share (a sixteenth); with it, one /48 holds at most NetShareFactor sixteenths.
func shed(limits func() (all, perIP int), next http.Handler) http.Handler {
	// An atomic counter rather than a channel semaphore: every request passes here, and a channel's lock taken
	// twice per request by every core is itself a bottleneck under load. The counts by address are a sharded map,
	// an entry only while the address (or its /48) has a request in flight: at most twice max_in_flight entries.
	var inFlight atomic.Int64
	var byIP inFlightByIP
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unshed(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		all, perIP := limits()
		if inFlight.Add(1) > int64(all) {
			inFlight.Add(-1)
			metrics.HTTPShed.Inc()
			w.Header().Set("Retry-After", "1")
			WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "The server is busy. Please try again."})
			return
		}
		defer inFlight.Add(-1)
		// One map for both: a /64's key ("2001:db8::/64") and a /48's ("2001:db8::/48") never collide, and an entry
		// lives only while a request of its key is in flight, so the map holds at most twice max_in_flight entries.
		ip, wide := rateKeys(r)
		ok := byIP.take(ip, perIP)
		if ok && wide != "" {
			if ok = byIP.take(wide, perIP*NetShareFactor); !ok {
				byIP.release(ip)
			}
		}
		if !ok {
			metrics.HTTPShedAddress.Inc()
			w.Header().Set("Retry-After", "1")
			WriteJSON(w, http.StatusTooManyRequests, ErrorBody{Error: "Too many requests from your address at once. Please try again."})
			return
		}
		defer byIP.release(ip)
		if wide != "" {
			defer byIP.release(wide)
		}
		next.ServeHTTP(w, r)
	})
}

// inFlightShards is how many locks the counts of requests in flight by address are spread over.
const inFlightShards = 64

// inFlightByIP counts the requests in flight by client address (shed).
type inFlightByIP struct {
	seed  maphash.Seed
	once  sync.Once
	shard [inFlightShards]struct {
		mu sync.Mutex
		n  map[string]int
	}
}

func (c *inFlightByIP) of(ip string) *struct {
	mu sync.Mutex
	n  map[string]int
} {
	c.once.Do(func() {
		c.seed = maphash.MakeSeed()
		for i := range c.shard {
			c.shard[i].n = map[string]int{}
		}
	})
	return &c.shard[maphash.String(c.seed, ip)%inFlightShards]
}

// take counts a request of ip in flight and reports true, unless ip has max in flight already.
func (c *inFlightByIP) take(ip string, max int) bool {
	s := c.of(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n[ip] >= max {
		return false
	}
	s.n[ip]++
	return true
}

// release ends a request of ip that take counted; the address's entry goes with its last.
func (c *inFlightByIP) release(ip string) {
	s := c.of(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n[ip] <= 1 {
		delete(s.n, ip)
		return
	}
	s.n[ip]--
}

// SetDenyNetworks sets the networks whose clients are refused (server.deny_networks; deny), at start-up and on a
// configuration reload: the next request is checked against them.
func (s *Server) SetDenyNetworks(nets []netip.Prefix) { s.denied.Store(&nets) }

// DenyNetworks returns the networks whose clients are refused now (SetDenyNetworks).
func (s *Server) DenyNetworks() []netip.Prefix {
	if nets := s.denied.Load(); nets != nil {
		return *nets
	}
	return nil
}

// deny answers a bare 403 to a client whose address (ClientIP, so behind server.trust_proxy the address the proxies
// name) is in server.deny_networks, before any other work: no request id, no store or session read, no body read, no
// access log line and no audit event, so a flood from it costs next to nothing and fills no log. It is counted
// (quisora_http_denied_total). The probes and /metrics (behind its own token) are never refused: a load balancer or
// Prometheus in a denied network still sees the node.
func (s *Server) deny(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if nets := s.DenyNetworks(); len(nets) > 0 && !undenied(r.URL.Path) && inNetworks(nets, ClientIP(r)) {
			metrics.HTTPDenied.Inc()
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// undenied reports whether a path answers a client in server.deny_networks too: the probes and the metrics.
func undenied(p string) bool { return p == "/healthz" || p == "/readyz" || p == "/metrics" }

// inNetworks reports whether address ip is in one of nets.
func inNetworks(nets []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// unshed reports whether a path is exempt from load shedding: the liveness and readiness probes (a busy node must
// not look dead or unready to its orchestrator and be restarted or drained for it), discovery and the signing keys
// (cheap, cached, and every relying party's token validation depends on them), and the admin console's event stream
// (long-lived streams have their own per-node limit, see internal/events).
func unshed(p string) bool {
	if strings.HasPrefix(p, "/.well-known/oauth-authorization-server/") || strings.HasPrefix(p, "/.well-known/openid-configuration/") {
		return true // an organization's metadata at its RFC 8414 address
	}
	switch InOrgPath(p) {
	case EventsPath, "/healthz", "/readyz", "/metrics", "/oauth/jwks", "/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server":
		return true
	}
	return false
}

// InOrgPath is p within its organization's address space: the rest of /o/<org>/... (OrgPath), or p itself outside one.
func InOrgPath(p string) string {
	rest, ok := strings.CutPrefix(p, "/o/")
	if !ok {
		return p
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[i:]
	}
	return "/"
}

// APIPath reports whether p is under the management API (/api/) or the console's and pages' own (/api-internal/,
// within an organization or not): such requests get their errors as JSON.
func APIPath(p string) bool {
	p = InOrgPath(p)
	return strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/api-internal/")
}

// EventsPath is the Server-Sent Events stream of the management API (the admin console's live updates).
const EventsPath = "/api/events"

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

// WithActor makes a the request's actor (bearer-token authenticated APIs, and the MCP server's in-process calls),
// and takes away any session and user a cookie put in the context: the request is the token's, and a session there
// would be read as the token holder's own (a re-authentication of whoever's cookie came with the token, which stepUp
// and Reauthed would count).
func WithActor(r *http.Request, a *service.Actor) *http.Request {
	ctx := context.WithValue(r.Context(), ctxActor, a)
	ctx = context.WithValue(ctx, ctxSession, (*model.Session)(nil))
	ctx = context.WithValue(ctx, ctxUser, (*model.User)(nil))
	return r.WithContext(ctx)
}

// WithSession loads the session (if any) into the request context. A session the store refused to check leaves the
// request signed out and marked (SessionUnchecked). The context's session values are set whatever it held before, so a
// request that arrives with another's identity in its context (an in-process request made for one, see selfTransport)
// is signed out unless its own cookie names a session.
func (s *Server) WithSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, u, err := s.Sessions.Check(r)
		var actor *service.Actor
		if sess != nil {
			if ri := service.RequestFrom(r.Context()); ri != nil {
				ri.SessionID = sess.ID
			}
			actor = service.ActorForUser(u, ClientIP(r))
			actor.Sources = sess.Sources
		}
		ctx := context.WithValue(r.Context(), ctxUnchecked, err != nil)
		ctx = context.WithValue(ctx, ctxSession, sess)
		ctx = context.WithValue(ctx, ctxUser, u)
		ctx = context.WithValue(ctx, ctxActor, actor)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SessionUnchecked reports whether the request's session could not be checked (the store refused): the request is
// answered 503 rather than taken for signed out.
func SessionUnchecked(r *http.Request) bool { u, _ := r.Context().Value(ctxUnchecked).(bool); return u }

// WriteUnchecked answers a request whose session could not be checked (SessionUnchecked).
func WriteUnchecked(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	WriteJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "This server cannot check your session right now. Please try again shortly."})
}

// RequirePage requires a signed-in user for an HTML page, redirecting to the sign-in page otherwise.
func (s *Server) RequirePage(next http.HandlerFunc) http.Handler {
	return s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SessionUnchecked(r) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "This server cannot check your session right now. Please try again shortly.", http.StatusServiceUnavailable)
			return
		}
		if User(r) == nil {
			to, err := s.signInFor(r)
			if err != nil {
				w.Header().Set("Retry-After", "5")
				http.Error(w, "This server cannot serve its sign-in page right now. Please try again shortly.", http.StatusServiceUnavailable)
				return
			}
			http.Redirect(w, r, to, http.StatusSeeOther)
			return
		}
		next(w, r)
	}))
}

// signInFor is where a signed-out visitor of a page goes, back here afterwards: an organization's own pages (under
// /o/<org>) and its console pages (/admin/orgs/<org>) to its sign-in page; the server's pages (the rest of the
// console) to the primary organization's, whose administrators administer the server. The error is the primary
// organization's, not known yet (service.PrimaryOrgID).
func (s *Server) signInFor(r *http.Request) (string, error) {
	org := r.PathValue("org")
	if o := Org(r); o != nil {
		org = o.ID
	} else if org == "" {
		var err error
		if org, err = s.Svc.PrimaryOrgID(r.Context()); err != nil {
			return "", err
		}
	}
	return "/o/" + url.PathEscape(org) + "/login?next=" + urlQueryEscape(r.URL.RequestURI()), nil
}

// RequireAPI requires a signed-in user for a JSON endpoint and, for unsafe methods, a matching CSRF header
// (X-CSRF-Token) and same-origin request.
func (s *Server) RequireAPI(next http.HandlerFunc) http.Handler {
	return s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SessionUnchecked(r) {
			WriteUnchecked(w)
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
		next(w, r)
	}))
}

// CheckCSRF verifies unsafe requests carry the expected token in X-CSRF-Token and come from this origin.
func (s *Server) CheckCSRF(r *http.Request, token string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return s.CheckCSRFAlways(r, token)
}

// CheckCSRFAlways is CheckCSRF for a request of any method: a GET that must not be made from another site with the
// browser's cookies (the backup download, which a link would otherwise start).
func (s *Server) CheckCSRFAlways(r *http.Request, token string) bool {
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

// requestInfo gives every request an id, answered as X-Request-ID, and carries it with the user agent in the
// context for the audit log (service.RequestInfo). A trusted proxy's X-Request-ID is kept, so its logs and the audit
// log name a request alike.
func requestInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID(id) || !fromTrustedProxy(r) {
			id = secure.RandomToken(12)
		}
		w.Header().Set("X-Request-ID", id)
		ri := &service.RequestInfo{ID: id, IP: ClientIP(r), UserAgent: r.UserAgent()}
		next.ServeHTTP(w, r.WithContext(service.WithRequest(r.Context(), ri)))
	})
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c == '-' || c == '_' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// fromTrustedProxy reports whether the connection comes from one of server.trust_proxy.
func fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && trusted(addr)
}

// observe counts every request by status class and time taken (metrics), and with log.access logs it: method, path
// (never the query string: it carries authorization codes, states and link tokens), status, duration, size, client
// address and request id. The probes, metrics scrapes and static files are counted but not logged.
func observe(log logger.Logger, access bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		d := time.Since(start)
		metrics.HTTPRequests.Inc(strconv.Itoa(sw.status/100) + "xx")
		metrics.HTTPDuration.Observe(d.Seconds())
		if access && !quiet(r.URL.Path) {
			id := ""
			if ri := service.RequestFrom(r.Context()); ri != nil {
				id = ri.ID
			}
			log.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status,
				"ms", float64(d.Microseconds())/1000, "bytes", sw.bytes, "ip", ClientIP(r), "request_id", id)
		}
	})
}

// quiet paths are not access-logged: probes, scrapes and static files.
func quiet(p string) bool {
	return p == "/healthz" || p == "/readyz" || p == "/metrics" || strings.HasPrefix(p, "/assets/") ||
		strings.HasPrefix(p, "/branding/") || p == "/favicon.ico"
}

// statusWriter remembers a response's status and size. Unwrap lets http.ResponseController reach the connection
// (flushing the event stream, a backup's write deadline).
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
