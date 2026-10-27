package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Organizations are self-contained: each has its own address space, /o/<org>/..., where <org> is its id (the form every
// link and the OAuth issuer use) or its name (which never looks like an id, model.ValidOrgName). Its sign-in pages,
// account page, invitations and OAuth endpoints are all there, and a browser holds one session per organization
// (SessionCookieFor): signed in to one organization is not signed in to another.

// OrgPath is the path of an organization's page or endpoint: /o/<id> followed by rest ("" or starting with "/").
func OrgPath(orgID, rest string) string { return model.OrgPath(orgID, rest) }

// sessionCookiePrefix starts every session cookie; the organization's id completes it (SessionCookieFor).
const sessionCookiePrefix = "__Host-quisora_s_"

// SessionCookieFor is the name of the cookie that carries a browser's session of an organization. The __Host- prefix
// pins it to this origin over HTTPS.
func SessionCookieFor(orgID string) string { return sessionCookiePrefix + orgID }

// setSessionCookie sets the cookie of session s (value raw), and records its organization as the browser's latest
// sign-in (lastOrgCookie).
func setSessionCookie(w http.ResponseWriter, s *model.Session, raw string) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookieFor(s.OrgID), Value: raw, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: s.Expires})
	http.SetCookie(w, &http.Cookie{Name: lastOrgCookie, Value: s.OrgID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: s.Expires})
}

type ctxOrgKey struct{}

// sessionOrgsKey holds the ids of the organizations whose session a request may present, in order (sessionOrgs).
type sessionOrgsKey struct{}

// InOrg serves next for the organization its path names ({org}: an id or a name): Org(r) is that organization, and the
// request's session is its session only. An organization that does not exist is not found; one that cannot be read
// now is unavailable (503), never "not found".
func (s *Server) InOrg(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		org, err := s.orgs.get(r.Context(), s.Svc, r.PathValue("org"))
		switch {
		case errors.Is(err, service.ErrNotFound):
			http.NotFound(w, r)
			return
		case err != nil:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "This server cannot serve this organization right now. Please try again shortly.",
				http.StatusServiceUnavailable)
			return
		}
		ctx := context.WithValue(r.Context(), ctxOrgKey{}, org)
		ctx = context.WithValue(ctx, sessionOrgsKey{}, []string{org.ID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// orgTTL bounds how long a change made on another node (which this one may not hear of: a shared database) can take
// to count here, as the OIDC provider's caches do; a change this node hears of counts at once (InvalidateOrgs).
const orgTTL = 5 * time.Second

// orgCache keeps the organizations InOrg resolved, by the reference the path gave (id or name). Every request under
// /o/<org> resolves one, and a store read may wait for the writes in flight (BadgerDB's read timestamp): uncached,
// the discovery and token endpoints queue behind every sign-in. It holds existing organizations only, so it is
// bounded by their number (twice: id and name), and is emptied whenever any organization changes, which is rare.
type orgCache struct {
	mu  sync.RWMutex
	m   map[string]orgEntry
	gen uint64 // bumped by every clear (mu): a read that began before one is not stored after it
}

type orgEntry struct {
	org *model.Org
	exp time.Time
}

func (c *orgCache) get(ctx context.Context, svc *service.Service, ref string) (*model.Org, error) {
	c.mu.RLock()
	e, ok := c.m[ref]
	gen := c.gen
	c.mu.RUnlock()
	if ok && time.Now().Before(e.exp) {
		return e.org, nil
	}
	org, err := svc.OrgByRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.gen == gen {
		if c.m == nil {
			c.m = map[string]orgEntry{}
		}
		c.m[ref] = orgEntry{org: org, exp: time.Now().Add(orgTTL)}
	}
	c.mu.Unlock()
	return org, nil
}

// InvalidateOrgs forgets every organization InOrg resolved: call it when one changes (its name may have gone to
// another, so the whole cache goes).
func (s *Server) InvalidateOrgs() {
	s.orgs.mu.Lock()
	s.orgs.gen++
	clear(s.orgs.m)
	s.orgs.mu.Unlock()
}

// Org returns the organization of the request's path (InOrg), or nil outside one.
func Org(r *http.Request) *model.Org {
	o, _ := r.Context().Value(ctxOrgKey{}).(*model.Org)
	return o
}

// maxConsoleSessions bounds the session cookies a console request is checked against (each may cost a read).
const maxConsoleSessions = 8

// lastOrgCookie names the organization of the browser's latest sign-in (set with every session cookie): the console
// acts as the person who signed in last, as it did when a browser held one session at a time.
const lastOrgCookie = "__Host-quisora_last_org"

// sessionOrgs returns the organizations whose session the request may present, in the order they are tried. Under
// /o/<org> it is that organization's only (InOrg). Elsewhere (the console and the management API, which are the
// server's) it is the organization of the browser's latest sign-in, then the organization the path administers
// ({org}), then the primary organization, whose administrators administer the server, then any other organization the
// browser holds a session of: whichever session is used, what its user may do is the service's to decide.
func (m *Sessions) sessionOrgs(r *http.Request) []string {
	if ids, ok := r.Context().Value(sessionOrgsKey{}).([]string); ok {
		return ids
	}
	var ids []string
	add := func(id string) {
		if !slices.Contains(ids, id) && len(ids) < maxConsoleSessions {
			ids = append(ids, id)
		}
	}
	if c, err := r.Cookie(lastOrgCookie); err == nil && model.IsID(c.Value) {
		add(c.Value)
	}
	if ref := r.PathValue("org"); ref != "" {
		if o, err := m.svc.OrgByRef(r.Context(), ref); err == nil {
			add(o.ID)
		}
	}
	add(model.PrimaryOrgID)
	for _, c := range r.Cookies() {
		if id, ok := strings.CutPrefix(c.Name, sessionCookiePrefix); ok && model.IsID(id) {
			add(id)
		}
	}
	return ids
}
