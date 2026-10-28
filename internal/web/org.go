package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

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

// InOrg serves next for the organization its path names ({org}: an id or a name): Org(r) is that organization, and the
// request's session is its session only. An organization that does not exist is not found; one that cannot be read
// now is unavailable (503), never "not found".
func (s *Server) InOrg(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		org, err := s.Svc.OrgByRef(r.Context(), r.PathValue("org"))
		switch {
		case errors.Is(err, service.ErrNotFound):
			http.NotFound(w, r)
			return
		case err != nil:
			writeUnavailable(w, r.URL.Path, "This server cannot serve this organization right now. Please try again shortly.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxOrgKey{}, org)))
	})
}

// Org returns the organization of the request's path (InOrg), or nil outside one.
func Org(r *http.Request) *model.Org {
	o, _ := r.Context().Value(ctxOrgKey{}).(*model.Org)
	return o
}

// maxConsoleSessions bounds the session cookies a console request is checked against (each may cost a read).
const maxConsoleSessions = 8

// lastOrgCookie names the organization of the browser's latest sign-in (set with every session cookie): the console
// acts as the person who signed in last, as it did when a browser held one session at a time, unless that person
// cannot use the console (Sessions.Check).
const lastOrgCookie = "__Host-quisora_last_org"

// sessionOrgs returns the organizations whose session the request may present, in the order they are tried. Under
// /o/<org> it is that organization's only (InOrg). Elsewhere (the console and the management API, which are the
// server's) it is the organization of the browser's latest sign-in, then the organization the path administers
// ({org}), then the primary organization, whose administrators administer the server, then any other organization the
// browser holds a session of. Sessions.Check prefers, in this order, the first session whose user can use the console;
// what that user may then do is the service's to decide. The error is the store's refusal to resolve {org}: skipping
// that organization would let the request act as another session than the one meant.
func (m *Sessions) sessionOrgs(r *http.Request) ([]string, error) {
	if org := Org(r); org != nil {
		return []string{org.ID}, nil
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
		switch o, err := m.svc.OrgByRef(r.Context(), ref); {
		case err == nil:
			add(o.ID)
		case !errors.Is(err, service.ErrNotFound):
			return nil, err
		}
	}
	add(model.PrimaryOrgID)
	for _, c := range r.Cookies() {
		if id, ok := strings.CutPrefix(c.Name, sessionCookiePrefix); ok && model.IsID(id) {
			add(id)
		}
	}
	return ids, nil
}
