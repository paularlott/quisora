// Package events streams change notifications to admin clients with Server-Sent Events, so lists update without a
// refresh when another administrator (on any node) changes something.
//
// Events say only what kind of record changed (and its id when the organization is known); clients refetch through
// the normal, permission-checked API, so nothing is revealed that the viewer could not already read.
package events

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// Kinds that are streamed.
var streamed = map[model.Kind]bool{
	model.KindOrg: true, model.KindUser: true, model.KindGroup: true, model.KindMember: true,
	model.KindTenant: true, model.KindAccess: true, model.KindClient: true, model.KindProvider: true, model.KindAudit: true,
	model.KindKey: true,
	// a tenant's SSH CA keys and the certificates it issued (the tenant page's SSH card)
	model.KindSSHKey: true, model.KindSSHCert: true,
	// a user's own records (the admin user page's cards); scoped by the user, so the hub looks up their organization
	model.KindSession: true, model.KindPasskey: true, model.KindAPIToken: true, model.KindIdentity: true, model.KindGrant: true,
}

// userScoped are the streamed kinds whose record scope is the owning user's id, not an organization's.
var userScoped = map[model.Kind]bool{
	model.KindSession: true, model.KindPasskey: true, model.KindAPIToken: true, model.KindIdentity: true, model.KindGrant: true,
}

// Event is one change notification.
type Event struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
	// User is the owning user of a user's own record (session, passkey, API token, provider link, grant, and an SSH
	// certificate of theirs), so a page showing one user refetches only for theirs. Sent only with the ID.
	User string `json:"user,omitempty"`
	Op   string `json:"op"` // "put" or "delete"
	org  string // organization id; "" when unknown (deletions replicated without their scope)
}

const (
	heartbeat   = 20 * time.Second
	bufferSize  = 64
	maxPerNode  = 2000 // concurrent streams per node
	maxPerUser  = 8    // concurrent streams per viewer (user, client or token owner) per node
	writeWindow = 30 * time.Second
)

// recheckEvery is how often an open stream checks again that its viewer may still have it (session still valid,
// account still enabled, role still allowed, token not revoked), and eventRecheck how soon before an event is sent
// (so a revoked viewer is not sent what changed after the revocation, however quiet the stream was). Variables so
// tests can change them.
var (
	recheckEvery = 5 * time.Second
	eventRecheck = time.Second
)

type subscriber struct {
	ch     chan Event
	orgID  string // organization the viewer administers (a personal stream: the user's own)
	self   string // a personal stream (the account page): only changes to this user's own records
	super  bool
	who    string // the viewer, for the per-viewer cap
	lagged bool   // events were dropped: the client must reload everything
}

// Hub fans change events out to subscribers.
type Hub struct {
	mu    sync.Mutex
	subs  map[*subscriber]struct{}
	perID map[string]int
	now   func() time.Time
	// OrgOfUser returns a user's organization id ("" when unknown), for records scoped by their owner. Set before
	// the hub is used; nil leaves those events without an organization (sent to everyone, without an id).
	OrgOfUser func(userID string) string
	orgMu     sync.Mutex
	orgOf     map[string]string // user id -> organization id (users never change organization)
}

// maxOrgCache bounds the user -> organization cache; it starts over when full.
const maxOrgCache = 10000

func (h *Hub) userOrg(userID string) string {
	if h.OrgOfUser == nil || userID == "" {
		return ""
	}
	h.orgMu.Lock()
	org, ok := h.orgOf[userID]
	h.orgMu.Unlock()
	if ok {
		return org
	}
	org = h.OrgOfUser(userID)
	if org == "" {
		return ""
	}
	h.orgMu.Lock()
	if h.orgOf == nil || len(h.orgOf) >= maxOrgCache {
		h.orgOf = map[string]string{}
	}
	h.orgOf[userID] = org
	h.orgMu.Unlock()
	return org
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{subs: map[*subscriber]struct{}{}, perID: map[string]int{}, now: time.Now}
}

// Publish delivers a record change to every subscriber allowed to see it. It never blocks: a subscriber whose
// buffer is full is marked lagged and told to resynchronise.
func (h *Hub) Publish(rec *store.Record) {
	if !streamed[rec.Kind] {
		return
	}
	h.mu.Lock()
	idle := len(h.subs) == 0
	h.mu.Unlock()
	if idle { // nobody to tell: no store read for the user's organization (this runs as replicated writes apply)
		return
	}
	ev := Event{Kind: string(rec.Kind), ID: rec.ID, Op: "put", org: rec.Scope}
	if rec.Kind == model.KindOrg {
		ev.org = rec.ID
	}
	if userScoped[rec.Kind] {
		ev.User, ev.org = rec.Scope, h.userOrg(rec.Scope)
	}
	if rec.Kind == model.KindKey {
		ev.org = ""
	}
	if rec.Kind == model.KindSSHCert { // org-scoped, and its user's own too (the account page lists them)
		ev.User, _ = rec.Fields["user_id"].(string)
	}
	if rec.Deleted {
		ev.Op = "delete"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if !s.wants(ev) {
			continue
		}
		e := ev
		if ev.org == "" || (ev.org != s.orgID && !s.super) {
			e.ID, e.User = "", "" // unknown or foreign scope: say only that something of this kind changed
		}
		select {
		case s.ch <- e:
		default:
			s.lagged = true
		}
	}
}

func (s *subscriber) wants(ev Event) bool {
	if s.self != "" {
		return s.ownChange(ev)
	}
	switch {
	case ev.Kind == string(model.KindKey):
		return s.super
	case ev.Kind == string(model.KindOrg):
		return s.super || ev.org == s.orgID
	case ev.org == "":
		return true
	}
	return ev.org == s.orgID
}

// ownChange: is ev about the personal stream's user? Their user record, a membership of theirs, or one of their own
// records (sessions, passkeys, API tokens, provider links, grants, SSH certificates), in their organization.
func (s *subscriber) ownChange(ev Event) bool {
	if ev.org != s.orgID {
		return false
	}
	switch {
	case ev.Kind == string(model.KindUser):
		return ev.ID == s.self
	case ev.Kind == string(model.KindMember):
		return strings.HasSuffix(ev.ID, ":"+s.self)
	case userScoped[model.Kind(ev.Kind)], ev.Kind == string(model.KindSSHCert):
		return ev.User == s.self
	}
	return false
}

func (h *Hub) add(s *subscriber) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= maxPerNode || (s.who != "" && h.perID[s.who] >= maxPerUser) {
		return false
	}
	h.subs[s] = struct{}{}
	if s.who != "" {
		h.perID[s.who]++
	}
	return true
}

func (h *Hub) remove(s *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[s]; !ok {
		return
	}
	delete(h.subs, s)
	if s.who != "" {
		if h.perID[s.who]--; h.perID[s.who] <= 0 {
			delete(h.perID, s.who)
		}
	}
}

// Count returns the number of open streams on this node.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Module serves GET /api/events?org=<org name> (administrators: their organization's changes) and
// GET /api-internal/account/events (any signed-in user: changes to their own records, for the account page).
type Module struct {
	Hub *Hub
	s   *web.Server
}

// Register implements web.Module.
func (m *Module) Register(s *web.Server) {
	m.s = s
	s.Mux.Handle("GET "+web.EventsPath, s.RequireManagement("", m.stream))
	s.Mux.Handle("GET /o/{org}"+web.AccountEventsPath, s.InOrg(s.WithSession(http.HandlerFunc(m.accountStream))))
}

// accountStream is the account page's stream: the signed-in user's own changes (an administrator elsewhere adding
// an address, a sign-in on another device, a link followed in another tab). Session only.
func (m *Module) accountStream(w http.ResponseWriter, r *http.Request) {
	u := web.User(r)
	if web.SessionUnchecked(r) {
		web.WriteUnchecked(w)
		return
	}
	if u == nil {
		web.WriteJSON(w, http.StatusUnauthorized, web.ErrorBody{Error: "Your session has ended. Please sign in again."})
		return
	}
	sub := &subscriber{ch: make(chan Event, bufferSize), orgID: u.OrgID, self: u.ID, who: "u:" + u.ID}
	m.serve(w, r, sub, func() bool {
		sess := web.Session(r)
		if sess == nil {
			return false
		}
		s, cur := m.s.Sessions.Lookup(r.Context(), sess.ID)
		return s != nil && cur != nil && cur.ID == u.ID
	})
}

func (m *Module) stream(w http.ResponseWriter, r *http.Request) {
	a := web.Actor(r)
	ctx := r.Context()
	orgID := a.OrgID
	if name := r.URL.Query().Get("org"); name != "" {
		org, err := m.s.Svc.OrgByName(ctx, name)
		if err != nil || (!a.IsSuper() && org.ID != a.OrgID) {
			web.WriteError(w, service.ErrNotFound)
			return
		}
		orgID = org.ID
	}
	if !m.s.Svc.CanManageUsers(a, orgID) {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	sub := &subscriber{ch: make(chan Event, bufferSize), orgID: orgID, super: a.IsSuper(), who: viewer(a)}
	m.serve(w, r, sub, func() bool { return m.stillAllowed(r, orgID, sub.super) })
}

// serve streams sub's events until the client goes, or allowed (checked every recheckEvery, and before an event) says the viewer may no
// longer have the stream.
func (m *Module) serve(w http.ResponseWriter, r *http.Request, sub *subscriber, allowed func() bool) {
	ctx := r.Context()
	if !m.Hub.add(sub) {
		w.Header().Set("Retry-After", "30")
		web.WriteJSON(w, http.StatusServiceUnavailable, web.ErrorBody{Error: "Too many live connections."})
		return
	}
	defer m.Hub.remove(sub)

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // tell reverse proxies not to buffer the stream
	w.WriteHeader(http.StatusOK)
	write := func(format string, args ...any) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(writeWindow))
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write("retry: 5000\nevent: ready\ndata: {}\n\n") {
		return
	}
	tick := time.NewTicker(heartbeat)
	defer tick.Stop()
	recheck := time.NewTicker(recheckEvery)
	defer recheck.Stop()
	checked := time.Now()
	stillAllowed := func() bool {
		checked = time.Now()
		if allowed() {
			return true
		}
		_ = write("event: ended\ndata: {}\n\n") // the client reloads, and signs in again if it must
		return false
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.s.Stopping(): // the server is shutting down: the client reconnects (retry), elsewhere or later
			return
		case <-recheck.C:
			if !stillAllowed() {
				return
			}
		case <-tick.C:
			if !write(": keep-alive\n\n") {
				return
			}
		case ev := <-sub.ch:
			if time.Since(checked) >= eventRecheck && !stillAllowed() {
				return
			}
			if m.lagged(sub) {
				if !write("event: resync\ndata: {}\n\n") {
					return
				}
				continue
			}
			b, _ := json.Marshal(ev)
			if !write("event: change\ndata: %s\n\n", b) {
				return
			}
		}
	}
}

// viewer names who opened a stream, for the per-viewer cap.
func viewer(a *service.Actor) string {
	switch {
	case a.UserID != "":
		return "u:" + a.UserID
	case a.ClientID != "":
		return "c:" + a.ClientID
	}
	return "n:" + a.Name
}

// stillAllowed checks again, for an open stream, what opening it checked: the session (or token) is still valid,
// its user still enabled, and still allowed to watch the organization at the same level. A stream outliving a
// sign-out, a disabled account, a demotion or a revoked token ends.
func (m *Module) stillAllowed(r *http.Request, orgID string, super bool) bool {
	ctx := r.Context()
	var a *service.Actor
	if tok, ok := web.BearerToken(r); ok {
		if m.s.Bearer == nil {
			return false
		}
		ba, err := m.s.Bearer(ctx, r, tok)
		if err != nil || ba == nil || !ba.HasScope(service.ScopeAdmin) {
			return false
		}
		a = ba
	} else {
		sess := web.Session(r)
		if sess == nil {
			return false
		}
		s, u := m.s.Sessions.Lookup(ctx, sess.ID)
		if s == nil || u == nil || (u.Role.Privileged() && !model.MFA(s.AMR)) {
			return false
		}
		a = service.ActorForUser(u, web.ClientIP(r))
	}
	if a.IsSuper() != super || (!a.IsSuper() && a.OrgID != orgID) {
		return false
	}
	return m.s.Svc.CanManageUsers(a, orgID)
}

// lagged reports (and clears) whether events were dropped for sub.
func (m *Module) lagged(s *subscriber) bool {
	m.Hub.mu.Lock()
	defer m.Hub.mu.Unlock()
	l := s.lagged
	s.lagged = false
	return l
}
