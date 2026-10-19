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
}

// Event is one change notification.
type Event struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
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
// account still enabled, role still allowed, token not revoked). A variable so tests can shorten it.
var recheckEvery = time.Minute

type subscriber struct {
	ch     chan Event
	orgID  string // organization the viewer administers
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
	ev := Event{Kind: string(rec.Kind), ID: rec.ID, Op: "put", org: rec.Scope}
	if rec.Kind == model.KindOrg {
		ev.org = rec.ID
	}
	if rec.Kind == model.KindKey {
		ev.org = ""
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
			e.ID = "" // unknown or foreign scope: say only that something of this kind changed
		}
		select {
		case s.ch <- e:
		default:
			s.lagged = true
		}
	}
}

func (s *subscriber) wants(ev Event) bool {
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

// Module serves GET /api/v1/events?org=<org name>.
type Module struct {
	Hub *Hub
	s   *web.Server
}

// Register implements web.Module.
func (m *Module) Register(s *web.Server) {
	m.s = s
	s.Mux.Handle("GET "+web.EventsPath, s.RequireManagement(m.stream))
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-recheck.C:
			if !m.stillAllowed(r, orgID, sub.super) {
				_ = write("event: ended\ndata: {}\n\n") // the client reloads, and signs in again if it must
				return
			}
		case <-tick.C:
			if !write(": keep-alive\n\n") {
				return
			}
		case ev := <-sub.ch:
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
