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
	model.KindConsent: true,
}

// userScoped are the streamed kinds whose record scope is the owning user's id, not an organization's.
var userScoped = map[model.Kind]bool{
	model.KindSession: true, model.KindPasskey: true, model.KindAPIToken: true, model.KindIdentity: true, model.KindGrant: true,
	model.KindConsent: true,
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
	maxPerNode  = 2000 // concurrent streams per node (staff only: managers and up)
	writeWindow = 30 * time.Second
	// maxPerUser is the concurrent streams per viewer (user, client or token owner) per node. A browser shares one
	// stream among its tabs (per stream URL), so 4 is a few devices, or a super admin with a few organizations open.
	maxPerUser = 4
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
	// UserInfo returns a user's organization id ("" when the user is unknown) and whether they are a super admin, for
	// records about a user. Set before the hub is used; nil leaves every user unknown (non-super viewers get no
	// event about one, and a user's own records are sent to everyone without an id).
	UserInfo func(userID string) (org string, super bool)
	infoMu   sync.Mutex
	infoOf   map[string]userInfo
}

type userInfo struct {
	org   string
	super bool
}

// maxInfoCache bounds the user -> info cache; it starts over when full.
const maxInfoCache = 10000

func (h *Hub) setInfo(userID string, in userInfo) {
	h.infoMu.Lock()
	if h.infoOf == nil || len(h.infoOf) >= maxInfoCache {
		h.infoOf = map[string]userInfo{}
	}
	h.infoOf[userID] = in
	h.infoMu.Unlock()
}

// info returns what is known of a user (one store read when not cached); ok is false for an unknown user.
func (h *Hub) info(userID string) (userInfo, bool) {
	if userID == "" {
		return userInfo{}, false
	}
	h.infoMu.Lock()
	in, ok := h.infoOf[userID]
	h.infoMu.Unlock()
	if ok {
		return in, true
	}
	if h.UserInfo == nil {
		return userInfo{}, false
	}
	org, super := h.UserInfo(userID)
	if org == "" {
		return userInfo{}, false
	}
	in = userInfo{org, super}
	h.setInfo(userID, in)
	return in, true
}

// remember keeps the role of a user that was written, so a promotion or demotion applies to the next event. A
// deletion keeps the last known one.
func (h *Hub) remember(rec *store.Record) {
	if rec.Kind != model.KindUser || rec.Deleted {
		return
	}
	if super, ok := rec.Fields["super_admin"].(bool); ok && rec.Scope != "" {
		h.setInfo(rec.ID, userInfo{rec.Scope, super})
		return
	}
	h.infoMu.Lock()
	delete(h.infoOf, rec.ID)
	h.infoMu.Unlock()
}

// concerns returns the user a record is about ("" when none), and whether the record is hidden from non-super
// viewers whatever the user: an audit event recorded as about a super admin, and any record whose user a deletion
// does not say (tombstones carry no scope or fields).
func concerns(rec *store.Record) (user string, hidden bool) {
	switch {
	case rec.Kind == model.KindUser:
		return rec.ID, false
	case rec.Kind == model.KindMember: // "groupID:userID"
		if u, _ := rec.Fields["user_id"].(string); u != "" {
			return u, false
		}
		if i := strings.LastIndex(rec.ID, ":"); i >= 0 {
			return rec.ID[i+1:], false
		}
		return "", true
	case rec.Kind == model.KindSSHCert:
		u, _ := rec.Fields["user_id"].(string)
		return u, rec.Deleted && u == ""
	case rec.Kind == model.KindAudit:
		sa, _ := rec.Fields["super_admin"].(bool)
		return "", rec.Deleted || sa
	case userScoped[rec.Kind]:
		return rec.Scope, rec.Scope == ""
	}
	return "", false
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{subs: map[*subscriber]struct{}{}, perID: map[string]int{}, now: time.Now}
}

// Publish delivers a record change to every subscriber allowed to see it. Super admins are hidden from everyone below
// super admin, so a viewer who is not one gets no event about one (or about a user the hub cannot tell). It never
// blocks: a subscriber whose buffer is full is marked lagged and told to resynchronise.
func (h *Hub) Publish(rec *store.Record) {
	if !streamed[rec.Kind] {
		return
	}
	h.remember(rec) // even when nobody listens: a later subscriber must not find a stale role
	h.mu.Lock()
	idle, plain := len(h.subs) == 0, false
	for s := range h.subs {
		plain = plain || !s.super
	}
	h.mu.Unlock()
	if idle { // nobody to tell: no store read for the user's organization (this runs as replicated writes apply)
		return
	}
	ev := Event{Kind: string(rec.Kind), ID: rec.ID, Op: "put", org: rec.Scope}
	if rec.Kind == model.KindOrg {
		ev.org = rec.ID
	}
	if rec.Kind == model.KindKey {
		ev.org = ""
	}
	user, hide := concerns(rec)
	if user != "" && (plain || userScoped[rec.Kind]) {
		in, ok := h.info(user)
		hide = hide || !ok || in.super
		if userScoped[rec.Kind] {
			ev.User, ev.org = rec.Scope, in.org
		}
	}
	if rec.Kind == model.KindSSHCert { // org-scoped, and its user's own too (the admin user page lists them)
		ev.User = user
	}
	if rec.Deleted {
		ev.Op = "delete"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if !s.wants(ev) || (hide && !s.super) {
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

// Module serves GET /api/events?org=<org name>: the admin console's live updates (managers and up: their
// organization's changes).
type Module struct {
	Hub *Hub
	s   *web.Server
}

// Register implements web.Module.
func (m *Module) Register(s *web.Server) {
	m.s = s
	s.Mux.Handle("GET "+web.EventsPath, s.RequireManagement("", m.stream))
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
