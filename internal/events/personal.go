package events

import (
	"net/http"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// A person's own stream (GET /o/{org}/api-internal/account/events): anyone signed in, not the staff only, is told of
// changes to the records about them that their account pages follow, and of nothing else. Today that is caller
// verifications: the customer's Verify a call page shows a verification as soon as an agent starts it, and the
// agent's Verify a caller page the customer's answer as soon as it is given. An event names only the kind: the page
// fetches what changed through the account API, as the admin console does through the management API.

// personal are the kinds sent on people's own streams, never on the console's.
var personal = map[model.Kind]bool{model.KindCallVerification: true}

// personalUsers are the people a record of a personal kind concerns: a verification's customer and the agent who
// started it (from its index fields; a deletion carries none, and concerns nobody: nothing a page shows is deleted).
func personalUsers(rec *store.Record) []string {
	if rec.Deleted {
		return nil
	}
	var out []string
	if u, _ := rec.Fields["user_id"].(string); u != "" {
		out = append(out, u)
	}
	if day, _ := rec.Fields["agent_day"].(string); day != "" { // "<agent>/<day>"
		if i := strings.LastIndexByte(day, '/'); i > 0 {
			out = append(out, day[:i])
		}
	}
	return out
}

// publishPersonal sends a change of a personal kind to the own streams of the people it concerns.
func (h *Hub) publishPersonal(rec *store.Record) {
	users := personalUsers(rec)
	if len(users) == 0 {
		return
	}
	ev := Event{Kind: string(rec.Kind), Op: "put"}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.own == "" {
			continue
		}
		for _, u := range users {
			if s.own == u {
				select {
				case s.ch <- ev:
				default:
					s.lagged = true
				}
				break
			}
		}
	}
}

// ownStream serves a signed-in person their own stream: their session (not a guest's from another organization) in
// the organization the path names. It ends when the session does, or the account is disabled.
func (m *Module) ownStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, u, a := web.Session(r), web.User(r), web.Actor(r)
	if sess == nil || u == nil || a == nil {
		web.WriteJSON(w, http.StatusUnauthorized, web.ErrorBody{Error: "Sign in first."})
		return
	}
	if len(a.Sources) > 0 || !u.Active {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	if org, err := m.s.Svc.OrgByRef(ctx, r.PathValue("org")); err != nil || org.ID != u.OrgID {
		web.WriteError(w, service.ErrNotFound)
		return
	}
	sub := &subscriber{ch: make(chan Event, bufferSize), own: u.ID, actor: a, who: viewer(a)}
	m.serve(w, r, sub, func() bool {
		s, cur := m.s.Sessions.Lookup(r.Context(), sess.ID)
		return s != nil && cur != nil && cur.ID == u.ID && cur.Active
	})
}
