package events

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A caller verification's changes go to the own streams of its customer and of the agent who started it, saying only
// what kind changed; never to anyone else's own stream, nor to the console's streams, a super admin's included.
func TestPersonalEventsGoToWhomTheyConcern(t *testing.T) {
	h := NewHub()
	customer := &subscriber{ch: make(chan Event, 8), own: "pat"}
	agent := &subscriber{ch: make(chan Event, 8), own: "sam"}
	other := &subscriber{ch: make(chan Event, 8), own: "kim"}
	admin := &subscriber{ch: make(chan Event, 8), orgID: "custa", actor: actorOf("custa", model.RoleAdmin)}
	super := &subscriber{ch: make(chan Event, 8), orgID: "primary", super: true}
	for _, s := range []*subscriber{customer, agent, other, admin, super} {
		h.add(s)
	}
	h.Publish(&store.Record{Kind: model.KindCallVerification, ID: "v1", Scope: "custa",
		Fields: map[string]any{"user_id": "pat", "agent_day": model.VerifyAgentDay("sam", time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC))}})
	h.Publish(&store.Record{Kind: model.KindCallVerification, ID: "v1", Deleted: true}) // removed: nobody's page shows it
	for name, c := range map[string]struct {
		s    *subscriber
		want string
	}{"customer": {customer, "callverification::put"}, "agent": {agent, "callverification::put"}, "someone else": {other, ""},
		"an administrator": {admin, ""}, "a super admin": {super, ""}} {
		if got := drain(c.s); got != c.want {
			t.Errorf("%s got %q, want %q", name, got, c.want)
		}
	}
	// and an own stream gets nothing of the console's kinds
	h.UserInfo = func(string) (string, model.Role) { return "custa", model.RoleUser }
	h.Publish(&store.Record{Kind: model.KindUser, ID: "pat", Scope: "custa"})
	if got := drain(customer); got != "" {
		t.Errorf("an own stream got a console event: %q", got)
	}
}
