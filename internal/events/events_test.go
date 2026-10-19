package events

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

func TestHubScoping(t *testing.T) {
	h := NewHub()
	a := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	b := &subscriber{ch: make(chan Event, 8), orgID: "org-b"}
	super := &subscriber{ch: make(chan Event, 8), orgID: "primary", super: true}
	for _, s := range []*subscriber{a, b, super} {
		h.add(s)
	}
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s1", Scope: "u1"}) // not streamed
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u2", Deleted: true})  // scope unknown
	h.Publish(&store.Record{Kind: model.KindOrg, ID: "org-b", Scope: ""})    // org record
	if got := drain(a); got != "user:u1:put user::delete" {
		t.Errorf("org-a got %q", got)
	}
	if got := drain(b); got != "user::delete org:org-b:put" {
		t.Errorf("org-b got %q", got)
	}
	if got := drain(super); got != "user::delete org:org-b:put" { // scoped to the org being viewed, plus org list changes
		t.Errorf("super got %q", got)
	}
}

func TestHubOverflowMarksLagged(t *testing.T) {
	h := NewHub()
	s := &subscriber{ch: make(chan Event, 1), orgID: "o"}
	h.add(s)
	h.Publish(&store.Record{Kind: model.KindUser, ID: "1", Scope: "o"})
	h.Publish(&store.Record{Kind: model.KindUser, ID: "2", Scope: "o"})
	if !s.lagged {
		t.Fatal("overflow must mark the subscriber lagged")
	}
}

func drain(s *subscriber) string {
	var out []string
	for {
		select {
		case e := <-s.ch:
			out = append(out, e.Kind+":"+e.ID+":"+e.Op)
		default:
			return strings.Join(out, " ")
		}
	}
}

// End to end: a super admin's stream receives a change made through the service by someone else; a plain user is
// refused.
func TestStream(t *testing.T) {
	hub := NewHub()
	env := webtest.New(t, webtest.Options{Modules: func(s *web.Server) []web.Module {
		return []web.Module{&Module{Hub: hub}}
	}})
	// Feed the hub from the store the way the app does (wrap writes through a hook).
	c, _ := env.ConsoleSession(env.Admin)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, env.URL+web.EventsPath+"?org=primary", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(resp.Body)
	next := func(event string) string {
		t.Helper()
		var name string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: ") && name == event:
				return strings.TrimPrefix(line, "data: ")
			}
		}
		t.Fatalf("stream ended before %s", event)
		return ""
	}
	next("ready")
	u, err := env.Svc.CreateUser(context.Background(), service.System, env.Primary.ID, service.UserInput{GivenName: gn("T"), Username: ptr("newbie"), Email: ptr("newbie@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := env.Store.Get(context.Background(), model.KindUser, u.ID)
	hub.Publish(rec)
	var ev Event
	if err := json.Unmarshal([]byte(next("change")), &ev); err != nil || ev.Kind != "user" || ev.ID != u.ID || ev.Op != "put" {
		t.Fatalf("event %+v %v", ev, err)
	}
	// A plain user cannot subscribe.
	plain, _ := env.Svc.CreateUser(context.Background(), service.System, env.Primary.ID, service.UserInput{GivenName: gn("T"), Username: ptr("plain"), Email: ptr("plain@example.com")})
	pc, _ := env.Session(plain)
	r2, _ := pc.Get(env.URL + web.EventsPath)
	if r2.StatusCode != http.StatusForbidden {
		t.Fatalf("plain user: %d", r2.StatusCode)
	}
	r2.Body.Close()
}

func ptr[T any](v T) *T { return &v }
