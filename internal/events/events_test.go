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
	h.OrgOfUser = func(id string) string { return map[string]string{"u1": "org-a"}[id] }
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindLink, ID: "l1", Scope: "u1"})    // not streamed
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s1", Scope: "u1"}) // a user's own record: their org only
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u2", Deleted: true})  // scope unknown
	h.Publish(&store.Record{Kind: model.KindOrg, ID: "org-b", Scope: ""})    // org record
	if got := drain(a); got != "user:u1:put session:s1:put user::delete" {
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

// A user's own record carries its owner for viewers of their organization (a user page refetches only for its user);
// a viewer of another organization learns only that something of the kind changed; without a lookup, nobody gets ids.
func TestHubUserScopedOwner(t *testing.T) {
	h := NewHub()
	a := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	b := &subscriber{ch: make(chan Event, 8), orgID: "org-b"}
	h.add(a)
	h.add(b)
	h.OrgOfUser = func(id string) string { return map[string]string{"u1": "org-a"}[id] }
	h.Publish(&store.Record{Kind: model.KindPasskey, ID: "pk1", Scope: "u1", Deleted: true})
	if e := <-a.ch; e.User != "u1" || e.ID != "pk1" || e.Op != "delete" {
		t.Errorf("same org: %+v", e)
	}
	select {
	case e := <-b.ch:
		t.Errorf("other org got %+v", e)
	default:
	}
	h2 := NewHub()
	c := &subscriber{ch: make(chan Event, 8), orgID: "org-a"}
	h2.add(c)
	h2.Publish(&store.Record{Kind: model.KindAPIToken, ID: "t1", Scope: "u1"})
	if e := <-c.ch; e.User != "" || e.ID != "" || e.Kind != "apitoken" {
		t.Errorf("no lookup: %+v", e)
	}
}

// A personal stream (the account page) carries only its user's own changes: their user record, their memberships and
// their own records; nothing about other users, groups or clients.
func TestHubPersonalStream(t *testing.T) {
	h := NewHub()
	h.OrgOfUser = func(id string) string { return map[string]string{"u1": "org-a", "u2": "org-a"}[id] }
	me := &subscriber{ch: make(chan Event, 16), orgID: "org-a", self: "u1"}
	h.add(me)
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u2", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindMember, ID: "g1:u1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindMember, ID: "g1:u2", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindSession, ID: "s1", Scope: "u1"})
	h.Publish(&store.Record{Kind: model.KindPasskey, ID: "p2", Scope: "u2"})
	h.Publish(&store.Record{Kind: model.KindGroup, ID: "g1", Scope: "org-a"})
	h.Publish(&store.Record{Kind: model.KindUser, ID: "u3", Deleted: true}) // scope unknown
	if got := drain(me); got != "user:u1:put member:g1:u1:put session:s1:put" {
		t.Errorf("personal stream got %q", got)
	}
}

// Any signed-in user may open the account stream; without a session it is refused.
func TestAccountStreamOpen(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&Module{Hub: NewHub()}} }})
	plain, _ := env.Svc.CreateUser(context.Background(), service.System, env.Primary.ID, service.UserInput{GivenName: gn("T"), Username: ptr("plain"), Email: ptr("plain@example.com")})
	pc, _ := env.Session(plain)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", env.URL+web.AccountEventsPath, nil)
	res, err := pc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(res.Body).ReadString('\n')
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" || !strings.HasPrefix(line, "retry:") {
		t.Fatalf("account stream: %d %q", res.StatusCode, line)
	}
	anon := env.Client()
	r2, err := anon.Get(env.URL + web.AccountEventsPath)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %d", r2.StatusCode)
	}
}
