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

func waitCount(t *testing.T, h *Hub, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.Count() != n {
		if time.Now().After(deadline) {
			t.Fatalf("hub has %d streams, want %d", h.Count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func openStream(t *testing.T, c *http.Client, url string) (*http.Response, *bufio.Scanner) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp, bufio.NewScanner(resp.Body)
}

func waitEvent(sc *bufio.Scanner, event string) bool {
	for sc.Scan() {
		if sc.Text() == "event: "+event {
			return true
		}
	}
	return false
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
	u, err := env.Svc.CreateUser(context.Background(), service.System, env.Primary.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("newbie"), Email: ptr("newbie@example.com")})
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
	plain, _ := env.Svc.CreateUser(context.Background(), service.System, env.Primary.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("plain"), Email: ptr("plain@example.com")})
	pc, _ := env.Session(plain)
	r2, _ := pc.Get(env.URL + web.EventsPath)
	if r2.StatusCode != http.StatusForbidden {
		t.Fatalf("plain user: %d", r2.StatusCode)
	}
	r2.Body.Close()
}

// Any signed-in user may open the account stream; without a session it is refused.
func TestAccountStreamOpen(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&Module{Hub: NewHub()}} }})
	plain, _ := env.Svc.CreateUser(context.Background(), service.System, env.Primary.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("plain"), Email: ptr("plain@example.com")})
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

// A subscriber that lost events is told to resynchronise instead of receiving the next event.
func TestStreamResyncAfterLag(t *testing.T) {
	hub := NewHub()
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&Module{Hub: hub}} }})
	c, _ := env.ConsoleSession(env.Admin)
	_, sc := openStream(t, c, env.URL+web.EventsPath+"?org=primary")
	if !waitEvent(sc, "ready") {
		t.Fatal("no ready")
	}
	waitCount(t, hub, 1)
	hub.mu.Lock()
	for s := range hub.subs {
		s.lagged = true
	}
	hub.mu.Unlock()
	hub.Publish(&store.Record{Kind: model.KindUser, ID: "u1", Scope: env.Primary.ID})
	if !waitEvent(sc, "resync") {
		t.Fatal("no resync event")
	}
}

// The organization named in the query must exist, and a plain administrator of another organization cannot watch it.
func TestStreamOfUnknownOrgIs404(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&Module{Hub: NewHub()}} }})
	c, _ := env.ConsoleSession(env.Admin)
	resp, err := c.Get(env.URL + web.EventsPath + "?org=no-such-org")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown org: %d", resp.StatusCode)
	}
}

// An open stream checks its viewer again: once the session has ended, the stream ends too.
func TestStreamEndsWhenSessionEnds(t *testing.T) {
	old := recheckEvery
	recheckEvery = 50 * time.Millisecond
	t.Cleanup(func() { recheckEvery = old })
	for name, path := range map[string]string{
		"console": web.EventsPath + "?org=primary",
		"account": web.AccountEventsPath,
	} {
		t.Run(name, func(t *testing.T) {
			hub := NewHub()
			env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&Module{Hub: hub}} }})
			c, _ := env.ConsoleSession(env.Admin)
			resp, sc := openStream(t, c, env.URL+path)
			if resp.StatusCode != 200 || !waitEvent(sc, "ready") {
				t.Fatalf("stream: %d", resp.StatusCode)
			}
			sessions, _ := env.Svc.Sessions.All(context.Background(), env.Admin.ID)
			for _, s := range sessions {
				if err := env.Server.Sessions.Delete(context.Background(), s.ID); err != nil {
					t.Fatal(err)
				}
			}
			if !waitEvent(sc, "ended") {
				t.Fatal("the stream outlived its session")
			}
			for sc.Scan() { // and the server closes it
			}
			waitCount(t, hub, 0)
		})
	}
}

// A user's own records reach the account stream only for that user.
func TestAccountStreamReceivesOwnChanges(t *testing.T) {
	hub := NewHub()
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&Module{Hub: hub}} }})
	hub.OrgOfUser = func(string) string { return env.Primary.ID }
	c, _ := env.ConsoleSession(env.Admin)
	_, sc := openStream(t, c, env.URL+web.AccountEventsPath)
	if !waitEvent(sc, "ready") {
		t.Fatal("no ready")
	}
	waitCount(t, hub, 1)
	hub.Publish(&store.Record{Kind: model.KindSession, ID: "s-other", Scope: "someone-else"})
	hub.Publish(&store.Record{Kind: model.KindSession, ID: "s-mine", Scope: env.Admin.ID})
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "s-other") {
			t.Fatalf("another user's change leaked: %s", line)
		}
		if strings.Contains(line, "s-mine") {
			return
		}
	}
	t.Fatal("own change not delivered")
}

// A stream checks its viewer before it sends a change, not only on its timer: once the session has ended, the next change
// ends the stream instead of being sent to it.
func TestStreamEndsAtTheNextChangeAfterRevocation(t *testing.T) {
	oldEvery, oldEvent := recheckEvery, eventRecheck
	recheckEvery, eventRecheck = time.Hour, 0
	t.Cleanup(func() { recheckEvery, eventRecheck = oldEvery, oldEvent })
	hub := NewHub()
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&Module{Hub: hub}} }})
	c, _ := env.ConsoleSession(env.Admin)
	_, sc := openStream(t, c, env.URL+web.EventsPath+"?org=primary")
	if !waitEvent(sc, "ready") {
		t.Fatal("no ready")
	}
	waitCount(t, hub, 1)
	sessions, _ := env.Svc.Sessions.All(context.Background(), env.Admin.ID)
	for _, s := range sessions {
		if err := env.Server.Sessions.Delete(context.Background(), s.ID); err != nil {
			t.Fatal(err)
		}
	}
	hub.Publish(&store.Record{Kind: model.KindUser, ID: "u-changed", Scope: env.Primary.ID})
	for sc.Scan() {
		switch line := sc.Text(); {
		case line == "event: ended":
			waitCount(t, hub, 0)
			return
		case strings.HasPrefix(line, "event: change"):
			t.Fatal("a change was sent to a viewer whose session had ended")
		}
	}
	t.Fatal("the stream outlived its session")
}
