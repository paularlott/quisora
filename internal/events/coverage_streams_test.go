package events

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
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
func TestStreamUnknownOrg(t *testing.T) {
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

// The account stream ends when the viewer's session does.
func TestAccountStreamEndsWithSession(t *testing.T) {
	old := recheckEvery
	recheckEvery = 50 * time.Millisecond
	t.Cleanup(func() { recheckEvery = old })
	hub := NewHub()
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&Module{Hub: hub}} }})
	c, _ := env.ConsoleSession(env.Admin)
	resp, sc := openStream(t, c, env.URL+web.AccountEventsPath)
	if resp.StatusCode != 200 || !waitEvent(sc, "ready") {
		t.Fatalf("account stream: %d", resp.StatusCode)
	}
	sessions, _ := env.Svc.Sessions.All(context.Background(), env.Admin.ID)
	for _, s := range sessions {
		if err := env.Server.Sessions.Delete(context.Background(), s.ID); err != nil {
			t.Fatal(err)
		}
	}
	if !waitEvent(sc, "ended") {
		t.Fatal("the account stream outlived its session")
	}
	for sc.Scan() {
	}
	waitCount(t, hub, 0)
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
