package events

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// An open stream checks its viewer again: once the session has ended, the stream ends too.
func TestStreamEndsWhenSessionEnds(t *testing.T) {
	old := recheckEvery
	recheckEvery = 50 * time.Millisecond
	t.Cleanup(func() { recheckEvery = old })
	hub := NewHub()
	env := webtest.New(t, webtest.Options{Modules: func(s *web.Server) []web.Module {
		return []web.Module{&Module{Hub: hub}}
	}})
	c, _ := env.ConsoleSession(env.Admin)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, env.URL+web.EventsPath+"?org=primary", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	waitFor := func(event string) bool {
		for sc.Scan() {
			if sc.Text() == "event: "+event {
				return true
			}
		}
		return false
	}
	if !waitFor("ready") {
		t.Fatal("no ready event")
	}
	sessions, _ := env.Svc.Sessions.All(context.Background(), env.Admin.ID)
	for _, s := range sessions {
		if err := env.Server.Sessions.Delete(context.Background(), s.ID); err != nil {
			t.Fatal(err)
		}
	}
	if !waitFor("ended") {
		t.Fatal("the stream outlived its session")
	}
	for sc.Scan() { // and the server closes it
	}
	if hub.Count() != 0 {
		t.Fatalf("%d streams still open", hub.Count())
	}
}

// One viewer cannot hold more than maxPerUser streams on a node; others are unaffected.
func TestStreamsCappedPerViewer(t *testing.T) {
	h := NewHub()
	for i := 0; i < maxPerUser; i++ {
		if !h.add(&subscriber{ch: make(chan Event, 1), orgID: "o", who: "u:1"}) {
			t.Fatalf("stream %d refused", i)
		}
	}
	extra := &subscriber{ch: make(chan Event, 1), orgID: "o", who: "u:1"}
	if h.add(extra) {
		t.Fatal("cap not enforced")
	}
	other := &subscriber{ch: make(chan Event, 1), orgID: "o", who: "u:2"}
	if !h.add(other) {
		t.Fatal("another viewer refused")
	}
	h.remove(other)
	h.remove(other) // twice is harmless
	for s := range h.subs {
		h.remove(s)
		break
	}
	if !h.add(extra) {
		t.Fatal("a closed stream did not free its slot")
	}
	if !strings.HasPrefix(viewer(env0()), "n:") {
		t.Fatal("viewer of an anonymous actor")
	}
}

func env0() *service.Actor { return &service.Actor{Name: "x"} }
