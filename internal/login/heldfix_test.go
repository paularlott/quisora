package login_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
)

// hookEph runs hook once, just before the entry ns/id is written back (set, or replaced where it is): the moment
// between a request's read of an entry and its save, in which another request ends the entry.
type hookEph struct {
	ephemeral.Store
	ns, id string
	hook   func()
}

func (e *hookEph) run(ns, id string) {
	if ns == e.ns && id == e.id && e.hook != nil {
		h := e.hook
		e.hook = nil
		h()
	}
}

func (e *hookEph) Set(ctx context.Context, ns, id string, v []byte, ttl time.Duration) error {
	e.run(ns, id)
	return e.Store.Set(ctx, ns, id, v, ttl)
}

func (e *hookEph) Replace(ctx context.Context, ns, id string, v []byte) error {
	e.run(ns, id)
	return e.Store.(interface {
		Replace(context.Context, string, string, []byte) error
	}).Replace(ctx, ns, id, v)
}

// heldWindow is the window of the held budgets now: a test that compares counts taken at two moments skips itself
// when the window turned between them.
func heldWindow() int64 { return time.Now().UnixNano() / int64(ephemeral.HeldWindow) }

// A sign-in's ticket that was used while another request was between reading it and storing it again is not made
// again by that request: it would come back with the stamp of a charge already given back, and a finished sign-in's
// ticket would work once more.
func TestTicketEndedIsNotSavedAgain(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	quinn := e.user(t, org, "quinn", model.RoleUser)
	tid, err := e.Mod.PutEnrolTicket(quinn.ID)
	if err != nil {
		t.Fatal(err)
	}
	b := e.browserAt(t, org)
	ctx := context.Background()
	orig := e.Server.Eph
	e.Server.Eph = &hookEph{Store: orig, ns: "login", id: tid, hook: func() {
		if _, err := orig.Take(ctx, "login", tid); err != nil { // the sign-in finished in another tab
			t.Errorf("take: %v", err)
		}
	}}
	t.Cleanup(func() { e.Server.Eph = orig })
	res, out := b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": tid})
	wantStatus(t, res, out, 401)
	if _, err := orig.Get(ctx, "login", tid); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("a ticket that was used is there again: %v", err)
	}
}

// A ticket's charge to the address its sign-in comes from is given back when the ticket is used: an address many
// people sign in from is bounded by the sign-ins it has under way, not by how many it finished in twenty minutes.
func TestTicketChargeGivenBackWhenUsed(t *testing.T) {
	e := newEnv(t, heldKB(64))
	secret := e.giveTOTP(t, e.member(t))
	ctx := context.Background()
	holding := func() int64 {
		n, _ := ephemeral.Holding(ctx, e.Server.Eph, ephemeral.HeldNS, "ip|127.0.0.1", ephemeral.HeldWindow)
		return n
	}
	window := heldWindow()
	next := "/o/primary/x?" + strings.Repeat("a", 1900) // the ticket carries the path the sign-in is to end at
	b := e.browser(t)
	res, out := b.post("/o/primary/api-internal/login/password", map[string]any{"email": "member@example.com",
		"password": userPassword, "next": next})
	wantStatus(t, res, out, 200)
	if n := holding(); n < 1900 {
		t.Fatalf("a ticket with a path of 1.9 KB is charged %d bytes to its address", n)
	}
	res, out = b.post("/o/primary/api-internal/login/totp", map[string]any{"ticket": str(out, "ticket"), "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)
	if heldWindow() != window {
		t.Skip("the held window turned during the test")
	}
	if n := holding(); n != 0 {
		t.Fatalf("after the sign-in finished its address is still charged %d bytes", n)
	}
}

// The spray limit holds when the record of the spray cannot be kept (the guard records' room is full): the spray is
// remembered by a counter instead, and an address is held to its budget across the organization as under a recorded
// one, rather than the limit lapsing for as long as that room stays full.
func TestSprayHoldsWhenItsRecordCannotBeKept(t *testing.T) {
	e := newEnv(t, sprayConfig(5))
	org := e.org(t, "acme", nil)
	var users []*model.User
	for i := range 30 {
		users = append(users, e.user(t, org, fmt.Sprintf("u%02d", i), model.RoleUser))
	}
	localEph(t, e).GuardBudget = 1 // nothing fits among the guard records
	for i := range 6 {
		b := e.browser(t)
		b.fromAddress("192.0.2.1")
		res, out := b.login("acme", fmt.Sprintf("nobody%d", i), "x")
		wantStatus(t, res, out, 401)
	}
	if _, err := e.Server.Eph.Get(context.Background(), ephemeral.GuardPrefix+"spray", org.ID); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("the spray's record was kept in a room with none: %v", err)
	}
	// one address, one guess at each account: under spray it has as many across the organization as one account gets
	b := e.browser(t)
	b.fromAddress("203.0.113.9")
	checked, refused := 0, 0
	for _, u := range users {
		switch res, out := b.login("acme", u.Username, "guess"); res.StatusCode {
		case http.StatusUnauthorized:
			checked++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Fatalf("a guess: %d %v", res.StatusCode, out["_raw"])
		}
	}
	if checked != 10 || refused != 20 {
		t.Fatalf("one address had %d guesses checked and %d refused across 30 accounts under a spray whose record "+
			"could not be kept, want 10 and 20", checked, refused)
	}
	if n := len(e.audits(t, "org.spray.start")); n != 1 {
		t.Fatalf("%d org.spray.start events", n)
	}
}
