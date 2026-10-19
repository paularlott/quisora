package login_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
)

// brokenCounters is an ephemeral store whose counters fail (a database that cannot take the write).
type brokenCounters struct{ ephemeral.Store }

func (brokenCounters) Incr(context.Context, string, string, int64, time.Duration) (int64, error) {
	return 0, errors.New("counter unavailable")
}

// Counters fail closed: when the rate-limit counter cannot be updated, sign-in is refused, not allowed.
func TestCountersFailClosed(t *testing.T) {
	e := newEnv(t, nil)
	e.member(t)
	e.Server.Eph = brokenCounters{e.Server.Eph}
	res, out := e.browser(t).login("primary", "member", userPassword)
	if res.StatusCode != 429 {
		t.Fatalf("sign-in with a failing rate-limit counter: %d %v", res.StatusCode, out)
	}
}

// A user past their end date cannot sign in, even before the sweep disables them.
func TestValidUntilStopsSignIn(t *testing.T) {
	e := newEnv(t, nil)
	m := e.member(t)
	past := time.Now().Add(-time.Minute)
	m.ValidUntil = &past
	if err := e.Svc.Users.Update(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	res, out := e.browser(t).login("primary", "member", userPassword)
	if res.StatusCode != 401 {
		t.Fatalf("sign-in after the end date: %d %v", res.StatusCode, out)
	}
}
