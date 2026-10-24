package login_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

type failSessionDeletes struct{ store.Store }

func (s failSessionDeletes) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindSession && r.Deleted {
		return errors.New("review: session deletion failed")
	}
	return s.Store.Put(ctx, r)
}

// A sign-out whose session deletion fails is not answered "signed out" (the session still works for whoever else
// holds its cookie, and a refresh grant of it keeps refreshing) and no plain logout is audited: 503, and the audit
// entry says the sign-out is incomplete.
func TestLogoutReportsFailureWhenSessionCannotBeEnded(t *testing.T) {
	e := newEnv(t, nil)
	u := e.member(t)
	b := e.signedIn(t, u)
	sid := b.sessionID()
	good := e.Svc.Sessions.S
	e.Svc.Sessions.S = failSessionDeletes{good}
	res, out := b.do("POST", "/logout", nil, nil)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("logout with failing deletion: %d %v", res.StatusCode, out)
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("control: the session should still exist: %v", err)
	}
	for _, a := range e.audits(t, "logout") {
		if a.Detail["result"] != "incomplete" {
			t.Fatalf("a logout that did not happen was audited as one: %v", a.Detail)
		}
	}
	// The cookie stays while the session does, so trying again (as the message says) really ends it.
	e.Svc.Sessions.S = good
	if res, out := b.do("POST", "/logout", nil, nil); res.StatusCode != 200 {
		t.Fatalf("logout once the store answers again: %d %v", res.StatusCode, out)
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session should be gone: %v", err)
	}
}

// "Sign out everywhere else" that could not end every other session says so (503 with how many did end), rather
// than a count that reads as all of them.
func TestRevokeOtherSessionsReportsPartialFailure(t *testing.T) {
	e := newEnv(t, nil)
	u := e.member(t)
	b := e.signedIn(t, u)
	other := e.signedIn(t, u)
	otherID := other.sessionID()
	good := e.Svc.Sessions.S
	e.Svc.Sessions.S = failSessionDeletes{good}
	res, out := b.api("DELETE", "/api-internal/account/sessions", nil)
	if res.StatusCode != http.StatusServiceUnavailable || out["revoked"] != float64(0) || out["error"] == "" {
		t.Fatalf("revoke others with failing deletion: %d %v", res.StatusCode, out)
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), otherID); err != nil {
		t.Fatalf("control: the other session should still exist: %v", err)
	}
	e.Svc.Sessions.S = good
	if res, out := b.api("DELETE", "/api-internal/account/sessions", nil); res.StatusCode != 200 || out["revoked"] != float64(1) {
		t.Fatalf("revoke others once the store answers again: %d %v", res.StatusCode, out)
	}
}
