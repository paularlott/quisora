package login_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// landsThenUnconfirmed makes the next change of a user record land and report store.ErrUnconfirmed.
type landsThenUnconfirmed struct {
	store.Store
	armed atomic.Bool
}

func (s *landsThenUnconfirmed) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindUser && !r.Deleted && expect != 0 && s.armed.CompareAndSwap(true, false) {
		if err := s.Store.CompareAndPut(ctx, r, expect); err != nil {
			return err
		}
		return store.ErrUnconfirmed
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// A reset whose commit the cluster did not confirm is answered with what to do (the password may be set: sign in with
// it, or ask for a new link), since a retry of the link, used up if it landed, only says the link is invalid.
func TestResetOfUnknownOutcomeSaysThePasswordMayBeSet(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	if err := e.Mailer.SendReset(context.Background(), pat, org); err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimPrefix(linkPath(t, e.nextMail(t)), "/reset?token=")
	f := &landsThenUnconfirmed{Store: e.Svc.Users.S}
	e.Svc.Users.S = f
	f.armed.Store(true)
	b := e.browser(t)
	res, out := b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "a brand new password"})
	wantStatus(t, res, out, http.StatusServiceUnavailable)
	if msg := str(out, "error"); !strings.Contains(msg, "sign") || !strings.Contains(msg, "may have been changed") {
		t.Fatalf("the answer does not say the password may be set: %q", msg)
	}
	wantUnknownAudit(t, e, "password.reset")
	// it was: the link is used up, and the new password signs in
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": tok, "password": "another new password"})
	wantStatus(t, res, out, http.StatusGone)
	res, out = e.browser(t).login("acme", "pat", "a brand new password")
	wantStatus(t, res, out, 200)
}

// wantUnknownAudit fails t unless action is on record once, with outcome "unknown": a change that may have been made
// is never missing from the audit log.
func wantUnknownAudit(t *testing.T, e *env, action string) {
	t.Helper()
	got := e.audits(t, action)
	if len(got) != 1 || got[0].Outcome != service.OutcomeUnknown {
		t.Fatalf("audit of %s with an unknown outcome: %+v", action, got)
	}
}

// The same for the acceptance of an invitation.
func TestInviteOfUnknownOutcomeSaysItMayHaveBeenAccepted(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	_, link := e.invitee(t, org, "newbie")
	tok := tokenOf(link)
	f := &landsThenUnconfirmed{Store: e.Svc.Users.S}
	e.Svc.Users.S = f
	f.armed.Store(true)
	b := e.browser(t)
	res, out := b.post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "my first password"})
	wantStatus(t, res, out, http.StatusServiceUnavailable)
	if msg := str(out, "error"); !strings.Contains(msg, "may have been accepted") || !strings.Contains(msg, "signing in") {
		t.Fatalf("the answer does not say the invitation may be accepted: %q", msg)
	}
	wantUnknownAudit(t, e, "invite.accept")
	res, out = b.post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "my first password"})
	wantStatus(t, res, out, http.StatusGone)
}

// landsSignInThenUnconfirmed makes the next write of a sign-in record land and report store.ErrUnconfirmed.
type landsSignInThenUnconfirmed struct {
	store.Store
	armed atomic.Bool
}

func (s *landsSignInThenUnconfirmed) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindSignIn && s.armed.CompareAndSwap(true, false) {
		if err := s.Store.CompareAndPut(ctx, r, expect); err != nil {
			return err
		}
		return store.ErrUnconfirmed
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// An authenticator code whose step the cluster did not confirm is answered 503 (try again), not as a wrong code, and is
// not counted toward the lockout: with two failures locking the account, that failure and one wrong code leave it open.
func TestTOTPOfUnknownOutcomeIsNotAWrongCode(t *testing.T) {
	e := newEnv(t, lockoutAfter(2), noIPLimit)
	u := e.user(t, e.Primary, "pat", model.RoleUser)
	secret := e.giveTOTP(t, u)
	b := e.browser(t)
	_, out := b.login("primary", "pat", userPassword)
	tk := str(out, "ticket")
	f := &landsSignInThenUnconfirmed{Store: e.Svc.SignIns.S}
	e.Svc.SignIns.S = f
	f.armed.Store(true)
	res, out := b.post("/api-internal/login/totp", map[string]any{"ticket": tk, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, http.StatusServiceUnavailable)
	res, out = b.post("/api-internal/login/totp", map[string]any{"ticket": tk, "code": "222222"})
	wantStatus(t, res, out, 401)
	// (the code of the first try is used up: the next step's is good)
	res, out = b.post("/api-internal/login/totp", map[string]any{"ticket": tk, "code": totpAt(secret, time.Now().Add(30*time.Second))})
	wantStatus(t, res, out, 200)
}
