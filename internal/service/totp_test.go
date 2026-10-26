package service_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
)

// consumed is the answer of ConsumeTOTP(At) when the step could be recorded.
func consumed(ok bool, err error) bool {
	if err != nil {
		panic(err)
	}
	return ok
}

// A TOTP code is accepted once: its step is recorded with a compare-and-swap before the answer, so the same code
// presented twice at the same moment (two requests, or two nodes) is accepted by exactly one.
func TestTOTPCodeAcceptedOnce(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	u := e.user(o.ID, "pat", model.RoleUser)
	secret := secure.NewTOTPSecret()
	now := time.Now()
	code := secure.TOTPCode(secret, now)
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if consumed(e.svc.ConsumeTOTPAt(e.ctx, u, secret, code, now)) {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("one code accepted %d times", ok.Load())
	}
	if consumed(e.svc.ConsumeTOTPAt(e.ctx, u, secret, code, now)) {
		t.Fatal("a used code was accepted again")
	}
	// a code verified while setting up the authenticator cannot sign in either
	next := now.Add(time.Minute)
	if err := e.svc.NoteTOTPStep(e.ctx, u, next.Unix()/30); err != nil {
		t.Fatal(err)
	}
	if consumed(e.svc.ConsumeTOTPAt(e.ctx, u, secret, secure.TOTPCode(secret, next), next)) {
		t.Fatal("the enrolment code signed in")
	}
	if user, _ := e.svc.Users.Get(e.ctx, u.ID); user.Version != u.Version {
		t.Fatal("recording TOTP steps rewrote the user record")
	}
	// a wrong code is refused
	if consumed(e.svc.ConsumeTOTPAt(e.ctx, u, secret, "000000", now.Add(time.Hour))) {
		t.Fatal("a wrong code was accepted")
	}
	// another user's step is independent: the same secret and code are theirs to use once
	v := e.user(o.ID, "bea", model.RoleUser)
	if !consumed(e.svc.ConsumeTOTPAt(e.ctx, v, secret, code, now)) {
		t.Fatal("one user's use spent another's step")
	}
	// a code at or before the step last recorded for the user is refused
	w := e.user(o.ID, "cy", model.RoleUser)
	if err := e.svc.SignIns.Create(e.ctx, &model.SignIn{Meta: model.Meta{ID: w.ID}, OrgID: w.OrgID, TOTPLastStep: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if consumed(e.svc.ConsumeTOTPAt(e.ctx, w, secret, code, now)) {
		t.Fatal("a code at or before the last recorded step was accepted")
	}
}
