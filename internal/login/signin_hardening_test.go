package login_test

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
)

// Attempts sent at once are each charged before they are checked: a burst of wrong passwords gets at most the
// lockout's number of real checks, the rest are refused as locked. (Charging only finished failures let every
// attempt in a burst pass the check before the first was counted.)
func TestLockoutHoldsForParallelAttempts(t *testing.T) {
	const attempts, burst = 3, 24
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LockoutAttempts = attempts
		c.Limits.LockoutMinutes = 15
		c.Limits.LoginPerIPMin = 0
	})
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)

	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for range burst {
		wg.Go(func() {
			res, _ := e.browser(t).login("acme", "pat", "wrong password")
			mu.Lock()
			codes[res.StatusCode]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if codes[401] > attempts || codes[401]+codes[429]+codes[503] != burst {
		t.Fatalf("a burst of %d wrong passwords got %d checked (limit %d): %v", burst, codes[401], attempts, codes)
	}
	res, out := e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
}

// Anyone can ask for a reset link for any address, so a request does not end the link an earlier mail carries: both
// open until one is used, and the password it sets ends the other.
func TestResetRequestKeepsEarlierLink(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	forgot := func() string {
		res, out := b.post("/api-internal/password/forgot", map[string]any{"org": "acme", "email": "pat@example.com"})
		wantStatus(t, res, out, 200)
		return tokenOf(linkPath(t, e.nextMail(t)))
	}
	first, second := forgot(), forgot()
	res, out := b.post("/api-internal/password/reset", map[string]any{"token": first, "password": "a brand new password"})
	wantStatus(t, res, out, 200)
	res, out = b.post("/api-internal/password/reset", map[string]any{"token": second, "password": "another new password"})
	if res.StatusCode == 200 {
		t.Fatalf("the second link still worked after the password changed: %v", out)
	}
	res, out = e.browser(t).login("acme", "pat", "a brand new password")
	wantStatus(t, res, out, 200)
}

// A failed sign-in for an account that was not found records the address typed, never anything else typed in its
// place (a password in the address box would otherwise be in the audit trail and the structured log).
func TestFailedSignInDoesNotRecordAPasswordTypedAsTheLogin(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	e.org(t, "acme", nil)
	b := e.browser(t)
	b.post("/api-internal/login/password", map[string]any{"org": "acme", "email": "Hunter2-my-secret!", "password": "x"})
	b.post("/api-internal/login/password", map[string]any{"org": "acme", "email": "nobody@example.com", "password": "x"})
	var seen []string
	for _, a := range e.audits(t, "login.failure") {
		seen = append(seen, a.Target, a.Actor)
	}
	for _, v := range seen {
		if strings.Contains(v, "Hunter2") {
			t.Fatalf("the typed secret is in the audit trail: %v", seen)
		}
	}
	if !slices.Contains(seen, "nobody@example.com") {
		t.Fatalf("the address tried is not recorded: %v", seen)
	}
}
