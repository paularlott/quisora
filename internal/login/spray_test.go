package login_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
)

// sprayConfig locks an account after 10 failures in 15 minutes, puts an organization under spray past perMinute
// failed passwords in a minute, and takes client addresses from a trusted proxy (browser.fromAddress).
func sprayConfig(perMinute int) func(*config.Config) {
	return func(c *config.Config) {
		c.Limits.LockoutAttempts, c.Limits.LockoutMinutes = 10, 15
		c.Limits.LoginPerIPMin = 0
		c.Limits.OrgFailuresPerMin = perMinute
		trustLoopbackProxy(c)
	}
}

// accountFailures is the lockout counter of an account (the failures charged to it from browsers new to it).
func (e *env) accountFailures(t *testing.T, u *model.User) int64 {
	t.Helper()
	n, err := e.Server.Eph.Incr(context.Background(), "lockout", u.ID, 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// reasons counts the sign-in failures audited with the reason.
func (e *env) reasons(t *testing.T, reason string) int {
	t.Helper()
	n := 0
	for _, a := range e.audits(t, "login.failure") {
		if a.Detail["reason"] == reason {
			n++
		}
	}
	return n
}

// A password spray from many addresses, ten wrong passwords for every account of the organization, does not lock
// every account: once the organization's failures pass the limit, each address fails only as often as one account
// may, across the organization. Each account still takes at most its ten guesses in all. A person who signed in
// from their browser before signs in from it, and so does a person whose account the spray did not get to from a
// browser and address new to it. The start of the spray is audited once, as a failure.
func TestSprayDoesNotLockTheOrganization(t *testing.T) {
	e := newEnv(t, sprayConfig(20))
	org := e.org(t, "acme", nil)
	var users []*model.User
	for i := range 30 {
		users = append(users, e.user(t, org, fmt.Sprintf("u%02d", i), model.RoleUser))
	}
	pat := users[0]
	known := e.browser(t) // pat's own browser, signed in from before
	res, out := known.login("acme", pat.Username, userPassword)
	wantStatus(t, res, out, 200)

	var attackers []*browser
	for i := range 10 {
		b := e.browser(t)
		b.fromAddress(fmt.Sprintf("203.0.113.%d", i+1))
		attackers = append(attackers, b)
	}
	guesses := map[string]int{} // wrong passwords checked (401) per account
	total, k := 0, 0
	for round := range 10 {
		for _, u := range users {
			res, out := attackers[k%len(attackers)].login("acme", u.Username, fmt.Sprintf("guess-%d", round))
			k++
			switch res.StatusCode {
			case http.StatusUnauthorized:
				guesses[u.ID]++
				total++
			case http.StatusTooManyRequests:
			default:
				t.Fatalf("spray attempt: %d %v", res.StatusCode, out["_raw"])
			}
		}
	}
	// 21 failures before the spray was noticed, then ten for each of the ten addresses.
	if total > 21+10*len(attackers) {
		t.Fatalf("the spray had %d passwords checked", total)
	}
	locked := 0
	var spared *model.User
	for _, u := range users {
		if guesses[u.ID] > 10 {
			t.Fatalf("%s took %d guesses", u.Username, guesses[u.ID])
		}
		if n := e.accountFailures(t, u); n >= 10 {
			locked++
		} else if u != pat {
			spared = u
		}
	}
	if locked == len(users) || spared == nil {
		t.Fatalf("the spray locked %d of %d accounts", locked, len(users))
	}
	if e.reasons(t, "address locked") == 0 {
		t.Fatal("no attempt was refused for its address")
	}

	res, out = known.login("acme", pat.Username, userPassword)
	wantStatus(t, res, out, 200)
	b := e.browser(t)
	b.fromAddress("198.51.100.7")
	res, out = b.login("acme", spared.Username, userPassword)
	wantStatus(t, res, out, 200)

	ev := e.audits(t, "org.spray.start")
	if len(ev) != 1 || ev[0].Outcome != "failure" || ev[0].OrgID != org.ID || ev[0].Detail["per_minute"] != "20" ||
		ev[0].Detail["failures"] != "21" || ev[0].Detail["minutes"] != "15" {
		t.Fatalf("org.spray.start: %+v", ev)
	}
	if n := len(e.audits(t, "org.spray.end")); n != 0 {
		t.Fatalf("the spray ended while it went on: %d", n)
	}
}

// Under spray, an account guessed from more addresses than its lockout attempts still takes no more than them: the
// address is charged as well as the account, never instead of it. The right password from a new address is then
// refused like a wrong one, and the owner's own browser still signs in.
func TestSprayBoundsGuessesPerAccount(t *testing.T) {
	e := newEnv(t, sprayConfig(5))
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	known := e.browser(t)
	res, out := known.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	for i := range 6 { // unknown accounts: the organization is under spray from the sixth failure on
		b := e.browser(t)
		b.fromAddress("192.0.2.1")
		res, out := b.login("acme", fmt.Sprintf("nobody%d", i), "x")
		wantStatus(t, res, out, 401)
	}
	if len(e.audits(t, "org.spray.start")) != 1 {
		t.Fatal("not under spray")
	}
	checked := 0
	for i := range 50 {
		b := e.browser(t)
		b.fromAddress(fmt.Sprintf("203.0.113.%d", i+1))
		res, out := b.login("acme", "pat", fmt.Sprintf("guess-%d", i))
		switch res.StatusCode {
		case http.StatusUnauthorized:
			checked++
		case http.StatusTooManyRequests:
		default:
			t.Fatalf("guess %d: %d %v", i, res.StatusCode, out["_raw"])
		}
	}
	if checked != 10 || e.accountFailures(t, pat) != 10 {
		t.Fatalf("50 addresses had %d guesses checked (counter %d), want 10", checked, e.accountFailures(t, pat))
	}
	b := e.browser(t)
	b.fromAddress("198.51.100.7")
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	res, out = known.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
}

// An address that has spent its attempts under spray is refused even the right password, and without charging the
// account; a successful sign-in gives back what it was charged. A lockout time after the last minute over the limit
// the spray is over: the first sign-in to find it so records the end once, and addresses are no longer limited.
func TestSprayEnds(t *testing.T) {
	e := newEnv(t, sprayConfig(3))
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	kim := e.user(t, org, "kim", model.RoleUser)
	b := e.browser(t)
	b.fromAddress("203.0.113.1")
	for i := range 14 { // 4 to start the spray, then the address's 10
		res, out := b.login("acme", fmt.Sprintf("nobody%d", i), "x")
		wantStatus(t, res, out, 401)
	}
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if n := e.accountFailures(t, pat); n != 0 {
		t.Fatalf("a refused address charged the account: %d", n)
	}
	for range 11 { // successes from browsers new to the account cost their address nothing
		other := e.browser(t)
		other.fromAddress("203.0.113.2")
		res, out = other.login("acme", "kim", userPassword)
		wantStatus(t, res, out, 200)
	}
	if n := e.accountFailures(t, kim); n != 0 {
		t.Fatalf("successful sign-ins charged the account: %d", n)
	}

	e.Mod.AgeSpray(org.ID, 15*time.Minute)
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	res, out = e.browser(t).login("acme", "kim", userPassword)
	wantStatus(t, res, out, 200)
	ev := e.audits(t, "org.spray.end")
	if len(ev) != 1 || ev[0].Outcome != "failure" || ev[0].Detail["minutes"] != "15" || ev[0].Detail["started"] == "" {
		t.Fatalf("org.spray.end: %+v", ev)
	}
}

// Below the limit nothing changes: an organization whose accounts are each sent their ten wrong passwords from one
// address has them locked as before, with no address refused and no spray recorded.
func TestNoSprayBelowLimit(t *testing.T) {
	e := newEnv(t, sprayConfig(100))
	org := e.org(t, "acme", nil)
	var users []*model.User
	for i := range 5 {
		users = append(users, e.user(t, org, fmt.Sprintf("u%d", i), model.RoleUser))
	}
	b := e.browser(t)
	b.fromAddress("203.0.113.1")
	for _, u := range users {
		for range 10 {
			res, out := b.login("acme", u.Username, "bad")
			wantStatus(t, res, out, 401)
		}
		res, out := b.login("acme", u.Username, userPassword)
		wantStatus(t, res, out, 429)
	}
	if len(e.audits(t, "login.lockout")) != len(users) || len(e.audits(t, "org.spray.start")) != 0 || e.reasons(t, "address locked") != 0 {
		t.Fatalf("lockouts %d, sprays %d, addresses refused %d", len(e.audits(t, "login.lockout")),
			len(e.audits(t, "org.spray.start")), e.reasons(t, "address locked"))
	}
}
