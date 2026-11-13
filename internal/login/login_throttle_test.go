package login_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestRateLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 5; c.Limits.LockoutAttempts = 0 })
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	for i := 1; i <= 5; i++ {
		res, out := b.login("primary", "admin", "wrong")
		if res.StatusCode != 401 {
			t.Fatalf("attempt %d: %d %v", i, res.StatusCode, out["_raw"])
		}
	}
	res, out := b.login("primary", "admin", e.Password) // even the right password is refused while limited
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") != "60" || b.hasSession() {
		t.Fatalf("429 details: retry-after=%q session=%v", res.Header.Get("Retry-After"), b.hasSession())
	}
	// limits are per organization
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
}

// A configuration reload that changes limits.login_per_ip_min applies at the next attempt, counted against the
// attempts already made in the minute: tightening the limit mid-attack hands the attacker no fresh budget, and
// loosening it lets the address in again at once.
func TestRateLimitReloadKeepsCount(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 10; c.Limits.LockoutAttempts = 0 })
	b := e.browser(t)
	for i := 1; i <= 3; i++ {
		res, out := b.login("primary", "admin", "wrong")
		wantStatus(t, res, out, 401)
	}
	l := e.Cfg.LiveLimits()
	l.LoginPerIPMin = 3
	e.Cfg.SetLiveLimits(l)
	res, out := b.login("primary", "admin", "wrong")
	wantStatus(t, res, out, 429)
	l.LoginPerIPMin = 10
	e.Cfg.SetLiveLimits(l)
	res, out = b.login("primary", "admin", "wrong") // the fifth attempt of the minute: within 10
	wantStatus(t, res, out, 401)
}

// An organization's name in any case and its id are one address space: they share one per-IP bucket. An organization
// that does not exist has no endpoints, so there is nothing for random names to mint buckets of.
func TestRateLimitOrgNormalisation(t *testing.T) {
	const limit = 50
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = limit; c.Limits.LockoutAttempts = 100000 })
	org := e.org(t, "acme", nil)
	b := e.browser(t)
	refs := []string{"acme", "ACME", "Acme", org.ID}
	first429 := 0
	for i := 1; i <= limit+10; i++ {
		ref := refs[i%len(refs)]
		res, _ := b.login(ref, "pat", "wrong-password")
		if res.StatusCode == http.StatusTooManyRequests {
			first429 = i
			break
		}
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d (%q): status %d", i, ref, res.StatusCode)
		}
	}
	if first429 != limit+1 {
		t.Fatalf("first 429 at attempt %d, want %d", first429, limit+1)
	}
	// The forgot-password form shares the bucket too.
	res, out := b.post("/o/ACME/api-internal/password/forgot", map[string]any{"email": "pat@example.com"})
	wantStatus(t, res, out, 429)
	// Another organization has its own.
	other := e.org(t, "other", nil)
	if res, out := e.browser(t).login(other.ID, "pat", "wrong-password"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("another organization shares the bucket: %d %v", res.StatusCode, out)
	}
	for i := range 5 {
		if res, _ := b.login(fmt.Sprintf("no-such-org-%d", i), "pat", "x"); res.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown organization: %d", res.StatusCode)
		}
	}
}

// One IP cannot exceed three times the per-org limit by spreading attempts across organizations.
func TestRateLimitIPCeiling(t *testing.T) {
	const limit = 10
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = limit; c.Limits.LockoutAttempts = 100000 })
	orgs := []string{"a1", "a2", "a3", "a4", "a5"}
	for _, o := range orgs {
		e.org(t, o, nil)
	}
	b := e.browser(t)
	for i := 1; i <= 3*limit+5; i++ {
		res, _ := b.login(orgs[i%len(orgs)], "pat", "wrong-password")
		want := http.StatusUnauthorized
		if i > 3*limit {
			want = http.StatusTooManyRequests
		}
		if res.StatusCode != want {
			t.Fatalf("attempt %d: status %d, want %d", i, res.StatusCode, want)
		}
	}
}

// A sign-in limit that starts refusing is recorded once per limit and minute, not once per refused request.
func TestRateLimitIsAuditedOnce(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 3; c.Limits.LockoutAttempts = 0 })
	b := e.browser(t)
	for range 8 {
		b.login("primary", "nobody", "wrong")
	}
	ev := e.audits(t, "login.limited")
	if len(ev) != 1 || ev[0].Detail["limit"] != "organization" || ev[0].Outcome != "failure" {
		t.Fatalf("login.limited: %+v", ev)
	}
}

// A flood of junk sign-ins from the same address (an office NAT, a load balancer without trusted_proxies) does not
// keep out a browser that has signed in to the account before: its device cookie moves it onto the account's own
// budget. A browser without one, another account typed into that browser, or a tampered cookie stay limited by
// address, and the account's own budget is limited too.
func TestKnownDeviceSurvivesFlood(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 5; c.Limits.LockoutAttempts = 0 })
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	e.user(t, org, "sam", model.RoleUser)
	e.org(t, "other", nil)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	attacker := e.browser(t)
	for i := 0; i < 20; i++ { // past the per-org limit and the address-wide ceiling
		attacker.login([]string{"acme", "primary", "other"}[i%3], "x@y.z", "x")
	}
	if res, out := e.browser(t).login("acme", "pat", userPassword); res.StatusCode != 429 {
		t.Fatalf("flood did not limit the address: %d %v", res.StatusCode, out["_raw"])
	}

	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	// the cookie is for pat: another account typed into the same browser is limited by address
	res, out = b.login("acme", "sam", userPassword)
	wantStatus(t, res, out, 429)

	// a tampered cookie is no cookie
	res, out = e.browserWithDevice(t, strings.Replace(b.deviceCookie().Value, ".", ".x", 1)).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)

	// the device's own budget is limited like an address's
	for i := 0; i < 4; i++ {
		res, out = b.login("acme", "pat", "wrong")
		wantStatus(t, res, out, 401)
	}
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
}

func TestLockout(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LockoutAttempts = 3
		c.Limits.LockoutMinutes = 15
		c.Limits.LoginPerIPMin = 0
	})
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)

	b := e.browser(t)
	// Two failures, a success, two more failures: the success reset the count.
	b.login("acme", "pat", "bad1")
	b.login("acme", "pat", "bad2")
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	b = e.browser(t)
	b.login("acme", "pat", "bad3")
	b.login("acme", "pat", "bad4")
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	// Three in a row lock the account: even the right password is refused, with Retry-After.
	b = e.browser(t)
	for range 3 {
		res, _ = b.login("acme", "pat", "bad")
		if res.StatusCode != 401 {
			t.Fatalf("expected 401 before lockout, got %d", res.StatusCode)
		}
	}
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") != "900" || b.hasSession() {
		t.Fatalf("lockout details: %q session=%v", res.Header.Get("Retry-After"), b.hasSession())
	}
	// Another browser (another session) is locked out as well: it is per account.
	res, out = e.browser(t).login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if n := len(e.audits(t, "login.lockout")); n != 1 {
		t.Fatalf("lockout audits: %d", n)
	}
	// Other accounts are unaffected.
	res, out = e.browser(t).login("primary", "admin", e.Password)
	wantStatus(t, res, out, 200)

	// No database writes: the lockout leaves the user record untouched.
	u, _ := e.Svc.FindUserByEmail(context.Background(), org.ID, "pat@example.com")
	if u == nil || u.Version != pat.Version {
		t.Fatalf("signing in or the lockout wrote to the user record: %+v", u)
	}
}

// An organization's own lockout replaces the server's for its accounts: fewer attempts, a longer lock.
func TestOrgLockout(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LockoutAttempts = 10
		c.Limits.LockoutMinutes = 15
		c.Limits.LoginPerIPMin = 0
	})
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	st := org.Settings
	st.LockoutAttempts, st.LockoutMinutes = 2, 60
	if _, err := e.Svc.UpdateOrg(context.Background(), service.System, org.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	b := e.browser(t)
	for range 2 {
		if res, _ := b.login("acme", "pat", "bad"); res.StatusCode != 401 {
			t.Fatalf("expected 401 before lockout, got %d", res.StatusCode)
		}
	}
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") != "3600" {
		t.Fatalf("Retry-After %q", res.Header.Get("Retry-After"))
	}
}

// An unknown login locks out after the same number of attempts, so lockout does not reveal which accounts exist.
// Someone who knows the email address can lock the account, but not its owner's browsers that have signed in to it
// before: they count failures of their own and lock after as many. A tampered device cookie is no cookie.
func TestKnownDeviceLockout(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LockoutAttempts = 3
		c.Limits.LockoutMinutes = 15
		c.Limits.LoginPerIPMin = 0
	})
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)

	stranger := e.browser(t)
	for range 3 {
		res, out = stranger.login("acme", "pat", "bad")
		wantStatus(t, res, out, 401)
	}
	res, out = stranger.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)

	// a cookie that is tampered with, cut short, has a bad time stamp or extra parts, is oversized or is no cookie at all
	// counts for nothing
	dev := b.deviceCookie().Value
	parts := strings.Split(dev, ".")
	if len(parts) < 6 {
		t.Fatalf("device cookie %q has an unexpected shape", dev)
	}
	withPart := func(i int, v string) string {
		p := slices.Clone(parts)
		p[i] = v
		return strings.Join(p, ".")
	}
	for name, v := range map[string]string{
		"tampered":                        strings.Replace(dev, ".", ".x", 1),
		"cut short":                       strings.Join(parts[:5], "."),
		"bad time stamp":                  withPart(3, "!!"),
		"time stamp the MAC cannot cover": withPart(3, "zzzzzzzzzzzz"),
		"extra part":                      dev + ".extra",
		"oversized":                       strings.Repeat("a", 5000),
		"not a cookie":                    "~~~",
	} {
		res, out = e.browserWithDevice(t, v).login("acme", "pat", userPassword)
		if res.StatusCode != 429 {
			t.Errorf("%s: counted as the known device: %d %v", name, res.StatusCode, out["_raw"])
		}
	}

	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	// the owner's sign-in does not reset the stranger's lockout (that would give the stranger fresh guesses)
	res, out = stranger.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)

	// the known browser's own failures lock it (and only it: the account-wide counter is the stranger's)
	for range 3 {
		res, out = b.login("acme", "pat", "bad")
		wantStatus(t, res, out, 401)
	}
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 429)
	if n, _ := e.Server.Eph.Incr(context.Background(), "lockout", pat.ID, 0, time.Hour); n != 3 {
		t.Fatalf("the known browser's failures charged the account-wide counter: %d", n)
	}
}

// A device cookie stops counting once the account's password changes (a reset, say): a browser that signed in with a
// stolen password does not keep its own budget and lockout counter after the owner takes the account back.
func TestDeviceCookieEndsWithPasswordChange(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LockoutAttempts = 3; c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	stranger := e.browser(t)
	for range 3 {
		stranger.login("acme", "pat", "bad")
	}
	if res, out := b.login("acme", "pat", userPassword); res.StatusCode != 200 {
		t.Fatalf("known browser while the account is locked: %d %v", res.StatusCode, out["_raw"])
	}
	pw := "a brand new password 42"
	if _, err := e.Svc.UpdateUser(context.Background(), service.System, pat.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	if res, _ := b.login("acme", "pat", pw); res.StatusCode != 429 {
		t.Fatalf("the old device cookie still counts after the password changed: %d", res.StatusCode)
	}
}

func TestLockoutDoesNotRevealAccounts(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LockoutAttempts = 2; c.Limits.LoginPerIPMin = 0 })
	b := e.browser(t)
	for _, login := range []string{"admin", "ghost"} {
		var codes []int
		for range 4 {
			res, _ := b.login("primary", login, "wrong")
			codes = append(codes, res.StatusCode)
		}
		if codes[0] != 401 || codes[1] != 401 || codes[2] != 429 || codes[3] != 429 {
			t.Fatalf("%s: status sequence %v", login, codes)
		}
	}
}

// Attempts sent at once are each charged before they are checked: a burst of wrong passwords gets at most the
// lockout's number of real checks, the rest are refused as locked. (Charging only finished failures let every
// attempt in a burst pass the check before the first was counted.)
func TestLockoutHoldsForParallelAttempts(t *testing.T) {
	const attempts, burst = 3, 12
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

// brokenCounters is an ephemeral store whose counters fail (a database that cannot take the write, or a cluster
// node that owns them and does not answer in time). Only the counters of namespace ns fail; "" is all of them.
type brokenCounters struct {
	ephemeral.Store
	ns string
}

func (b brokenCounters) Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	if b.ns != "" && b.ns != ns {
		return b.Store.Incr(ctx, ns, key, delta, window)
	}
	return 0, errors.New("counter unavailable")
}

// Counters fail closed: when a rate-limit or lockout counter cannot be used, sign-in is refused, not allowed. But the
// answer is "unavailable" (retry), not a limit or lockout that was never reached: a valid user is not told they
// failed too often, and no limit or lockout is audited.
func TestCountersFailClosed(t *testing.T) {
	for _, c := range []struct{ name, ns string }{
		{"rate limit counters", "rl"},
		{"lockout counters", "lockout"},
		{"all counters", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, lockoutAfter(3))
			e.member(t)
			e.Server.Eph = brokenCounters{e.Server.Eph, c.ns}
			b := e.browser(t)
			res, out := b.login("primary", "member", userPassword)
			wantStatus(t, res, out, 503)
			if res.Header.Get("Retry-After") == "" {
				t.Errorf("no Retry-After: %v", res.Header)
			}
			if b.hasSession() {
				t.Error("signed in with a failing counter")
			}
			if n := e.lockedReasons(t); n != 0 {
				t.Errorf("%d sign-in failures audited as locked, none was", n)
			}
			if l := e.audits(t, "login.limited"); len(l) != 0 {
				t.Errorf("%d limits audited as tripped, none was", len(l))
			}
		})
	}
}

// The refusals of a locked account are audited once per minute (the first), not once per attempt: anyone can repeat
// them for as long as the lock lasts, and a row per attempt would make the audit log the target.
func TestLockedRefusalsAuditedOncePerWindow(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.LockoutAttempts = 3
		c.Limits.LockoutMinutes = 15
		c.Limits.LoginPerIPMin = 0
		c.Audit.Logins = true
	})
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	for range 3 {
		b.login("acme", "pat", "bad")
	}
	for range 20 {
		res, out := b.login("acme", "pat", userPassword)
		wantStatus(t, res, out, 429)
	}
	locked := 0
	for _, a := range e.audits(t, "login.failure") {
		if a.Detail["reason"] == "locked" {
			locked++
		}
	}
	if locked != 1 {
		t.Fatalf("locked refusals audited: %d, want 1", locked)
	}
}
