package login_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// sessionsRefused refuses every session read, as a node that cannot vouch for the session partition does.
type sessionsRefused struct{ store.Store }

func (s sessionsRefused) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindSession {
		return nil, store.ErrUnavailable
	}
	return s.Store.Get(ctx, kind, id)
}

// usersRefused refuses every lookup of a user by an address.
type usersRefused struct{ store.Store }

func (s usersRefused) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	if kind == model.KindUser {
		return nil, store.ErrUnavailable
	}
	return s.Store.GetByUnique(ctx, kind, value)
}

// A sign-out of a session the store cannot check is answered "try again" (503), never "already signed out": the
// session may be alive, and the browser would be told it ended. Once the store answers, signing out ends it.
func TestLogoutWhenTheSessionCannotBeCheckedAsksToRetry(t *testing.T) {
	e := newEnv(t, nil)
	u := e.member(t)
	b := e.signedIn(t, u)
	sid := b.sessionID()
	good := e.Svc.Sessions.S
	e.Server.Sessions.Evict(sid, "") // the cached copy would answer without the store
	e.Svc.Sessions.S = sessionsRefused{good}

	res, out := b.do("POST", "/logout", nil, nil)
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" {
		t.Fatalf("fetch sign-out with an unreadable session: %d %q %v", res.StatusCode, res.Header.Get("Retry-After"), out)
	}
	// A plain form post (no JSON, no CSRF header: the token is a form field) is answered the same way.
	form := url.Values{"csrf": {b.csrf}}
	req, _ := http.NewRequest(http.MethodPost, e.URL+b.at("/logout"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b.c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("form sign-out with an unreadable session: %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if len(e.audits(t, "logout")) != 0 {
		t.Fatal("a sign-out that did not happen was audited")
	}

	e.Svc.Sessions.S = good
	if res, out := b.do("POST", "/logout", nil, nil); res.StatusCode != 200 {
		t.Fatalf("sign-out once the store answers: %d %v", res.StatusCode, out)
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); err == nil {
		t.Fatal("the session should be gone")
	}
}

// A sign-in whose account cannot be looked up now is answered "try again" (503), not "the email address or password is
// incorrect": no failure is audited and no lockout is charged, so the right password works once the store answers.
func TestPasswordSignInWhenTheAccountCannotBeLookedUpAsksToRetry(t *testing.T) {
	e := newEnv(t, lockoutAfter(1), noIPLimit)
	e.member(t)
	good := e.Svc.Users.S
	e.Svc.Users.S = usersRefused{good}
	b := e.browser(t)
	body := map[string]any{"email": "member@example.com", "password": userPassword}
	res, out := b.do("POST", "/api-internal/login/password", body, nil)
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" {
		t.Fatalf("sign-in with the account unreadable: %d %q %v, want 503", res.StatusCode, res.Header.Get("Retry-After"), out)
	}
	if n := len(e.audits(t, "login.failure")); n != 0 {
		t.Fatalf("%d sign-in failures audited for an outage", n)
	}
	e.Svc.Users.S = good
	// One failure would lock the account (lockoutAfter(1)): the outage was not charged to it.
	if res, out := b.do("POST", "/api-internal/login/password", body, nil); res.StatusCode != 200 {
		t.Fatalf("sign-in once the store answers: %d %v", res.StatusCode, out)
	}
}

// "Forgot password" is not answered "if the address has an account, a link is on its way" when the account could not
// be looked up: no link would come.
func TestForgotPasswordWhenTheAccountCannotBeLookedUpAsksToRetry(t *testing.T) {
	e := newEnv(t, noIPLimit)
	e.member(t)
	good := e.Svc.Users.S
	e.Svc.Users.S = usersRefused{good}
	b := e.browser(t)
	res, out := b.post("/api-internal/password/forgot", map[string]any{"email": "member@example.com"})
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("forgot with the account unreadable: %d %v, want 503", res.StatusCode, out)
	}
	e.noMail(t)
	e.Svc.Users.S = good
	res, out = b.post("/api-internal/password/forgot", map[string]any{"email": "member@example.com"})
	wantStatus(t, res, out, 200)
	e.nextMail(t)
}

// ephemeralReadsRefused refuses every read of one namespace.
type ephemeralReadsRefused struct {
	ephemeral.Store
	ns string
}

func (s ephemeralReadsRefused) Get(ctx context.Context, ns, id string) ([]byte, error) {
	if ns == s.ns {
		return nil, store.ErrUnavailable
	}
	return s.Store.Get(ctx, ns, id)
}

// ticketTakeRefused fails consuming a sign-in ticket, as an ephemeral store that cannot answer does.
type ticketTakeRefused struct{ ephemeral.Store }

func (s ticketTakeRefused) Take(ctx context.Context, ns, id string) ([]byte, error) {
	if ns == "login" { // the sign-in tickets
		return nil, store.ErrUnavailable
	}
	return s.Store.Take(ctx, ns, id)
}

// An emailed code that cannot be looked up (the store, not a missing code) is answered "try again" (503): not "no code
// has been sent", and not a wrong code charged to the account; asking for a new one is refused the same way, as
// the number already sent is not known.
func TestEmailCodeWhenTheStoreCannotBeReadAsksToRetry(t *testing.T) {
	e, org := emailEnv(t, func(s *model.OrgSettings) { s.RequireMFA = true; s.EmailCodes = true })
	e.verifiedUser(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	tk := str(out, "ticket")
	code := codeFrom(t, e)
	good := e.Server.Eph
	e.Server.Eph = ephemeralReadsRefused{good, "login.emailcode"}
	res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": code})
	wantStatus(t, res, out, 503)
	res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": tk})
	wantStatus(t, res, out, 503)
	e.noMail(t)
	if n := len(e.audits(t, "login.failure")); n != 0 {
		t.Fatalf("%d failures audited for an outage", n)
	}
	e.Server.Eph = good
	res, out = b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": code})
	wantStatus(t, res, out, 200)
}

// usersReadsRefused refuses every read of a user by its id.
type usersReadsRefused struct{ store.Store }

func (s usersReadsRefused) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindUser {
		return nil, store.ErrUnavailable
	}
	return s.Store.Get(ctx, kind, id)
}

// A second-factor step whose sign-in cannot be loaded (its ticket or its account unreadable: the store, not a missing
// ticket) is answered "try again" (503), not "your sign-in has expired": the sign-in is alive, and starting again would
// not help. Once the store answers, the same ticket still works.
func TestSecondFactorStepWhenTheSignInCannotBeLoadedAsksToRetry(t *testing.T) {
	e, org := emailEnv(t, func(s *model.OrgSettings) { s.RequireMFA = true; s.EmailCodes = true })
	e.verifiedUser(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	tk := str(out, "ticket")
	code := codeFrom(t, e)
	step := func() (*http.Response, map[string]any) {
		return b.post("/api-internal/login/email", map[string]any{"ticket": tk, "code": code})
	}

	goodEph := e.Server.Eph
	e.Server.Eph = ephemeralReadsRefused{goodEph, "login"}
	res, out = step()
	wantStatus(t, res, out, 503)
	e.Server.Eph = goodEph

	goodUsers := e.Svc.Users.S
	e.Svc.Users.S = usersReadsRefused{goodUsers}
	res, out = step()
	wantStatus(t, res, out, 503)
	e.Svc.Users.S = goodUsers

	// The ticket reads, but consuming it (the last check before the session) fails: not "expired" either. The code
	// was spent by then (codes are checked first), so the person asks for a new one and the sign-in goes on.
	e.Server.Eph = ticketTakeRefused{goodEph}
	res, out = step()
	wantStatus(t, res, out, 503)
	e.Server.Eph = goodEph
	e.Mod.AgeEmailCode(tk)
	res, out = b.post("/api-internal/login/email/send", map[string]any{"ticket": tk})
	wantStatus(t, res, out, 200)
	code = codeFrom(t, e)

	if n := len(e.audits(t, "login.failure")); n != 0 {
		t.Fatalf("%d failures audited for an outage", n)
	}
	res, out = step()
	wantStatus(t, res, out, 200)
	// A ticket that is gone is still "expired".
	res, out = step()
	wantStatus(t, res, out, 401)
}

// Signing in while the browser's existing session cannot be checked is answered "try again" (503): a second session
// beside one that may be another user's (or this user's, with grants held on it) would leave the first alive. Once the
// store answers, the sign-in replaces it.
func TestSignInWhenTheExistingSessionCannotBeCheckedAsksToRetry(t *testing.T) {
	e := newEnv(t, noIPLimit)
	e.member(t)
	b := e.browser(t)
	body := map[string]any{"email": "member@example.com", "password": userPassword}
	res, out := b.do("POST", "/api-internal/login/password", body, nil)
	wantStatus(t, res, out, 200)
	e.Server.Sessions.Evict(b.sessionID(), "") // the cached copy would answer without the store
	good := e.Svc.Sessions.S
	e.Svc.Sessions.S = sessionsRefused{good}
	res, out = b.do("POST", "/api-internal/login/password", body, nil)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("sign-in with an unreadable session: %d %v, want 503", res.StatusCode, out)
	}
	e.Svc.Sessions.S = good
	res, out = b.do("POST", "/api-internal/login/password", body, nil)
	wantStatus(t, res, out, 200)
}
