package login_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

type failSessionDeletes struct{ store.Store }

func (s failSessionDeletes) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindSession && r.Deleted {
		return errors.New("injected: session deletion failed")
	}
	return s.Store.Put(ctx, r)
}

func (s failSessionDeletes) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindSession && r.Deleted {
		return errors.New("injected: session deletion failed")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
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

// "Sign out everywhere else" ends the other sessions at once (the account's session epoch moves on, so they stop
// counting whatever happens to their records), and says so when it could not remove their records (503 with how many
// ended) rather than a clean answer. The session it was asked from goes on working.
func TestRevokeOtherSessionsReportsPartialFailure(t *testing.T) {
	e := newEnv(t, nil)
	u := e.member(t)
	b := e.signedIn(t, u)
	other := e.signedIn(t, u)
	otherID := other.sessionID()
	good := e.Svc.Store
	e.Svc.Store = failSessionDeletes{good}
	b.markReauth()
	res, out := b.api("DELETE", "/api-internal/account/sessions", nil)
	if res.StatusCode != http.StatusServiceUnavailable || out["revoked"] != float64(1) || out["error"] == "" {
		t.Fatalf("revoke others with failing deletion: %d %v", res.StatusCode, out)
	}
	e.Svc.Store = good
	if _, err := e.Svc.Sessions.Get(context.Background(), otherID); err != nil {
		t.Fatalf("control: the other session's record should still exist: %v", err)
	}
	if res, _ := other.api("GET", "/api-internal/account/sessions", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the other session still works though it was signed out: %d", res.StatusCode)
	}
	if res, _ := b.api("GET", "/api-internal/account/sessions", nil); res.StatusCode != 200 {
		t.Fatalf("the session that signed the others out stopped working: %d", res.StatusCode)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(t)
	e.member(t)
	b.login("primary", "member", userPassword)
	if !b.hasSession() {
		t.Fatal("no session")
	}
	sid := b.sessionID()

	// GET shows a confirmation and never signs out.
	res, body := b.get("/logout?next=/admin")
	if res.StatusCode != 200 || !strings.Contains(body, "Sign out") || !strings.Contains(body, `data-next="/admin"`) {
		t.Fatalf("logout page: %d", res.StatusCode)
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); err != nil {
		t.Fatal("GET /logout ended the session")
	}
	csrf := metaRe.FindStringSubmatch(body)[1]

	// POST without the CSRF token is refused and the session survives.
	req, _ := http.NewRequest("POST", e.URL+e.primaryBase()+"/logout", nil)
	req.Header.Set("Accept", "application/json")
	res2, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != 403 {
		t.Fatalf("logout without csrf: %d", res2.StatusCode)
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), sid); err != nil {
		t.Fatal("unauthenticated POST /logout ended the session")
	}
	// Cross-site POST refused.
	req, _ = http.NewRequest("POST", e.URL+e.primaryBase()+"/logout", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Origin", "https://evil.example")
	res2, _ = b.c.Do(req)
	res2.Body.Close()
	if res2.StatusCode != 403 {
		t.Fatalf("cross-origin logout: %d", res2.StatusCode)
	}

	// fetch-style POST ends the session and answers JSON; hostile or missing next falls back to the org's sign-in page.
	for next, want := range map[string]string{e.primaryBase() + "/bye": e.primaryBase() + "/bye", "/bye": e.primaryBase() + "/login", "//evil.example": e.primaryBase() + "/login", "": e.primaryBase() + "/login"} {
		b2 := e.browser(t)
		b2.login("primary", "member", userPassword)
		page, body := b2.get("/logout")
		_ = page
		tok := metaRe.FindStringSubmatch(body)[1]
		sid2 := b2.sessionID()
		res, out := b2.do(http.MethodPost, "/logout?next="+url.QueryEscape(next), nil, hdrs{"X-CSRF-Token": tok})
		wantStatus(t, res, out, 200)
		if str(out, "next") != want {
			t.Fatalf("logout next %q -> %q want %q", next, str(out, "next"), want)
		}
		if _, err := e.Svc.Sessions.Get(context.Background(), sid2); err == nil {
			t.Fatal("session survived logout")
		}
		if res, _ := b2.get("/account"); res.StatusCode != 303 {
			t.Fatalf("account after logout: %d", res.StatusCode)
		}
	}

	// plain form post (no JS): CSRF in the form field, redirect.
	b3 := e.browser(t)
	b3.login("primary", "member", userPassword)
	_, body = b3.get("/logout")
	tok := metaRe.FindStringSubmatch(body)[1]
	res3, err := b3.c.PostForm(e.URL+e.primaryBase()+"/logout", url.Values{"csrf": {tok}, "next": {e.primaryBase() + "/farewell"}})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res3.Body)
	res3.Body.Close()
	if res3.StatusCode != 303 || res3.Header.Get("Location") != e.primaryBase()+"/farewell" {
		t.Fatalf("form logout: %d %q", res3.StatusCode, res3.Header.Get("Location"))
	}
	if res, _ := b3.get("/account"); res.StatusCode != 303 {
		t.Fatal("still signed in after form logout")
	}
	// form post with a bad token fails
	b4 := e.browser(t)
	b4.login("primary", "member", userPassword)
	res4, _ := b4.c.PostForm(e.URL+e.primaryBase()+"/logout", url.Values{"csrf": {"nope"}})
	res4.Body.Close()
	if res4.StatusCode != 403 {
		t.Fatalf("form logout with bad token: %d", res4.StatusCode)
	}
	if res, _ := b4.get("/account"); res.StatusCode != 200 {
		t.Fatal("session ended by a rejected logout")
	}
	// signed-out POST is harmless
	b5 := e.browser(t)
	res5, out := b5.do(http.MethodPost, "/logout", nil, hdrs{"X-CSRF-Token": "x"})
	wantStatus(t, res5, out, 200)
}

func TestReauthShowsLoginAndReplacesSession(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.browser(t)
	res, out := b.login("primary", "admin", e.Password)
	wantStatus(t, res, out, 200)
	oldSession := b.sessionID()

	res, body := b.get("/o/primary/login?reauth=1&next=/admin")
	if res.StatusCode != 200 || !strings.Contains(body, "sign in again") {
		t.Fatalf("reauth page: %d", res.StatusCode)
	}
	// The page still carries a working anonymous token even though a session exists.
	b.csrf = metaRe.FindStringSubmatch(body)[1]
	res, out = b.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if b.sessionID() == oldSession {
		t.Fatal("session not replaced")
	}
	if _, err := e.Svc.Sessions.Get(context.Background(), oldSession); err == nil {
		t.Fatal("old session still exists after re-authentication")
	}
	sess, _ := e.Svc.Sessions.All(context.Background(), pat.ID)
	if len(sess) != 1 {
		t.Fatalf("sessions of pat: %d", len(sess))
	}
	res, body = b.get("/account")
	if !strings.Contains(body, "pat") || res.StatusCode != 200 {
		t.Fatalf("account after reauth: %d", res.StatusCode)
	}
	// the page shows who is signed in, whatever address a link suggests
	res, body = b.get("/o/acme/login?reauth=1&login_hint=someone@example.com")
	if res.StatusCode != 200 || !strings.Contains(body, "pat@example.com") {
		t.Fatalf("reauth page with a hint: %d", res.StatusCode)
	}
}

// Signing in again as the same user upgrades the browser's session: same id (the refresh grants made in it, and
// the sid applications know, stay), a new sign-in time and a new cookie value (the old one stops working). Signing
// in as someone else replaces the session and ends its grants.
func TestSameUserSignInUpgradesSession(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	b := e.browser(t)
	m := e.member(t)
	res, out := b.login("primary", "member", userPassword)
	wantStatus(t, res, out, 200)
	sid := b.sessionID()
	b.signedInAt(time.Now().Add(-time.Minute)) // so a renewed sign-in time is visibly later
	first, _ := e.Svc.Sessions.Get(ctx, sid)
	oldCookie := b.cookie()
	g := &model.Grant{ClientID: "other-rp", UserID: m.ID, OrgID: m.OrgID, SessionID: sid, Scopes: []string{"openid"},
		Expires: time.Now().Add(time.Hour)}
	if err := e.Svc.Grants.Create(ctx, g); err != nil {
		t.Fatal(err)
	}

	res, out = b.do("POST", "/o/primary/api-internal/login/password", map[string]any{"email": "member@example.com",
		"password": userPassword, "next": "/account"}, nil)
	wantStatus(t, res, out, 200)
	if b.sessionID() != sid {
		t.Fatalf("re-authentication made a new session: %s -> %s", sid, b.sessionID())
	}
	if b.cookie() == oldCookie {
		t.Fatal("the cookie value was not rotated")
	}
	up, err := e.Svc.Sessions.Get(ctx, sid)
	if err != nil || !up.AuthTime.After(first.AuthTime) {
		t.Fatalf("auth time not renewed: %v %v -> %v", err, first.AuthTime, up)
	}
	if _, err := e.Svc.Grants.Get(ctx, g.ID); err != nil {
		t.Fatalf("the other application's grant ended: %v", err)
	}
	if res, _ := b.get("/account"); res.StatusCode != 200 {
		t.Fatalf("upgraded session: %d", res.StatusCode)
	}
	// The cookie from before the upgrade no longer signs anyone in.
	stale := e.browser(t)
	stale.setCookie(oldCookie)
	if res, _ := stale.get("/account"); res.StatusCode == 200 {
		t.Fatal("the pre-upgrade cookie still works")
	}

	// Another user signing in on this browser: the old session and its grants end.
	e.user(t, e.Primary, "someone", model.RoleUser)
	res, out = b.do("POST", "/o/primary/api-internal/login/password", map[string]any{"email": "someone@example.com",
		"password": userPassword, "next": "/account"}, nil)
	wantStatus(t, res, out, 200)
	if b.sessionID() == sid {
		t.Fatal("a different user took over the session")
	}
	if _, err := e.Svc.Sessions.Get(ctx, sid); err == nil {
		t.Fatal("the previous user's session survived")
	}
	if _, err := e.Svc.Grants.Get(ctx, g.ID); err == nil {
		t.Fatal("the previous user's grant survived")
	}
}

func (b *browser) cookie() string {
	u, _ := url.Parse(b.e.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if strings.HasPrefix(c.Name, web.SessionCookieFor("")) {
			return c.Value
		}
	}
	return ""
}

func (b *browser) setCookie(v string) {
	u, _ := url.Parse(b.e.URL)
	b.c.Jar.SetCookies(u, []*http.Cookie{{Name: web.SessionCookieFor(b.e.Primary.ID), Value: v, Path: "/", Secure: true}})
}

type failSessionCreates struct{ store.Store }

func (s failSessionCreates) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindSession && !r.Deleted {
		return store.ErrUnconfirmed
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func (s failSessionCreates) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindSession && !r.Deleted {
		return store.ErrUnconfirmed
	}
	return s.Store.Put(ctx, r)
}

// A sign-in whose new session the cluster could not confirm in time is answered 503 with Retry-After (trying again is
// safe), not 500; once the cluster answers, the same sign-in works.
func TestSignInWithUnconfirmedSessionAsksToRetry(t *testing.T) {
	e := newEnv(t, nil)
	e.member(t)
	b := e.browser(t)
	good := e.Svc.Sessions.S
	e.Svc.Sessions.S = failSessionCreates{good}
	body := map[string]any{"email": "member@example.com", "password": userPassword}
	res, out := b.do("POST", "/api-internal/login/password", body, nil)
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" {
		t.Fatalf("sign-in with an unconfirmed session write: %d %q %v", res.StatusCode, res.Header.Get("Retry-After"), out)
	}
	e.Svc.Sessions.S = good
	if res, out := b.do("POST", "/api-internal/login/password", body, nil); res.StatusCode != 200 {
		t.Fatalf("sign-in once the cluster answers: %d %v", res.StatusCode, out)
	}
}

// orgsRefused refuses every organization read as a node that cannot vouch for the global partition does.
type orgsRefused struct{ store.Store }

func (s orgsRefused) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	if kind == model.KindOrg {
		return nil, store.ErrUnavailable
	}
	return s.Store.GetByUnique(ctx, kind, value)
}

func (s orgsRefused) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindOrg {
		return nil, store.ErrUnavailable
	}
	return s.Store.Get(ctx, kind, id)
}

func (s orgsRefused) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindOrg {
		return nil, store.ErrUnavailable
	}
	return s.Store.List(ctx, kind, q)
}

// A sign-in whose organization cannot be read now is answered "try again" (503), never "the email address or password
// is incorrect": the organization exists, this node just cannot vouch for it at the moment.
func TestSignInWhenTheOrganizationCannotBeReadAsksToRetry(t *testing.T) {
	e := newEnv(t, nil)
	org, err := e.Svc.Org(context.Background(), e.member(t).OrgID)
	if err != nil {
		t.Fatal(err)
	}
	b := e.browser(t)
	good := e.Svc.Orgs.S
	e.Svc.Orgs.S = orgsRefused{good}
	// Not read lately (a copy read within the cache's bound would answer for it): the path names it by name, which
	// orgsRefused lets through, so the sign-in itself meets the refusal.
	e.Svc.InvalidateOrgs()
	body := map[string]any{"email": "member@example.com", "password": userPassword}
	res, out := b.do("POST", "/o/"+org.Name+"/api-internal/login/password", body, nil)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("sign-in with the organization unreadable: %d %v, want 503", res.StatusCode, out)
	}
	e.Svc.Orgs.S = good
	if res, out := b.do("POST", "/api-internal/login/password", body, nil); res.StatusCode != 200 {
		t.Fatalf("once it can be read: %d %v", res.StatusCode, out)
	}
}
