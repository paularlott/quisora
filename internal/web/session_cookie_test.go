package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// Signing out ends the session and clears the cookie; without a session it only clears the cookie.
func TestSessionsEnd(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&routes{}} }})
	c, _ := env.Session(env.Admin)
	resp, body := post(t, c, env.URL+"/t/signout", "", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"ended":true`) || !strings.Contains(body, `"err":false`) {
		t.Fatalf("sign out: %d %s", resp.StatusCode, body)
	}
	var cleared bool
	for _, ck := range resp.Cookies() {
		if ck.Name == web.SessionCookie && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("cookie not cleared")
	}
	// The old cookie no longer opens anything.
	if r, _ := get(t, c, env.URL+"/t/page"); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("session survived sign-out: %d", r.StatusCode)
	}
	// Ending without a session is harmless and clears the cookie too.
	resp, body = post(t, env.Client(), env.URL+"/t/signout", "", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"ended":false`) || len(resp.Cookies()) != 1 {
		t.Fatalf("sign out without a session: %d %s %v", resp.StatusCode, body, resp.Cookies())
	}
}

// Upgrading a session (a second factor, a provider sign-in) keeps its id but issues a new cookie and CSRF token: the
// old cookie stops working, so a cookie planted before the upgrade gains nothing from it.
func TestSessionUpgradeRotatesTheCookieAndKillsTheOldOne(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&routes{}} }})
	ctx := context.Background()
	c, _ := env.Session(env.Admin)
	u := mustURL(t, env.URL)
	oldCookie := c.Jar.Cookies(u)[0]

	r := httptest.NewRequest("GET", env.URL+"/", nil)
	r.AddCookie(oldCookie)
	old, user := env.Server.Sessions.Current(r)
	if old == nil {
		t.Fatal("no current session")
	}
	org, _ := env.Svc.Orgs.Get(ctx, user.OrgID)
	rec := httptest.NewRecorder()
	up, err := env.Server.Sessions.Upgrade(ctx, rec, r, old, user, org, web.SessionOptions{AMR: []string{"pwd", "otp", "mfa"}, Provider: "prov"})
	if err != nil {
		t.Fatal(err)
	}
	if up.ID != old.ID || up.Provider != "prov" || len(up.AMR) != 3 || up.CSRF == old.CSRF || len(up.CookieHash) == 0 {
		t.Fatalf("upgraded session %+v", up)
	}
	newCookies := rec.Result().Cookies()
	if len(newCookies) != 1 || !strings.HasPrefix(newCookies[0].Value, up.ID+".") {
		t.Fatalf("new cookie %+v", newCookies)
	}
	// The session id is kept but the old cookie value is dead (no fixation), and the new one works.
	if s, _ := env.Server.Sessions.Current(r); s != nil {
		t.Fatal("old cookie still valid after the upgrade")
	}
	r2 := httptest.NewRequest("GET", env.URL+"/", nil)
	r2.AddCookie(newCookies[0])
	if s, _ := env.Server.Sessions.Current(r2); s == nil || s.ID != old.ID {
		t.Fatal("new cookie not accepted")
	}
	// A different user's session cannot be upgraded by someone else.
	other, _ := env.Svc.CreateUser(ctx, service.System, env.Primary.ID, userInput("other"))
	if _, err := env.Server.Sessions.Upgrade(ctx, httptest.NewRecorder(), r2, old, other, org, web.SessionOptions{}); err == nil {
		t.Fatal("upgrade by another user accepted")
	}
	// The upgraded session signs out with its new cookie.
	sess, err := env.Server.Sessions.End(ctx, httptest.NewRecorder(), r2)
	if err != nil || sess == nil {
		t.Fatalf("end: %v %v", sess, err)
	}
}
