package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// Ending a session the store cannot check is an error and leaves the cookie, not a sign-out of nothing: callers
// would report (and audit) a sign-out that did not happen, and the browser would lose the cookie it needs to retry.
func TestEndOfASessionThatCannotBeCheckedFailsAndKeepsTheCookie(t *testing.T) {
	env := webtest.New(t, webtest.Options{})
	c, _ := env.Session(env.Admin)
	u, _ := url.Parse(env.URL)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	var sid string
	for _, ck := range c.Jar.Cookies(u) {
		req.AddCookie(ck)
		if strings.HasPrefix(ck.Name, web.SessionCookieFor("")) {
			sid = web.SessionID(ck.Value)
		}
	}
	env.Server.Sessions.Evict(sid, "")
	good := env.Svc.Sessions.S
	env.Svc.Sessions.S = sessionsRefused{good, ""}
	defer func() { env.Svc.Sessions.S = good }()

	rec := httptest.NewRecorder()
	sess, err := env.Server.Sessions.End(context.Background(), rec, req)
	if err == nil || sess != nil {
		t.Fatalf("End of an unreadable session: %v, %v; want an error", sess, err)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("the cookie was cleared over a session that may be alive: %v", got)
	}
}
