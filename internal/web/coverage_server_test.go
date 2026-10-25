package web_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// routes registers a few handlers behind the middleware under test.
type routes struct{ s *web.Server }

func (m *routes) Register(s *web.Server) {
	m.s = s
	s.Mux.Handle("GET /t/page", s.RequirePage(func(w http.ResponseWriter, r *http.Request) {
		p := s.Page(w, r, "Title", "nav", nil)
		web.WriteJSON(w, 200, map[string]any{"user": p.User.Username, "csrf": p.CSRF, "super": p.IsSuper, "admin": p.IsAdmin,
			"mgr": p.IsMgr, "home": p.HomeOrg, "path": p.Path, "title": p.Title})
	}))
	s.Mux.Handle("GET /admin/orgs/{org}/page", s.RequirePage(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	s.Mux.Handle("GET /t/anon", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := s.Page(w, r, "Anon", "", nil)
		web.WriteJSON(w, 200, map[string]any{"csrf": p.CSRF, "user": p.User == nil})
	}))
	s.Mux.Handle("POST /t/api", s.RequireAPI(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ A string }
		if !web.DecodeJSON(w, r, &in) {
			return
		}
		web.WriteJSON(w, 200, in)
	}))
	s.Mux.Handle("GET /t/api", s.RequireAPI(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	s.Mux.Handle("POST /t/signout", s.WithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.Sessions.End(r.Context(), w, r)
		web.WriteJSON(w, 200, map[string]any{"ended": sess != nil, "err": err != nil})
	})))
	s.Mux.Handle("GET /t/panic", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("kaboom") }))
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func post(t *testing.T, c *http.Client, url, csrf, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestRequirePageAndPage(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&routes{}} }})

	// Signed out: pages redirect to the sign-in page (the organization's for its admin pages).
	anon := env.Client()
	resp, _ := get(t, anon, env.URL+"/t/page")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("signed out: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = get(t, anon, env.URL+"/admin/orgs/acme/page?tab=2")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/acme?next=%2Fadmin%2Forgs%2Facme%2Fpage%3Ftab%3D2" {
		t.Fatalf("admin page signed out: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Signed in as a super admin: page data reflects the user, role flags and the session CSRF token.
	c, csrf := env.Session(env.Admin)
	resp, body := get(t, c, env.URL+"/t/page?x=1")
	if resp.StatusCode != 200 {
		t.Fatalf("signed in: %d %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got["csrf"] != csrf || got["super"] != true || got["admin"] != true || got["mgr"] != true || got["home"] != env.Primary.Name ||
		got["path"] != "/t/page?x=1" || got["user"] != env.Admin.Username {
		t.Fatalf("page data %v", got)
	}

	// A plain user is neither admin nor manager.
	plain, err := env.Svc.CreateUser(context.Background(), webtestSystem(), env.Primary.ID, userInput("plain"))
	if err != nil {
		t.Fatal(err)
	}
	pc, _ := env.Session(plain)
	_, body = get(t, pc, env.URL+"/t/page")
	got = nil
	_ = json.Unmarshal([]byte(body), &got)
	if got["super"] != false || got["admin"] != false || got["mgr"] != false {
		t.Fatalf("plain user page data %v", got)
	}

	// Signed out, Page hands out an anonymous double-submit token, once.
	_, body = get(t, anon, env.URL+"/t/anon")
	got = nil
	_ = json.Unmarshal([]byte(body), &got)
	tok, _ := got["csrf"].(string)
	if len(tok) < 32 || got["user"] != true {
		t.Fatalf("anonymous page %v", got)
	}
	_, body = get(t, anon, env.URL+"/t/anon")
	if !strings.Contains(body, tok) {
		t.Fatalf("anonymous token not stable across requests: %s", body)
	}
}

func TestRequireAPI(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&routes{}} }})
	c, csrf := env.Session(env.Admin)

	if resp, _ := get(t, env.Client(), env.URL+"/t/api"); resp.StatusCode != 401 {
		t.Fatalf("signed out: %d", resp.StatusCode)
	}
	if resp, _ := get(t, c, env.URL+"/t/api"); resp.StatusCode != 204 {
		t.Fatalf("GET needs no CSRF token: %d", resp.StatusCode)
	}
	if resp, body := post(t, c, env.URL+"/t/api", "", `{"A":"x"}`); resp.StatusCode != 403 || !strings.Contains(body, "could not be verified") {
		t.Fatalf("POST without a token: %d %s", resp.StatusCode, body)
	}
	if resp, _ := post(t, c, env.URL+"/t/api", "wrong", `{"A":"x"}`); resp.StatusCode != 403 {
		t.Fatalf("POST with a wrong token: %d", resp.StatusCode)
	}
	if resp, body := post(t, c, env.URL+"/t/api", csrf, `{"A":"x"}`); resp.StatusCode != 200 || !strings.Contains(body, `"A":"x"`) {
		t.Fatalf("POST: %d %s", resp.StatusCode, body)
	}
	if resp, _ := post(t, c, env.URL+"/t/api", csrf, `{"A":"x","Nope":1}`); resp.StatusCode != 400 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
	// A cross-site request carrying the right token is still refused.
	req, _ := http.NewRequest("POST", env.URL+"/t/api", strings.NewReader(`{}`))
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("foreign origin: %d", resp.StatusCode)
	}
}

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

func TestSessionsUpgradeRotatesCookie(t *testing.T) {
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
	other, _ := env.Svc.CreateUser(ctx, webtestSystem(), env.Primary.ID, userInput("other"))
	if _, err := env.Server.Sessions.Upgrade(ctx, httptest.NewRecorder(), r2, old, other, org, web.SessionOptions{}); err == nil {
		t.Fatal("upgrade by another user accepted")
	}
	// The upgraded session signs out with its new cookie.
	sess, err := env.Server.Sessions.End(ctx, httptest.NewRecorder(), r2)
	if err != nil || sess == nil {
		t.Fatalf("end: %v %v", sess, err)
	}
}

func TestSessionHandle(t *testing.T) {
	a, b := web.SessionHandle("sess-1"), web.SessionHandle("sess-2")
	if a == b || a != web.SessionHandle("sess-1") || strings.Contains(a, "sess-1") || len(a) != 22 {
		t.Fatalf("handles %q %q", a, b)
	}
}

func TestPanicBecomesJSON500(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&routes{}} }})
	resp, body := get(t, env.Client(), env.URL+"/t/panic")
	if resp.StatusCode != 500 || strings.Contains(body, "kaboom") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	// And the server still answers.
	if r, _ := get(t, env.Client(), env.URL+"/healthz"); r.StatusCode != 200 {
		t.Fatalf("healthz after panic: %d", r.StatusCode)
	}
}

// Every response, error pages included, carries the security headers; a request id is always answered.
func TestSecurityHeadersAndRequestID(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&routes{}} }})
	for _, path := range []string{"/healthz", "/t/panic", "/nope", "/t/api"} {
		resp, _ := get(t, env.Client(), env.URL+path)
		for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
			"Referrer-Policy": "strict-origin-when-cross-origin", "Cross-Origin-Opener-Policy": "same-origin"} {
			if resp.Header.Get(h) != want {
				t.Errorf("%s %s: %q", path, h, resp.Header.Get(h))
			}
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src") || strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src 'unsafe-inline'") {
			t.Errorf("%s CSP %q", path, csp)
		}
		if !strings.Contains(resp.Header.Get("Strict-Transport-Security"), "max-age=") || resp.Header.Get("Permissions-Policy") == "" {
			t.Errorf("%s: HSTS/Permissions-Policy missing", path)
		}
		if resp.Header.Get("X-Request-ID") == "" {
			t.Errorf("%s: no request id", path)
		}
	}
}

func TestBrandingDefaultsAndUnknown(t *testing.T) {
	env := webtest.New(t, webtest.Options{})
	for _, name := range []string{"logo-light", "logo-dark"} {
		resp, body := get(t, env.Client(), env.URL+"/branding/"+name)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/svg+xml" || !strings.Contains(body, "<svg") ||
			!strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	if resp, _ := get(t, env.Client(), env.URL+"/branding/other"); resp.StatusCode != 404 {
		t.Fatalf("unknown branding file: %d", resp.StatusCode)
	}
	if resp, _ := get(t, env.Client(), env.URL+"/branding/skin.css"); resp.StatusCode != 404 {
		t.Fatalf("skin.css without a skin: %d", resp.StatusCode)
	}
	if resp, _ := get(t, env.Client(), env.URL+"/metrics"); resp.StatusCode != 404 {
		t.Fatalf("metrics without a token: %d", resp.StatusCode)
	}
}
