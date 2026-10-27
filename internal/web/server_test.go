package web_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
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
			"mgr": p.IsMgr, "home": p.Org.Name, "path": p.Path, "title": p.Title})
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

// Signed out, a page redirects to sign-in (an organization's admin page to that organization's sign-in, coming back
// afterwards); signed in, the page data carries the user, their role flags and the session's CSRF token.
func TestPagesRedirectWhenSignedOutAndCarryRoleFlags(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&routes{}} }})

	// Signed out: pages redirect to the sign-in page (the organization's for its admin pages).
	anon := env.Client()
	resp, _ := get(t, anon, env.URL+"/t/page")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/o/"+model.PrimaryOrgID+"/login?next=%2Ft%2Fpage" {
		t.Fatalf("signed out: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = get(t, anon, env.URL+"/admin/orgs/acme/page?tab=2")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/o/acme/login?next=%2Fadmin%2Forgs%2Facme%2Fpage%3Ftab%3D2" {
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
	plain, err := env.Svc.CreateUser(context.Background(), service.System, env.Primary.ID, userInput("plain"))
	if err != nil {
		t.Fatal(err)
	}
	pc, _ := env.Session(plain)
	_, body = get(t, pc, env.URL+"/t/page")
	got = nil
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("plain user page: %v %s", err, body)
	}
	if got["super"] != false || got["admin"] != false || got["mgr"] != false {
		t.Fatalf("plain user page data %v", got)
	}

	// Signed out, Page hands out an anonymous double-submit token, once.
	_, body = get(t, anon, env.URL+"/t/anon")
	got = nil
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("anonymous page: %v %s", err, body)
	}
	tok, _ := got["csrf"].(string)
	if len(tok) < 32 || got["user"] != true {
		t.Fatalf("anonymous page %v", got)
	}
	_, body = get(t, anon, env.URL+"/t/anon")
	if !strings.Contains(body, tok) {
		t.Fatalf("anonymous token not stable across requests: %s", body)
	}
}

// A JSON endpoint needs a session, and for a POST the session's CSRF token from the same origin; its body is decoded
// strictly. (Which tokens and origins pass is TestCheckCSRF's.)
func TestAPIRequiresSessionAndCSRF(t *testing.T) {
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

// A handler that panics answers a JSON 500 that does not repeat the panic, and the server goes on serving.
func TestPanicBecomesJSON500(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{&routes{}} }})
	resp, body := get(t, env.Client(), env.URL+"/t/panic")
	if resp.StatusCode != 500 || strings.Contains(body, "kaboom") || !strings.Contains(body, "Something went wrong") {
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

// Without a skin or configured logos the built-in logos are served, as images that can run nothing; other names are
// not found.
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
}

func userInput(name string) service.UserInput {
	s := func(v string) *string { return &v }
	return service.UserInput{GivenName: s(name), Username: s(name), Email: s(name + "@example.com")}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
