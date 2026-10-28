package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

func ptr[T any](v T) *T { return &v }

// world is a test environment with an org "acme" holding one admin, manager and user, and an org "globex".
type world struct {
	t     *testing.T
	env   *webtest.Env
	acme  *model.Org
	other *model.Org
	users map[string]*model.User // admin, manager, user (acme); other (globex admin)
	mod   *admin.Module
}

func newWorld(t *testing.T) *world { t.Helper(); return newWorldWith(t, nil) }

// newWorldWith is newWorld with a configuration hook.
func newWorldWith(t *testing.T, cfgFn func(*config.Config)) *world {
	t.Helper()
	w := &world{t: t, mod: admin.New(), users: map[string]*model.User{}}
	w.env = webtest.New(t, webtest.Options{Configure: cfgFn, Modules: func(s *web.Server) []web.Module {
		s.Mux.Handle("/", admin.NotFound(s))
		return []web.Module{w.mod}
	}})
	// Sessions here count as recently re-authenticated (the dangerous changes need it: stepUp); tests of the
	// re-authentication itself set their own.
	w.env.Server.Reauthed = func(*http.Request) bool { return true }
	ctx := context.Background()
	sys := service.System
	// Everyone may make api tokens here (the tokens most tests make are not about that); tests of the setting change it.
	st := model.DefaultOrgSettings()
	st.APITokens = model.APITokensEveryone
	var err error
	if w.env.Primary, err = w.env.Svc.UpdateOrg(ctx, sys, w.env.Primary.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	if w.acme, err = w.env.Svc.CreateOrg(ctx, sys, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme"), Settings: &st}); err != nil {
		t.Fatal(err)
	}
	if w.other, err = w.env.Svc.CreateOrg(ctx, sys, service.OrgInput{Name: ptr("globex"), DisplayName: ptr("Globex"), Settings: &st}); err != nil {
		t.Fatal(err)
	}
	mk := func(key string, org *model.Org, name string, role model.Role) {
		u, err := w.env.Svc.CreateUser(ctx, sys, org.ID, service.UserInput{GivenName: ptr("T"), Username: ptr(name), Email: ptr(name + "@x.example"),
			Role: ptr(role), Password: ptr("correct horse battery")})
		if err != nil {
			t.Fatal(err)
		}
		w.users[key] = u
	}
	mk("admin", w.acme, "ada", model.RoleAdmin)
	mk("manager", w.acme, "grace", model.RoleManager)
	mk("user", w.acme, "alan", model.RoleUser)
	mk("other", w.other, "otto", model.RoleAdmin)
	return w
}

// caller performs requests as one identity.
type caller struct {
	w      *world
	c      *http.Client
	csrf   string
	bearer string
}

func (w *world) as(key string) *caller {
	u := w.env.Admin
	if key != "super" {
		u = w.users[key]
	}
	c, csrf := w.env.SessionAMR(u, []string{"pwd", "otp", "mfa"}) // the console needs a second factor
	return &caller{w: w, c: detach(c), csrf: csrf}
}

// asSingleFactor signs in as key with a password only.
func (w *world) asSingleFactor(key string) *caller {
	u := w.env.Admin
	if key != "super" {
		u = w.users[key]
	}
	c, csrf := w.env.Session(u)
	return &caller{w: w, c: detach(c), csrf: csrf}
}

// detach copies a webtest client so later webtest.Client()/Session() calls (which reuse one shared *http.Client and
// replace its cookie jar) cannot change which identity this caller uses.
func detach(c *http.Client) *http.Client {
	return &http.Client{Transport: c.Transport, Jar: c.Jar, CheckRedirect: c.CheckRedirect}
}

func (w *world) anon() *caller { return &caller{w: w, c: detach(w.env.Client())} }

// withBearer returns a caller that authenticates with an API token of the given scopes for user key.
func (w *world) withBearer(key string, scopes ...string) *caller {
	u := w.env.Admin
	if key != "super" {
		u = w.users[key]
	}
	_, tok, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(u, ""), service.APITokenInput{Name: "t", Scopes: scopes})
	if err != nil {
		w.t.Fatal(err)
	}
	w.env.Server.Bearer = func(ctx context.Context, r *http.Request, token string) (*service.Actor, error) {
		t, u, err := w.env.Svc.ValidateAPIToken(ctx, token)
		if err != nil {
			return nil, err
		}
		return service.ActorForToken(t, u, web.ClientIP(r)), nil
	}
	return &caller{w: w, c: detach(w.env.Client()), bearer: tok}
}

type resp struct {
	Status int
	Header http.Header
	Raw    []byte
	JSON   map[string]any
}

func (r resp) items() []any        { l, _ := r.JSON["items"].([]any); return l }
func (r resp) total() int          { n, _ := r.JSON["total"].(float64); return int(n) }
func (r resp) str(k string) string { s, _ := r.JSON[k].(string); return s }

func (c *caller) do(method, path string, body any, hdr ...string) resp {
	c.w.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.w.env.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	} else if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	res, err := c.c.Do(req)
	if err != nil {
		c.w.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Header: res.Header, Raw: raw}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

func (c *caller) get(path string) resp             { return c.do("GET", path, nil) }
func (c *caller) post(path string, body any) resp  { return c.do("POST", path, body) }
func (c *caller) patch(path string, body any) resp { return c.do("PATCH", path, body) }
func (c *caller) put(path string, body any) resp   { return c.do("PUT", path, body) }
func (c *caller) delete(path string) resp          { return c.do("DELETE", path, nil) }

func want(t *testing.T, r resp, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status %d, want %d: %s", r.Status, status, r.Raw)
	}
}

func wantField(t *testing.T, r resp, status int, field string) {
	t.Helper()
	want(t, r, status)
	if r.str("field") != field || r.str("error") == "" {
		t.Fatalf("error body %s, want field %q", r.Raw, field)
	}
}

const (
	A  = "/api/orgs/acme"
	G  = "/api/orgs/globex"
	AU = A + "/users"
)

// fakeMailer records the mail it is asked to send, or refuses every mail with err.
type fakeMailer struct {
	sent []string
	err  error
}

func (m *fakeMailer) SendInviteLink(_ context.Context, _ *model.Org, u *model.User, url string, _ time.Time) error {
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, u.Username+" "+url)
	return nil
}

func (m *fakeMailer) SendVerifyAddress(_ context.Context, _ *model.Org, u *model.User, address string) error {
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, "verify "+u.Username+" "+address)
	return nil
}

type notReady struct{}

func (notReady) Ready() (bool, string) { return false, "catching up" }

func auditActions(t *testing.T, w *world, action string) []*model.Audit {
	t.Helper()
	l, _, err := w.env.Svc.Audits.List(context.Background(), store.ListQuery{Filters: []store.Filter{{Field: "action", Value: action}}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}
