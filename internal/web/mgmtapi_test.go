package web_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

type probe struct{}

func (probe) Register(s *web.Server) {
	s.Mux.Handle("POST /api/probe", s.RequireManagement(func(w http.ResponseWriter, r *http.Request) {
		web.WriteJSON(w, 200, map[string]string{"actor": web.Actor(r).Name, "version": web.APIVersion(r)})
	}))
	s.Bearer = func(ctx context.Context, r *http.Request, tok string) (*service.Actor, error) {
		switch tok {
		case "admin":
			return &service.Actor{Name: "tok", Scopes: []string{service.ScopeAdmin}}, nil
		case "scim":
			return &service.Actor{Name: "tok", Scopes: []string{service.ScopeSCIM}}, nil
		case "down": // the store failed while the token was checked
			return nil, service.ErrUnavailable
		}
		return nil, errors.New("bad")
	}
}

func TestManagementAuthAndVersion(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{probe{}} }})
	do := func(c *http.Client, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, env.URL+"/api/probe", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	anon := env.Client()
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"no auth", nil, 401},
		{"bad token", map[string]string{"Authorization": "Bearer nope"}, 401},
		{"wrong scope", map[string]string{"Authorization": "Bearer scim"}, 403},
		{"admin token", map[string]string{"Authorization": "Bearer admin"}, 200},
		{"bad version", map[string]string{"Authorization": "Bearer admin", "Api-Version": "99"}, 400},
		{"unknown date", map[string]string{"Authorization": "Bearer admin", "Api-Version": "2026-10-19"}, 400},
		{"old numeric version", map[string]string{"Authorization": "Bearer admin", "Api-Version": "1"}, 400},
	}
	for _, c := range cases {
		if r := do(anon, c.hdr); r.StatusCode != c.want {
			t.Errorf("%s: got %d want %d", c.name, r.StatusCode, c.want)
		}
	}
	if r := do(anon, map[string]string{"Authorization": "Bearer admin"}); r.Header.Get("Api-Version") != web.APIVersionLatest {
		t.Error("version not echoed")
	}
	sess, csrf := env.ConsoleSession(env.Admin)
	if r := do(sess, nil); r.StatusCode != 403 {
		t.Errorf("session without CSRF: %d", r.StatusCode)
	}
	if r := do(sess, map[string]string{"X-CSRF-Token": csrf, "Api-Version": web.APIVersionLatest}); r.StatusCode != 200 {
		t.Errorf("session with CSRF: %d", r.StatusCode)
	}
}

// API versions are release dates, oldest first, ending with the latest; the browser UI sends the latest.
func TestAPIVersions(t *testing.T) {
	prev := ""
	for _, v := range web.APIVersions {
		d, err := time.Parse(time.DateOnly, v)
		if err != nil || d.Format(time.DateOnly) != v {
			t.Errorf("API version %q is not a YYYY-MM-DD date", v)
		}
		if v <= prev {
			t.Errorf("API versions out of order: %q after %q", v, prev)
		}
		prev = v
	}
	if prev != web.APIVersionLatest {
		t.Errorf("the last API version is %q, APIVersionLatest %q", prev, web.APIVersionLatest)
	}
	js, err := os.ReadFile("../../web/src/js/lib/api.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "export const API_VERSION = '"+web.APIVersionLatest+"'") {
		t.Errorf("web/src/js/lib/api.js does not send API version %s", web.APIVersionLatest)
	}
}

type auditCapture struct{ actions chan string }

func (c auditCapture) WriteAudit(e *model.Audit) {
	c.actions <- e.Action + " " + e.Target + " " + e.Detail["reason"]
}

// Failed bearer authentications are limited per address: past the limit every bearer request from it is refused
// before its token is looked at, the right one too. Refusals of a known actor are audited.
func TestManagementBearerLimitAndRefusalAudit(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{probe{}} }})
	audit := auditCapture{actions: make(chan string, 16)}
	env.Svc.AuditWriter = audit
	do := func(c *http.Client, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, env.URL+"/api/probe", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	anon := env.Client()
	if r := do(anon, map[string]string{"Authorization": "Bearer scim"}); r.StatusCode != 403 {
		t.Fatalf("wrong scope: %d", r.StatusCode)
	}
	if got := <-audit.actions; !strings.HasPrefix(got, "api.request.refused POST /api/probe") || !strings.Contains(got, "admin scope") {
		t.Errorf("wrong-scope refusal audited as %q", got)
	}
	sess, _ := env.ConsoleSession(env.Admin)
	if r := do(sess, nil); r.StatusCode != 403 {
		t.Fatalf("session without CSRF: %d", r.StatusCode)
	}
	if got := <-audit.actions; !strings.Contains(got, "CSRF") {
		t.Errorf("CSRF refusal audited as %q", got)
	}
	for range web.BearerFailuresPerIPMin + 5 { // a store failure is not the caller's: never counted
		if r := do(anon, map[string]string{"Authorization": "Bearer down"}); r.StatusCode != 503 {
			t.Fatalf("store failure: %d, want 503", r.StatusCode)
		}
	}
	for i := range web.BearerFailuresPerIPMin {
		if r := do(anon, map[string]string{"Authorization": "Bearer nope"}); r.StatusCode != 401 {
			t.Fatalf("failure %d: %d", i+1, r.StatusCode)
		}
	}
	r := do(anon, map[string]string{"Authorization": "Bearer admin"})
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" {
		t.Fatalf("valid token after the limit: %d, want 429 with Retry-After", r.StatusCode)
	}
	if r := do(sess, nil); r.StatusCode == http.StatusTooManyRequests {
		t.Error("a session request was limited: only bearer authentication counts")
	}
}
