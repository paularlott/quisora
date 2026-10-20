package web_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

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
	}
	for _, c := range cases {
		if r := do(anon, c.hdr); r.StatusCode != c.want {
			t.Errorf("%s: got %d want %d", c.name, r.StatusCode, c.want)
		}
	}
	if r := do(anon, map[string]string{"Authorization": "Bearer admin"}); r.Header.Get("Api-Version") != "1" {
		t.Error("version not echoed")
	}
	sess, csrf := env.ConsoleSession(env.Admin)
	if r := do(sess, nil); r.StatusCode != 403 {
		t.Errorf("session without CSRF: %d", r.StatusCode)
	}
	if r := do(sess, map[string]string{"X-CSRF-Token": csrf, "Api-Version": "1"}); r.StatusCode != 200 {
		t.Errorf("session with CSRF: %d", r.StatusCode)
	}
}
