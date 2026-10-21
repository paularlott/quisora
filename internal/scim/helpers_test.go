package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/scim"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

type env struct {
	*webtest.Env
	t      testing.TB
	ctx    context.Context
	client *http.Client
	super  string // super admin token
	orgA   *model.Org
	orgB   *model.Org
	admA   string // admin token of org A
	mgrA   string // manager token of org A
	admB   string // admin token of org B
	users  map[string]*model.User
	verify scim.TokenVerifier
}

func ptr[T any](v T) *T { return &v }

func newEnv(t testing.TB) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), users: map[string]*model.User{}}
	e.Env = webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module {
		return []web.Module{&scim.Module{TokenVerifier: func(r *http.Request, scheme, b string) (*service.Actor, error) {
			if e.verify != nil {
				return e.verify(r, scheme, b)
			}
			return nil, service.ErrBadToken
		}}}
	}})
	e.client = e.Env.Client()
	e.super = e.token(e.Admin, "scim")
	e.orgA = e.org("acme")
	e.orgB = e.org("globex")
	e.admA = e.token(e.mkUser(e.orgA, "adm-a", model.RoleAdmin), "scim")
	e.mgrA = e.token(e.mkUser(e.orgA, "mgr-a", model.RoleManager), "scim")
	e.admB = e.token(e.mkUser(e.orgB, "adm-b", model.RoleAdmin), "scim")
	return e
}

func (e *env) org(name string) *model.Org {
	o, err := e.Svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: &name})
	if err != nil {
		e.t.Fatal(err)
	}
	return o
}

func (e *env) mkUser(o *model.Org, name string, role model.Role) *model.User {
	u, err := e.Svc.CreateUser(e.ctx, service.System, o.ID, service.UserInput{GivenName: gn("T"), Username: &name, Role: &role,
		Email: ptr(name + "@example.com")})
	if err != nil {
		e.t.Fatal(err)
	}
	e.users[name] = u
	return u
}

func (e *env) token(u *model.User, scopes ...string) string {
	_, plain, err := e.Svc.CreateAPIToken(e.ctx, service.ActorForUser(u, ""), service.APITokenInput{Name: "t", Scopes: scopes})
	if err != nil {
		e.t.Fatal(err)
	}
	return plain
}

type resp struct {
	Status int
	Header http.Header
	Body   map[string]any
	Raw    []byte
}

func (e *env) do(method, path, token string, body any, hdr ...string) resp {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	r := resp{Status: res.StatusCode, Header: res.Header, Raw: raw}
	_ = json.Unmarshal(raw, &r.Body)
	return r
}

// get helpers for nested JSON.
func (r resp) str(path ...string) string {
	v := any(r.Body)
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[p]
	}
	s, _ := v.(string)
	return s
}

func (r resp) list(key string) []any {
	l, _ := r.Body[key].([]any)
	return l
}

func (r resp) names(attr string) []string {
	var out []string
	for _, it := range r.list("Resources") {
		s, _ := it.(map[string]any)[attr].(string)
		out = append(out, s)
	}
	return out
}

func (r resp) total() int {
	f, _ := r.Body["totalResults"].(float64)
	return int(f)
}

func qs(s string) string { return url.QueryEscape(s) }

func op(o, path string, value any) map[string]any {
	m := map[string]any{"op": o}
	if path != "" {
		m["path"] = path
	}
	if value != nil {
		m["value"] = value
	}
	return m
}

func patchBody(ops ...map[string]any) map[string]any {
	l := make([]any, len(ops))
	for i, o := range ops {
		l[i] = o
	}
	return map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": l}
}

func readAll(res *http.Response) ([]byte, error) {
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}
