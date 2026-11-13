package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/scim"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// The schema URNs the tests address: the enterprise extension and Quisora's own User, Group and Organization schemas.
const (
	entURN       = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	quisoraURN   = "urn:paularlott:quisora:scim:schemas:2.0:User"
	groupURN     = "urn:paularlott:quisora:scim:schemas:2.0:Group"
	schemaOrgURN = "urn:paularlott:quisora:scim:schemas:2.0:Organization"
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

func newEnv(t testing.TB) *env { return newEnvStore(t, nil) }

// newEnvStore is newEnv over st (nil: an in-memory store).
func newEnvStore(t testing.TB, st store.Store) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), users: map[string]*model.User{}}
	e.Env = webtest.New(t, webtest.Options{Store: st, Modules: func(*web.Server) []web.Module {
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
	// Everyone may make api tokens here (a test makes one to see SCIM refuse it); an organization starts with nobody.
	st := model.DefaultOrgSettings()
	st.APITokens = model.APITokensEveryone
	o, err := e.Svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: &name, Settings: &st})
	if err != nil {
		e.t.Fatal(err)
	}
	return o
}

func (e *env) mkUser(o *model.Org, name string, role model.Role) *model.User {
	u, err := e.Svc.CreateUser(e.ctx, service.System, o.ID, service.UserInput{GivenName: ptr("T"), Username: &name, Role: &role,
		Email: ptr(name + "@example.com")})
	if err != nil {
		e.t.Fatal(err)
	}
	e.users[name] = u
	return u
}

func (e *env) primary() *model.Org { return e.Env.Primary }

// serviceAccount makes a service account of organization o with scopes and returns a bearer value that signs in as it
// (through the module's token verifier, as a client_credentials token would).
func (e *env) serviceAccount(o *model.Org, scopes ...string) string {
	e.t.Helper()
	cl, _, err := e.Svc.CreateServiceAccount(e.ctx, service.System, o.ID, service.ServiceAccountInput{Name: ptr("sa-" + o.Name), Scopes: &scopes})
	if err != nil {
		e.t.Fatal(err)
	}
	bearer, prev := "sa-"+cl.ID, e.verify
	e.verify = func(r *http.Request, scheme, b string) (*service.Actor, error) {
		if b == bearer {
			return service.ActorForServiceAccount(cl, cl.Scopes, ""), nil
		}
		if prev != nil {
			return prev(r, scheme, b)
		}
		return nil, service.ErrBadToken
	}
	return bearer
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

func wantStatus(t *testing.T, what string, r resp, status int) {
	t.Helper()
	if r.Status != status {
		t.Errorf("%s: status %d, want %d: %s", what, r.Status, status, r.Raw)
	}
}

// mail is an emails attribute with one primary address.
func mail(addr string) []any {
	return []any{map[string]any{"value": addr, "type": "work", "primary": true}}
}

// createUser POSTs a user. Most fixtures only care about userName, so an address (<userName>@acme.test) is added when
// the body has none; tests of the missing-email rules post with e.do instead.
func (e *env) createUser(org, token string, body map[string]any) resp {
	if un, ok := body["userName"].(string); ok && body["emails"] == nil {
		body["emails"] = mail(un + "@acme.test")
	}
	if body["schemas"] == nil {
		body["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}
	}
	return e.do("POST", "/scim/v2/"+org+"/Users", token, body)
}

// mk creates a user in org A through SCIM, with extra attributes, and returns its id.
func (e *env) mk(name string, extra map[string]any) string {
	body := map[string]any{"userName": name, "emails": []any{map[string]any{"value": name + "@acme.test", "type": "work", "primary": true}}}
	for k, v := range extra {
		body[k] = v
	}
	r := e.createUser("acme", e.admA, body)
	if r.Status != 201 {
		e.t.Fatalf("create %s: %d %s", name, r.Status, r.Raw)
	}
	return r.str("id")
}

// patch PATCHes a user of org A with org A's admin token.
func (e *env) patch(id string, ops ...map[string]any) resp {
	return e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, patchBody(ops...))
}

// group creates a group in org A with the given member ids and returns its id.
func (e *env) group(name string, members ...string) string {
	body := map[string]any{"displayName": name}
	if len(members) > 0 {
		ms := make([]any, len(members))
		for i, m := range members {
			ms[i] = map[string]any{"value": m}
		}
		body["members"] = ms
	}
	r := e.do("POST", "/scim/v2/acme/Groups", e.admA, body)
	if r.Status != 201 {
		e.t.Fatalf("group %s: %d %s", name, r.Status, r.Raw)
	}
	return r.str("id")
}

func memberValues(r resp) []string {
	var out []string
	for _, m := range r.list("members") {
		out = append(out, m.(map[string]any)["value"].(string))
	}
	slices.Sort(out)
	return out
}

func sorted(s ...string) []string { slices.Sort(s); return s }

type seed struct {
	name, given, family, email, title, dept, ext string
	role                                         model.Role
	inactive                                     bool
}

// seedOrg creates a small set of distinct users in org A, and a group Engineering of alice and bob.
func seedOrg(e *env) {
	t := e.t
	people := []seed{
		{"alice", "Alice", "Anderson", "alice@acme.test", "Engineer", "Tech", "ext-A", model.RoleUser, false},
		{"bob", "Bob", "Brown", "bob@acme.test", "Designer", "Design", "ext-b", model.RoleUser, false},
		{"carol", "Carol", "Clark", "carol@other.test", "", "Tech", "", model.RoleUser, true},
		{"dave", "Dave", "Davis", "dave@acme.test", "Manager", "Ops", "", model.RoleManager, false},
		{"erin", "Erin", "Evans", "erin@acme.test", "Engineer", "", "", model.RoleUser, false},
	}
	for _, p := range people {
		in := service.UserInput{Username: &p.name, GivenName: &p.given, FamilyName: &p.family, Role: &p.role,
			Work: &service.WorkInput{Title: &p.title, Department: &p.dept}}
		if p.email != "" {
			in.Email = &p.email
		}
		if p.ext != "" {
			in.ExternalID = &p.ext
		}
		if p.inactive {
			in.Active = ptr(false)
		}
		if _, err := e.Svc.CreateUser(e.ctx, service.System, e.orgA.ID, in); err != nil {
			t.Fatal(err)
		}
	}
	g1, err := e.Svc.CreateGroup(e.ctx, service.System, e.orgA.ID, service.GroupInput{DisplayName: ptr("Engineering")})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alice", "bob"} {
		u, _ := e.Svc.FindUserByEmail(e.ctx, e.orgA.ID, n+"@acme.test")
		if err := e.Svc.SetMembership(e.ctx, service.System, g1.ID, u.ID, true); err != nil {
			t.Fatal(err)
		}
	}
}

// usernames lists org A's users matching filter, sorted by userName.
func (e *env) usernames(filter string, extra ...string) ([]string, resp) {
	path := "/scim/v2/acme/Users?count=1000&sortBy=userName&filter=" + qs(filter)
	for _, x := range extra {
		path += "&" + x
	}
	r := e.do("GET", path, e.admA, nil)
	return r.names("userName"), r
}
