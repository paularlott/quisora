package web_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// whoami answers who the request's session is of, and, under /o/<org>, which organization the path names.
type whoami struct{}

func (whoami) Register(s *web.Server) {
	who := func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"user": ""}
		if u := web.User(r); u != nil {
			out["user"] = u.Username
		}
		if o := web.Org(r); o != nil {
			out["org"] = o.ID
		}
		web.WriteJSON(w, 200, out)
	}
	s.Mux.Handle("GET /o/{org}/whoami", s.InOrg(s.WithSession(http.HandlerFunc(who))))
	s.Mux.Handle("GET /admin/orgs/{org}/whoami", s.WithSession(http.HandlerFunc(who)))
	s.Mux.Handle("GET /admin/whoami", s.WithSession(http.HandlerFunc(who)))
}

// Organizations are self-contained: under /o/<org> (by id or by name) a request is that organization's, and only a
// session of it counts there; the console, which is the server's, uses the session of the browser's latest sign-in,
// else that of the organization it administers, else the primary organization's, else any other the browser holds.
func TestSessionsBelongToTheirOrganization(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{whoami{}} }})
	ctx := context.Background()
	beta, err := env.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("beta"), DisplayName: ptr("Beta")})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := env.Svc.CreateUser(ctx, service.System, beta.ID, service.UserInput{Username: ptr("bob"), GivenName: ptr("Bob"),
		Email: ptr("bob@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	primary, _ := env.Session(env.Admin)
	inBeta, _ := env.Session(bob)
	u := mustURL(t, env.URL)
	// both holds both sessions, bob's signed in last (a jar takes the later of two cookies of one name)
	both := &http.Client{Transport: primary.Transport}
	both.Jar, _ = cookiejar.New(nil)
	both.Jar.SetCookies(u, append(primary.Jar.Cookies(u), inBeta.Jar.Cookies(u)...))
	// superLast holds both, the super admin's signed in last
	superLast := &http.Client{Transport: primary.Transport}
	superLast.Jar, _ = cookiejar.New(nil)
	superLast.Jar.SetCookies(u, append(inBeta.Jar.Cookies(u), primary.Jar.Cookies(u)...))
	user := func(c *http.Client, path string) string {
		t.Helper()
		resp, body := get(t, c, env.URL+path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
		_, rest, _ := strings.Cut(body, `"user":"`)
		name, _, _ := strings.Cut(rest, `"`)
		return name
	}
	admin := env.Admin.Username
	for path, want := range map[string]map[*http.Client]string{
		"/o/" + beta.ID + "/whoami":            {primary: "", inBeta: "bob", both: "bob", superLast: "bob"},
		"/o/beta/whoami":                       {primary: "", inBeta: "bob", both: "bob", superLast: "bob"}, // by name
		"/o/" + model.PrimaryOrgID + "/whoami": {primary: admin, inBeta: "", both: admin, superLast: admin},
		"/admin/orgs/beta/whoami":              {primary: admin, inBeta: "bob", both: "bob", superLast: admin},
		"/admin/whoami":                        {primary: admin, inBeta: "bob", both: "bob", superLast: admin},
	} {
		for c, w := range want {
			if got := user(c, path); got != w {
				t.Errorf("%s: signed in as %q, want %q", path, got, w)
			}
		}
	}
	if resp, body := get(t, inBeta, env.URL+"/o/beta/whoami"); !strings.Contains(body, `"org":"`+beta.ID+`"`) {
		t.Errorf("the organization of /o/beta: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, primary, env.URL+"/o/no-such-org/whoami"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown organization: %d", resp.StatusCode)
	}
}

func ptr[T any](v T) *T { return &v }
