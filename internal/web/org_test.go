package web_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// whoami answers who the request's session is of, and, under /o/<org>, which organization the path names.
type whoami struct{}

func (whoami) Register(s *web.Server) {
	who := func(w http.ResponseWriter, r *http.Request) {
		if web.SessionUnchecked(r) {
			web.WriteUnchecked(w)
			return
		}
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
// else that of the organization it administers, else the primary organization's, else any other the browser holds,
// but the first whose user can use the console (a manager or above) before any whose user cannot: a super admin's
// guest account in another organization, signed in last, must not shut them out of it.
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
	carol, err := env.Svc.CreateUser(ctx, service.System, beta.ID, service.UserInput{Username: ptr("carol"), GivenName: ptr("Carol"),
		Email: ptr("carol@example.com"), Role: ptr(model.RoleManager)})
	if err != nil {
		t.Fatal(err)
	}
	primary, _ := env.Session(env.Admin)
	inBeta, _ := env.Session(bob)
	carolInBeta, _ := env.Session(carol)
	u := mustURL(t, env.URL)
	holding := func(first, last *http.Client) *http.Client {
		c := &http.Client{Transport: primary.Transport}
		c.Jar, _ = cookiejar.New(nil)
		c.Jar.SetCookies(u, append(first.Jar.Cookies(u), last.Jar.Cookies(u)...)) // a jar takes the later of two cookies of one name
		return c
	}
	// both holds both sessions, bob's (a plain user of beta, a guest as far as the console goes) signed in last
	both := holding(primary, inBeta)
	// superLast holds both, the super admin's signed in last
	superLast := holding(inBeta, primary)
	// managerLast holds the super admin's session and carol's, a manager of beta who can use the console, signed in last
	managerLast := holding(primary, carolInBeta)
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
		"/o/" + beta.ID + "/whoami":            {primary: "", inBeta: "bob", both: "bob", superLast: "bob", managerLast: "carol"},
		"/o/beta/whoami":                       {primary: "", inBeta: "bob", both: "bob", superLast: "bob", managerLast: "carol"}, // by name
		"/o/" + model.PrimaryOrgID + "/whoami": {primary: admin, inBeta: "", both: admin, superLast: admin, managerLast: admin},
		// The console skips a session that cannot use it: bob, last, does not shut the super admin out; carol, a
		// manager, can use it, and being last she is the one it acts as.
		"/admin/orgs/beta/whoami": {primary: admin, inBeta: "bob", both: admin, superLast: admin, managerLast: "carol"},
		"/admin/whoami":           {primary: admin, inBeta: "bob", both: admin, superLast: admin, managerLast: "carol"},
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

// The organization cache keeps an organization under its id and its name only: the many spellings a name is matched
// in still resolve, but each would otherwise be an entry of its own, and a client could grow the cache without end. So
// the canonical forms are served from the cache, and every other spelling is read from the store each time.
func TestOrgCacheKeepsCanonicalReferencesOnly(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{whoami{}} }})
	beta, err := env.Svc.CreateOrg(context.Background(), service.System, service.OrgInput{Name: ptr("beta"), DisplayName: ptr("Beta")})
	if err != nil {
		t.Fatal(err)
	}
	reads := &orgReads{Store: env.Svc.Orgs.S}
	env.Svc.Orgs.S = reads
	c := env.Client()
	resolve := func(ref string) int64 {
		t.Helper()
		before := reads.n.Load()
		if resp, body := get(t, c, env.URL+"/o/"+ref+"/whoami"); !strings.Contains(body, `"org":"`+beta.ID+`"`) {
			t.Fatalf("%s: %d %s", ref, resp.StatusCode, body)
		}
		return reads.n.Load() - before
	}
	spellings := []string{"BETA", "Beta", "bEtA"}
	for _, ref := range append([]string{beta.ID, "beta"}, spellings...) {
		resolve(ref)
	}
	for _, ref := range []string{beta.ID, "beta"} {
		if n := resolve(ref); n != 0 {
			t.Errorf("%s: read from the store %d times, want the cached copy", ref, n)
		}
	}
	for _, ref := range spellings {
		if n := resolve(ref); n == 0 {
			t.Errorf("%s: served from the cache: every spelling of a name would be an entry of its own", ref)
		}
	}
}

// orgReads counts the reads of organizations.
type orgReads struct {
	store.Store
	n atomic.Int64
}

func (s *orgReads) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindOrg {
		s.n.Add(1)
	}
	return s.Store.Get(ctx, kind, id)
}

func (s *orgReads) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	if kind == model.KindOrg {
		s.n.Add(1)
	}
	return s.Store.GetByUnique(ctx, kind, value)
}

// sessionsRefused refuses the reads of sessions, as a node that cannot vouch for the session partition does: of every
// session, or only of the one with id only when it is set.
type sessionsRefused struct {
	store.Store
	only string
}

func (s sessionsRefused) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindSession && (s.only == "" || s.only == id) {
		return nil, store.ErrUnavailable
	}
	return s.Store.Get(ctx, kind, id)
}

// A console request whose first session cannot be checked is unchecked (503): the next cookie is not tried, or the
// request would act as another account than the one the browser signed in as last.
func TestConsoleSessionThatCannotBeCheckedIsNotSkipped(t *testing.T) {
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
	c := &http.Client{Transport: primary.Transport}
	c.Jar, _ = cookiejar.New(nil)
	c.Jar.SetCookies(u, append(primary.Jar.Cookies(u), inBeta.Jar.Cookies(u)...)) // bob's signed in last
	if resp, body := get(t, c, env.URL+"/admin/whoami"); resp.StatusCode != 200 {
		t.Fatalf("control: %d %s", resp.StatusCode, body)
	}
	// Bob's session, the first of the order, is read afresh and refused; the super admin's still reads, so a request that
	// passed on to it would be answered.
	var bobSession string
	for _, ck := range inBeta.Jar.Cookies(u) {
		if strings.HasPrefix(ck.Name, web.SessionCookieFor("")) {
			bobSession = web.SessionID(ck.Value)
		}
	}
	env.Server.Sessions.Evict(bobSession, "")
	good := env.Svc.Sessions.S
	env.Svc.Sessions.S = sessionsRefused{good, bobSession}
	defer func() { env.Svc.Sessions.S = good }()
	resp, body := get(t, c, env.URL+"/admin/whoami")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a console request whose first session cannot be checked: %d %s, want 503", resp.StatusCode, body)
	}
}

// sessionMissesRefused answers session reads as a cluster node does while some partition is between owners: a session id
// it does not hold, read by Get, may be in any partition and is refused, while one asked of its organization's
// partition (store.GetIn), which is readable, is answered.
type sessionMissesRefused struct{ store.Store }

func (s sessionMissesRefused) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	r, err := s.Store.Get(ctx, kind, id)
	if kind == model.KindSession && errors.Is(err, store.ErrNotFound) {
		return nil, store.ErrUnavailable
	}
	return r, err
}

func (s sessionMissesRefused) GetIn(ctx context.Context, kind model.Kind, partitionKey, id string) (*store.Record, error) {
	return store.GetIn(ctx, s.Store, kind, partitionKey, id)
}

// A session cookie whose session is not there (a stale one, a made-up one) is signed out, not 503, while the session's
// organization can be read: its session is looked for in that organization's partition only, so another partition
// between owners does not leave every such request unchecked.
func TestUnknownSessionCookieIsSignedOutWhileAnotherPartitionIsUnreadable(t *testing.T) {
	env := webtest.New(t, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{whoami{}} }})
	good := env.Svc.Sessions.S
	env.Svc.Sessions.S = sessionMissesRefused{good}
	defer func() { env.Svc.Sessions.S = good }()
	c := env.Client()
	c.Jar.SetCookies(mustURL(t, env.URL), []*http.Cookie{{Name: web.SessionCookieFor(env.Primary.ID),
		Value: "made-up-cookie-value-abcdefghijklmnopqrstuvwxyz", Path: "/"}})
	resp, body := get(t, c, env.URL+"/o/"+env.Primary.ID+"/whoami")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"user":""`) {
		t.Fatalf("an unknown session cookie: %d %s, want signed out", resp.StatusCode, body)
	}
}
