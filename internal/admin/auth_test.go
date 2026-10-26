package admin_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

func TestAuthAndCSRF(t *testing.T) {
	w := newWorld(t)
	want(t, w.anon().get("/api/orgs"), 401)
	want(t, w.anon().post("/api/orgs", map[string]any{"name": "x"}), 401)

	ad := w.as("admin")
	c := &caller{w: w, c: ad.c} // session cookie without CSRF header
	want(t, c.post(A+"/groups", map[string]any{"display_name": "g"}), 403)
	want(t, c.get(A+"/groups"), 200) // safe methods need no token
	bad := &caller{w: w, c: ad.c, csrf: "wrong"}
	want(t, bad.post(A+"/groups", map[string]any{"display_name": "g"}), 403)
	// cross-origin
	want(t, ad.do("POST", A+"/groups", map[string]any{"display_name": "g"}, "Origin", "https://evil.example"), 403)
	want(t, ad.do("POST", A+"/groups", map[string]any{"display_name": "g"}, "Sec-Fetch-Site", "cross-site"), 403)
	want(t, ad.post(A+"/groups", map[string]any{"display_name": "g"}), 201)
}

func TestBearerAndVersioning(t *testing.T) {
	w := newWorld(t)
	// manager token with admin scope: same limits as the manager's session
	mt := w.withBearer("manager", service.ScopeAdmin)
	r := mt.get(AU)
	want(t, r, 200)
	if r.Header.Get("Api-Version") != web.APIVersionLatest {
		t.Error("version not echoed")
	}
	want(t, mt.post(AU, map[string]any{"given_name": "T", "username": "viabearer", "email": "viabearer@x.example"}), 201)
	want(t, mt.post(AU, map[string]any{"given_name": "T", "username": "viabearer2", "email": "viabearer2@x.example", "role": "admin"}), 403)
	want(t, mt.get(A+"/clients"), 403)
	want(t, mt.get("/api/orgs/globex/users"), 404)
	want(t, mt.get("/api/keys"), 403)

	// admin token: no CSRF needed, can administer its org but not create orgs
	at := w.withBearer("admin", service.ScopeAdmin)
	want(t, at.post(A+"/groups", map[string]any{"display_name": "viatoken"}), 201)
	want(t, at.post("/api/orgs", map[string]any{"name": "nope"}), 403)
	want(t, at.get("/api/orgs/primary"), 404)

	// super admin token
	st := w.withBearer("super", service.ScopeAdmin)
	want(t, st.post("/api/orgs", map[string]any{"name": "viabearer"}), 201)
	want(t, st.get("/api/keys"), 200)
	want(t, st.get("/api/orgs/globex/users"), 200)

	// wrong scope, bad token, missing token
	api := w.withBearer("super", service.ScopeAPI)
	want(t, api.get("/api/orgs"), 403)
	// the scheme name is case-insensitive
	for _, scheme := range []string{"bearer", "BEARER"} {
		want(t, st.do("GET", "/api/orgs", nil, "Authorization", scheme+" "+st.bearer), 200)
	}
	bad := &caller{w: w, c: detach(w.env.Client()), bearer: "qsr_nope_nope"}
	want(t, bad.get("/api/orgs"), 401)
	want(t, w.anon().get("/api/orgs"), 401)

	// version negotiation
	want(t, st.do("GET", "/api/orgs", nil, "Api-Version", web.APIVersionLatest), 200)
	r = st.do("GET", "/api/orgs", nil, "Api-Version", "2000-01-01")
	wantField(t, r, 400, "")
	if r.Header.Get("Api-Version") != web.APIVersionLatest {
		t.Error("an unsupported version is answered with the latest supported one")
	}
	// session callers may send the header too, and the old /api/admin paths are gone
	want(t, w.as("admin").do("GET", AU, nil, "Api-Version", web.APIVersionLatest), 200)
	want(t, w.as("admin").get("/api/admin/orgs"), 404)
}

// The console needs a session that used a second factor, whatever the organization requires: a password-only (or
// provider-only) sign-in of a manager or administrator is refused, pages and API alike.
func TestConsoleNeedsSecondFactor(t *testing.T) {
	w := newWorld(t)
	for _, who := range []string{"admin", "manager", "super"} {
		c := w.asSingleFactor(who)
		r := c.get(A + "/users")
		if r.Status != 403 || r.str("field") != "mfa" {
			t.Errorf("%s API: %d %s", who, r.Status, r.Raw)
		}
		req, _ := http.NewRequest("GET", w.env.URL+"/admin/orgs/acme/users", nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 403 || !strings.Contains(string(b), "second factor") {
			t.Errorf("%s page: %d", who, res.StatusCode)
		}
	}
	// a plain user's account page is not the console
	c := w.asSingleFactor("user")
	req, _ := http.NewRequest("GET", w.env.URL+"/admin/orgs/acme/users", nil)
	if res, _ := c.c.Do(req); res.StatusCode != 403 {
		t.Errorf("user: %d", res.StatusCode)
	}
	want(t, w.as("admin").get(A+"/users"), 200)
}

// Dangerous changes need a recent re-authentication of the browser session (403 with field "reauth" otherwise, which
// the console answers with its dialog), and an API token can never make them. A backup holds every sealed secret, so
// downloading one counts.
func TestDangerousChangesNeedStepUp(t *testing.T) {
	w := newWorld(t)
	w.mod.RotateKeys = func(context.Context) error { return nil }
	w.mod.RemoveKey = func(context.Context, string) error { return nil }
	w.mod.ReloadCluster = func(context.Context) (any, error) { return nil, nil }
	fresh := false
	w.env.Server.Reauthed = func(*http.Request) bool { return fresh }
	su, tok := w.as("super"), w.withBearer("super", "admin")
	primary, _ := w.env.Svc.PrimaryOrg(context.Background())
	settings := primary.Settings
	settings.SessionIdle = 600
	victim := w.users["manager"].ID
	peer := func(name string) string { // an administrator of acme to demote, disable or delete
		u, err := w.env.Svc.CreateUser(context.Background(), service.System, w.acme.ID, service.UserInput{GivenName: ptr("P"),
			Username: ptr(name), Email: ptr(name + "@x.example"), Role: ptr(model.RoleAdmin)})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	demoted, disabled, deleted, ended := peer("demoted"), peer("disabled"), peer("deleted"), peer("ended")
	for name, call := range map[string]func(c *caller) resp{
		"demote an administrator":  func(c *caller) resp { return c.patch(AU+"/"+demoted, map[string]any{"role": "user"}) },
		"disable an administrator": func(c *caller) resp { return c.patch(AU+"/"+disabled, map[string]any{"active": false}) },
		"delete an administrator":  func(c *caller) resp { return c.delete(AU + "/" + deleted) },
		"end an administrator's account": func(c *caller) resp {
			return c.patch(AU+"/"+ended, map[string]any{"valid_until": time.Now().Add(48 * time.Hour).Format(time.DateOnly)})
		},
		"delete an organization":        func(c *caller) resp { return c.delete("/api/orgs/globex?cascade=1") },
		"rotate the signing keys":       func(c *caller) resp { return c.post("/api/keys/rotate", nil) },
		"remove a signing key":          func(c *caller) resp { return c.delete("/api/keys/old") },
		"reload the cluster":            func(c *caller) resp { return c.post("/api/cluster/reload", nil) },
		"download a backup":             func(c *caller) resp { return c.get("/api/backup?plain=1") },
		"primary org sign-in settings":  func(c *caller) resp { return c.patch("/api/orgs/primary", map[string]any{"settings": settings}) },
		"make someone an administrator": func(c *caller) resp { return c.patch(AU+"/"+victim, map[string]any{"role": "admin"}) },
		"create an administrator": func(c *caller) resp {
			return c.post(AU, map[string]any{"username": "boss", "email": "boss@x.example", "given_name": "B", "role": "admin"})
		},
		"remove another user's password": func(c *caller) resp { return c.delete(AU + "/" + victim + "/password") },
		"sign an organization out": func(c *caller) resp {
			return c.post("/api/orgs/acme/sign-out", map[string]any{"reason": "test"})
		},
		"sign the server out": func(c *caller) resp { return c.post("/api/sign-out", map[string]any{"reason": "test"}) },
		"lock a user out": func(c *caller) resp {
			return c.post(AU+"/"+w.users["user"].ID+"/lock-out", map[string]any{"reason": "test"})
		},
	} {
		fresh = false
		if r := call(su); r.Status != 403 || r.str("field") != "reauth" {
			t.Errorf("%s without re-authentication: %d %s", name, r.Status, r.Raw)
		}
		if r := call(tok); r.Status != 403 {
			t.Errorf("%s with an API token: %d %s", name, r.Status, r.Raw)
		}
		fresh = true
		if r := call(su); r.Status/100 != 2 {
			t.Errorf("%s after re-authentication: %d %s", name, r.Status, r.Raw)
		}
	}
	// ordinary changes need none
	fresh = false
	want(t, su.patch("/api/orgs/acme", map[string]any{"display_name": "Acme Ltd"}), 200)
	want(t, su.patch(AU+"/"+w.users["admin"].ID, map[string]any{"given_name": "Ada"}), 200) // editing an administrator
	want(t, su.patch(AU+"/"+w.users["user"].ID, map[string]any{"active": false}), 200)      // disabling a user
}

// A request the service refuses for want of permission is an access-control event: it is audited, like the
// refusals the API makes itself (scope, CSRF, second factor).
func TestForbiddenRequestIsAudited(t *testing.T) {
	w := newWorld(t)
	want(t, w.as("manager").patch(A, map[string]any{"display_name": "Mine now"}), 403)
	evs, _, err := w.env.Svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Action == "api.request.refused" && e.Detail["reason"] == "not permitted" && e.ActorID == w.users["manager"].ID {
			return
		}
	}
	t.Fatal("the refused request was not audited")
}
