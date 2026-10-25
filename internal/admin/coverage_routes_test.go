package admin_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// concretePath fills a route template: {org} with org, every other placeholder with id.
func concretePath(tpl, org, id string) string {
	var b strings.Builder
	for i := 0; i < len(tpl); {
		if tpl[i] != '{' {
			b.WriteByte(tpl[i])
			i++
			continue
		}
		j := strings.IndexByte(tpl[i:], '}')
		if tpl[i+1:i+j] == "org" {
			b.WriteString(org)
		} else {
			b.WriteString(id)
		}
		i += j + 1
	}
	return b.String()
}

// Every organization-scoped route answers an administrator of another organization with 404, whatever it addresses.
func TestCoverageCrossOrgSweep(t *testing.T) {
	w := newWorld(t)
	other := w.as("other")
	for _, rt := range w.mod.Routes() {
		if !strings.HasPrefix(rt.Path, "/api/orgs/{org}") {
			continue
		}
		p := concretePath(rt.Path, "acme", "nope")
		var body any
		if rt.Method != "GET" && rt.Method != "DELETE" {
			body = map[string]any{}
		}
		if r := other.do(rt.Method, p, body); r.Status != 404 {
			t.Errorf("%s %s as other org: %d %s", rt.Method, p, r.Status, r.Raw)
		}
	}
}

// Addressing something that does not exist inside the caller's own organization is a 404 (or a refusal of the
// request's own content), never a success and never a server error.
func TestCoverageUnknownIDSweep(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	for _, rt := range w.mod.Routes() {
		if !strings.HasPrefix(rt.Path, "/api/orgs/{org}/") || !strings.Contains(rt.Path, "{id}") {
			continue
		}
		p := concretePath(rt.Path, "acme", "nope")
		var body any
		if rt.Method != "GET" && rt.Method != "DELETE" {
			body = map[string]any{}
		}
		if r := ad.do(rt.Method, p, body); r.Status < 400 || r.Status >= 500 {
			t.Errorf("%s %s: %d %s", rt.Method, p, r.Status, r.Raw)
		}
	}
	// A malformed body is refused before anything is looked up further.
	for _, p := range []string{AU, A + "/groups", A + "/clients", A + "/providers", A + "/tenants"} {
		if r := ad.do("POST", p, "not json"); r.Status != 400 {
			t.Errorf("POST %s with junk: %d %s", p, r.Status, r.Raw)
		}
	}
}

// Managers and users do not reach what only administrators administer.
func TestCoverageRoleSweep(t *testing.T) {
	w := newWorld(t)
	for _, who := range []string{"manager", "user"} {
		c := w.as(who)
		for _, rt := range w.mod.Routes() {
			if !strings.HasPrefix(rt.Path, "/api/orgs/{org}/") {
				continue
			}
			res := strings.Split(rt.Path, "/")[4]
			if res == "users" || res == "audit" || res == "groups" {
				continue // those are readable by managers, or tested with their own rules
			}
			p := concretePath(rt.Path, "acme", "nope")
			var body any
			if rt.Method != "GET" && rt.Method != "DELETE" {
				body = map[string]any{}
			}
			if r := c.do(rt.Method, p, body); r.Status != 403 && r.Status != 404 {
				t.Errorf("%s %s %s: %d %s", who, rt.Method, p, r.Status, r.Raw)
			}
		}
	}
}

func TestCoverageServerWideRoutes(t *testing.T) {
	w := newWorldWith(t, func(c *config.Config) {
		c.Secrets.Vault.Address = "https://vault.example"
		c.Secrets.OnePassword.ConnectURL = "https://op.example"
		c.Secrets.OnePassword.ServiceAccountToken = "x"
	})
	su, ad := w.as("super"), w.as("admin")
	routes := [][2]string{{"GET", "/api/keys"}, {"POST", "/api/keys/rotate"}, {"DELETE", "/api/keys/old"}, {"GET", "/api/master-key"},
		{"GET", "/api/cluster"}, {"POST", "/api/cluster/reload"}, {"GET", "/api/system"}, {"GET", "/api/backup?plain=1"}, {"GET", "/api/audit"},
		{"POST", "/api/sign-out"}}
	for _, rt := range routes {
		if r := ad.do(rt[0], rt[1], nil); r.Status != 403 {
			t.Errorf("admin %s %s: %d %s", rt[0], rt[1], r.Status, r.Raw)
		}
		if r := w.as("user").do(rt[0], rt[1], nil); r.Status != 403 {
			t.Errorf("user %s %s: %d %s", rt[0], rt[1], r.Status, r.Raw)
		}
	}

	// Not wired: key rotation and removal are not available, the cluster is standalone.
	want(t, su.post("/api/keys/rotate", nil), 501)
	want(t, su.delete("/api/keys/old"), 501)
	want(t, su.post("/api/cluster/reload", nil), 501)
	r := su.get("/api/cluster")
	want(t, r, 200)
	if r.JSON["standalone"] != true {
		t.Errorf("standalone: %s", r.Raw)
	}
	want(t, su.get("/api/keys"), 200)
	want(t, su.get("/api/master-key"), 200)

	r = su.get("/api/system")
	want(t, r, 200)
	stores, _ := r.JSON["secret_stores"].([]any)
	if len(stores) != 3 || r.JSON["organizations"].(float64) < 3 {
		t.Errorf("system: %s", r.Raw)
	}

	// Wired: errors from the hooks surface, successes are audited.
	w.mod.RotateKeys = func(context.Context) error { return errors.New("hsm down") }
	w.mod.RemoveKey = func(context.Context, string) error { return service.ErrNotFound }
	if r := su.post("/api/keys/rotate", nil); r.Status != 500 {
		t.Errorf("rotate error: %d %s", r.Status, r.Raw)
	}
	want(t, su.delete("/api/keys/old"), 404)
	w.mod.RotateKeys = func(context.Context) error { return nil }
	w.mod.RemoveKey = func(context.Context, string) error { return nil }
	want(t, su.post("/api/keys/rotate", nil), 200)
	want(t, su.delete("/api/keys/old"), 200)

	w.mod.ClusterStatus = func() any { return map[string]any{"nodes": 3} }
	if r := su.get("/api/cluster"); r.Status != 200 || r.JSON["nodes"] != float64(3) {
		t.Errorf("cluster status: %d %s", r.Status, r.Raw)
	}
	w.mod.ReloadCluster = func(context.Context) (any, error) { return []string{"a", "b"}, nil }
	if r := su.post("/api/cluster/reload", nil); r.Status != 200 || r.JSON["reloaded"] != true {
		t.Errorf("reload: %d %s", r.Status, r.Raw)
	}
	w.mod.ReloadCluster = func(context.Context) (any, error) { return []string{"a"}, errors.New("node b disagrees") }
	if r := su.post("/api/cluster/reload", nil); r.Status != 409 || !strings.Contains(r.str("error"), "disagrees") {
		t.Errorf("reload failure: %d %s", r.Status, r.Raw)
	}
	if n := len(auditActions(t, w, "cluster.reload.failure")); n != 1 {
		t.Errorf("reload failure audited %d times", n)
	}
	// These need a recent re-authentication.
	w.env.Server.Reauthed = func(*http.Request) bool { return false }
	for _, rt := range [][2]string{{"POST", "/api/keys/rotate"}, {"DELETE", "/api/keys/old"}, {"POST", "/api/cluster/reload"}} {
		if r := su.do(rt[0], rt[1], nil); r.Status != 403 || r.str("field") != "reauth" {
			t.Errorf("%s %s: %d %s", rt[0], rt[1], r.Status, r.Raw)
		}
	}
}

func TestCoverageAuditAll(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")
	want(t, w.as("admin").post(A+"/groups", map[string]any{"display_name": "audited"}), 201)
	r := su.get("/api/audit")
	want(t, r, 200)
	if r.total() == 0 {
		t.Errorf("empty: %s", r.Raw)
	}
	want(t, su.get("/api/audit?org=acme"), 200)
	want(t, su.get("/api/audit?org=nope"), 404)
	want(t, su.get("/api/audit?action=group.create&outcome=success"), 200)
	want(t, su.get("/api/audit?from=not-a-time"), 422)
	want(t, su.get("/api/audit?to=nope"), 422)
	want(t, su.get(A+"/audit?from=nope"), 422)
	want(t, su.get(A+"/audit?action_group=group."), 200)
	// The page of every organization's audit log is for super admins.
	for who, status := range map[string]int{"super": 200, "admin": 403} {
		c := w.as(who)
		req, _ := http.NewRequest("GET", w.env.URL+"/admin/audit", nil)
		res, err := c.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != status {
			t.Errorf("audit page as %s: %d", who, res.StatusCode)
		}
	}
	_ = time.Now
	_ = model.RoleUser
}
