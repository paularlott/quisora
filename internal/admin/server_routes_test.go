package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

// The server-wide routes (signing keys, master key, cluster, system, backup, every organization's audit log, the
// emergency sign-out of the whole server) are for super admins only.
func TestServerWideRoutesAreSuperAdminOnly(t *testing.T) {
	w := newWorld(t)
	su, ad, us := w.as("super"), w.as("admin"), w.as("user")
	for _, rt := range [][2]string{{"GET", "/api/keys"}, {"POST", "/api/keys/rotate"}, {"DELETE", "/api/keys/old"}, {"GET", "/api/master-key"},
		{"GET", "/api/cluster"}, {"POST", "/api/cluster/reload"}, {"GET", "/api/system"}, {"GET", "/api/backup?plain=1"}, {"GET", "/api/audit"},
		{"POST", "/api/sign-out"}} {
		for _, c := range []*caller{ad, us} {
			if r := c.do(rt[0], rt[1], nil); r.Status != 403 {
				t.Errorf("%s %s: %d %s", rt[0], rt[1], r.Status, r.Raw)
			}
		}
	}
	want(t, su.get("/api/master-key"), 200)
}

// The cluster page reads the cluster's status and reloads its configuration through hooks; a standalone server has
// neither. A reload that fails is a 409 and is audited. The system overview counts the secret stores configured.
func TestClusterAndSystemStatus(t *testing.T) {
	w := newWorldWith(t, func(c *config.Config) {
		c.Secrets.Vault.Address = "https://vault.example"
		c.Secrets.OnePassword.ConnectURL = "https://op.example"
		c.Secrets.OnePassword.ServiceAccountToken = "x"
	})
	su := w.as("super")
	r := su.get("/api/cluster")
	want(t, r, 200)
	if r.JSON["standalone"] != true {
		t.Errorf("standalone: %s", r.Raw)
	}
	want(t, su.post("/api/cluster/reload", nil), 501)

	r = su.get("/api/system")
	want(t, r, 200)
	stores, _ := r.JSON["secret_stores"].([]any)
	if len(stores) != 3 || r.JSON["organizations"] != float64(3) {
		t.Errorf("system: %s", r.Raw)
	}

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
}
