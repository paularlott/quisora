package app

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The audit API: an organization's administrator reads that organization only; GET /api/audit (every
// organization) is for super admins. With VictoriaLogs configured the events go there, not to the database, and
// the same endpoints read them back (QUISORA_TEST_VICTORIALOGS=http://host:9428 for that part).
func TestAuditAPI(t *testing.T) {
	t.Run("store", func(t *testing.T) { auditAPI(t, "") })
	t.Run("victorialogs", func(t *testing.T) {
		vl := os.Getenv("QUISORA_TEST_VICTORIALOGS")
		if vl == "" {
			t.Skip("QUISORA_TEST_VICTORIALOGS not set")
		}
		auditAPI(t, vl)
	})
}

func auditAPI(t *testing.T, vl string) {
	a, hc, base := startAppWith(t, "sqlite", func(c *config.Config) { c.Audit.VictoriaLogs = vl })
	ctx := context.Background()
	primary, _ := a.Svc.PrimaryOrg(ctx)
	super, err := a.Svc.FindUserByEmail(ctx, primary.ID, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	name := "acme" + strings.ToLower(model.NewID()[24:])
	org, err := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	role := model.RoleAdmin
	boss, err := a.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: ptr("boss"), Email: ptr("boss@acme.test"),
		GivenName: ptr("Boss"), Role: &role})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Svc.CreateUser(ctx, service.ActorForUser(boss, ""), org.ID, service.UserInput{Username: ptr("pat"),
		Email: ptr("pat@acme.test"), GivenName: ptr("Pat")}); err != nil {
		t.Fatal(err)
	}
	token := func(u *model.User) map[string]string {
		_, tok, err := a.Svc.CreateAPIToken(ctx, service.ActorForUser(u, ""), service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAdmin}})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"Authorization": "Bearer " + tok, "Api-Version": "1"}
	}
	bossHdr, superHdr := token(boss), token(super)

	var out map[string]any
	code := 0
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) { // VictoriaLogs makes rows searchable within a second or so
		code, out = doJSON(t, hc, "GET", base+"/api/orgs/"+name+"/audit?q=user.create", bossHdr, nil)
		if code == 200 && out["total"].(float64) >= 1 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	want := "store"
	if vl != "" {
		want = "victorialogs"
	}
	if code != 200 || out["total"].(float64) < 1 || out["source"] != want {
		t.Fatalf("org audit: %d %v", code, out)
	}
	for _, it := range out["items"].([]any) {
		if it.(map[string]any)["org_id"] != org.ID {
			t.Fatalf("another organization's event: %v", it)
		}
	}
	if code, _ := doJSON(t, hc, "GET", base+"/api/orgs/primary/audit", bossHdr, nil); code != 404 {
		t.Fatalf("an org admin read another organization's audit log: %d", code)
	}
	if code, _ := doJSON(t, hc, "GET", base+"/api/audit", bossHdr, nil); code != 403 {
		t.Fatalf("an org admin read every organization's audit log: %d", code)
	}
	found := false
	for deadline := time.Now().Add(10 * time.Second); !found && time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		code, out = doJSON(t, hc, "GET", base+"/api/audit?q=user.create&limit=100", superHdr, nil)
		for _, it := range out["items"].([]any) {
			m := it.(map[string]any)
			found = found || (m["org_id"] == org.ID && m["org_name"] == name)
		}
	}
	if code != 200 || !found {
		t.Fatalf("super admin, every organization: %d %v", code, out)
	}
	if code, out = doJSON(t, hc, "GET", base+"/api/audit?org="+name, superHdr, nil); code != 200 || out["total"].(float64) < 1 {
		t.Fatalf("super admin, one organization: %d %v", code, out)
	}
	if vl != "" {
		if n, _ := a.Store.Count(ctx, model.KindAudit, ""); n != 0 {
			t.Fatalf("with VictoriaLogs the database keeps %d audit events", n)
		}
	}
}
