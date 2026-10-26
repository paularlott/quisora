package app

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// "quisora set-primary" through a running server: the signed request makes another organization primary.
func TestSetPrimaryThroughRunningServer(t *testing.T) {
	a, _, _ := startAppWith(t, "badgerdb", nil)
	ctx := context.Background()
	name := "acme"
	org, err := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	user, email, role := "pat", "pat@acme.example", "user"
	_ = role
	if _, err := a.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: &user, Email: &email, GivenName: &user}); err != nil {
		t.Fatal(err)
	}
	prev, demoted, err := RemoteSetPrimary(ctx, a.Cfg, "", "", false, "acme", email)
	if err != nil || prev != "primary" || len(demoted) != 1 {
		t.Fatalf("%q %v %v", prev, demoted, err)
	}
	if p, err := a.Svc.PrimaryOrg(ctx); err != nil || p.ID != org.ID {
		t.Fatalf("the primary organization: %v %v", p, err)
	}
	requireCommandActor(t, a, "org.primary", "set-primary")
	if _, _, err := RemoteSetPrimary(ctx, a.Cfg, "", "", false, "nope", email); err == nil || !strings.Contains(err.Error(), "no organization") {
		t.Fatalf("unknown organization: %v", err)
	}
}

// set-primary refusals: no key, unknown organization.
func TestSetPrimaryRefusals(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNullLogger()
	c := sqliteNode(t, "")
	if _, _, err := SetPrimary(ctx, c, log, "x", "a@b.test"); err == nil || !strings.Contains(err.Error(), "master_key") {
		t.Fatalf("no key: %v", err)
	}
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	c.Server.PreviousMasterKeys = []string{"!"}
	if _, _, err := SetPrimary(ctx, c, log, "x", "a@b.test"); err == nil {
		t.Fatal("bad previous key accepted")
	}
	c.Server.PreviousMasterKeys = nil
	if _, _, err := SetPrimary(ctx, c, log, "nope", "a@b.test"); err == nil || !strings.Contains(err.Error(), "no organization") {
		t.Fatalf("unknown org: %v", err)
	}
	_ = model.PrimaryOrgID
}

// requireCommandActor checks that the audit event of action was recorded as the operator's command, not as the system:
// the command's actor, the address the request came from, and the command and its authentication in the detail.
func requireCommandActor(t *testing.T, a *App, action, command string) {
	t.Helper()
	items, _, err := a.Svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range items {
		if e.Action != action {
			continue
		}
		found = true
		if e.Actor != "command:"+command || e.IP == "" || e.Detail["command"] != command || !strings.Contains(e.Detail["authenticated"], "master key") {
			t.Fatalf("%s recorded as actor %q ip %q detail %v", action, e.Actor, e.IP, e.Detail)
		}
	}
	if !found {
		t.Fatalf("no %s event was recorded", action)
	}
}
