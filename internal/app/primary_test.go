package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A server that has not been set up is not ready and knows no primary organization (none is guessed). Bootstrapped,
// it is ready with the organization the bootstrap made, whose id is its own (not a fixed one); started again over the
// same data, it finds the same one.
func TestPrimaryOrgKnownFromTheStore(t *testing.T) {
	ctx := context.Background()
	c := appConfig(t, "badgerdb", nil)
	a, _, _ := runApp(t, c)
	if ok, why := a.Server.Health.Ready(); ok || !strings.Contains(why, "not set up") {
		t.Fatalf("ready before bootstrap: %v %q", ok, why)
	}
	if _, err := a.Svc.PrimaryOrgID(ctx); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("a primary organization before bootstrap: %v", err)
	}
	admin, _, err := a.Svc.Bootstrap(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := a.Server.Health.Ready(); !ok {
		t.Fatalf("not ready once set up: %s", why)
	}
	if id, err := a.Svc.PrimaryOrgID(ctx); err != nil || id != admin.OrgID || !model.IsID(id) {
		t.Fatalf("primary %q %v, want the bootstrap's %q", id, err, admin.OrgID)
	}
	a.Close()
	b, _, _ := runApp(t, c) // a restart
	if id, err := b.Svc.PrimaryOrgID(ctx); err != nil || id != admin.OrgID {
		t.Fatalf("after a restart: primary %q %v, want %q", id, err, admin.OrgID)
	}
	if ok, why := b.Server.Health.Ready(); !ok {
		t.Fatalf("not ready after a restart: %s", why)
	}
}

// samePrimary checks that every node of a cluster knows the same primary organization, the one the first node's
// bootstrap made: those that did not bootstrap learned it from the data they share or copied.
func samePrimary(t *testing.T, apps []*App) {
	t.Helper()
	want, err := apps[0].Svc.PrimaryOrg(context.Background())
	if err != nil || !want.Primary {
		t.Fatalf("node 0: %v %v", want, err)
	}
	for i, a := range apps {
		if id, err := a.Svc.PrimaryOrgID(context.Background()); err != nil || id != want.ID {
			t.Fatalf("node %d: primary %q %v, want %q", i, id, err, want.ID)
		}
	}
}
