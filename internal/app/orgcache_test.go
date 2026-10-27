package app

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// The organizations /o/<org> resolves are cached (a store read per request queues behind the writes in flight), but a
// rename or a deletion made on this node counts at once: the old name, and a deleted organization, are not found.
func TestOrgChangesCountAtOnceUnderOrgPaths(t *testing.T) {
	a, hc, base := startApp(t, "badgerdb")
	ctx := context.Background()
	name, renamed := "cache-a", "cache-b"
	o, err := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: &name, DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	status := func(ref string) int {
		t.Helper()
		resp, err := hc.Get(base + "/o/" + ref + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if s, sn := status(o.ID), status(name); s != 200 || sn != 308 { // both forms resolved, and cached
		t.Fatalf("before: by id %d, by name %d", s, sn)
	}
	if _, err := a.Svc.UpdateOrg(ctx, service.System, o.ID, service.OrgInput{Name: &renamed}); err != nil {
		t.Fatal(err)
	}
	if s, sn := status(name), status(renamed); s != 404 || sn != 308 {
		t.Fatalf("after the rename: old name %d, new name %d", s, sn)
	}
	if err := a.Svc.DeleteOrg(ctx, service.System, o.ID, true); err != nil {
		t.Fatal(err)
	}
	if s := status(o.ID); s != 404 {
		t.Fatalf("after the deletion: %d", s)
	}
}
