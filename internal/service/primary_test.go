package service_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// The primary organization is the one marked so in the store, with an id of its own: every node over the same data
// (another node of a shared database, a restart) finds the same one, and no other organization is, or can be made, it.
func TestPrimaryOrgIsTheMarkedOne(t *testing.T) {
	e := newEnv(t)
	other := e.org("other")
	if p, err := e.svc.PrimaryOrg(e.ctx); err != nil || p.ID != e.primary.ID || !p.Primary || other.Primary || !model.IsID(p.ID) {
		t.Fatalf("the primary: %v %v (another: %v)", p, err, other.Primary)
	}
	fresh := service.New(e.svc.Cfg, e.svc.Store, e.svc.Sealer) // another node, or a restart: nothing remembered
	if id, err := fresh.PrimaryOrgID(e.ctx); err != nil || id != e.primary.ID {
		t.Fatalf("the primary on another node: %v %v", id, err)
	}
	// A second organization marked primary clashes with the first.
	second := &model.Org{Name: "second", Settings: model.DefaultOrgSettings(), Primary: true}
	if err := e.svc.Orgs.Create(e.ctx, second); err == nil {
		t.Fatal("a second primary organization was stored")
	}
}

// Before the primary organization is stored (a server not set up, a node that has not copied it yet) nothing is
// guessed: PrimaryOrgID says it is not found, then finds it once it is there.
func TestPrimaryOrgIDBeforeBootstrap(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	e := newEnv(t)
	svc := service.New(e.svc.Cfg, st, e.svc.Sealer)
	if id, err := svc.PrimaryOrgID(ctx); !errors.Is(err, service.ErrNotFound) || id != "" {
		t.Fatalf("before bootstrap: %q %v", id, err)
	}
	if _, err := svc.SessionStamp(ctx, model.NewID()); err == nil {
		t.Fatal("a session stamped with no primary organization's counters")
	}
	if _, _, err := svc.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	p, err := svc.PrimaryOrg(ctx)
	if err != nil || !p.Primary {
		t.Fatalf("after bootstrap: %v %v", p, err)
	}
	if _, err := svc.SessionStamp(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
}

// A backup restored into an empty store keeps the primary organization: its id, its super admins and its server-wide
// sign-out counters; the restored server finds it as its primary.
func TestBackupRestoreKeepsThePrimaryOrg(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.SignOutServer(e.ctx, service.System, service.SignOutOptions{Reason: "drill"}); err != nil {
		t.Fatal(err)
	}
	before, err := e.svc.PrimaryOrg(e.ctx)
	if err != nil || before.ServerSignOut.Sessions == 0 {
		t.Fatalf("the sign-out did not count: %+v %v", before, err)
	}
	var buf bytes.Buffer
	if _, err := backup.WriteWith(e.ctx, e.svc.Store, e.svc.Sealer, &buf, backup.Options{}); err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	if _, err := backup.Restore(e.ctx, st, e.svc.Sealer, bytes.NewReader(buf.Bytes()), false, "", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	restored := service.New(e.svc.Cfg, st, e.svc.Sealer)
	after, err := restored.PrimaryOrg(e.ctx)
	if err != nil || after.ID != before.ID || !after.Primary || after.ServerSignOut != before.ServerSignOut {
		t.Fatalf("restored primary %+v %v, want %+v", after, err, before)
	}
	if u, err := restored.Users.Get(e.ctx, e.super.ID); err != nil || u.OrgID != after.ID || u.Role != model.RoleSuperAdmin {
		t.Fatalf("restored super admin %+v %v", u, err)
	}
	// Nothing to bootstrap: it is set up.
	if u, _, err := restored.Bootstrap(e.ctx, "someone@example.com"); err != nil || u != nil {
		t.Fatalf("bootstrap after the restore made %v (%v)", u, err)
	}
}
