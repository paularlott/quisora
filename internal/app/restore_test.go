package app

import (
	"bytes"
	"context"
	"github.com/paularlott/quisora/internal/store"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func restoreConfig(t *testing.T, dataDir, from string) *config.Config {
	t.Helper()
	addr := freeAddr(t)
	c := config.Default()
	c.Server.Listen, c.Server.PublicURL, c.Server.DataDir = addr, "https://"+addr, dataDir
	c.Storage.Backend = "sqlite"
	c.Limits.PasswordWorkers = 2
	c.Server.RestoreFrom = from
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

// serve --restore-from: a new node starts from the backup of a running one (taken through the store while it
// serves), later starts leave the restored store alone, and a restore that did not finish blocks the start.
func TestRestoreFromAtStart(t *testing.T) {
	ctx := context.Background()
	src, _, _ := startApp(t, "sqlite")
	var buf bytes.Buffer
	if _, err := backup.Write(ctx, src.Store, src.Svc.Sealer, &buf); err != nil { // as GET /api/v1/backup does
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "quisora.bak")
	if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// without a master key the start is refused, and no key is invented
	if _, err := Start(ctx, restoreConfig(t, dir, file), logger.NewNullLogger()); err == nil || !strings.Contains(err.Error(), "master_key is not set") {
		t.Fatalf("start without the master key: %v", err)
	}
	start := func() *App {
		t.Helper()
		c := restoreConfig(t, dir, file)
		c.Server.MasterKey = src.Cfg.Server.MasterKey
		a, err := Start(ctx, c, logger.NewNullLogger())
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := start()
	want, _ := src.Svc.Users.Count(ctx, "")
	got, _ := a.Svc.Users.Count(ctx, "")
	primary, _ := a.Svc.PrimaryOrg(ctx)
	srcPrimary, _ := src.Svc.PrimaryOrg(ctx)
	if got != want || primary == nil || primary.ID != srcPrimary.ID {
		t.Fatalf("restored %d users (want %d), primary %v", got, want, primary)
	}
	// the restore is on record in the primary organization's audit log, with who ran it
	var restored *model.Audit
	for deadline := time.Now().Add(10 * time.Second); restored == nil && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		l, _, _ := a.Svc.Audits.List(ctx, store.ListQuery{Scope: primary.ID})
		for _, e := range l {
			if e.Action == "backup.restore" {
				restored = e
			}
		}
	}
	if restored == nil || restored.Detail["file"] != file || restored.Detail["command"] != "serve --restore-from" ||
		restored.Detail["records"] == "" {
		t.Fatalf("backup.restore event: %+v", restored)
	}
	// a change made after the restore survives a restart with the setting still in place
	org := &model.Org{Name: "later", DisplayName: "Later"}
	if err := a.Svc.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	a.Close()
	a = start()
	if _, err := a.Svc.OrgByName(ctx, "later"); err != nil {
		t.Fatalf("restart restored over newer data: %v", err)
	}
	a.Close()

	// an unfinished restore (marker left behind) stops the start instead of serving a partial store
	if err := os.WriteFile(filepath.Join(dir, "restore-incomplete"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	unfinished := restoreConfig(t, dir, file)
	unfinished.Server.MasterKey = src.Cfg.Server.MasterKey
	if _, err := Start(ctx, unfinished, logger.NewNullLogger()); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("start after an unfinished restore: %v", err)
	}
}
