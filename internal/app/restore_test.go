package app

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	// without the backup's master key the start is refused, and no key is invented
	if _, err := Start(ctx, restoreConfig(t, dir, file), logger.NewNullLogger()); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("start without the master key: %v", err)
	}
	key, _ := os.ReadFile(filepath.Join(src.Cfg.Server.DataDir, "master.key"))
	if err := os.WriteFile(filepath.Join(dir, "master.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	start := func() *App {
		t.Helper()
		a, err := Start(ctx, restoreConfig(t, dir, file), logger.NewNullLogger())
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
	if _, err := Start(ctx, restoreConfig(t, dir, file), logger.NewNullLogger()); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("start after an unfinished restore: %v", err)
	}
}
