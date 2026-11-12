package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// sqliteNode returns a configuration for an offline command over a fresh SQLite store with the given master key.
func sqliteNode(t *testing.T, key string) *config.Config {
	t.Helper()
	c := restoreConfig(t, t.TempDir(), "")
	c.Server.MasterKey = key
	return c
}

// backupPassword is the password of every backup these tests write: there are no unencrypted backups.
const backupPassword = "s3cret-passphrase"

// populatedBackup starts a node, stops it, and takes its backup offline (quisora backup).
func populatedBackup(t *testing.T) (*config.Config, []byte, backup.Stats) {
	t.Helper()
	a, _, _ := startApp(t, "sqlite")
	cfg := a.Cfg
	a.Close()
	var buf bytes.Buffer
	stats, err := Backup(context.Background(), cfg, &buf, backup.Options{Password: backupPassword})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total() == 0 || buf.Len() == 0 {
		t.Fatalf("empty backup: %v", stats)
	}
	return cfg, buf.Bytes(), stats
}

// The offline commands refuse to run without a usable master key, and a corrupt previous key is refused.
func TestOfflineCommandsNeedMasterKey(t *testing.T) {
	ctx := context.Background()
	c := sqliteNode(t, "")
	if _, err := Backup(ctx, c, &bytes.Buffer{}, backup.Options{Password: backupPassword}); err == nil || !strings.Contains(err.Error(), "master_key is not set") {
		t.Fatalf("backup without a key: %v", err)
	}
	if _, err := Restore(ctx, c, bytes.NewReader(nil), false, ""); err == nil || !strings.Contains(err.Error(), "master_key is not set") {
		t.Fatalf("restore without a key: %v", err)
	}
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	c.Server.PreviousMasterKeys = []string{"not base64!"}
	if _, _, err := openForCommand(ctx, c); err == nil || !strings.Contains(err.Error(), "previous_master_keys") {
		t.Fatalf("bad previous key: %v", err)
	}
	c.Server.PreviousMasterKeys = nil
	c.Storage.Backend = "nonesuch"
	if _, _, err := openForCommand(ctx, c); err == nil || !strings.Contains(err.Error(), "storage:") {
		t.Fatalf("unknown backend: %v", err)
	}
}

// A badger store held open by a running node reports ErrStoreLocked to an offline command.
func TestOpenForCommandStoreLocked(t *testing.T) {
	a, _, _ := startApp(t, "badgerdb")
	_, _, err := openForCommand(context.Background(), a.Cfg)
	if !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("want ErrStoreLocked, got %v", err)
	}
}

// Backup then Restore round trip, and every refusal leaves the node as it was.
func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	password := backupPassword
	src, data, stats := populatedBackup(t)
	key := src.Server.MasterKey

	dst := sqliteNode(t, key)
	if _, err := Restore(ctx, dst, bytes.NewReader(data), false, "wrong"); err == nil {
		t.Fatal("restore with the wrong password succeeded")
	}
	if _, err := os.Stat(filepath.Join(dst.Server.DataDir, restoreIncomplete)); err == nil {
		t.Fatal("a refused restore left the incomplete marker")
	}
	// another master key: refused, nothing written
	other := sqliteNode(t, base64.StdEncoding.EncodeToString(secure.RandomBytes(32)))
	if _, err := Restore(ctx, other, bytes.NewReader(data), false, password); err == nil {
		t.Fatal("restore under another master key succeeded")
	}
	if _, err := os.Stat(filepath.Join(other.Server.DataDir, restoreIncomplete)); err == nil {
		t.Fatal("a refused restore left the incomplete marker")
	}
	// garbage
	if _, err := Restore(ctx, other, bytes.NewReader([]byte("not a backup")), false, ""); err == nil {
		t.Fatal("garbage restored")
	}

	file := filepath.Join(t.TempDir(), "q.bak")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	dst = sqliteNode(t, key)
	f, err := os.Open(file) // an *os.File names itself in the audit note
	if err != nil {
		t.Fatal(err)
	}
	got, err := Restore(ctx, dst, f, false, password)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got.Total() != stats.Total() {
		t.Fatalf("restored %d records, backed up %d", got.Total(), stats.Total())
	}
	dir := dst.Server.DataDir
	if _, err := os.Stat(filepath.Join(dir, restoreIncomplete)); err == nil {
		t.Fatal("incomplete marker left after a complete restore")
	}
	b, err := os.ReadFile(filepath.Join(dir, restoreAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	var notes []restoreNote
	if err := json.Unmarshal(b, &notes); err != nil || len(notes) != 1 || notes[0].File != file ||
		notes[0].Records != got.Total() || notes[0].Forced {
		t.Fatalf("audit note %+v (%v)", notes, err)
	}

	// a second restore needs force
	if _, err := Restore(ctx, dst, bytes.NewReader(data), false, password); !errors.Is(err, backup.ErrNotEmpty) {
		t.Fatalf("restore over data: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, restoreIncomplete)); err == nil {
		t.Fatal("refused restore left the marker")
	}
	if _, err := Restore(ctx, dst, bytes.NewReader(data), true, password); err != nil {
		t.Fatalf("forced restore: %v", err)
	}
	// both restores are noted until the node writes them to the audit log: the second does not replace the first
	b, _ = os.ReadFile(filepath.Join(dir, restoreAuditFile))
	notes = nil
	if json.Unmarshal(b, &notes) != nil || len(notes) != 2 || notes[0].File != file || !notes[1].Forced || notes[1].File != "" {
		t.Fatalf("notes after a forced restore %+v", notes)
	}

}

// Running `quisora restore` again over a store an interrupted run part-filled is refused (the store is not empty) and
// keeps the incomplete marker: removing it would make the half-restored store servable.
func TestRestoreRerunKeepsIncompleteMarker(t *testing.T) {
	ctx := context.Background()
	src, data, _ := populatedBackup(t)
	dst := sqliteNode(t, src.Server.MasterKey)
	if _, err := Restore(ctx, dst, bytes.NewReader(data), false, backupPassword); err != nil {
		t.Fatal(err)
	}
	// the state an interrupted run leaves: records in the store, the marker present
	marker := filepath.Join(dst.Server.DataDir, restoreIncomplete)
	if err := os.WriteFile(marker, []byte("quisora restore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, dst, bytes.NewReader(data), false, backupPassword); !errors.Is(err, backup.ErrNotEmpty) {
		t.Fatalf("rerun over a part-filled store: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the rerun removed the marker of the interrupted restore")
	}
	if err := checkRestoreIncomplete(dst); err == nil {
		t.Fatal("a store of an interrupted restore passes the start-up check")
	}
}

// restoreAtStart refusals: a missing file, a backup of another key (marker removed), a non-empty store (skipped).
func TestRestoreAtStartRefusals(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNullLogger()
	src, data, _ := populatedBackup(t)

	c := sqliteNode(t, src.Server.MasterKey)
	if err := restoreAtStart(ctx, c, nil, nil, log); err != nil { // no restore_from: nothing to do
		t.Fatal(err)
	}
	c.Server.RestoreFrom = filepath.Join(t.TempDir(), "missing.bak")
	key, _ := masterKey(c)
	sealer, _ := newSealer(c, key)
	st, err := OpenStore(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := restoreAtStart(ctx, c, st, sealer, log); err == nil || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("missing file: %v", err)
	}

	file := filepath.Join(t.TempDir(), "q.bak")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c.Server.RestoreFrom, c.Server.RestorePassword = file, backupPassword
	wrong, _ := newSealer(c, secure.RandomBytes(32))
	if err := restoreAtStart(ctx, c, st, wrong, log); err == nil {
		t.Fatal("restored under another master key")
	}
	if _, err := os.Stat(filepath.Join(c.Server.DataDir, restoreIncomplete)); err == nil {
		t.Fatal("refused restore left the marker")
	}
	if err := restoreAtStart(ctx, c, st, sealer, log); err != nil {
		t.Fatal(err)
	}
	// now not empty: skipped, and a wrong key does not matter
	if err := restoreAtStart(ctx, c, st, wrong, log); err != nil {
		t.Fatalf("non-empty store: %v", err)
	}
}

func restoreConfig(t *testing.T, dataDir, from string) *config.Config {
	t.Helper()
	addr := clustertest.FreeAddr(t)
	c := config.Default()
	c.Server.Listen, c.Server.PublicURL, c.Server.DataDir = addr, "https://"+addr, dataDir
	c.Storage.Backend = "sqlite"
	c.Limits.PasswordWorkers = 2
	c.Server.RestoreFrom = from
	if from != "" {
		c.Server.RestorePassword = backupPassword
	}
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
	if _, err := backup.WriteWith(ctx, src.Store, src.Svc.Sealer, &buf, backup.Options{Password: backupPassword}); err != nil { // as GET /api/backup does
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

// "quisora restore" on a gossip node seeds its partitions (the records become the first writes of their partitions) and
// records that its data is the cluster's; over data it is refused, forced or not.
func TestRestoreIntoGossipNodeSeedsItsPartitions(t *testing.T) {
	ctx := context.Background()
	src, data, stats := populatedBackup(t)
	dst := sqliteNode(t, src.Server.MasterKey)
	dst.Cluster.Bind, dst.Cluster.Size = "127.0.0.1:1", 3
	if _, err := Restore(ctx, dst, bytes.NewReader(data), true, backupPassword); err == nil || !strings.Contains(err.Error(), "empty database") {
		t.Fatalf("a forced restore into a gossip node: %v", err)
	}
	got, err := Restore(ctx, dst, bytes.NewReader(data), false, backupPassword)
	if err != nil || got.Total() != stats.Total() {
		t.Fatalf("restore: %v (%d of %d records)", err, got.Total(), stats.Total())
	}
	state, err := os.ReadFile(filepath.Join(dst.Server.DataDir, "cluster-state.json"))
	if err != nil || !strings.Contains(string(state), `"intact":true`) || !strings.Contains(string(state), `"genesis":"`) {
		t.Fatalf("cluster state %s %v", state, err)
	}
	st, err := OpenStore(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seeded := 0
	for p := range 64 {
		if ps, err := st.(store.PartitionStore).PartitionState(ctx, p); err != nil {
			t.Fatal(err)
		} else if ps.Committed.Seq > 0 {
			seeded++
		}
	}
	if seeded == 0 {
		t.Fatal("no partition was seeded")
	}
}

// A restore note that cannot be read is dropped; a missing one is ignored.
func TestAuditRestoreNotes(t *testing.T) {
	a, _, _ := startApp(t, "sqlite")
	ctx := context.Background()
	a.auditRestore(ctx) // no note
	path := filepath.Join(a.Cfg.Server.DataDir, restoreAuditFile)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.auditRestore(ctx)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("corrupt note kept")
	}
	// a valid note is written to the audit log and removed
	noteRestore(a.Cfg, "x.bak", 7, true, "restore")
	a.auditRestore(ctx)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("note kept after it was audited")
	}
	org, err := a.Svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found *model.Audit
	for deadline := time.Now().Add(10 * time.Second); found == nil && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		l, _, _ := a.Svc.Audits.List(ctx, store.ListQuery{Scope: org.ID})
		for _, e := range l {
			if e.Action == "backup.restore" {
				found = e
			}
		}
	}
	if found == nil || found.Detail["file"] != "x.bak" || found.Detail["records"] != "7" || found.Detail["forced"] != "true" {
		t.Fatalf("backup.restore event: %+v", found)
	}
}
