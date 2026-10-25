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

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
)

// sqliteNode returns a configuration for an offline command over a fresh SQLite store with the given master key.
func sqliteNode(t *testing.T, key string) *config.Config {
	t.Helper()
	c := restoreConfig(t, t.TempDir(), "")
	c.Server.MasterKey = key
	return c
}

// populatedBackup starts a node, stops it, and takes its backup offline (quisora backup).
func populatedBackup(t *testing.T, password string) (*config.Config, []byte, backup.Stats) {
	t.Helper()
	a, _, _ := startApp(t, "sqlite")
	cfg := a.Cfg
	a.Close()
	var buf bytes.Buffer
	stats, err := Backup(context.Background(), cfg, &buf, backup.Options{Password: password})
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
	if _, err := Backup(ctx, c, &bytes.Buffer{}, backup.Options{}); err == nil || !strings.Contains(err.Error(), "master_key is not set") {
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
	if _, _, err := PurgeLostQueueItems(ctx, c, logger.NewNullLogger()); err == nil {
		t.Fatal("purge-lost accepted a bad previous key")
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

// Backup then Restore round trip, with and without a password, and every refusal leaves the node as it was.
func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	for _, password := range []string{"", "s3cret-passphrase"} {
		src, data, stats := populatedBackup(t, password)
		key := src.Server.MasterKey

		if password != "" {
			dst := sqliteNode(t, key)
			if _, err := Restore(ctx, dst, bytes.NewReader(data), false, "wrong"); err == nil {
				t.Fatal("restore with the wrong password succeeded")
			}
			if _, err := os.Stat(filepath.Join(dst.Server.DataDir, restoreIncomplete)); err == nil {
				t.Fatal("a refused restore left the incomplete marker")
			}
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
		dst := sqliteNode(t, key)
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
		if _, err := os.Stat(filepath.Join(dir, cluster.RestoredMarker)); err != nil {
			t.Fatalf("restored marker: %v", err)
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
}

// restoreAtStart refusals: a missing file, a backup of another key (marker removed), a non-empty store (skipped).
func TestRestoreAtStartRefusals(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNullLogger()
	src, data, _ := populatedBackup(t, "")

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
	c.Server.RestoreFrom = file
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
