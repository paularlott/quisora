package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/paularlott/quisora/internal/cluster"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// openForCommand opens the configured store and the master key's sealer for an offline command.
func openForCommand(ctx context.Context, c *config.Config) (store.Store, *secure.Sealer, error) {
	key, err := masterKey(c)
	if err != nil {
		return nil, nil, err
	}
	sealer, err := newSealer(c, key)
	if err != nil {
		return nil, nil, err
	}
	st, err := OpenStore(ctx, c)
	if err != nil {
		if c.Storage.Backend == "badgerdb" && strings.Contains(strings.ToLower(err.Error()), "lock") {
			return nil, nil, ErrStoreLocked
		}
		return nil, nil, fmt.Errorf("storage: %w", err)
	}
	store.SetOrigin("cli")
	return st, sealer, nil
}

// Backup writes every live record of the configured store to w (see package backup).
func Backup(ctx context.Context, c *config.Config, w io.Writer, opt backup.Options) (backup.Stats, error) {
	st, sealer, err := openForCommand(ctx, c)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	return backup.WriteWith(ctx, st, sealer, w, opt)
}

// Restore loads a backup into the configured store, which must be empty unless force is set.
func Restore(ctx context.Context, c *config.Config, r io.ReadSeeker, force bool, password string) (backup.Stats, error) {
	st, sealer, err := openForCommand(ctx, c)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	// Checked in full before anything changes: a backup that is refused leaves the node as it was.
	if _, err := backup.Verify(r, sealer, password); err != nil {
		return nil, err
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	marker := filepath.Join(c.Server.DataDir, restoreIncomplete)
	_ = os.MkdirAll(c.Server.DataDir, 0o700)
	if err := os.WriteFile(marker, []byte("quisora restore\n"), 0o600); err != nil {
		return nil, err
	}
	if force && c.Cluster.Bind != "" {
		_ = os.Remove(marker)
		return nil, errors.New("a gossip node's backup is restored into an empty database (the first node of a new cluster), " +
			"never over data: its records would be written outside the partitions the others copy")
	}
	if c.Cluster.Bind != "" { // a node that already holds a data set is refused before anything is written
		if err := cluster.CheckNewCluster(c.Server.DataDir, st); err != nil {
			_ = os.Remove(marker)
			return nil, err
		}
	}
	stats, err := backup.Restore(ctx, st, sealer, r, force, password)
	if err != nil {
		if stats.Total() == 0 {
			_ = os.Remove(marker) // refused before writing anything
		}
		return stats, err
	}
	if err := seedRestored(ctx, c, st); err != nil {
		return stats, err // not complete: the marker stays
	}
	name := ""
	if f, ok := r.(interface{ Name() string }); ok {
		name = f.Name()
	}
	if err := noteRestore(c, name, stats.Total(), force, "restore"); err != nil {
		return stats, err // not complete: the marker stays, and the store is not served until a restore is
	}
	return stats, os.Remove(marker)
}

// restoreIncomplete exists in the data directory while a restore is under way: one that stopped part-way leaves a
// store that is not empty, which must not be served as if it were whole.
const restoreIncomplete = "restore-incomplete"

// checkRestoreIncomplete refuses to start over a restore that did not finish.
func checkRestoreIncomplete(c *config.Config) error {
	marker := filepath.Join(c.Server.DataDir, restoreIncomplete)
	if _, err := os.Stat(marker); err == nil {
		return fmt.Errorf("an earlier restore from a backup did not finish (%s exists): empty the store, delete that "+
			"file and start again", marker)
	}
	return nil
}

// seedRestored makes a restored gossip node the first node of a new cluster: its restored records become the first
// writes of their partitions and its state says that its data is the cluster's (cluster.StartNewCluster). The other
// nodes start with empty databases and copy everything from it. Without gossip there is nothing to do.
func seedRestored(ctx context.Context, c *config.Config, st store.Store) error {
	if c.Cluster.Bind == "" {
		return nil
	}
	return cluster.StartNewCluster(ctx, c.Server.DataDir, st)
}

// restoreAtStart loads server.restore_from into the store before anything else uses it, when the store is empty.
// A store that already holds data is left alone, so the setting can stay in place across restarts. The records go
// in with their versions (PutReplicated); a gossip node then makes them the first writes of their partitions
// (seedRestored), and the other nodes copy them from it. Start the first node of a new cluster with it, not a node
// joining a running cluster.
func restoreAtStart(ctx context.Context, c *config.Config, st store.Store, sealer *secure.Sealer, log logger.Logger) error {
	file := c.Server.RestoreFrom
	if file == "" {
		return nil
	}
	marker := filepath.Join(c.Server.DataDir, restoreIncomplete)
	empty, err := backup.Empty(ctx, st)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if !empty {
		log.Info("restore skipped: the store already holds data", "file", file)
		return nil
	}
	if c.Cluster.Bind != "" { // a node that already holds a data set (copying it, say) is refused before anything is written
		if err := cluster.CheckNewCluster(c.Server.DataDir, st); err != nil {
			return fmt.Errorf("restore from %s: %w", file, err)
		}
	}
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	defer f.Close()
	if err := os.WriteFile(marker, []byte(file+"\n"), 0o600); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	stats, err := backup.Restore(ctx, st, sealer, f, false, c.Server.RestorePassword)
	if err != nil {
		if stats.Total() == 0 { // refused before writing anything (another master key): nothing to clean up
			_ = os.Remove(marker)
		}
		return fmt.Errorf("restore from %s: %w", file, err)
	}
	if err := seedRestored(ctx, c, st); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if err := noteRestore(c, file, stats.Total(), false, "serve --restore-from"); err != nil {
		return err
	}
	if err := os.Remove(marker); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	log.Warn("restored the store from a backup", "file", file, "records", stats.Total())
	return nil
}
