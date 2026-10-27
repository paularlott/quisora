package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

// OpenStore opens the configured storage backend.
func OpenStore(ctx context.Context, c *config.Config) (store.Store, error) {
	st := c.Storage
	switch st.Backend {
	case "badgerdb":
		var key []byte
		if st.BadgerDB.EncryptionKey != "" {
			var err error
			if key, err = base64.StdEncoding.DecodeString(st.BadgerDB.EncryptionKey); err != nil {
				return nil, fmt.Errorf("storage.badgerdb.encryption_key: %w", err)
			}
		}
		return kvstore.OpenBadger(ctx, c.DataPath(config.DirBadgerDB), kvstore.BadgerOptions{
			NoSync: !st.BadgerDB.SyncWrites, SyncInterval: time.Duration(st.BadgerDB.SyncIntervalMs) * time.Millisecond,
			EncryptionKey: key})
	case "sqlite":
		return sqlstore.Open(ctx, sqlstore.Config{Driver: "sqlite", DSN: c.DataPath(config.FileSQLite)})
	case "postgres", "mysql", "mariadb":
		db := map[string]config.SQLDSN{"postgres": st.Postgres, "mysql": st.MySQL, "mariadb": st.MariaDB}[st.Backend]
		pool, err := caPool(db.CAFile, "storage."+st.Backend+".ca_file")
		if err != nil {
			return nil, err
		}
		return sqlstore.Open(ctx, sqlstore.Config{Driver: st.Backend, DSN: db.DSN, RootCAs: pool,
			MaxOpenConns: db.MaxOpenConns, MaxIdleConns: db.MaxIdleConns})
	}
	return nil, fmt.Errorf("unknown storage backend %q", st.Backend)
}
