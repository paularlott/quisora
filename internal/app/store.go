package app

import (
	"context"
	"fmt"

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
		return kvstore.OpenBadger(ctx, st.BadgerDB.Path, kvstore.BadgerOptions{
			NoSync: !st.BadgerDB.SyncWrites})
	case "sqlite":
		return sqlstore.Open(ctx, sqlstore.Config{Driver: "sqlite", DSN: st.SQLite.Path, Feed: c.Replicate()})
	case "postgres":
		return sqlstore.Open(ctx, sqlstore.Config{Driver: "postgres", DSN: st.Postgres.DSN,
			MaxOpenConns: st.Postgres.MaxOpenConns, MaxIdleConns: st.Postgres.MaxIdleConns,
			Feed: c.Replicate()})
	case "mysql":
		return sqlstore.Open(ctx, sqlstore.Config{Driver: "mysql", DSN: st.MySQL.DSN,
			MaxOpenConns: st.MySQL.MaxOpenConns, MaxIdleConns: st.MySQL.MaxIdleConns,
			Feed: c.Replicate()})
	case "mariadb":
		return sqlstore.Open(ctx, sqlstore.Config{Driver: "mariadb", DSN: st.MariaDB.DSN,
			MaxOpenConns: st.MariaDB.MaxOpenConns, MaxIdleConns: st.MariaDB.MaxIdleConns,
			Feed: c.Replicate()})
	case "valkey":
		v := st.Valkey
		return kvstore.OpenValkey(ctx, kvstore.ValkeyConfig{Addrs: v.Addrs, Username: v.Username, Password: v.Password,
			DB: v.DB, KeyPrefix: v.KeyPrefix, TLS: v.TLS})
	}
	return nil, fmt.Errorf("unknown storage backend %q", st.Backend)
}
