package cluster

import (
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

// The store's conformance suite run against cluster.Store on a node without gossip, over every database the cluster
// tests run on: a single node (BadgerDB, SQLite), and a node sharing a database server with others (PostgreSQL, MySQL,
// MariaDB, when their test DSNs are set: scripts/test-dbs.sh). cluster.Store then writes through its own local path
// (change hooks, the shared database's lease) to the driver: the application must not see a difference from the driver
// alone. (The gossip variants are TestConformance.)
func TestConformanceWithoutGossip(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		storetest.Run(t, func(tb testing.TB) store.Store {
			cfg := config.Default()
			cfg.Server.DataDir = tb.TempDir()
			cfg.Storage.Backend = b.name // postgres, mysql, mariadb: a database server the node shares
			n, err := New(cfg, b.open(tb, cfg.Server.DataDir), Options{})
			if err != nil {
				tb.Fatal(err)
			}
			if err := n.Start(bg); err != nil {
				tb.Fatal(err)
			}
			tb.Cleanup(func() { n.Close() })
			return noClose{n.Store()}
		})
	})
}
