package sqlstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func hasIndex(t *testing.T, s *Store, table, index string) bool {
	t.Helper()
	var n int
	var q string
	switch {
	case s.d.name == "sqlite":
		q = "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?"
		if err := s.wdb.QueryRow(q, index).Scan(&n); err != nil {
			t.Fatal(err)
		}
	case s.d.isPG():
		if err := s.wdb.QueryRow("SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1", index).Scan(&n); err != nil {
			t.Fatal(err)
		}
	default:
		if err := s.wdb.QueryRow("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?", table, index).Scan(&n); err != nil {
			t.Fatal(err)
		}
	}
	return n > 0
}

// A database written by an older build (missing a table, a column and an index) is brought up to date on Open.
func TestReconcileOlderSchema(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			if d.env != "" && os.Getenv(d.env) == "" {
				t.Skipf("%s not set", d.env)
			}
			ctx := context.Background()
			var cfg Config
			if d.name == "sqlite" {
				cfg = Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "quisora.db")}
			} else {
				cfg = Config{Driver: d.name, DSN: createDatabase(t, d.name, os.Getenv(d.env), fmt.Sprintf("qsr_c_%d_%d", time.Now().UnixNano()%1e9, dbCounter.Add(1)))}
			}
			s, err := Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			put := func(s *Store, kind, id, tenant string, created time.Time) {
				t.Helper()
				f := map[string]any{"name": id, "created": created}
				if kind == "client" {
					f["tenant_id"] = tenant
				}
				if err := s.Put(ctx, &store.Record{Kind: model.Kind(kind), ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "o", Data: []byte("x"), Fields: f}); err != nil {
					t.Fatal(err)
				}
			}
			put(s, "client", "old", "", time.Unix(100, 0))

			// Simulate an older model: no tenant table, no client.tenant_id, no created sort index.
			drop := "DROP INDEX ix_client_s_created"
			if s.d.isMySQL() {
				drop += " ON qsr_client"
			}
			for _, q := range []string{drop, "ALTER TABLE qsr_client DROP COLUMN tenant_id", "DROP TABLE qsr_tenant"} {
				if _, err := s.wdb.Exec(q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
			s.Close()

			var wg sync.WaitGroup
			stores := make([]*Store, 3)
			errs := make([]error, 3)
			for i := range stores { // concurrent opens (as separate processes would) must all succeed
				wg.Add(1)
				go func() { defer wg.Done(); stores[i], errs[i] = Open(ctx, cfg) }()
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("open %d: %v", i, err)
				}
			}
			for _, o := range stores[1:] {
				o.Close()
			}
			s = stores[0]
			defer s.Close()
			if !hasIndex(t, s, "qsr_client", "ix_client_s_created") {
				t.Fatal("sort index not recreated")
			}
			put(s, "client", "new", "t1", time.Unix(200, 0))
			put(s, "tenant", "t1", "", time.Unix(300, 0))
			res, err := s.List(ctx, "client", store.ListQuery{Scope: "o", Filters: []store.Filter{{Field: "tenant_id", Value: "t1"}}, Sort: "created", Desc: true})
			if err != nil || len(res.Records) != 1 || res.Records[0].ID != "new" {
				t.Fatalf("filter on new column: %v %+v", err, res)
			}
			// the pre-existing row reads as the zero value and matches an empty filter
			res, err = s.List(ctx, "client", store.ListQuery{Scope: "o", Filters: []store.Filter{{Field: "tenant_id", Value: ""}}})
			if err != nil || len(res.Records) != 1 || res.Records[0].ID != "old" {
				t.Fatalf("old row: %v %+v", err, res)
			}
			if got, err := s.Get(ctx, "tenant", "t1"); err != nil || got.Fields["name"] != "t1" {
				t.Fatalf("tenant table: %v %+v", err, got)
			}
			s.Close()
			s2, err := Open(ctx, cfg) // idempotent
			if err != nil {
				t.Fatal(err)
			}
			if n, err := s2.Count(ctx, "client", "o"); err != nil || n != 2 {
				t.Fatalf("count %d %v", n, err)
			}
			s2.Close()
		})
	}
}
