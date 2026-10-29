package sqlstore

import (
	"context"
	"path/filepath"
	"strings"
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
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		ctx := context.Background()
		cfg := schemaDatabase(t, d)
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

		// Simulate an older model: no tenant table, no client.tenant_id (nor its index), no created sort index.
		drop := func(index string) string {
			if s.d.isMySQL() {
				return "DROP INDEX " + index + " ON clients"
			}
			return "DROP INDEX " + index
		}
		for _, q := range []string{drop("ix_clients_s_created"), drop("ix_clients_f_tenant_id"),
			"ALTER TABLE clients DROP COLUMN tenant_id", "DROP TABLE tenants"} {
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
		if !hasIndex(t, s, "clients", "ix_clients_s_created") {
			t.Fatal("sort index not recreated")
		}
		if have, err := s.columns(ctx, s.wdb, "clients"); err != nil || !have["tenant_id"] || !have["epoch"] {
			t.Fatalf("columns after reconcile: %v %v", have, err)
		}
		if have, err := s.columns(ctx, s.wdb, "no_such_table"); err != nil || len(have) != 0 {
			t.Fatalf("columns of a missing table: %v %v", have, err)
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

// A database this build cannot read is refused at open: one whose schema a newer build wrote (no downgrade), and one an
// earlier pre-release build made (no epoch column).
func TestSchemaVersionGuards(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, change, want string
	}{
		{"NewerBuild", "UPDATE " + schemaTable + " SET version = 99", "newer than this build"},
		{"PreReleaseWithoutEpoch", "ALTER TABLE link_tokens DROP COLUMN epoch", "incompatible pre-release"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "q.db")
			s, err := Open(ctx, Config{Driver: "sqlite", DSN: path})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.wdb.ExecContext(ctx, c.change); err != nil {
				t.Fatal(err)
			}
			s.Close()
			if s, err := Open(ctx, Config{Driver: "sqlite", DSN: path}); err == nil || !strings.Contains(err.Error(), c.want) {
				if err == nil {
					s.Close()
				}
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

// A database from before records carried a request id gains the column at open; its rows read with none, and a write
// stores one.
func TestReconcileAddsRequestColumn(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		ctx := context.Background()
		cfg := schemaDatabase(t, d)
		s, err := Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		rec := record(model.KindLink, "old", time.Time{}, "u/old")
		if err := s.Put(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if _, err := s.wdb.Exec("ALTER TABLE link_tokens DROP COLUMN req"); err != nil {
			t.Fatal(err)
		}
		s.Close()
		if s, err = Open(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if have, err := s.columns(ctx, s.wdb, "link_tokens"); err != nil || !have["req"] {
			t.Fatalf("columns after reconcile: %v %v", have, err)
		}
		if got, err := s.Get(ctx, model.KindLink, "old"); err != nil || got.Req != "" || got.Version != rec.Version {
			t.Fatalf("a row from before the column: %v %+v", err, got)
		}
		next := record(model.KindLink, "old", time.Time{}, "u/old")
		if err := s.Put(ctx, next); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Get(ctx, model.KindLink, "old"); err != nil || got.Req == "" {
			t.Fatalf("a write after the column was added: %v %+v", err, got)
		}
	})
}

// A table has an index only for what is queried: none by scope where every record has the empty scope, none by expiry
// where no record has an expiry, and (where the database has partial ones) one of the expiring records only for a
// kind that expires only now and then.
func TestIndexesFollowTheModel(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres", "mysql"} {
		d, err := newDialect(driver)
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, k := range model.Kinds() {
			ix := newTable(d, k).ddl(d)[1:] // (the first statement makes the table)
			total += len(ix)
			has := func(name string) string {
				for _, stmt := range ix {
					if strings.Contains(stmt, d.quote("ix_"+tableName(k)+"_"+name)+" ON") {
						return stmt
					}
				}
				return ""
			}
			if got := has("scope") != ""; got == model.Unscoped(k) {
				t.Errorf("%s %s: scope index %v, unscoped %v", driver, k, got, model.Unscoped(k))
			}
			e := has("expires")
			switch {
			case model.ExpiryOf(k) == model.NeverExpires && e != "":
				t.Errorf("%s %s never expires and has an expiry index: %s", driver, k, e)
			case model.ExpiryOf(k) != model.NeverExpires && e == "":
				t.Errorf("%s %s may expire and has no expiry index", driver, k)
			case model.ExpiryOf(k) == model.MayExpire && !d.isMySQL() && !strings.Contains(e, "WHERE expires IS NOT NULL"):
				t.Errorf("%s %s: the expiry index is not partial: %s", driver, k, e)
			case model.ExpiryOf(k) == model.AlwaysExpires && strings.Contains(e, "WHERE"):
				t.Errorf("%s %s: every record expires, but the expiry index is partial: %s", driver, k, e)
			}
		}
		t.Logf("%s: %d indexes in all", driver, total)
	}
}
