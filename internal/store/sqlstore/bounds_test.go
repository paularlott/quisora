package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Every connection of a store carries the statement bounds (statementTimeout, lockTimeout), the one the schema migration
// ran on too (it lifts them for itself, and must not go back to the pool so).
func TestConnectionsAreBounded(t *testing.T) {
	ctx := context.Background()
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		s, _ := openTest(t, d.name, d.env, 1) // one connection: the migration's, if it were kept
		defer s.Close()
		var q string
		var want []string
		switch d.name {
		case "sqlite":
			q, want = "PRAGMA busy_timeout", []string{"5000"}
		case "postgres":
			q, want = "SELECT current_setting('statement_timeout'), current_setting('lock_timeout')", []string{"10s", "5s"}
		case "mysql":
			q, want = "SELECT @@SESSION.max_execution_time, @@SESSION.innodb_lock_wait_timeout", []string{"10000", "5"}
		case "mariadb":
			q, want = "SELECT @@SESSION.max_statement_time, @@SESSION.innodb_lock_wait_timeout", []string{"10", "5"}
		}
		for _, db := range []*sql.DB{s.wdb, s.rdb} {
			got := make([]string, len(want))
			dest := make([]any, len(got))
			for i := range got {
				dest[i] = &got[i]
			}
			if err := db.QueryRowContext(ctx, q).Scan(dest...); err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("%s: %v, want %v", q, got, want)
			}
		}
	})
}

// withBounds returns a server's dsn with short bounds, as an operator may set their own: 2 s on a statement, and 200 ms
// (1 s on MySQL and MariaDB, which count whole seconds) on a lock wait. SQLite's path is the store's own: it keeps the
// store's bound (lockTimeout).
func withBounds(t *testing.T, driver, dsn string) string {
	t.Helper()
	switch driver {
	case "sqlite":
		return dsn
	case "postgres":
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		v := u.Query()
		v.Set("statement_timeout", "2000")
		v.Set("lock_timeout", "200")
		u.RawQuery = v.Encode()
		return u.String()
	}
	c, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if c.Params == nil {
		c.Params = map[string]string{}
	}
	if driver == "mysql" {
		c.Params["max_execution_time"] = "2000"
	} else {
		c.Params["max_statement_time"] = "2"
	}
	c.Params["innodb_lock_wait_timeout"] = "1"
	return c.FormatDSN()
}

// A statement that outlasts its bound fails as store.ErrUnavailable, promptly, instead of holding its connection: a write
// waiting for a lock another connection holds, and (on a server) a query running past the statement bound; on SQLite,
// which has no bound on a statement, the caller's deadline interrupts it. The DSN's own bounds are kept.
func TestStatementBoundsFailUnavailable(t *testing.T) {
	ctx := context.Background()
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		s, dsn := openTest(t, d.name, d.env, 0)
		s.Close()
		s, err := Open(ctx, Config{Driver: d.name, DSN: withBounds(t, d.name, dsn)})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		limit := 5 * time.Second // well past the short bounds, and far below a wait retried as a deadlock is
		if d.name == "sqlite" {
			limit = 3 * lockTimeout
		}
		prompt := func(t *testing.T, what string, start time.Time, err error) {
			t.Helper()
			if !errors.Is(err, store.ErrUnavailable) {
				t.Errorf("%s: %v, want unavailable", what, err)
			}
			if el := time.Since(start); el > limit {
				t.Errorf("%s took %v: the bound held it far longer than itself", what, el)
			}
		}

		t.Run("LockWait", func(t *testing.T) {
			if err := s.Put(ctx, record(model.KindLink, "held", time.Time{})); err != nil {
				t.Fatal(err)
			}
			// Another connection holds the lock: on SQLite the database's write lock, on a server the record's row lock.
			var holder *sql.Tx
			if d.name == "sqlite" {
				db := openRaw(t, "sqlite", dsn+"?_txlock=immediate")
				if holder, err = db.BeginTx(ctx, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				if holder, err = s.wdb.BeginTx(ctx, nil); err != nil {
					t.Fatal(err)
				}
				var id string
				q := s.d.bind("SELECT id FROM " + s.tables[model.KindLink].name + " WHERE id = ?" + s.d.lockClause(""))
				if err := holder.QueryRowContext(ctx, q, "held").Scan(&id); err != nil {
					t.Fatal(err)
				}
			}
			defer holder.Rollback()
			start := time.Now()
			prompt(t, "a write waiting for a held lock", start, s.Put(ctx, record(model.KindLink, "held", time.Time{})))
		})

		t.Run("Statement", func(t *testing.T) {
			var q string
			qctx := ctx
			switch d.name {
			case "sqlite": // counts to a billion: far past the caller's deadline
				q = "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 1000000000) SELECT COUNT(*) FROM c"
				var cancel context.CancelFunc
				qctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
				defer cancel()
			case "postgres":
				q = "SELECT pg_sleep(4)::text"
			default: // two rows: SLEEP alone in an interrupted query returns 1 instead of failing
				q = "SELECT SLEEP(4) FROM (SELECT 1 AS a UNION ALL SELECT 2) t"
			}
			start := time.Now()
			rows, err := s.reader().query(qctx, q)
			if err == nil {
				for rows.Next() { // (the error may come after a first row)
				}
				err = rows.Err()
				rows.Close()
			}
			prompt(t, "a slow query", start, unavailable(err))
		})
	})
}

// openRaw opens a database/sql pool of its own on dsn, closed when the test ends.
func openRaw(t *testing.T, driver, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
