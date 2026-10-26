package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

// testDialect is a database to test. A server database is skipped unless its DSN variable is set (see
// scripts/test-dbs.sh).
type testDialect struct {
	name, env string
}

var dialects = []testDialect{
	{"sqlite", ""},
	{"postgres", "QUISORA_TEST_POSTGRES_DSN"},
	{"mysql", "QUISORA_TEST_MYSQL_DSN"},
	{"mariadb", "QUISORA_TEST_MARIADB_DSN"},
}

// forEachDialect runs fn as a subtest per dialect of ds, skipping the server databases whose DSN variable is unset.
func forEachDialect(t *testing.T, ds []testDialect, fn func(t *testing.T, d testDialect)) {
	for _, d := range ds {
		t.Run(d.name, func(t *testing.T) {
			if d.env != "" && os.Getenv(d.env) == "" {
				t.Skipf("%s not set", d.env)
			}
			fn(t, d)
		})
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	pool.dropAll()
	os.Exit(code)
}

var dbCounter atomic.Int64

func factory(name, env string) storetest.Factory {
	return func(t testing.TB) store.Store {
		s, _ := openTest(t, name, env, 8) // a small pool: a database per test would otherwise wear out the ephemeral ports
		return s
	}
}

// openTest opens a store on an empty database (a new file for SQLite, a pooled database on the server for the others);
// the DSN lets the test open the same database again. maxConns caps the pool (0: the default).
func openTest(t testing.TB, name, env string, maxConns int) (*Store, string) {
	t.Helper()
	ctx := context.Background()
	if name == "sqlite" {
		dsn := filepath.Join(t.TempDir(), "quisora.db")
		s, err := Open(ctx, Config{Driver: "sqlite", DSN: dsn, MaxOpenConns: maxConns})
		if err != nil {
			t.Fatal(err)
		}
		return s, dsn
	}
	dsn := pool.take(t, name, os.Getenv(env))
	s, err := Open(ctx, Config{Driver: name, DSN: dsn, MaxOpenConns: maxConns})
	if err != nil {
		t.Fatal(err)
	}
	// Empty it as a new database is: no records, unique values or partition state, and a new FeedID.
	if err := s.Wipe(ctx); err != nil {
		t.Fatal(err)
	}
	return s, dsn
}

// pool keeps the server databases of finished tests for the next ones: creating the schema takes MySQL and MariaDB a
// second or more (a table and its indexes per kind), emptying it a few milliseconds. TestMain drops the databases at the
// end.
var pool = &dbPool{free: map[string][]string{}, drops: map[string]func() error{}}

type dbPool struct {
	mu    sync.Mutex
	free  map[string][]string     // driver -> DSNs of databases no test is using
	drops map[string]func() error // DSN -> drops the database
}

// take returns the DSN of a database of driver no other test is using (a new one if none is free), and gives it back
// when the test ends.
func (p *dbPool) take(t testing.TB, driver, admin string) string {
	t.Helper()
	p.mu.Lock()
	free := p.free[driver]
	var dsn string
	if n := len(free); n > 0 {
		dsn, p.free[driver] = free[n-1], free[:n-1]
	}
	p.mu.Unlock()
	if dsn == "" {
		db := fmt.Sprintf("qsr_t_%s_%d", strings.ReplaceAll(uuid.NewString()[:8], "-", ""), dbCounter.Add(1))
		var drop func() error
		var err error
		if dsn, drop, err = newDatabase(driver, admin, db); err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		p.drops[dsn] = drop
		p.mu.Unlock()
	}
	t.Cleanup(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.drops[dsn] != nil { // (not discarded)
			p.free[driver] = append(p.free[driver], dsn)
		}
	})
	return dsn
}

// discard drops the database of dsn, taken by this test, when the test ends instead of giving it to another test.
func (p *dbPool) discard(t testing.TB, dsn string) {
	t.Cleanup(func() {
		p.mu.Lock()
		drop := p.drops[dsn]
		delete(p.drops, dsn)
		p.mu.Unlock()
		if err := drop(); err != nil {
			t.Log(err)
		}
	})
}

func (p *dbPool) dropAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, drop := range p.drops {
		if err := drop(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	p.drops, p.free = map[string]func() error{}, map[string][]string{}
}

// newDatabase creates database db through the admin DSN and returns a DSN for it and the function that drops it.
func newDatabase(driver, admin, db string) (string, func() error, error) {
	sqlDriver, dsn := "pgx", ""
	if driver == "postgres" {
		u, err := url.Parse(admin)
		if err != nil {
			return "", nil, err
		}
		u.Path = "/" + db
		dsn = u.String()
	} else {
		cfg, err := mysql.ParseDSN(admin)
		if err != nil {
			return "", nil, err
		}
		sqlDriver, admin = "mysql", cfg.FormatDSN()
		cfg.DBName = db
		dsn = cfg.FormatDSN()
	}
	exec := func(q string) error {
		sdb, err := sql.Open(sqlDriver, admin)
		if err != nil {
			return err
		}
		defer sdb.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute) // a database still in use cannot be dropped
		defer cancel()
		_, err = sdb.ExecContext(ctx, q)
		return err
	}
	if err := exec("CREATE DATABASE " + db); err != nil {
		return "", nil, err
	}
	drop := func() error {
		q := "DROP DATABASE " + db
		if driver == "postgres" {
			q += " WITH (FORCE)"
		}
		if err := exec(q); err != nil {
			return fmt.Errorf("drop %s: %w", db, err)
		}
		return nil
	}
	return dsn, drop, nil
}

// schemaDatabase returns the configuration of an empty database of d for a test that changes its schema: it is not given
// to another test.
func schemaDatabase(t *testing.T, d testDialect) Config {
	t.Helper()
	s, dsn := openTest(t, d.name, d.env, 0)
	s.Close()
	if d.name != "sqlite" {
		pool.discard(t, dsn)
	}
	return Config{Driver: d.name, DSN: dsn}
}

// openSQLite opens a store on a new SQLite file, closed when the test ends; the path lets the test open it again.
func openSQLite(t *testing.T) (*Store, string) {
	t.Helper()
	s, path := openTest(t, "sqlite", "", 0)
	t.Cleanup(func() { s.Close() })
	return s, path
}

// openMem opens a scratch SQLite database (not a Store) for tests that need real driver errors.
func openMem(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "scratch.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// record returns a record of kind in scope "sc" with a fresh version, expiring at expires (zero: never).
func record(kind model.Kind, id string, expires time.Time, uniq ...string) *store.Record {
	return &store.Record{Kind: kind, ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "sc", Unique: uniq,
		Data: []byte("d"), Expires: expires, Fields: map[string]any{"purpose": "p"}}
}

// userRecord returns user u encoded as a record.
func userRecord(t *testing.T, u *model.User) *store.Record {
	t.Helper()
	r, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
