// Package sqlstore is a store.Store backed by SQL: SQLite (pure Go, no cgo), PostgreSQL, MySQL and MariaDB.
//
// Layout: one table per kind with the columns id, version, origin, deleted, scope, expires, seq, uniq, data plus one
// typed column per schema field; a (kind, value) -> id table for unique values; and a feed table holding the feed id
// and the sequence counter. Versions are stored as BIGINT (an HLC timestamp stays below 2^63 for centuries);
// times are stored as unix microseconds (0 = unset), expiry as nullable unix microseconds.
//
// Writes run in one transaction under an in-process mutex, and the sequence counter is a row bumped inside the
// transaction, so seq follows commit order. Replication runs only against single-process local backends (SQLite);
// for shared servers several processes may write at once: Put, CompareAndPut and unique values stay correct through
// row locks and constraints (and retried deadlocks), and the change feed is correct per process.
//
// Limits: on MySQL and MariaDB string fields are VARCHAR(255), ids and scopes VARCHAR(191), unique values
// VARCHAR(512) (utf8mb4, NO PAD binary collation); longer values are rejected by the server. MySQL needs 8.0.13+
// (functional indexes for case-insensitive sorting); MariaDB sorts strings with a filesort inside the scope.
// SQLite's LOWER folds ASCII only, so case-insensitive search and sort are ASCII-only there.
package sqlstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib" // also registers the "pgx" database/sql driver
	_ "modernc.org/sqlite"           // registers the "sqlite" database/sql driver

	"github.com/paularlott/quisora/internal/model"
)

// Config selects and tunes the database.
type Config struct {
	Driver       string // sqlite, postgres, mysql or mariadb
	DSN          string // sqlite: a file path (or file: URI); others: the driver's DSN or URL
	MaxOpenConns int    // 0 = default (sqlite: readers max(4, CPUs); servers: 32)
	MaxIdleConns int    // 0 = default (servers: 8)
	// RootCAs verifies the server's TLS certificate (a private CA; nil: the system's roots). For MySQL/MariaDB it
	// also turns TLS on when the DSN does not; for PostgreSQL it applies when the DSN asks for TLS (sslmode).
	RootCAs *x509.CertPool
	// Feed enables the change feed (Changes, commit-ordered seq). It costs a serialised write path: an in-process
	// mutex and a counter row locked until commit. Leave it off unless the data is replicated.
	Feed bool
}

// ErrFeedDisabled is returned by Changes when the store was opened without Config.Feed.
var ErrFeedDisabled = errors.New("sqlstore: change feed disabled")

// Store implements store.Store over SQL.
type Store struct {
	d      *dialect
	rdb    *sql.DB // readers (same pool as wdb except on SQLite)
	wdb    *sql.DB // writes
	rc, wc *stmtCache
	mu     sync.Mutex   // serialises write transactions so seq follows commit order
	feedID atomic.Value // string
	feed   bool
	tables map[model.Kind]*table

	releaseQ, seqQ, seqSelQ string // unique release and feed counter statements
}

// Open connects to the database, creates or migrates the schema and returns the store.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	d, err := newDialect(cfg.Driver)
	if err != nil {
		return nil, err
	}
	s := &Store{d: d, feed: cfg.Feed, tables: map[model.Kind]*table{}}
	for _, k := range model.Kinds() {
		s.tables[k] = newTable(d, k)
	}
	s.releaseQ = d.bind("DELETE FROM " + uniqueTable + " WHERE kind = ? AND value = ? AND id = ?")
	if !cfg.Feed {
		// no counter
	} else if d.isMySQL() {
		s.seqQ = "UPDATE " + feedTable + " SET seq = LAST_INSERT_ID(seq + 1) WHERE id = 1"
		s.seqSelQ = "SELECT LAST_INSERT_ID()"
	} else {
		s.seqQ = "UPDATE " + feedTable + " SET seq = seq + 1 WHERE id = 1 RETURNING seq"
	}
	switch {
	case d.name == "sqlite":
		err = s.openSQLite(ctx, cfg)
	case d.isPG():
		var pc *pgx.ConnConfig
		if pc, err = pgx.ParseConfig(cfg.DSN); err == nil {
			if cfg.RootCAs != nil {
				for _, t := range append([]*tls.Config{pc.TLSConfig}, fallbackTLS(pc)...) {
					if t == nil {
						continue
					}
					// verify-full uses RootCAs directly; verify-ca is InsecureSkipVerify with a peer check that reads
					// RootCAs; require checks nothing, so with a CA file it gets that chain check too (verify-ca).
					t.RootCAs = cfg.RootCAs
					if t.InsecureSkipVerify && t.VerifyPeerCertificate == nil {
						t.VerifyPeerCertificate = verifyChain(cfg.RootCAs)
					}
				}
			}
			s.useServerPool(stdlib.OpenDB(*pc), cfg)
		}
	default:
		var mc *mysql.Config
		if mc, err = mysql.ParseDSN(cfg.DSN); err == nil {
			mc.Collation = "utf8mb4_bin"
			mc.InterpolateParams = false
			if cfg.RootCAs != nil && mc.Net != "unix" {
				switch {
				case mc.TLS == nil: // no tls in the DSN: a CA file asks for verified TLS
					host, _, _ := net.SplitHostPort(mc.Addr)
					mc.TLS = &tls.Config{RootCAs: cfg.RootCAs, ServerName: host, MinVersion: tls.VersionTLS12}
				case !mc.TLS.InsecureSkipVerify:
					mc.TLS.RootCAs = cfg.RootCAs
				}
			}
			var conn driver.Connector
			if conn, err = mysql.NewConnector(mc); err == nil {
				s.useServerPool(sql.OpenDB(conn), cfg)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: open: %w", err)
	}
	if err := s.wdb.PingContext(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("sqlstore: connect: %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	var feed string
	if err := s.wdb.QueryRowContext(ctx, "SELECT feed_id FROM "+feedTable+" WHERE id = 1").Scan(&feed); err != nil {
		s.Close()
		return nil, fmt.Errorf("sqlstore: read feed id: %w", err)
	}
	s.feedID.Store(feed)
	return s, nil
}

func (s *Store) useServerPool(db *sql.DB, cfg Config) {
	open, idle := cfg.MaxOpenConns, cfg.MaxIdleConns
	if open <= 0 {
		open = 32
	}
	if idle <= 0 {
		// Keep every connection the pool may open. A smaller idle limit makes database/sql close and re-dial (TCP,
		// TLS and authentication) the connections above it on every burst, which cost ~1 ms each and showed up as
		// intermittent "failed to connect" errors and halved throughput at 64+ concurrent requests.
		idle = open
	}
	if idle > open {
		idle = open
	}
	db.SetMaxOpenConns(open)
	db.SetMaxIdleConns(idle)
	db.SetConnMaxLifetime(30 * time.Minute)
	s.rdb, s.wdb = db, db
	s.rc = newStmtCache(db)
	s.wc = s.rc
}

// openSQLite opens one writer connection and a pool of readers (WAL lets readers run beside the writer).
func (s *Store) openSQLite(ctx context.Context, cfg Config) error {
	if cfg.DSN == "" {
		return errors.New("sqlite needs a DSN (file path)")
	}
	w, err := sql.Open("sqlite", sqliteDSN(cfg.DSN, true))
	if err != nil {
		return err
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	if err := w.PingContext(ctx); err != nil { // creates the file and switches it to WAL
		w.Close()
		return err
	}
	r, err := sql.Open("sqlite", sqliteDSN(cfg.DSN, false))
	if err != nil {
		w.Close()
		return err
	}
	n := cfg.MaxOpenConns
	if n <= 0 {
		n = max(4, runtime.NumCPU())
	}
	r.SetMaxOpenConns(n)
	r.SetMaxIdleConns(n)
	s.wdb, s.rdb = w, r
	s.wc, s.rc = newStmtCache(w), newStmtCache(r)
	return nil
}

func sqliteDSN(dsn string, writer bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(0)")
	if writer {
		q.Add("_txlock", "immediate")
	} else {
		q.Add("_pragma", "query_only(1)")
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + strings.ReplaceAll(q.Encode(), "+", "%20")
}

// FeedID identifies this store's change feed.
func (s *Store) FeedID() string { return s.feedID.Load().(string) }

// Close closes the connection pools.
func (s *Store) Close() error {
	var errs []error
	for _, c := range []*stmtCache{s.rc, s.wc} {
		if c != nil {
			c.close()
		}
	}
	if s.rdb != nil && s.rdb != s.wdb {
		errs = append(errs, s.rdb.Close())
	}
	if s.wdb != nil {
		errs = append(errs, s.wdb.Close())
	}
	return errors.Join(errs...)
}

func (s *Store) table(kind model.Kind) (*table, error) {
	t, ok := s.tables[kind]
	if !ok {
		return nil, fmt.Errorf("sqlstore: unknown kind %q", kind)
	}
	return t, nil
}

// stmtCache caches prepared statements by SQL text. MySQL in particular would otherwise prepare, execute and
// close on every call. The cache is bounded; past the bound statements run unprepared.
type stmtCache struct {
	db *sql.DB
	mu sync.RWMutex
	m  map[string]*sql.Stmt
}

const maxStmts = 1024

func newStmtCache(db *sql.DB) *stmtCache { return &stmtCache{db: db, m: map[string]*sql.Stmt{}} }

func (c *stmtCache) get(ctx context.Context, q string) (*sql.Stmt, error) {
	c.mu.RLock()
	st, full := c.m[q], len(c.m) >= maxStmts
	c.mu.RUnlock()
	if st != nil || full {
		return st, nil
	}
	// Prepare without holding the lock: it waits for a pooled connection, and transactions that hold every
	// connection call peek, which needs the read lock.
	st, err := c.db.PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	old, full := c.m[q], len(c.m) >= maxStmts
	if old == nil && !full {
		c.m[q] = st
	}
	c.mu.Unlock()
	switch {
	case old != nil:
		go st.Close() // Close waits for busy connections; never under the lock or in the caller's way
		return old, nil
	case full:
		go st.Close()
		return nil, nil
	}
	return st, nil
}

func (c *stmtCache) peek(q string) *sql.Stmt {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.m[q]
}

func (c *stmtCache) close() {
	c.mu.Lock()
	m := c.m
	c.m = map[string]*sql.Stmt{}
	c.mu.Unlock()
	for _, st := range m {
		st.Close()
	}
}

// runner executes statements through the cache, inside tx when set.
type runner struct {
	c  *stmtCache
	tx *sql.Tx
}

// stmt returns the cached statement for q. Inside a transaction nothing is prepared (the single SQLite writer
// connection is held by the transaction); statements are warmed before it begins.
func (r runner) stmt(ctx context.Context, q string) (*sql.Stmt, error) {
	if r.tx != nil {
		return r.c.peek(q), nil
	}
	return r.c.get(ctx, q)
}

func (r runner) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	st, err := r.stmt(ctx, q)
	switch {
	case err != nil:
		return nil, err
	case st == nil && r.tx != nil:
		return r.tx.ExecContext(ctx, q, args...)
	case st == nil:
		return r.c.db.ExecContext(ctx, q, args...)
	case r.tx != nil:
		return r.tx.StmtContext(ctx, st).ExecContext(ctx, args...)
	}
	return st.ExecContext(ctx, args...)
}

func (r runner) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	st, err := r.stmt(ctx, q)
	switch {
	case err != nil:
		return nil, err
	case st == nil && r.tx != nil:
		return r.tx.QueryContext(ctx, q, args...)
	case st == nil:
		return r.c.db.QueryContext(ctx, q, args...)
	case r.tx != nil:
		return r.tx.StmtContext(ctx, st).QueryContext(ctx, args...)
	}
	return st.QueryContext(ctx, args...)
}

// queryRow returns the row (or error) of a single-row query.
func (r runner) queryRow(ctx context.Context, q string, args ...any) scanner {
	rows, err := r.query(ctx, q, args...)
	return &row{rows: rows, err: err}
}

// row mimics *sql.Row over *sql.Rows so cached statements can be used.
type row struct {
	rows *sql.Rows
	err  error
}

func (r *row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	defer r.rows.Close()
	if !r.rows.Next() {
		if err := r.rows.Err(); err != nil {
			return err
		}
		return sql.ErrNoRows
	}
	return r.rows.Scan(dest...)
}

func (s *Store) reader() runner { return runner{c: s.rc} }

// fallbackTLS returns the TLS configurations of a PostgreSQL connection's fallbacks (sslmode=prefer tries TLS, then
// plain).
func fallbackTLS(pc *pgx.ConnConfig) []*tls.Config {
	var out []*tls.Config
	for _, f := range pc.Fallbacks {
		out = append(out, f.TLSConfig)
	}
	return out
}

// verifyChain checks a server certificate chain against roots, without the host name (sslmode=verify-ca).
func verifyChain(roots *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("postgres: the server sent no certificate")
		}
		certs := make([]*x509.Certificate, len(raw))
		for i, b := range raw {
			c, err := x509.ParseCertificate(b)
			if err != nil {
				return err
			}
			certs[i] = c
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
		return err
	}
}
