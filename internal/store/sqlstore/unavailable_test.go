package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"modernc.org/sqlite"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// sqliteBusy returns the error SQLite gives a writer that waits out its busy timeout for another writer's lock.
func sqliteBusy(t *testing.T) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "busy.db")
	open := func() *sql.DB {
		db, err := sql.Open("sqlite", path+"?_txlock=immediate&_pragma=busy_timeout(1)")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	holder, err := open().Begin() // takes the write lock at BEGIN
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	_, err = open().Begin()
	var se *sqlite.Error
	if !errors.As(err, &se) {
		t.Fatalf("expected a sqlite busy error, got %v", err)
	}
	return err
}

// classify and unavailable: transient failures of every dialect, and only those, are ErrUnavailable.
func TestClassifyTransientErrors(t *testing.T) {
	timeout := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	lost := map[string]error{
		"bad conn":         driver.ErrBadConn,
		"wrapped bad conn": fmt.Errorf("commit: %w", driver.ErrBadConn),
		"refused":          &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}},
		"reset":            &net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}},
		"bare reset":       syscall.ECONNRESET,
		"broken pipe":      syscall.EPIPE,
		"eof":              io.EOF,
		"unexpected eof":   io.ErrUnexpectedEOF,
		"net timeout":      timeout,
		"deadline":         context.DeadlineExceeded,
		"wrapped deadline": fmt.Errorf("query: %w", context.DeadlineExceeded),
		"pg 08006":         &pgconn.PgError{Code: "08006"},
		"pg 08001":         &pgconn.PgError{Code: "08001"},
		"pg admin":         &pgconn.PgError{Code: "57P01"},
		"pg crash":         &pgconn.PgError{Code: "57P02"},
		"pg starting up":   &pgconn.PgError{Code: "57P03"},
		"pg conn closed":   pgconn.ErrConnClosed,
		"pg wrapped":       fmt.Errorf("w: %w", &pgconn.PgError{Code: "57P01"}),
		"my invalid conn":  mysql.ErrInvalidConn,
		"my gone away":     &mysql.MySQLError{Number: 2006},
		"my lost":          &mysql.MySQLError{Number: 2013},
		"my shutdown":      &mysql.MySQLError{Number: 1053},
		"my killed":        &mysql.MySQLError{Number: 1927},
	}
	retry := map[string]error{
		"pg serialization": &pgconn.PgError{Code: "40001"},
		"pg deadlock":      &pgconn.PgError{Code: "40P01"},
		"pg too many":      &pgconn.PgError{Code: "53300"},
		"my galera":        &mysql.MySQLError{Number: 1047, Message: "WSREP has not yet prepared node for application use"},
		"my deadlock":      &mysql.MySQLError{Number: 1213},
		"my lock wait":     &mysql.MySQLError{Number: 1205},
		"my too many":      &mysql.MySQLError{Number: 1040},
		"sqlite busy":      sqliteBusy(t),
	}
	other := map[string]error{
		"nil":             nil,
		"plain":           errors.New("x"),
		"no rows":         sql.ErrNoRows,
		"canceled":        context.Canceled,
		"closed":          errors.New("sql: database is closed"),
		"pg duplicate":    &pgconn.PgError{Code: "23505"},
		"pg no table":     &pgconn.PgError{Code: "42P01"},
		"my duplicate":    &mysql.MySQLError{Number: 1062},
		"my no table":     &mysql.MySQLError{Number: 1146},
		"my data":         &mysql.MySQLError{Number: 1406},
		"store conflict":  store.ErrConflict,
		"store not found": store.ErrNotFound,
	}
	for n, err := range lost {
		if got := classify(err); got != failLost {
			t.Errorf("%s: classified %d, want failLost", n, got)
		}
	}
	for n, err := range retry {
		if got := classify(err); got != failRetry {
			t.Errorf("%s: classified %d, want failRetry", n, got)
		}
	}
	for n, err := range other {
		if got := classify(err); got != failOther {
			t.Errorf("%s: classified %d, want failOther", n, got)
		}
		if got := unavailable(err); got != err {
			t.Errorf("%s: an ordinary error was changed to %v", n, got)
		}
	}
	for _, m := range []map[string]error{lost, retry} {
		for n, err := range m {
			got := unavailable(err)
			if !errors.Is(got, store.ErrUnavailable) || !errors.Is(got, store.ErrNotWritable) {
				t.Errorf("%s: %v is not ErrUnavailable", n, got)
			}
			if !errors.Is(got, err) && n != "pg wrapped" { // the cause stays in the chain
				t.Errorf("%s: the cause was lost", n)
			}
			if again := unavailable(got); again != got {
				t.Errorf("%s: wrapped twice", n)
			}
		}
	}
}

// A closed store and a canceled caller are real errors; a database call that ran out of time is "unavailable".
func TestUnavailableAtTheBoundary(t *testing.T) {
	s, _ := openSQLite(t)
	ctx := context.Background()
	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	if _, err := s.Get(expired, model.KindLink, "a"); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("Get after the deadline: %v", err)
	}
	if err := s.Put(expired, record(model.KindLink, "a", time.Time{})); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("Put after the deadline: %v", err)
	}
	s.Close()
	for n, err := range map[string]error{
		"Put": s.Put(ctx, record(model.KindLink, "a", time.Time{})),
		"Tx":  s.Tx(ctx, []store.Op{{Rec: record(model.KindLink, "a", time.Time{})}}),
	} {
		if err == nil || errors.Is(err, store.ErrUnavailable) {
			t.Errorf("%s on a closed store: %v", n, err)
		}
	}
}

// faults makes the commits of a store's writer connections fail, as the test says.
type faults struct {
	mu     sync.Mutex
	commit func() (land bool, err error) // nil: commits are not touched; else decides each (land: the commit goes through first)
}

func (f *faults) set(land bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commit = func() (bool, error) { return land, err }
}

func (f *faults) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commit = nil
}

// openConnector is a driver.Connector over a driver that has none (SQLite's).
type openConnector struct {
	drv driver.Driver
	dsn string
}

func (c openConnector) Connect(context.Context) (driver.Conn, error) { return c.drv.Open(c.dsn) }
func (c openConnector) Driver() driver.Driver                        { return c.drv }

type faultConnector struct {
	inner driver.Connector
	f     *faults
}

func (c faultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &faultConn{Conn: conn, f: c.f}, nil
}
func (c faultConnector) Driver() driver.Driver { return c.inner.Driver() }

type faultConn struct {
	driver.Conn
	f *faults
}

func (c *faultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	var tx driver.Tx
	var err error
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		tx, err = b.BeginTx(ctx, opts)
	} else {
		tx, err = c.Conn.Begin()
	}
	if err != nil {
		return nil, err
	}
	return &faultTx{Tx: tx, f: c.f}, nil
}

func (c *faultConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, q)
	}
	return c.Conn.Prepare(q)
}

type faultTx struct {
	driver.Tx
	f *faults
}

func (x *faultTx) Commit() error {
	x.f.mu.Lock()
	fn := x.f.commit
	x.f.mu.Unlock()
	if fn == nil {
		return x.Tx.Commit()
	}
	land, err := fn()
	switch {
	case land:
		if cerr := x.Tx.Commit(); cerr != nil {
			return cerr
		}
	default:
		x.Tx.Rollback()
	}
	return err
}

// faultStore opens a store of d whose writes go through a connection wrapper that can fail commits; reads use the
// ordinary pool (other connections, as after a lost one).
func faultStore(t *testing.T, d testDialect) (*Store, *faults) {
	t.Helper()
	s, dsn := openTest(t, d.name, d.env, 8)
	f := &faults{}
	var inner driver.Connector
	switch {
	case d.name == "sqlite":
		inner = openConnector{drv: s.wdb.Driver(), dsn: sqliteDSN(dsn, true)}
	case d.name == "postgres":
		pc, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		inner = stdlib.GetConnector(*pc)
	default:
		mc, err := mysql.ParseDSN(dsn)
		if err != nil {
			t.Fatal(err)
		}
		mc.Collation, mc.InterpolateParams = "utf8mb4_bin", false
		if inner, err = mysql.NewConnector(mc); err != nil {
			t.Fatal(err)
		}
	}
	db := sql.OpenDB(faultConnector{inner: inner, f: f})
	if d.name == "sqlite" {
		db.SetMaxOpenConns(1)
		old := s.wdb
		t.Cleanup(func() { old.Close() }) // the writer this replaces (Close closes the new one)
	} else {
		db.SetMaxOpenConns(8)
	}
	s.wc.close()
	s.wdb, s.wc = db, newStmtCache(db)
	t.Cleanup(func() { s.Close() })
	return s, f
}

// A commit that fails with a lost connection may have landed: the store reads the record back and, if the write's
// request is stored, answers as done (with the stored version); otherwise it answers ErrUnavailable, and the same
// request retried is applied or recognised. Failures that are not a lost connection are real errors.
func TestLostCommitIsSettled(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		s, f := faultStore(t, d)
		ctx := context.Background()
		lostErrs := map[string]error{
			"bad conn": driver.ErrBadConn,
			"reset":    &net.OpError{Op: "read", Err: syscall.ECONNRESET},
		}
		for name, lost := range lostErrs {
			t.Run(name, func(t *testing.T) {
				id := "settle-" + name
				stored := func() *store.Record {
					t.Helper()
					r, err := s.Lookup(ctx, model.KindLink, id)
					if errors.Is(err, store.ErrNotFound) {
						return nil
					}
					if err != nil {
						t.Fatal(err)
					}
					return r
				}

				// A create that landed before the connection was lost: done.
				rec := record(model.KindLink, id, time.Time{}, "u/"+id)
				rec.Req = store.NewReq() // a request its caller may retry: it names itself
				f.set(true, lost)
				if err := s.CompareAndPut(ctx, rec, 0); err != nil {
					t.Fatalf("a create that landed: %v", err)
				}
				r := stored()
				if r == nil || r.Version != rec.Version || r.Req != rec.Req || rec.Req == "" || r.Created != rec.Created {
					t.Fatalf("settled create: stored %+v, record %+v", r, rec)
				}

				// An update that did not land: unavailable, nothing changed; the same request, retried, is applied.
				upd := record(model.KindLink, id, time.Time{}, "u/"+id)
				upd.Req = store.NewReq()
				upd.Data = []byte("changed")
				f.set(false, lost)
				err := s.CompareAndPut(ctx, upd, r.Version)
				if !errors.Is(err, store.ErrUnavailable) {
					t.Fatalf("an update that did not land: want ErrUnavailable, got %v", err)
				}
				if got := stored(); got.Version != r.Version || string(got.Data) != "d" {
					t.Fatalf("a lost update changed the record: %+v", got)
				}
				f.clear()
				if err := s.CompareAndPut(ctx, upd, r.Version); err != nil {
					t.Fatalf("the update retried: %v", err)
				}
				if got := stored(); string(got.Data) != "changed" || got.Version != upd.Version || got.Req != upd.Req {
					t.Fatalf("the retried update: %+v, record %+v", got, upd)
				}

				// An update that landed, and is asked again though its expectation is now stale: done, once.
				again := record(model.KindLink, id, time.Time{}, "u/"+id)
				again.Req = store.NewReq()
				again.Data = []byte("third")
				f.set(true, lost)
				if err := s.CompareAndPut(ctx, again, upd.Version); err != nil {
					t.Fatalf("an update that landed: %v", err)
				}
				f.clear()
				v := again.Version
				if err := s.CompareAndPut(ctx, again, upd.Version); err != nil || again.Version != v {
					t.Fatalf("the same request again: %v (version %d, was %d)", err, again.Version, v)
				}

				// A deletion that landed.
				tomb := store.Tombstone(model.KindLink, id)
				tomb.Req = store.NewReq()
				f.set(true, lost)
				if err := s.Put(ctx, tomb); err != nil {
					t.Fatalf("a deletion that landed: %v", err)
				}
				if r := stored(); r == nil || !r.Deleted || r.Version != tomb.Version {
					t.Fatalf("the settled deletion: %+v, tombstone %+v", r, tomb)
				}
				f.clear()
			})
		}

		t.Run("tx", func(t *testing.T) {
			defer f.clear()
			mk := func(id string, uniq ...string) *store.Record { return record(model.KindLink, id, time.Time{}, uniq...) }
			a, b := mk("txs-a", "u/txs-a"), mk("txs-b", "u/txs-b")
			a.Req = store.NewReq() // the transaction's request, which its caller may retry
			ops := func(recs ...*store.Record) []store.Op {
				var o []store.Op
				for _, r := range recs {
					o = append(o, store.Op{Rec: r, Match: true})
				}
				return o
			}
			f.set(false, driver.ErrBadConn)
			if err := s.Tx(ctx, ops(a, b)); !errors.Is(err, store.ErrUnavailable) {
				t.Fatalf("a transaction that did not land: want ErrUnavailable, got %v", err)
			}
			for _, id := range []string{a.ID, b.ID} {
				if _, err := s.Lookup(ctx, model.KindLink, id); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("%s stored by a transaction that did not land: %v", id, err)
				}
			}
			f.set(true, driver.ErrBadConn)
			if err := s.Tx(ctx, ops(a, b)); err != nil {
				t.Fatalf("a transaction that landed: %v", err)
			}

			for _, r := range []*store.Record{a, b} {
				if got, err := s.Lookup(ctx, model.KindLink, r.ID); err != nil || got.Version != r.Version || got.Req != a.Req {
					t.Fatalf("%s after the settled transaction: %+v %v", r.ID, got, err)
				}
			}
			f.clear()
			va := a.Version
			if err := s.Tx(ctx, ops(a, b)); err != nil || a.Version != va { // the same request again
				t.Fatalf("the transaction retried: %v (version %d, was %d)", err, a.Version, va)
			}
		})

		t.Run("other errors", func(t *testing.T) {
			defer f.clear()
			boom := errors.New("disk full")
			f.set(false, boom)
			rec := record(model.KindLink, "other", time.Time{})
			if err := s.Put(ctx, rec); !errors.Is(err, boom) || errors.Is(err, store.ErrUnavailable) {
				t.Fatalf("a commit that failed for another reason: %v", err)
			}
			if _, err := s.Lookup(ctx, model.KindLink, "other"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a refused commit left a record: %v", err)
			}
		})
	})
}
