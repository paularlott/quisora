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
	"strings"
	"syscall"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"

	"github.com/paularlott/quisora/internal/store"
)

// errDBClosed is what database/sql answers once the database was closed.
const errDBClosed = "sql: database is closed"

// failure is what a database error says about the operation that met it.
type failure int

const (
	failOther failure = iota // a real error: a refused statement, a bug, bad data
	failRetry                // the database cannot serve now (a lock or busy timeout, a deadlock, a node that refuses work): nothing was done
	failLost                 // the connection, or the call, failed: a statement or commit may or may not have been applied
)

// classify sorts a database error: the one place that knows which failures are transient. The drivers' errors are
// matched by type and code, never by message, so a change of wording cannot turn an outage into a 500.
func classify(err error) failure {
	if err == nil {
		return failOther
	}
	switch {
	case errors.Is(err, driver.ErrBadConn), errors.Is(err, mysql.ErrInvalidConn), errors.Is(err, pgconn.ErrConnClosed),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), errors.Is(err, sql.ErrConnDone),
		errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EPIPE),
		pgconn.Timeout(err):
		return failLost
	case strings.HasSuffix(err.Error(), errDBClosed): // (the one match by message: database/sql exports no error for it)
		return failRetry // a closed store: nothing was done (store.Store: ErrUnavailable)
	}
	var ne net.Error // dial, read and write errors, timeouts, DNS
	if errors.As(err, &ne) {
		return failLost
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch {
		case strings.HasPrefix(pg.Code, "08"), // connection exception
			pg.Code == "57P01", pg.Code == "57P02", pg.Code == "57P03": // admin shutdown, crash shutdown, cannot connect now
			return failLost
		case pg.Code == "40001", pg.Code == "40P01", pg.Code == "53300": // serialization failure, deadlock, too many connections
			return failRetry
		}
		return failOther
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		switch my.Number {
		case 1053, 1152, 1158, 1159, 1160, 1161, 1927, 2002, 2003, 2006, 2013, 4031:
			// shutdown in progress, aborted connection, network read/write errors and timeouts, connection killed, can't connect,
			// server gone away, lost connection, inactive client disconnected
			return failLost
		case 1040, 1047, 1205, 1213:
			// too many connections; Galera "WSREP has not yet prepared node for application use"; lock wait timeout; deadlock
			return failRetry
		}
		return failOther
	}
	var sq *sqlite.Error
	if errors.As(err, &sq) {
		if c := sq.Code() & 0xff; c == 5 || c == 6 { // BUSY, LOCKED: still held after the busy timeout
			return failRetry
		}
	}
	return failOther
}

// unavailable returns err as store.ErrUnavailable (keeping the cause) when it is a transient failure of the database,
// and as it is otherwise.
func unavailable(err error) error {
	if err == nil || errors.Is(err, store.ErrUnavailable) || classify(err) == failOther {
		return err
	}
	return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
}
