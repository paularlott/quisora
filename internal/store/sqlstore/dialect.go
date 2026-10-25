package sqlstore

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"

	"github.com/paularlott/quisora/internal/model"
)

// dialect captures the SQL differences between the supported databases.
type dialect struct {
	name string // sqlite, postgres, mysql or mariadb
}

func newDialect(driver string) (*dialect, error) {
	switch driver {
	case "sqlite", "postgres", "mysql", "mariadb":
		return &dialect{driver}, nil
	}
	return nil, fmt.Errorf("sqlstore: unknown driver %q (want sqlite, postgres, mysql or mariadb)", driver)
}

func (d *dialect) isPG() bool    { return d.name == "postgres" }
func (d *dialect) isMySQL() bool { return d.name == "mysql" || d.name == "mariadb" }

// quote quotes an identifier. Only schema-defined names ever reach it.
func (d *dialect) quote(id string) string {
	if d.isMySQL() {
		return "`" + id + "`"
	}
	return `"` + id + `"`
}

// bind rewrites ? placeholders to the driver's style.
func (d *dialect) bind(q string) string {
	if !d.isPG() {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

// lockClause is appended to SELECTs whose rows are about to be changed.
func (d *dialect) lockClause(of string) string {
	switch {
	case d.isPG():
		if of != "" {
			return " FOR UPDATE OF " + of
		}
		return " FOR UPDATE"
	case d.isMySQL():
		return " FOR UPDATE"
	}
	return "" // sqlite: the single writer already holds the database lock
}

func (d *dialect) insertIgnore(table, cols, vals string) string {
	if d.isMySQL() {
		return "INSERT IGNORE INTO " + table + " (" + cols + ") VALUES (" + vals + ")"
	}
	return "INSERT INTO " + table + " (" + cols + ") VALUES (" + vals + ") ON CONFLICT DO NOTHING"
}

// strCollate is the collation applied to every text column: binary and NO PAD so equality is exact.
func (d *dialect) strCollate() string {
	switch d.name {
	case "mysql":
		return " COLLATE utf8mb4_0900_bin"
	case "mariadb":
		return " COLLATE utf8mb4_nopad_bin"
	}
	return ""
}

// keyType is the type of id, scope and origin columns (byte-wise ordering so ID order is creation order).
func (d *dialect) keyType(n int) string {
	switch {
	case d.isPG():
		return `TEXT COLLATE "C"`
	case d.isMySQL():
		return fmt.Sprintf("VARCHAR(%d) CHARACTER SET utf8mb4%s", n, d.strCollate())
	}
	return "TEXT"
}

func (d *dialect) colType(f model.Field) string {
	switch f.Type {
	case model.FieldString:
		if d.isMySQL() {
			n := 255 // every queryable string is clipped to 255 characters (service.Audit, model limits)
			if f.Words {
				n = model.MaxTagsText // the space-joined tags: never indexed, so not bound by the key length
			}
			return fmt.Sprintf("VARCHAR(%d) CHARACTER SET utf8mb4%s NOT NULL DEFAULT ''", n, d.strCollate())
		}
		return "TEXT NOT NULL DEFAULT ''"
	case model.FieldBool:
		return "BOOLEAN NOT NULL DEFAULT FALSE"
	}
	return "BIGINT NOT NULL DEFAULT 0" // ints and times (unix microseconds)
}

func (d *dialect) blobType() string {
	switch {
	case d.isPG():
		return "BYTEA"
	case d.isMySQL():
		return "MEDIUMBLOB"
	}
	return "BLOB"
}

func (d *dialect) textType() string {
	if d.isMySQL() {
		return "MEDIUMTEXT"
	}
	return "TEXT"
}

// sortExpr is the ORDER BY / index expression for a sortable field: strings compare case-insensitively and
// byte-wise, like the in-memory reference.
func (d *dialect) sortExpr(f model.Field) string {
	col := d.quote(f.Name)
	if f.Type != model.FieldString {
		return col
	}
	if d.isPG() {
		return "LOWER(" + col + `) COLLATE "C"`
	}
	return "LOWER(" + col + ")"
}

// sortIndexExpr is the index key part for a sortable field, or "" when the database cannot index it
// (MariaDB has no functional indexes, so case-insensitive string sorts are a filesort within the scope).
func (d *dialect) sortIndexExpr(f model.Field) string {
	if f.Type != model.FieldString {
		return d.quote(f.Name)
	}
	switch {
	case d.isPG():
		return "(" + d.sortExpr(f) + ")"
	case d.name == "mysql":
		return "(" + d.sortExpr(f) + ")"
	case d.name == "mariadb":
		return ""
	}
	return d.sortExpr(f)
}

// retryable reports whether a failed write transaction should be run again: deadlocks, serialization failures,
// busy databases and duplicate keys (a concurrent writer created the same row first).
func (d *dialect) retryable(err error) bool {
	if d.isDuplicate(err) {
		return true
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "40001" || pg.Code == "40P01"
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1213 || my.Number == 1205
	}
	var sq *sqlite.Error
	if errors.As(err, &sq) {
		c := sq.Code() & 0xff
		return c == 5 || c == 6 // BUSY, LOCKED
	}
	return false
}

func (d *dialect) isDuplicate(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505"
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1062
	}
	var sq *sqlite.Error
	if errors.As(err, &sq) {
		return sq.Code() == 1555 || sq.Code() == 2067 // PRIMARYKEY, UNIQUE
	}
	return false
}

// ignorableDDL reports errors from re-running idempotent DDL (MySQL has no CREATE INDEX IF NOT EXISTS).
func (d *dialect) ignorableDDL(err error) bool {
	var my *mysql.MySQLError
	return errors.As(err, &my) && my.Number == 1061 // duplicate key name
}
