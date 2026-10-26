package sqlstore

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"

	"github.com/paularlott/quisora/internal/model"
)

func mustDialect(t *testing.T, name string) *dialect {
	t.Helper()
	d, err := newDialect(name)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNewDialectKnowsFourDrivers(t *testing.T) {
	for _, n := range []string{"sqlite", "postgres", "mysql", "mariadb"} {
		if d := mustDialect(t, n); d.name != n {
			t.Fatalf("%s: got %q", n, d.name)
		}
	}
	if _, err := newDialect("oracle"); err == nil || !strings.Contains(err.Error(), "unknown driver") {
		t.Fatalf("unknown driver: %v", err)
	}
}

// The SQL each dialect writes: identifiers, placeholders, locking, types, sort expressions and DDL.
func TestDialectSQL(t *testing.T) {
	sq, pg, my, mdb := mustDialect(t, "sqlite"), mustDialect(t, "postgres"), mustDialect(t, "mysql"), mustDialect(t, "mariadb")
	str := model.Field{Name: "n", Type: model.FieldString}
	num := model.Field{Name: "c", Type: model.FieldInt}
	boo := model.Field{Name: "b", Type: model.FieldBool}

	t.Run("QuoteAndBind", func(t *testing.T) {
		if sq.quote("a") != `"a"` || pg.quote("a") != `"a"` || my.quote("a") != "`a`" || mdb.quote("a") != "`a`" {
			t.Fatal("quote")
		}
		if got := pg.bind("a = ? AND b = ? AND c = ?"); got != "a = $1 AND b = $2 AND c = $3" {
			t.Fatalf("pg bind: %q", got)
		}
		for _, d := range []*dialect{sq, my, mdb} {
			if got := d.bind("a = ?"); got != "a = ?" {
				t.Fatalf("%s bind: %q", d.name, got)
			}
		}
	})
	t.Run("LockingAndInsertIgnore", func(t *testing.T) {
		locks := map[string][2]string{
			"sqlite":   {"", ""},
			"postgres": {" FOR UPDATE", " FOR UPDATE OF t"},
			"mysql":    {" FOR UPDATE", " FOR UPDATE"},
			"mariadb":  {" FOR UPDATE", " FOR UPDATE"},
		}
		for _, d := range []*dialect{sq, pg, my, mdb} {
			if got := d.lockClause(""); got != locks[d.name][0] {
				t.Fatalf("%s lock: %q", d.name, got)
			}
			if got := d.lockClause("t"); got != locks[d.name][1] {
				t.Fatalf("%s lock of: %q", d.name, got)
			}
		}
		if got := my.insertIgnore("t", "a", "?"); got != "INSERT IGNORE INTO t (a) VALUES (?)" {
			t.Fatal(got)
		}
		if got := pg.insertIgnore("t", "a", "?"); got != "INSERT INTO t (a) VALUES (?) ON CONFLICT DO NOTHING" {
			t.Fatal(got)
		}
	})
	t.Run("Types", func(t *testing.T) {
		if my.strCollate() != " COLLATE utf8mb4_0900_bin" || mdb.strCollate() != " COLLATE utf8mb4_nopad_bin" || sq.strCollate() != "" || pg.strCollate() != "" {
			t.Fatal("strCollate")
		}
		if sq.keyType(10) != "TEXT" || pg.keyType(10) != `TEXT COLLATE "C"` {
			t.Fatal("keyType")
		}
		if got := my.keyType(64); got != "VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin" {
			t.Fatal(got)
		}
		if got := mdb.keyType(64); !strings.Contains(got, "utf8mb4_nopad_bin") {
			t.Fatal(got)
		}
		if sq.blobType() != "BLOB" || pg.blobType() != "BYTEA" || my.blobType() != "MEDIUMBLOB" || mdb.blobType() != "MEDIUMBLOB" {
			t.Fatal("blobType")
		}
		if sq.textType() != "TEXT" || pg.textType() != "TEXT" || my.textType() != "MEDIUMTEXT" || mdb.textType() != "MEDIUMTEXT" {
			t.Fatal("textType")
		}

		if got := my.colType(str); !strings.HasPrefix(got, "VARCHAR(255)") || !strings.Contains(got, "NOT NULL DEFAULT ''") {
			t.Fatal(got)
		}
		if sq.colType(str) != "TEXT NOT NULL DEFAULT ''" || pg.colType(str) != "TEXT NOT NULL DEFAULT ''" {
			t.Fatal("string colType")
		}
		if sq.colType(boo) != "BOOLEAN NOT NULL DEFAULT FALSE" {
			t.Fatal("bool colType")
		}
		if sq.colType(num) != "BIGINT NOT NULL DEFAULT 0" || sq.colType(model.Field{Type: model.FieldTime}) != "BIGINT NOT NULL DEFAULT 0" {
			t.Fatal("int colType")
		}
	})
	t.Run("SortExpr", func(t *testing.T) {
		if pg.sortExpr(str) != `LOWER("n") COLLATE "C"` || sq.sortExpr(str) != `quisora_lower("n")` || my.sortExpr(str) != "LOWER(`n`)" {
			t.Fatal("sortExpr string")
		}
		if pg.sortExpr(num) != `"c"` || my.sortExpr(num) != "`c`" {
			t.Fatal("sortExpr int")
		}
		if got := pg.sortIndexExpr(str); got != `(LOWER("n") COLLATE "C")` {
			t.Fatal(got)
		}
		if got := my.sortIndexExpr(str); got != "(LOWER(`n`))" {
			t.Fatal(got)
		}
		if got := mdb.sortIndexExpr(str); got != "" {
			t.Fatalf("mariadb has no functional indexes: %q", got)
		}
		if got := sq.sortIndexExpr(str); got != `quisora_lower("n")` {
			t.Fatal(got)
		}
		if got := mdb.sortIndexExpr(num); got != "`c`" {
			t.Fatal(got)
		}
	})
	t.Run("DDLSuffixes", func(t *testing.T) {
		if ifNotExists(my) != "" || ifNotExists(mdb) != "IF NOT EXISTS " || ifNotExists(sq) != "IF NOT EXISTS " {
			t.Fatal("ifNotExists")
		}
		if tableSuffix(sq) != "" || !strings.Contains(tableSuffix(my), "ENGINE=InnoDB") || !strings.Contains(tableSuffix(mdb), "utf8mb4_nopad_bin") {
			t.Fatal("tableSuffix")
		}
		if uniqueSuffix(sq) != " WITHOUT ROWID" || uniqueSuffix(pg) != "" || uniqueSuffix(my) != tableSuffix(my) {
			t.Fatal("uniqueSuffix")
		}
	})
}

// Duplicate keys, deadlocks and serialisation failures of every driver are told apart from other errors.
func TestDialectClassifiesDuplicateAndRetryableErrors(t *testing.T) {
	d := mustDialect(t, "sqlite")
	pgDup := &pgconn.PgError{Code: "23505"}
	pgDead := &pgconn.PgError{Code: "40P01"}
	pgSer := &pgconn.PgError{Code: "40001"}
	pgOther := &pgconn.PgError{Code: "42P01"}
	myDup := &mysql.MySQLError{Number: 1062}
	myDead := &mysql.MySQLError{Number: 1213}
	myWait := &mysql.MySQLError{Number: 1205}
	myOther := &mysql.MySQLError{Number: 1146}
	myIdx := &mysql.MySQLError{Number: 1061}

	// sqlite.Error has unexported fields; obtain real ones from the driver.
	sqErr := func(q string) error {
		db := openMem(t)
		defer db.Close()
		if _, err := db.Exec("CREATE TABLE u (id INTEGER PRIMARY KEY, v TEXT UNIQUE)"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO u VALUES (1, 'a')"); err != nil {
			t.Fatal(err)
		}
		_, err := db.Exec(q)
		return err
	}
	sqPK, sqUniq, sqMisc := sqErr("INSERT INTO u VALUES (1, 'b')"), sqErr("INSERT INTO u VALUES (2, 'a')"), sqErr("INSERT INTO nope VALUES (1)")
	var se *sqlite.Error
	if !errors.As(sqPK, &se) || !errors.As(sqUniq, &se) {
		t.Fatalf("expected sqlite errors: %v %v", sqPK, sqUniq)
	}

	dups := map[string]error{"pg": pgDup, "my": myDup, "sqPK": sqPK, "sqUniq": sqUniq, "wrapped": fmt.Errorf("w: %w", pgDup)}
	for n, err := range dups {
		if !d.isDuplicate(err) || !d.retryable(err) {
			t.Errorf("%s: duplicate=%v retryable=%v", n, d.isDuplicate(err), d.retryable(err))
		}
	}
	for n, err := range map[string]error{"pgDead": pgDead, "pgSer": pgSer, "myDead": myDead, "myWait": myWait} {
		if d.isDuplicate(err) || !d.retryable(err) {
			t.Errorf("%s: duplicate=%v retryable=%v", n, d.isDuplicate(err), d.retryable(err))
		}
	}
	for n, err := range map[string]error{"pgOther": pgOther, "myOther": myOther, "sqMisc": sqMisc, "plain": errors.New("x"), "nil": nil} {
		if d.isDuplicate(err) || d.retryable(err) {
			t.Errorf("%s: duplicate=%v retryable=%v", n, d.isDuplicate(err), d.retryable(err))
		}
	}
	if !d.ignorableDDL(myIdx) || d.ignorableDDL(myOther) || d.ignorableDDL(pgDup) || d.ignorableDDL(nil) {
		t.Fatal("ignorableDDL")
	}
}

// Field values are converted to the column type, and values of the wrong type refused.
func TestFieldArgConvertsAndRejects(t *testing.T) {
	s := model.Field{Type: model.FieldString}
	b := model.Field{Type: model.FieldBool}
	i := model.Field{Type: model.FieldInt}
	tm := model.Field{Type: model.FieldTime}
	ok := []struct {
		f    model.Field
		in   any
		want any
	}{
		{s, nil, ""}, {s, "x", "x"},
		{b, nil, false}, {b, true, true},
		{i, nil, int64(0)}, {i, 3, int64(3)}, {i, int32(4), int64(4)}, {i, int64(5), int64(5)}, {i, uint32(6), int64(6)}, {i, uint64(7), int64(7)},
		{tm, nil, int64(0)}, {tm, time.Time{}, int64(0)}, {tm, time.UnixMicro(42), int64(42)},
	}
	for _, c := range ok {
		got, err := fieldArg(c.f, c.in)
		if err != nil || got != c.want {
			t.Errorf("fieldArg(%v, %#v) = %#v, %v; want %#v", c.f.Type, c.in, got, err, c.want)
		}
	}
	for _, c := range []struct {
		f  model.Field
		in any
	}{{s, 1}, {b, "t"}, {i, "1"}, {i, 1.5}, {tm, "now"}} {
		if _, err := fieldArg(c.f, c.in); err == nil {
			t.Errorf("fieldArg(%v, %#v) accepted a wrong type", c.f.Type, c.in)
		}
	}
	if fromMicros(0) != (time.Time{}) || !fromMicros(5).Equal(time.UnixMicro(5)) || fromMicros(5).Location() != time.UTC {
		t.Fatal("fromMicros")
	}
}
