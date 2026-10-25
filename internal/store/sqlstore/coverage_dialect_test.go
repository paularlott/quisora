package sqlstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
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

func TestCoverageNewDialect(t *testing.T) {
	for _, n := range []string{"sqlite", "postgres", "mysql", "mariadb"} {
		if d := mustDialect(t, n); d.name != n {
			t.Fatalf("%s: got %q", n, d.name)
		}
	}
	if _, err := newDialect("oracle"); err == nil || !strings.Contains(err.Error(), "unknown driver") {
		t.Fatalf("unknown driver: %v", err)
	}
	if _, err := Open(t.Context(), Config{Driver: "oracle"}); err == nil {
		t.Fatal("Open with an unknown driver succeeded")
	}
}

func TestCoverageDialectSQL(t *testing.T) {
	sq, pg, my, mdb := mustDialect(t, "sqlite"), mustDialect(t, "postgres"), mustDialect(t, "mysql"), mustDialect(t, "mariadb")

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

	str := model.Field{Name: "n", Type: model.FieldString}
	num := model.Field{Name: "c", Type: model.FieldInt}
	boo := model.Field{Name: "b", Type: model.FieldBool}
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

	if pg.sortExpr(str) != `LOWER("n") COLLATE "C"` || sq.sortExpr(str) != `LOWER("n")` || my.sortExpr(str) != "LOWER(`n`)" {
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
	if got := sq.sortIndexExpr(str); got != `LOWER("n")` {
		t.Fatal(got)
	}
	if got := mdb.sortIndexExpr(num); got != "`c`" {
		t.Fatal(got)
	}
	if ifNotExists(my) != "" || ifNotExists(mdb) != "IF NOT EXISTS " || ifNotExists(sq) != "IF NOT EXISTS " {
		t.Fatal("ifNotExists")
	}
	if tableSuffix(sq) != "" || !strings.Contains(tableSuffix(my), "ENGINE=InnoDB") || !strings.Contains(tableSuffix(mdb), "utf8mb4_nopad_bin") {
		t.Fatal("tableSuffix")
	}
	if uniqueSuffix(sq) != " WITHOUT ROWID" || uniqueSuffix(pg) != "" || uniqueSuffix(my) != tableSuffix(my) {
		t.Fatal("uniqueSuffix")
	}
}

func TestCoverageDialectErrors(t *testing.T) {
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

func TestCoverageFieldArg(t *testing.T) {
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

func TestCoverageSQLiteDSN(t *testing.T) {
	w := sqliteDSN("/x/y.db", true)
	r := sqliteDSN("file:/x/y.db?mode=ro", false)
	if !strings.HasPrefix(w, "/x/y.db?") || !strings.Contains(w, "_txlock=immediate") || strings.Contains(w, "query_only") {
		t.Fatal(w)
	}
	if !strings.HasPrefix(r, "file:/x/y.db?mode=ro&") || !strings.Contains(r, "query_only%281%29") || strings.Contains(r, "+") {
		t.Fatal(r)
	}
}

func TestCoverageOpenErrors(t *testing.T) {
	ctx := t.Context()
	if _, err := Open(ctx, Config{Driver: "sqlite"}); err == nil || !strings.Contains(err.Error(), "needs a DSN") {
		t.Fatalf("sqlite without DSN: %v", err)
	}
	if _, err := Open(ctx, Config{Driver: "sqlite", DSN: "/nonexistent-dir-qsr/x/y.db"}); err == nil {
		t.Fatal("sqlite in a missing directory opened")
	}
	if _, err := Open(ctx, Config{Driver: "postgres", DSN: "postgres://%zz"}); err == nil || !strings.Contains(err.Error(), "sqlstore: open") {
		t.Fatalf("bad postgres DSN: %v", err)
	}
	if _, err := Open(ctx, Config{Driver: "mysql", DSN: "not a dsn"}); err == nil || !strings.Contains(err.Error(), "sqlstore: open") {
		t.Fatalf("bad mysql DSN: %v", err)
	}
}

func TestCoverageOpenUnreachableServers(t *testing.T) {
	ctx := t.Context()
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	cases := []struct {
		name string
		cfg  Config
	}{
		{"pg", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=2"}},
		{"pg-pool-limits", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=disable", MaxOpenConns: 2, MaxIdleConns: 10}},
		{"pg-verify-full", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=verify-full", RootCAs: pool}},
		{"pg-require", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=require", RootCAs: pool}},
		{"pg-prefer", Config{Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=prefer", RootCAs: pool}},
		{"mysql", Config{Driver: "mysql", DSN: "u:p@tcp(127.0.0.1:1)/db"}},
		{"mariadb-ca", Config{Driver: "mariadb", DSN: "u:p@tcp(127.0.0.1:1)/db", RootCAs: pool, MaxOpenConns: 3}},
		{"mysql-ca-unix", Config{Driver: "mysql", DSN: "u:p@unix(/nonexistent.sock)/db", RootCAs: pool}},
		{"mysql-tls-custom", Config{Driver: "mysql", DSN: "u:p@tcp(127.0.0.1:1)/db?tls=skip-verify", RootCAs: pool}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := Open(ctx, c.cfg)
			if err == nil {
				s.Close()
				t.Fatal("opened a database that is not there")
			}
			if !strings.Contains(err.Error(), "sqlstore: connect") {
				t.Fatalf("expected a connect error, got: %v", err)
			}
		})
	}
}

func TestCoverageUseServerPool(t *testing.T) {
	s := &Store{d: mustDialect(t, "mysql")}
	db := openMem(t)
	defer db.Close()
	s.useServerPool(db, Config{MaxOpenConns: 0, MaxIdleConns: 0})
	if s.rdb != db || s.wdb != db || s.rc == nil || s.rc != s.wc {
		t.Fatal("pool wiring")
	}
	if got := db.Stats().MaxOpenConnections; got != 32 {
		t.Fatalf("default max open: %d", got)
	}
	s.useServerPool(db, Config{MaxOpenConns: 4, MaxIdleConns: 9})
	if got := db.Stats().MaxOpenConnections; got != 4 {
		t.Fatalf("max open: %d", got)
	}
}

func TestCoverageFallbackTLS(t *testing.T) {
	pc, err := pgx.ParseConfig("postgres://u:p@127.0.0.1:1/db?sslmode=prefer")
	if err != nil {
		t.Fatal(err)
	}
	got := fallbackTLS(pc)
	if len(got) != len(pc.Fallbacks) {
		t.Fatalf("fallbacks: %d vs %d", len(got), len(pc.Fallbacks))
	}
	pc, err = pgx.ParseConfig("postgres://u:p@127.0.0.1:1/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if got := fallbackTLS(pc); len(got) != 0 {
		t.Fatalf("no fallbacks expected: %d", len(got))
	}
}

func TestCoverageVerifyChain(t *testing.T) {
	mk := func(tmpl, parent *x509.Certificate, pk, parentKey *ecdsa.PrivateKey) *x509.Certificate {
		if parent == nil {
			parent, parentKey = tmpl, pk
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &pk.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now()
	tmpl := func(n int64, cn string, ca bool) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: ca, BasicConstraintsValid: true,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
	}
	rk, ik, lk, ok := key(), key(), key(), key()
	root := mk(tmpl(1, "root", true), nil, rk, nil)
	inter := mk(tmpl(2, "inter", true), root, ik, rk)
	leaf := mk(tmpl(3, "leaf", false), inter, lk, ik)
	other := mk(tmpl(4, "other", true), nil, ok, nil)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	verify := verifyChain(roots)

	if err := verify([][]byte{leaf.Raw, inter.Raw}, nil); err != nil {
		t.Fatalf("valid chain: %v", err)
	}
	if err := verify([][]byte{leaf.Raw}, nil); err == nil {
		t.Fatal("chain without its intermediate verified")
	}
	if err := verify([][]byte{other.Raw}, nil); err == nil {
		t.Fatal("certificate from another CA verified")
	}
	if err := verify(nil, nil); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatalf("empty chain: %v", err)
	}
	if err := verify([][]byte{[]byte("garbage")}, nil); err == nil {
		t.Fatal("garbage certificate verified")
	}
}
