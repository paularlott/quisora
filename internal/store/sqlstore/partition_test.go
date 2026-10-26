package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

// partFactory opens stores for the partition suite with a small pool: the suite opens a database per test, and a server's
// default pool of 32 connections each would wear out the machine's ephemeral ports.
func partFactory(name, env string) storetest.Factory {
	return func(t testing.TB) store.Store {
		s, _ := openTest(t, name, env, 4)
		return s
	}
}

func TestPartition(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) { storetest.RunPartition(t, partFactory(d.name, d.env)) })
}

func TestPartitionDurable(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		storetest.RunPartitionDurable(t, func(t testing.TB) *storetest.Durable {
			s, dsn := openTest(t, d.name, d.env, 4)
			cur := s
			open := func(dsn string) *Store {
				n, err := Open(context.Background(), Config{Driver: d.name, DSN: dsn, MaxOpenConns: 4})
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
			du := &storetest.Durable{Store: s}
			du.Reopen = func() store.Store {
				cur.Close()
				cur = open(dsn)
				return cur
			}
			if d.name == "sqlite" {
				du.Crash = func() store.Store {
					img := filepath.Join(t.TempDir(), "quisora.db")
					for _, suffix := range []string{"", "-wal"} { // not the shared-memory index: a crash leaves it unusable
						copyFile(t, dsn+suffix, img+suffix)
					}
					n := open(img)
					t.Cleanup(func() { n.Close() })
					return n
				}
			}
			t.Cleanup(func() { cur.Close() })
			return du
		})
	})
}

func copyFile(t testing.TB, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
}

// How the partition writes commit, per database: unsynced for applies, imports and purges, synced for the state writes,
// and the SQLite connection always back at FULL afterwards.
func TestPartitionSyncMode(t *testing.T) {
	ctx := context.Background()
	// SQLite and PostgreSQL have a per-transaction setting; the MySQL family is always durable
	forEachDialect(t, dialects[:2], func(t *testing.T, d testDialect) {
		s, _ := openTest(t, d.name, d.env, 4)
		defer s.Close()
		var mu sync.Mutex
		var seen []string
		partitionTxHook = func(ctx context.Context, tx *sql.Tx, unsynced bool) {
			var v string
			var err error
			if d.name == "sqlite" {
				var n int
				err = tx.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&n)
				v = map[int]string{0: "off", 1: "normal", 2: "full"}[n]
			} else {
				err = tx.QueryRowContext(ctx, "SHOW synchronous_commit").Scan(&v)
			}
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if unsynced {
				seen = append(seen, "unsynced:"+v)
			} else {
				seen = append(seen, "synced:"+v)
			}
		}
		defer func() { partitionTxHook = nil }()
		u, _ := store.Encode(&model.User{OrgID: "o", Username: "sm", Role: model.RoleUser})
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(s.ApplyPartition(ctx, 1, []*store.Record{u}, store.PartitionPos{Seq: 1}))
		must(s.SetPartitionPending(ctx, 1, 2, []byte("x")))
		must(s.ImportPartition(ctx, 1, nil, store.PartitionPos{Seq: 3}, store.ImportStep{First: true, Final: true}))
		_, err := s.PurgePartition(ctx, 1, 2)
		must(err)
		must(s.SetPartitionPromised(ctx, 1, store.PartitionEpoch{Counter: 1}))
		mu.Lock()
		got := append([]string(nil), seen...)
		mu.Unlock()
		off, on := "unsynced:normal", "synced:full"
		if d.name == "postgres" {
			off, on = "unsynced:off", "synced:"+got[1][len("synced:"):] // the server's own setting
		}
		want := []string{off, on, off, off, on}
		for i := range want {
			if i >= len(got) || got[i] != want[i] {
				t.Fatalf("commit modes: %v, want %v", got, want)
			}
		}
		if d.name == "sqlite" { // the writer connection is back at FULL
			var n int
			if err := s.wdb.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&n); err != nil || n != 2 {
				t.Fatalf("writer synchronous after a partition write: %d %v", n, err)
			}
			// ... and an ordinary write is not unsynced either
			partitionTxHook = nil
			must(s.Put(ctx, mustRec(t, "o", "after")))
			if err := s.wdb.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&n); err != nil || n != 2 {
				t.Fatalf("writer synchronous after a put: %d %v", n, err)
			}
		}
	})
}

func mustRec(t testing.TB, org, name string) *store.Record {
	t.Helper()
	r, err := store.Encode(&model.User{OrgID: org, Username: name, Role: model.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A write that fails changes nothing, not the records before the failing one nor the position.
func TestPartitionApplyFailureChangesNothing(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t, "sqlite", "", 0)
	defer s.Close()
	good := mustRec(t, "o", "good")
	bad := &store.Record{Kind: model.Kind("no-such-kind"), ID: "x", Version: store.Clock.Now()}
	if err := s.ApplyPartition(ctx, 2, []*store.Record{good, bad}, store.PartitionPos{Seq: 1}); err == nil {
		t.Fatal("a record of an unknown kind was accepted")
	}
	if _, err := s.Get(ctx, model.KindUser, good.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("part of a failed write was kept")
	}
	if st, _ := s.PartitionState(ctx, 2); st.Committed.Seq != 0 {
		t.Fatalf("a failed write moved the position: %+v", st.Committed)
	}
}

// A database made before the partition columns and state table existed gains them at open.
func TestPartitionSchemaUpgrade(t *testing.T) {
	ctx := context.Background()
	s, dsn := openTest(t, "sqlite", "", 0)
	for _, stmt := range []string{
		`DROP INDEX "ix_user_part"`, `DROP INDEX "ix_user_parttomb"`, `ALTER TABLE "qsr_user" DROP COLUMN part`, `ALTER TABLE "qsr_user" DROP COLUMN pnum`,
		`ALTER TABLE "qsr_user" DROP COLUMN pseq`, `DROP TABLE qsr_partition`,
	} {
		if _, err := s.wdb.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	s.Close()
	s, err := Open(ctx, Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u := mustRec(t, "o", "upgraded")
	if err := s.ApplyPartition(ctx, 1, []*store.Record{u}, store.PartitionPos{Seq: 4}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.ExportPartition(ctx, 1, 0, func(store.PartitionPos) error { return nil }, func(r store.PartitionRecord) error {
		n++
		if r.Seq != 4 || r.Partition != "o" {
			t.Errorf("exported %+v seq %d", r.Record, r.Seq)
		}
		return nil
	}); err != nil || n != 1 {
		t.Fatalf("export after the upgrade: %d %v", n, err)
	}
}
