package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
		`DROP INDEX "ix_user_part"`, `DROP INDEX "ix_user_parttomb"`, `DROP INDEX "ix_user_tomb"`, `ALTER TABLE "qsr_user" DROP COLUMN part`, `ALTER TABLE "qsr_user" DROP COLUMN pnum`,
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

// SQLite uses a partial index only for a query whose WHERE clause implies the index's, so every partition read says
// pseq > 0 outright: a bound lower bound such as pseq > ? implies it only when bound to 0 exactly, and a delta export
// (after sequence 5, say) or a check for an unfinished import would scan the whole table.
func TestPartitionReadsUseThePartialIndex(t *testing.T) {
	s, _ := openTest(t, "sqlite", "", 0)
	defer s.Close()
	tb := s.tables[model.KindUser]
	for name, q := range map[string]string{"export": tb.exportSQL, "above": tb.aboveSQL, "tombstones": tb.tombSQL, "gone": tb.goneSQL} {
		args := []any{1, 5, 10, 5, 5, ""}[:strings.Count(q, "?")] // the partition, after sequence 5, up to 10 (an export: from its first page)
		rows, err := s.wdb.Query("EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		if p := strings.Join(plan, "; "); !strings.Contains(p, "INDEX ix_user_part") {
			t.Errorf("%s uses no partition index: %s", name, p)
		}
	}
}

// An export reads a page to a statement (so a slow peer never holds one open), in (sequence, id) order: a sequence whose
// records span several pages is exported whole, each record once, and one at the export's lower bound not at all.
func TestExportPagesAcrossASequence(t *testing.T) {
	ctx := context.Background()
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		s, _ := openTest(t, d.name, d.env, 4)
		defer s.Close()
		apply := func(seq uint64, n int, prefix string) {
			recs := make([]*store.Record, n)
			for i := range recs {
				recs[i] = mustRec(t, "o", fmt.Sprintf("%s%04d", prefix, i))
			}
			if err := s.ApplyPartition(ctx, 2, recs, store.PartitionPos{Seq: seq}); err != nil {
				t.Fatal(err)
			}
		}
		apply(1, 3, "a")             // below the export's lower bound
		apply(2, 2*batchRows+1, "b") // one sequence over three pages
		apply(3, batchRows-1, "c")   // the rest of the third page, and a page that is exactly full
		seen := map[string]bool{}
		var last uint64
		err := s.ExportPartition(ctx, 2, 1, func(store.PartitionPos) error { return nil }, func(r store.PartitionRecord) error {
			if seen[r.ID] || r.Seq < last || r.Seq < 2 {
				t.Fatalf("exported %s at %d after %d (seen: %v)", r.ID, r.Seq, last, seen[r.ID])
			}
			seen[r.ID], last = true, r.Seq
			return nil
		})
		if want := 3 * batchRows; err != nil || len(seen) != want {
			t.Fatalf("exported %d records (%v), want %d", len(seen), err, want)
		}
	})
}
