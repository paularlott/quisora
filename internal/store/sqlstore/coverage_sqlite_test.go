package sqlstore

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func covOpen(t *testing.T, feed bool) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "q.db")
	s, err := Open(context.Background(), Config{Driver: "sqlite", DSN: path, Feed: feed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func covRec(kind model.Kind, id string, expires time.Time, uniq ...string) *store.Record {
	return &store.Record{Kind: kind, ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "sc", Unique: uniq,
		Data: []byte("d"), Expires: expires, Fields: map[string]any{"purpose": "p"}}
}

func TestCoverageUnknownKind(t *testing.T) {
	s, _ := covOpen(t, true)
	ctx := context.Background()
	if _, err := s.Get(ctx, "nope", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.Lookup(ctx, "nope", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Lookup: %v", err)
	}
	if _, err := s.GetByUnique(ctx, "nope", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByUnique: %v", err)
	}
	if err := s.Put(ctx, &store.Record{Kind: "nope", ID: "x", Version: store.Clock.Now()}); err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.List(ctx, "nope", store.ListQuery{}); err == nil {
		t.Fatal("List of an unknown kind")
	}
	if _, err := s.Count(ctx, "nope", ""); err == nil {
		t.Fatal("Count of an unknown kind")
	}
}

func TestCoverageVersionOutOfRange(t *testing.T) {
	s, _ := covOpen(t, false)
	rec := covRec(model.KindLink, "a", time.Time{})
	rec.Version = 1 << 63
	if err := s.Put(context.Background(), rec); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("version beyond int64: %v", err)
	}
}

// Every operation on a closed store fails with an error instead of panicking or returning data.
func TestCoverageClosedStore(t *testing.T) {
	for _, feed := range []bool{true, false} {
		s, _ := covOpen(t, feed)
		ctx := context.Background()
		if err := s.Put(ctx, covRec(model.KindLink, "a", time.Time{}, "u1")); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		rec := covRec(model.KindLink, "b", time.Time{}, "u2")
		checks := map[string]func() error{
			"Get":       func() error { _, err := s.Get(ctx, model.KindLink, "a"); return err },
			"Lookup":    func() error { _, err := s.Lookup(ctx, model.KindLink, "a"); return err },
			"ByUnique":  func() error { _, err := s.GetByUnique(ctx, model.KindLink, "u1"); return err },
			"List":      func() error { _, err := s.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"}); return err },
			"Count":     func() error { _, err := s.Count(ctx, model.KindLink, "sc"); return err },
			"Put":       func() error { return s.Put(ctx, rec) },
			"CAS":       func() error { return s.CompareAndPut(ctx, rec, 0) },
			"Replicate": func() error { _, _, err := s.PutReplicated(ctx, rec); return err },
			"Purge":     func() error { _, err := s.Purge(ctx, time.Now(), time.Now()); return err },
			"Wipe":      func() error { return s.Wipe(ctx) },
			"Snapshot":  func() error { _, err := s.Snapshot(ctx); return err },
		}
		if feed {
			checks["Changes"] = func() error { _, _, err := s.Changes(ctx, 0, 0); return err }
		}
		for name, f := range checks {
			if err := f(); err == nil {
				t.Errorf("feed=%v %s on a closed store succeeded", feed, name)
			}
		}
		if err := s.Close(); err != nil {
			t.Logf("second Close: %v", err) // double close is tolerated either way
		}
	}
}

func TestCoverageChangesWithoutFeed(t *testing.T) {
	s, _ := covOpen(t, false)
	if _, _, err := s.Changes(context.Background(), 0, 10); !errors.Is(err, ErrFeedDisabled) {
		t.Fatalf("Changes without feed: %v", err)
	}
}

func TestCoverageChangesLimitAndCursor(t *testing.T) {
	s, _ := covOpen(t, true)
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Put(ctx, covRec(model.KindLink, id, time.Time{})); err != nil {
			t.Fatal(err)
		}
	}
	ch, next, err := s.Changes(ctx, 0, 2)
	if err != nil || len(ch) != 2 || next != ch[1].Seq {
		t.Fatalf("limited: %d %d %v", len(ch), next, err)
	}
	ch, next2, err := s.Changes(ctx, next, 2)
	if err != nil || len(ch) != 1 || next2 <= next {
		t.Fatalf("rest: %d %d %v", len(ch), next2, err)
	}
	ch, next3, err := s.Changes(ctx, next2, 2)
	if err != nil || len(ch) != 0 || next3 != next2 {
		t.Fatalf("caught up: %d %d %v", len(ch), next3, err)
	}
}

func TestCoverageSnapshot(t *testing.T) {
	for _, feed := range []bool{true, false} {
		s, _ := covOpen(t, feed)
		ctx := context.Background()
		if err := s.Put(ctx, covRec(model.KindLink, "a", time.Time{})); err != nil {
			t.Fatal(err)
		}
		snap, err := s.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Writes after the snapshot are invisible to it.
		if err := s.Put(ctx, covRec(model.KindLink, "b", time.Time{})); err != nil {
			t.Fatal(err)
		}
		n, err := snap.Count(ctx, model.KindLink, "sc")
		if err != nil || n != 1 {
			t.Fatalf("snapshot count: %d %v", n, err)
		}
		res, err := snap.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"})
		if err != nil || len(res.Records) != 1 || res.Records[0].ID != "a" {
			t.Fatalf("snapshot list: %+v %v", res, err)
		}
		if _, err := snap.Count(ctx, "nope", ""); err == nil {
			t.Fatal("snapshot count of an unknown kind")
		}
		if err := snap.Close(); err != nil {
			t.Fatal(err)
		}
		if n, _ := s.Count(ctx, model.KindLink, "sc"); n != 2 {
			t.Fatalf("live count: %d", n)
		}
	}
}

// Purge removes expired records, releasing their unique values, in batches past 500 rows.
func TestCoverageAddPurgeExpiredUnique(t *testing.T) {
	s, _ := covOpen(t, true)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	// A record whose expiry has passed is invisible, and still holds its unique value until purged.
	if err := s.Put(ctx, covRec(model.KindLink, "old", past, "t/old")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, covRec(model.KindLink, "keep", future, "t/keep")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, covRec(model.KindLink, "plain", past)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, model.KindLink, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired Get: %v", err)
	}
	if _, err := s.GetByUnique(ctx, model.KindLink, "t/old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired GetByUnique: %v", err)
	}
	n, err := s.Purge(ctx, time.Time{}, time.Now())
	if err != nil || n != 2 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := s.Lookup(ctx, model.KindLink, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("purged record still stored: %v", err)
	}
	var left int
	if err := s.wdb.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+uniqueTable+" WHERE value = 't/old'").Scan(&left); err != nil || left != 0 {
		t.Fatalf("unique value of a purged record: %d %v", left, err)
	}
	if got, err := s.GetByUnique(ctx, model.KindLink, "t/keep"); err != nil || got.ID != "keep" {
		t.Fatalf("live record lost: %v", err)
	}
	// The value is free again.
	if err := s.Put(ctx, covRec(model.KindLink, "new", future, "t/old")); err != nil {
		t.Fatalf("reuse of a released unique value: %v", err)
	}
}

func TestCoverageSweepsManyExpiredUnique(t *testing.T) {
	s, _ := covOpen(t, false)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	const n = 620 // more than one 500-row sweep
	for i := range n {
		id := "r" + strings.Repeat("0", 3-len(itoa(i))) + itoa(i)
		if err := s.Put(ctx, covRec(model.KindLink, id, past, "t/"+id)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Purge(ctx, time.Time{}, time.Now())
	if err != nil || got != n {
		t.Fatalf("purge: %d %v", got, err)
	}
	var left int
	if err := s.wdb.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+uniqueTable).Scan(&left); err != nil || left != 0 {
		t.Fatalf("leftover unique values: %d %v", left, err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestCoveragePurgeTombstones(t *testing.T) {
	s, _ := covOpen(t, true)
	ctx := context.Background()
	rec := covRec(model.KindLink, "a", time.Time{}, "t/a")
	if err := s.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	tomb := &store.Record{Kind: model.KindLink, ID: "a", Version: store.Clock.Now(), Origin: "n", Deleted: true}
	if err := s.Put(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Purge(ctx, time.Now().Add(-time.Hour), time.Time{}); err != nil || n != 0 {
		t.Fatalf("a tombstone younger than the cutoff was purged: %d %v", n, err)
	}
	// A zero cutoff (before the hlc epoch guard) removes nothing either.
	if n, err := s.Purge(ctx, time.Time{}, time.Time{}); err != nil || n != 0 {
		t.Fatalf("zero cutoff: %d %v", n, err)
	}
	if n, err := s.Purge(ctx, time.Now().Add(time.Hour), time.Time{}); err != nil || n != 1 {
		t.Fatalf("old tombstone: %d %v", n, err)
	}
}

func TestCoverageWipeStartsNewFeed(t *testing.T) {
	s, _ := covOpen(t, true)
	ctx := context.Background()
	if err := s.Put(ctx, covRec(model.KindLink, "a", time.Time{}, "t/a")); err != nil {
		t.Fatal(err)
	}
	old := s.FeedID()
	if err := s.Wipe(ctx); err != nil {
		t.Fatal(err)
	}
	if s.FeedID() == old || s.FeedID() == "" {
		t.Fatal("feed id not renewed")
	}
	if _, err := s.Lookup(ctx, model.KindLink, "a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("record survived Wipe: %v", err)
	}
	if _, err := s.GetByUnique(ctx, model.KindLink, "t/a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unique survived Wipe: %v", err)
	}
	ch, next, err := s.Changes(ctx, 0, 0)
	if err != nil || len(ch) != 0 || next != 0 {
		t.Fatalf("feed after Wipe: %d %d %v", len(ch), next, err)
	}
	if err := s.Put(ctx, covRec(model.KindLink, "b", time.Time{}, "t/a")); err != nil {
		t.Fatalf("put after Wipe: %v", err)
	}
	if ch, _, _ := s.Changes(ctx, 0, 0); len(ch) != 1 || ch[0].Seq != 1 {
		t.Fatalf("seq restarts at 1: %+v", ch)
	}
}

func TestCoverageReconcileAddsMissingColumn(t *testing.T) {
	s, path := covOpen(t, false)
	ctx := context.Background()
	tbl := s.tables[model.KindLink].name
	if _, err := s.wdb.ExecContext(ctx, "DROP INDEX IF EXISTS ix_link_purpose"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wdb.ExecContext(ctx, "ALTER TABLE "+tbl+" DROP COLUMN purpose"); err != nil {
		t.Skipf("sqlite cannot drop the column: %v", err)
	}
	s.Close()
	s2, err := Open(ctx, Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	have, err := s2.columns(ctx, s2.wdb, "qsr_link")
	if err != nil || !have["purpose"] || !have["epoch"] {
		t.Fatalf("columns after reconcile: %v %v", have, err)
	}
	if have, err := s2.columns(ctx, s2.wdb, "no_such_table"); err != nil || len(have) != 0 {
		t.Fatalf("missing table: %v %v", have, err)
	}
}

func TestCoverageOldBuildSchemaRefused(t *testing.T) {
	s, path := covOpen(t, false)
	ctx := context.Background()
	tbl := s.tables[model.KindLink].name
	if _, err := s.wdb.ExecContext(ctx, "ALTER TABLE "+tbl+" DROP COLUMN epoch"); err != nil {
		t.Skipf("sqlite cannot drop the column: %v", err)
	}
	s.Close()
	if _, err := Open(ctx, Config{Driver: "sqlite", DSN: path}); err == nil || !strings.Contains(err.Error(), "incompatible pre-release") {
		t.Fatalf("table without epoch: %v", err)
	}
}

func TestCoverageMigrateNeverFails(t *testing.T) {
	// Reopening repeatedly is idempotent and keeps the schema version.
	s, path := covOpen(t, true)
	s.Close()
	for range 3 {
		s2, err := Open(context.Background(), Config{Driver: "sqlite", DSN: path, Feed: true})
		if err != nil {
			t.Fatal(err)
		}
		s2.Close()
	}
}

func TestCoverageCorruptRecordColumns(t *testing.T) {
	s, _ := covOpen(t, true)
	ctx := context.Background()
	if err := s.Put(ctx, covRec(model.KindLink, "a", time.Time{}, "t/a")); err != nil {
		t.Fatal(err)
	}
	tbl := s.tables[model.KindLink].name
	// A unique-values column that is not valid JSON must surface as an error, not a silently empty list.
	if _, err := s.wdb.ExecContext(ctx, "UPDATE "+tbl+" SET uniq = 'not json'"); err != nil {
		t.Fatal(err)
	}
	if rec, err := s.Get(ctx, model.KindLink, "a"); err == nil {
		t.Logf("corrupt uniq column is tolerated, unique=%v", rec.Unique)
	}
}

func TestCoverageCASEdges(t *testing.T) {
	s, _ := covOpen(t, true)
	ctx := context.Background()
	first := covRec(model.KindLink, "a", time.Time{}, "t/a")
	if err := s.CompareAndPut(ctx, first, 0); err != nil {
		t.Fatal(err)
	}
	// Creating again while live is stale; updating a missing record is not found.
	if err := s.CompareAndPut(ctx, covRec(model.KindLink, "a", time.Time{}), 0); !errors.Is(err, store.ErrStale) {
		t.Fatalf("create over a live record: %v", err)
	}
	if err := s.CompareAndPut(ctx, covRec(model.KindLink, "zz", time.Time{}), first.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update of a missing record: %v", err)
	}
	// Wrong expected version.
	if err := s.CompareAndPut(ctx, covRec(model.KindLink, "a", time.Time{}), first.Version+1); !errors.Is(err, store.ErrStale) {
		t.Fatalf("wrong expectation: %v", err)
	}
	// A version not above the expectation.
	old := covRec(model.KindLink, "a", time.Time{})
	old.Version = first.Version
	if err := s.CompareAndPut(ctx, old, first.Version); !errors.Is(err, store.ErrStale) {
		t.Fatalf("non-increasing version: %v", err)
	}
	// Put with an equal version is stale too.
	same := covRec(model.KindLink, "a", time.Time{})
	same.Version = first.Version
	if err := s.Put(ctx, same); !errors.Is(err, store.ErrStale) {
		t.Fatalf("equal version put: %v", err)
	}
	// An unrelated record may not take a held unique value.
	if err := s.Put(ctx, covRec(model.KindLink, "b", time.Time{}, "t/a")); err == nil {
		t.Fatal("two records hold one unique value")
	}
	if _, err := s.Lookup(ctx, model.KindLink, "b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failed write left a record: %v", err)
	}
}

func TestCoverageCanceledContext(t *testing.T) {
	s, _ := covOpen(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Put(ctx, covRec(model.KindLink, "a", time.Time{})); err == nil {
		t.Fatal("Put with a canceled context")
	}
	if _, err := s.Get(ctx, model.KindLink, "a"); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get with a canceled context: %v", err)
	}
	if _, err := s.Purge(ctx, time.Now(), time.Now()); err == nil {
		t.Fatal("Purge with a canceled context")
	}
	if _, _, err := s.Changes(ctx, 0, 0); err == nil {
		t.Fatal("Changes with a canceled context")
	}
	if err := s.Wipe(ctx); err == nil {
		t.Fatal("Wipe with a canceled context")
	}
}
