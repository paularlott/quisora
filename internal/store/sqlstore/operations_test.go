package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A kind with no table (each kind has its own) is not found by the reads and refused by the writes.
func TestUnknownKindIsRejectedByEveryOperation(t *testing.T) {
	s, _ := openSQLite(t)
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
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	if _, err := snap.Count(ctx, "nope", ""); err == nil {
		t.Fatal("snapshot count of an unknown kind")
	}
}

func TestVersionBeyondInt64IsRefused(t *testing.T) {
	s, _ := openSQLite(t)
	rec := record(model.KindLink, "a", time.Time{})
	rec.Version = 1 << 63 // a replicated record keeps its version; Put and CompareAndPut stamp their own
	if _, err := s.PutReplicated(context.Background(), rec); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("version beyond int64: %v", err)
	}
}

// Every operation on a closed store fails with an error instead of panicking or returning data; closing again is
// harmless.
func TestOperationsOnClosedStoreFail(t *testing.T) {
	s, _ := openSQLite(t)
	ctx := context.Background()
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{}, "u1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rec := record(model.KindLink, "b", time.Time{}, "u2")
	checks := map[string]func() error{
		"Get":       func() error { _, err := s.Get(ctx, model.KindLink, "a"); return err },
		"Lookup":    func() error { _, err := s.Lookup(ctx, model.KindLink, "a"); return err },
		"ByUnique":  func() error { _, err := s.GetByUnique(ctx, model.KindLink, "u1"); return err },
		"List":      func() error { _, err := s.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"}); return err },
		"Count":     func() error { _, err := s.Count(ctx, model.KindLink, "sc"); return err },
		"Put":       func() error { return s.Put(ctx, rec) },
		"CAS":       func() error { return s.CompareAndPut(ctx, rec, 0) },
		"Replicate": func() error { _, err := s.PutReplicated(ctx, rec); return err },
		"Purge":     func() error { _, err := s.Purge(ctx, time.Now(), time.Now()); return err },
		"Wipe":      func() error { return s.Wipe(ctx) },
		"Snapshot":  func() error { _, err := s.Snapshot(ctx); return err },
	}
	for name, f := range checks {
		if err := f(); err == nil {
			t.Errorf("%s on a closed store succeeded", name)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Purge removes expired records and releases their unique values, in batches past 500 rows. Until then an expired
// record is invisible but its unique value stays stored.
func TestPurgeReleasesExpiredUniqueValues(t *testing.T) {
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	t.Run("FewRows", func(t *testing.T) {
		s, _ := openSQLite(t)
		if err := s.Put(ctx, record(model.KindLink, "old", past, "t/old")); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, record(model.KindLink, "keep", future, "t/keep")); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, record(model.KindLink, "plain", past)); err != nil {
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
		if err := s.Put(ctx, record(model.KindLink, "new", future, "t/old")); err != nil {
			t.Fatalf("reuse of a released unique value: %v", err)
		}
	})
	t.Run("ManyRows", func(t *testing.T) {
		s, _ := openSQLite(t)
		const n = 501 // one more than a sweep's 500 rows
		for i := range n {
			id := fmt.Sprintf("r%03d", i)
			if err := s.Put(ctx, record(model.KindLink, id, past, "t/"+id)); err != nil {
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
	})
}

// A tombstone is purged only once it is older than the cutoff; a zero cutoff purges nothing.
func TestPurgeHonoursTombstoneCutoff(t *testing.T) {
	s, _ := openSQLite(t)
	ctx := context.Background()
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{}, "t/a")); err != nil {
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

func TestCanceledContextFailsOperations(t *testing.T) {
	s, _ := openSQLite(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{})); err == nil {
		t.Fatal("Put with a canceled context")
	}
	if _, err := s.Get(ctx, model.KindLink, "a"); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get with a canceled context: %v", err)
	}
	if _, err := s.Purge(ctx, time.Now(), time.Now()); err == nil {
		t.Fatal("Purge with a canceled context")
	}
	if err := s.Wipe(ctx); err == nil {
		t.Fatal("Wipe with a canceled context")
	}
}

// GetMany reads ids in batches of 500 and returns the records in the order asked, an id asked twice (in two batches)
// twice, a missing one left out.
func TestGetManyKeepsInputOrderAcrossBatches(t *testing.T) {
	s, _ := openSQLite(t)
	ctx := context.Background()
	const n = getManyBatch + 1
	recs := make([]*store.Record, n)
	for i := range n {
		recs[i] = userRecord(t, &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: fmt.Sprintf("user-%04d", i)})
		if err := s.Put(ctx, recs[i]); err != nil {
			t.Fatal(err)
		}
	}
	ids := make([]string, 0, n+2)
	for i := n - 1; i >= 0; i-- {
		ids = append(ids, recs[i].ID)
	}
	ids = append(ids, "missing", recs[n-1].ID) // recs[n-1] is first in the first batch and last in the second
	got, err := s.GetMany(ctx, model.KindUser, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n+1 {
		t.Fatalf("got %d records, expected %d", len(got), n+1)
	}
	for i := range n {
		if got[i].ID != recs[n-1-i].ID {
			t.Fatalf("wrong record at input position %d", i)
		}
	}
	if got[n].ID != recs[n-1].ID {
		t.Fatal("duplicate ID not preserved across batches")
	}
}

// A record whose stored unique values cannot be decoded is an error to read and to overwrite, as on the key-value
// stores: read as having none, a write would leave its unique values claimed for ever.
func TestCorruptUniqueValuesAreAnError(t *testing.T) {
	s, _ := openSQLite(t)
	ctx := context.Background()
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{}, "u/a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wdb.ExecContext(ctx, "UPDATE "+s.tables[model.KindLink].name+" SET uniq = 'not json' WHERE id = 'a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, model.KindLink, "a"); err == nil || !strings.Contains(err.Error(), "unique values") {
		t.Fatalf("Get: %v", err)
	}
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{})); err == nil {
		t.Fatal("overwrite of a record with corrupt unique values succeeded")
	}
}

// The request id comes back from every read, and is kept by the write paths that take a record as it is.
func TestRequestIDIsReadEverywhere(t *testing.T) {
	s, _ := openSQLite(t)
	ctx := context.Background()
	a := record(model.KindLink, "a", time.Time{}, "u/a")
	a.Req = "set-by-put"
	if err := s.Put(ctx, a); err != nil {
		t.Fatal(err)
	}

	b := record(model.KindLink, "b", time.Time{}, "u/b")
	b.Req = "set-by-writer"
	if applied, err := s.PutReplicated(ctx, b); err != nil || !applied {
		t.Fatalf("PutReplicated: %v %v", applied, err)
	}
	c := record(model.KindLink, "c", time.Time{})
	if applied, err := s.PutReplicated(ctx, c); err != nil || !applied {
		t.Fatalf("PutReplicated: %v %v", applied, err)
	}
	if c.Req != "" {
		t.Fatalf("PutReplicated gave a request id: %q", c.Req)
	}
	want := map[string]string{"a": a.Req, "b": "set-by-writer", "c": ""}
	for id, req := range want {
		for name, read := range map[string]func() (*store.Record, error){
			"Get":    func() (*store.Record, error) { return s.Get(ctx, model.KindLink, id) },
			"Lookup": func() (*store.Record, error) { return s.Lookup(ctx, model.KindLink, id) },
		} {
			if r, err := read(); err != nil || r.Req != req {
				t.Fatalf("%s of %s: %q %v, want %q", name, id, r.Req, err, req)
			}
		}
	}
	if r, err := s.GetByUnique(ctx, model.KindLink, "u/a"); err != nil || r.Req != a.Req {
		t.Fatalf("GetByUnique: %+v %v", r, err)
	}
	many, err := s.GetMany(ctx, model.KindLink, []string{"b", "a"})
	if err != nil || len(many) != 2 || many[0].Req != "set-by-writer" || many[1].Req != a.Req {
		t.Fatalf("GetMany: %+v %v", many, err)
	}
	res, err := s.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"})
	if err != nil || len(res.Records) != 3 || res.Records[0].Req != a.Req {
		t.Fatalf("List: %+v %v", res, err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	if res, err := snap.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"}); err != nil || res.Records[1].Req != "set-by-writer" {
		t.Fatalf("snapshot List: %+v %v", res, err)
	}
}

// Transactions racing for one unique value: exactly one wins, the others are refused whole (nothing of theirs is
// stored), and a deadlock between them is retried, not reported.
func TestConcurrentTransactionsOnOneUniqueValue(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		s, _ := openTest(t, d.name, d.env, 0)
		defer s.Close()
		ctx := context.Background()
		var wg sync.WaitGroup
		var won, conflicts atomic.Int32
		for i := range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				a := record(model.KindLink, fmt.Sprintf("a%d", i), time.Time{}, "u/shared")
				b := record(model.KindLink, fmt.Sprintf("b%d", i), time.Time{}, fmt.Sprintf("u/own%d", i))
				ops := []store.Op{{Rec: a, Match: true}, {Rec: b, Match: true}}
				if i%2 == 1 {
					ops[0], ops[1] = ops[1], ops[0]
				}
				switch err := s.Tx(ctx, ops); {
				case err == nil:
					won.Add(1)
				case errors.Is(err, store.ErrConflict):
					conflicts.Add(1)
				default:
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if won.Load() != 1 || conflicts.Load() != 15 {
			t.Fatalf("won %d, conflicts %d", won.Load(), conflicts.Load())
		}
		if n, err := s.Count(ctx, model.KindLink, "sc"); err != nil || n != 2 {
			t.Fatalf("%d records stored, want the winner's two: %v", n, err)
		}
	})
}
