package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Writes that share a commit keep their own outcomes: a refused one (a held unique value, a stale version) leaves nothing
// behind and does not touch the others, and the ones that succeed are all stored.
func TestGroupCommitKeepsEachWritesOutcome(t *testing.T) {
	s, _ := openSQLite(t)
	ctx := context.Background()
	shared := record(model.KindLink, "shared", time.Time{}, "u/shared")
	if err := s.Put(ctx, shared); err != nil {
		t.Fatal(err)
	}
	const writers, rounds = 48, 25
	var conflicts, stale atomic.Int32
	var wg sync.WaitGroup
	for g := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range rounds {
				own := record(model.KindLink, fmt.Sprintf("own-%d-%d", g, i), time.Time{}, fmt.Sprintf("u/own-%d-%d", g, i))
				if err := s.Put(ctx, own); err != nil {
					t.Errorf("own record: %v", err)
				}
				// Refused after its own unique value was claimed: the claim must be undone with the write.
				dup := record(model.KindLink, fmt.Sprintf("dup-%d-%d", g, i), time.Time{}, fmt.Sprintf("u/dup-%d-%d", g, i), "u/shared")
				if err := s.Put(ctx, dup); errors.Is(err, store.ErrConflict) {
					conflicts.Add(1)
				} else {
					t.Errorf("a held unique value: %v", err)
				}
				old := record(model.KindLink, "shared", time.Time{}, "u/shared")
				if err := s.CompareAndPut(ctx, old, 1); errors.Is(err, store.ErrStale) {
					stale.Add(1)
				} else {
					t.Errorf("a stale version: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	if conflicts.Load() != writers*rounds || stale.Load() != writers*rounds {
		t.Fatalf("refusals: %d conflicts, %d stale; want %d each", conflicts.Load(), stale.Load(), writers*rounds)
	}
	for g := range writers {
		for i := range rounds {
			if _, err := s.Get(ctx, model.KindLink, fmt.Sprintf("own-%d-%d", g, i)); err != nil {
				t.Fatalf("own-%d-%d: %v", g, i, err)
			}
			if _, err := s.Lookup(ctx, model.KindLink, fmt.Sprintf("dup-%d-%d", g, i)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a refused write is stored: %v", err)
			}
		}
	}
	var held int
	if err := s.rdb.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+uniqueTable+" WHERE value LIKE 'u/dup-%'").Scan(&held); err != nil || held != 0 {
		t.Fatalf("%d unique values of refused writes are held: %v", held, err)
	}
	if got, err := s.GetByUnique(ctx, model.KindLink, "u/shared"); err != nil || got.ID != "shared" || got.Version != shared.Version {
		t.Fatalf("the shared record: %v %+v", err, got)
	}
}

// A caller whose context ends while its write is still queued gets the context's error and the write is skipped.
func TestGroupCommitSkipsAWriteItsCallerLeft(t *testing.T) {
	s, _ := openSQLite(t)
	ctx := context.Background()
	hold, err := s.wdb.Conn(ctx) // the writer connection: no commit can begin
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err := s.Put(short, record(model.KindLink, "left", time.Time{})); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a write that waited too long: %v", err)
	}
	hold.Close()
	if err := s.Put(ctx, record(model.KindLink, "next", time.Time{})); err != nil { // the committer works on
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, model.KindLink, "left"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the abandoned write was applied: %v", err)
	}
}

// Closing the store commits what was queued, answers the rest with an error and never leaves a caller waiting: every write
// that was acknowledged is in the database when it is opened again.
func TestGroupCommitClose(t *testing.T) {
	s, dsn := openTest(t, "sqlite", "", 0)
	ctx := context.Background()
	var mu sync.Mutex
	var acked []string
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				id := fmt.Sprintf("w-%d-%d", g, i)
				err := s.Put(ctx, record(model.KindLink, id, time.Time{}))
				if err != nil {
					return
				}
				mu.Lock()
				acked = append(acked, id)
				mu.Unlock()
			}
		}()
	}
	for {
		mu.Lock()
		n := len(acked)
		mu.Unlock()
		if n >= 200 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	again, err := Open(ctx, Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	for _, id := range acked {
		if _, err := again.Lookup(ctx, model.KindLink, id); err != nil {
			t.Fatalf("%s was acknowledged but is not stored: %v", id, err)
		}
	}
}

// A listing that asks for ids only reads no record: its records carry the kind and the id, and the total is the same.
func TestListIDsOnly(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		s, _ := openTest(t, d.name, d.env, 0)
		defer s.Close()
		ctx := context.Background()
		for i := range 7 {
			rec := record(model.KindLink, fmt.Sprintf("l%d", i), time.Time{})
			if err := s.Put(ctx, rec); err != nil {
				t.Fatal(err)
			}
		}
		q := store.ListQuery{Scope: "sc", Limit: 3, Offset: 2}
		full, err := s.List(ctx, model.KindLink, q)
		if err != nil {
			t.Fatal(err)
		}
		q.IDsOnly = true
		ids, err := s.List(ctx, model.KindLink, q)
		if err != nil {
			t.Fatal(err)
		}
		if ids.Total != full.Total || len(ids.Records) != len(full.Records) || len(ids.Records) != 3 {
			t.Fatalf("ids only: total %d, %d records; with records: total %d, %d records", ids.Total, len(ids.Records), full.Total, len(full.Records))
		}
		for i, r := range ids.Records {
			if r.ID != full.Records[i].ID || r.Kind != model.KindLink || r.Data != nil {
				t.Fatalf("record %d: %+v, want only the id %s", i, r, full.Records[i].ID)
			}
		}
	})
}
