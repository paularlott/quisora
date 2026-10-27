//go:build faults

package kvstore

// The tests that read the instrumentation the faults build tag adds (faults.go): run with -tags faults.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A partition too big for one Badger transaction is imported in several, with the position last; the result is the same.
func TestImportTooBigForOneTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const n = 60000
	recs := make([]store.PartitionRecord, n)
	for i := range recs {
		id := fmt.Sprintf("lock-%06d", i)
		recs[i] = store.PartitionRecord{Seq: uint64(i%5000) + 1, Record: &store.Record{Kind: model.KindLock, ID: id, Partition: id,
			Version: hlc.Timestamp(100 + i), Origin: "n", Data: []byte("x")}}
	}
	// something already there that a full import removes, and something in another partition that it leaves
	if err := s.ApplyPartition(ctx, 2, []*store.Record{{Kind: model.KindLock, ID: "old", Version: 1, Origin: "n", Data: []byte("y")}},
		store.PartitionPos{Seq: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPartition(ctx, 3, []*store.Record{{Kind: model.KindLock, ID: "other", Version: 1, Origin: "n", Data: []byte("y")}},
		store.PartitionPos{Seq: 1}); err != nil {
		t.Fatal(err)
	}
	before := importFallbacks.Load()
	if err := s.ImportPartition(ctx, 2, recs, store.PartitionPos{Seq: 5000}, store.ImportStep{Full: true, First: true, Final: true}); err != nil {
		t.Fatal(err)
	}
	if importFallbacks.Load() == before {
		t.Fatal("the import fitted one transaction: raise n")
	}
	st, _ := s.PartitionState(ctx, 2)
	if st.Committed.Seq != 5000 || st.Purged != 0 {
		t.Fatalf("state: %+v", st)
	}
	count := 0
	if _, err := exportAfter(s, ctx, 2, 0, func(store.PartitionRecord) error { count++; return nil }); err != nil || count != n {
		t.Fatalf("exported %d (%v), want %d", count, err, n)
	}
	if _, err := s.Lookup(ctx, model.KindLock, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the old record is removed: %v", err)
	}
	if _, err := s.Lookup(ctx, model.KindLock, "other"); err != nil {
		t.Fatalf("another partition's record: %v", err)
	}
	// repeating the import (a crash between the chunks) is refused only once the position has moved
	if err := s.ImportPartition(ctx, 2, recs, store.PartitionPos{Seq: 5000}, store.ImportStep{Full: true, First: true, Final: true}); !errors.Is(err, store.ErrPartitionBehind) {
		t.Fatalf("repeat: %v", err)
	}
}

// The writes of one busy partition's state (the next write's pending while the last one commits, from many requests
// at once) queue for the partition rather than conflict and retry against each other: under load, retries ran out.
func TestBusyPartitionStateWritesNeverConflict(t *testing.T) {
	s := openBadger(t, BadgerOptions{NoSync: true})
	ctx := context.Background()
	before := retryConflicts.Load()
	const workers, each = 32, 50
	errs := make(chan error, workers*each*2)
	var wg sync.WaitGroup
	var seq atomic.Uint64
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				n := seq.Add(1)
				errs <- s.SetPartitionPending(ctx, 1, n, []byte("w"))
				rec := record(model.KindLink, fmt.Sprintf("r%d-%d", w, i), time.Time{})
				err := s.ApplyPartition(ctx, 1, []*store.Record{rec}, store.PartitionPos{Epoch: store.PartitionEpoch{Counter: 1}, Seq: n})
				if errors.Is(err, store.ErrPartitionBehind) {
					err = nil // another worker committed a later position first
				}
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := retryConflicts.Load() - before; n != 0 {
		t.Fatalf("%d transactions on one partition's state conflicted", n)
	}
}

// Commits on many partitions at once, each adding records of one kind (so all of them move that kind's counters),
// all succeed, with durable commits as in production: the committer applies them one after another, so they never conflict
// on a counter (run on their own, they exhausted the retries under load).
func TestConcurrentPartitionCommitsOnSharedCountersSucceed(t *testing.T) {
	s := openBadger(t, BadgerOptions{}) // durable: every commit is fsynced
	ctx := context.Background()
	before := retryConflicts.Load()
	const parts, each = 64, 40
	errs := make(chan error, parts*each)
	var wg sync.WaitGroup
	for p := range parts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				rec := record(model.KindLink, fmt.Sprintf("p%d-%d", p, i), time.Now().Add(time.Hour))
				pos := store.PartitionPos{Epoch: store.PartitionEpoch{Counter: 1}, Seq: uint64(i + 1)}
				errs <- s.ApplyPartition(ctx, p, []*store.Record{rec}, pos)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.Count(ctx, model.KindLink, "sc"); err != nil || n != parts*each {
		t.Fatalf("count after the commits: %d %v", n, err)
	}
	if n := retryConflicts.Load() - before; n != 0 {
		t.Fatalf("%d commits conflicted", n)
	}
}
