package kvstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

func TestBadgerPartition(t *testing.T) {
	storetest.RunPartition(t, func(t testing.TB) store.Store {
		s, err := OpenBadger(context.Background(), t.TempDir(), BadgerOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestBadgerPartitionDurable(t *testing.T) {
	storetest.RunPartitionDurable(t, func(t testing.TB) *storetest.Durable {
		dir := t.TempDir()
		open := func(dir string) store.Store {
			s, err := OpenBadger(context.Background(), dir, BadgerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		d := &storetest.Durable{Store: open(dir)}
		cur := d.Store
		d.Reopen = func() store.Store {
			cur.Close()
			cur = open(dir)
			return cur
		}
		d.Crash = func() store.Store {
			img := t.TempDir()
			copyTree(t, dir, img)
			return open(img)
		}
		t.Cleanup(func() { cur.Close() })
		return d
	})
}

// copyTree copies a directory as it is on disk, files Badger pre-allocates (sparse) included without writing their
// holes.
func copyTree(t testing.TB, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		dst := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()
		buf := make([]byte, 1<<20)
		var off int64
		for {
			n, err := in.Read(buf)
			if n > 0 {
				zero := true
				for _, b := range buf[:n] {
					if b != 0 {
						zero = false
						break
					}
				}
				if !zero {
					if _, werr := out.WriteAt(buf[:n], off); werr != nil {
						return werr
					}
				}
				off += int64(n)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
		}
		return out.Truncate(off)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func rec(t testing.TB, org, name string) *store.Record {
	t.Helper()
	r, err := store.Encode(&model.User{OrgID: org, Username: name, Email: name + "@example.com", Role: model.RoleUser, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

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

// The partition stamp survives a rewrite by a format migration, and a plain write clears it.
func TestStampKeptByRewriteClearedByPlainWrite(t *testing.T) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u := rec(t, "o", "stamp")
	if err := s.ApplyPartition(ctx, 4, []*store.Record{u}, store.PartitionPos{Seq: 7}); err != nil {
		t.Fatal(err)
	}
	n, err := s.rewriteRecords(ctx, model.KindUser, func(r *store.Record) (bool, error) { r.Data = slices.Clone(r.Data); return true, nil })
	if err != nil || n != 1 {
		t.Fatalf("rewrite: %d %v", n, err)
	}
	var got []store.PartitionRecord
	if _, err := exportAfter(s, ctx, 4, 0, func(r store.PartitionRecord) error { got = append(got, r); return nil }); err != nil || len(got) != 1 || got[0].Seq != 7 {
		t.Fatalf("after rewrite: %v %+v", err, got)
	}
	v := *u
	v.Version = store.Clock.Now()
	if err := s.Put(ctx, &v); err != nil {
		t.Fatal(err)
	}
	got = nil
	if _, err := exportAfter(s, ctx, 4, 0, func(r store.PartitionRecord) error { got = append(got, r); return nil }); err != nil || len(got) != 0 {
		t.Fatalf("after a plain put: %v %+v", err, got)
	}
	if ents, _ := s.eng.Range(ctx, psBucket(4), "", "", 0); len(ents) != 0 {
		t.Fatalf("index entries left: %v", ents)
	}
}

// exportAfter runs ExportPartition and returns the position it started with.
func exportAfter(s *Store, ctx context.Context, p int, after uint64, fn func(store.PartitionRecord) error) (store.PartitionPos, error) {
	var pos store.PartitionPos
	err := s.ExportPartition(ctx, p, after, func(at store.PartitionPos) error { pos = at; return nil }, fn)
	return pos, err
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
