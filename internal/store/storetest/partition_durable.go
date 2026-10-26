package storetest

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Durable is a store on storage that outlives it, for the durability tests of store.PartitionStore.
type Durable struct {
	// Store is the open store.
	Store store.Store
	// Reopen closes the store cleanly and opens it again on the same storage.
	Reopen func() store.Store
	// Crash opens a second store on a copy of the storage as it is on disk right now, the first still open and not told to
	// close: what the files hold if the process dies here (no clean shutdown, so nothing a Close would flush). nil if the
	// backend cannot copy its storage. The copy cannot show what an operating system loses in a power cut; what it does
	// show is that nothing the protocol relies on lives only in the process, and that recovery from the files works.
	Crash func() store.Store
}

// DurableFactory returns a new Durable on empty storage; the test closes the stores it is given.
type DurableFactory func(t testing.TB) *Durable

// RunPartitionDurable runs the tests of what survives a restart.
func RunPartitionDurable(t *testing.T, f DurableFactory) {
	tests := []struct {
		name string
		fn   func(*testing.T, *Durable)
	}{
		{"StateSurvivesReopen", testDurState},
		{"AppliedDataSurvivesReopen", testDurApplied},
		{"ImportAndPurgeSurviveReopen", testDurImportPurge},
		{"UnfinishedImportRefusesExportAfterReopen", testDurUnfinishedImport},
		{"AppliedThenSyncedStateSurvivesCrash", testDurCrash},
		{"FullImportInterruptedAfterItsResetRefusesExport", testDurResetImport},
		{"FullImportInterruptedAfterABatchRepeatsFromFirst", testDurFullImportRepeated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := f(t)
			tc.fn(t, d)
		})
	}
}

func testDurState(t *testing.T, d *Durable) {
	ps := pstore(t, d.Store)
	must(t, ps.SetPartitionPromised(ctx, 3, epoch(7, 4)))
	must(t, ps.SetPartitionPending(ctx, 3, 2, []byte("the pending write")))
	must(t, ps.SetPartitionPromised(ctx, 4, epoch(1, 1)))
	s := d.Reopen()
	defer s.Close()
	ps = pstore(t, s)
	st, err := ps.PartitionState(ctx, 3)
	must(t, err)
	if st.Promised != epoch(7, 4) || string(st.Pending) != "the pending write" || st.PendingSeq != 2 || st.Committed.Seq != 0 {
		t.Fatalf("state after reopen: %+v", st)
	}
	if st, _ = ps.PartitionState(ctx, 4); st.Promised != epoch(1, 1) || st.Pending != nil {
		t.Fatalf("another partition after reopen: %+v", st)
	}
	if err := ps.SetPartitionPromised(ctx, 3, epoch(7, 3)); !errors.Is(err, store.ErrPartitionRegress) {
		t.Fatalf("the promise is still held after reopen: %v", err)
	}
}

// ApplyPartition is atomic: after a restart the records and the position are both there, whether or not a durable state write
// followed.
func testDurApplied(t *testing.T, d *Durable) {
	ps := pstore(t, d.Store)
	a, b := urec(t, "od", "du-a"), urec(t, "od", "du-b")
	must(t, ps.ApplyPartition(ctx, 10, []*store.Record{a, b}, pos(2, 1)))
	must(t, ps.ApplyPartition(ctx, 10, []*store.Record{trec(b)}, pos(2, 2)))
	s := d.Reopen()
	defer s.Close()
	ps = pstore(t, s)
	st, _ := ps.PartitionState(ctx, 10)
	if st.Committed != pos(2, 2) {
		t.Fatalf("position after reopen: %+v", st.Committed)
	}
	got, err := s.Get(ctx, model.KindUser, a.ID)
	must(t, err)
	sameRecord(t, "after reopen", got, a)
	if tomb, err := s.Lookup(ctx, model.KindUser, b.ID); err != nil || !tomb.Deleted {
		t.Fatalf("tombstone after reopen: %v %+v", err, tomb)
	}
	if r, err := s.GetByUnique(ctx, model.KindUser, model.UserEmailKey("od", "du-a@example.com")); err != nil || r.ID != a.ID {
		t.Fatalf("unique index after reopen: %v %v", err, r)
	}
	if exp, at := exported(t, ps, 10, 0); len(exp) != 2 || at != pos(2, 2) || exp[rkey(a)].Seq != 1 || exp[rkey(b)].Seq != 2 {
		t.Fatalf("export after reopen: %v %+v", keysOf(exp), at)
	}
	// and the log of the reopened store continues
	must(t, ps.ApplyPartition(ctx, 10, []*store.Record{urec(t, "od", "du-c")}, pos(2, 3)))
}

func testDurImportPurge(t *testing.T, d *Durable) {
	ps := pstore(t, d.Store)
	a, b := urec(t, "oe", "du-ia"), urec(t, "oe", "du-ib")
	old := urec(t, "oe", "du-old")
	must(t, ps.ApplyPartition(ctx, 11, []*store.Record{old}, pos(1, 1)))
	must(t, ps.ImportPartition(ctx, 11, []store.PartitionRecord{{Record: a, Seq: 3}, {Record: trec(b), Seq: 4}}, pos(1, 5), whole))
	must(t, ps.ApplyPartition(ctx, 11, []*store.Record{trec(a)}, pos(1, 6)))
	if n, err := ps.PurgePartition(ctx, 11, 6); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	s := d.Reopen()
	defer s.Close()
	ps = pstore(t, s)
	st, _ := ps.PartitionState(ctx, 11)
	if st.Committed != pos(1, 6) || st.Purged != 5 {
		t.Fatalf("state after reopen: %+v", st)
	}
	if _, err := s.Lookup(ctx, model.KindUser, old.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a record a full import removed is back: %v", err)
	}
	if _, err := s.Lookup(ctx, model.KindUser, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a purged tombstone is back: %v", err)
	}
	if tomb, err := s.Lookup(ctx, model.KindUser, a.ID); err != nil || !tomb.Deleted {
		t.Fatalf("tombstone of a: %v %+v", err, tomb)
	}
}

// What the protocol needs of the order: an unsynced apply followed by a synced state write. Whatever the files hold when the
// process dies after the state write returned must have both.
func testDurCrash(t *testing.T, d *Durable) {
	if d.Crash == nil {
		t.Skip("no crash image for this backend")
	}
	ps := pstore(t, d.Store)
	a := urec(t, "of", "cr-a")
	must(t, ps.ApplyPartition(ctx, 13, []*store.Record{a}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, 13, []*store.Record{urec(t, "of", "cr-b")}, pos(1, 2)))
	must(t, ps.SetPartitionPending(ctx, 13, 3, []byte("write three"))) // synced: the acknowledgement of write 3
	must(t, ps.SetPartitionPromised(ctx, 13, epoch(2, 2)))
	s := d.Crash()
	defer s.Close()
	cp := pstore(t, s)
	st, err := cp.PartitionState(ctx, 13)
	must(t, err)
	if st.Committed != pos(1, 2) || st.Promised != epoch(2, 2) || string(st.Pending) != "write three" || st.PendingSeq != 3 {
		t.Fatalf("state in the crash image: %+v", st)
	}
	got, err := s.Get(ctx, model.KindUser, a.ID)
	must(t, err)
	sameRecord(t, "crash image", got, a)
	if exp, at := exported(t, cp, 13, 0); len(exp) != 2 || at != pos(1, 2) {
		t.Fatalf("export of the crash image: %v %+v", keysOf(exp), at)
	}
}

// An import that stopped before its final batch still refuses exports after a restart: the data is the mark.
func testDurUnfinishedImport(t *testing.T, d *Durable) {
	r2, finish := unfinishedImport(t, pstore(t, d.Store), 14, "og")
	s := d.Reopen()
	defer s.Close()
	ps := pstore(t, s)
	called := false
	err := ps.ExportPartition(ctx, 14, 0, func(store.PartitionPos) error { called = true; return nil }, func(store.PartitionRecord) error { return nil })
	if !errors.Is(err, store.ErrImportUnfinished) || called {
		t.Fatalf("an export after a restart in the middle of an import: %v (start called: %v)", err, called)
	}
	must(t, ps.ImportPartition(ctx, 14, []store.PartitionRecord{{Record: r2, Seq: 2}}, pos(1, 2), finish))
	if got, at := exported(t, ps, 14, 0); at != pos(1, 2) || len(got) != 1 || got[rkey(r2)].Seq != 2 {
		t.Fatalf("export after the import: %+v %v", at, got)
	}
}

// refusesExport checks that s refuses to export partition p because an import into it has not finished.
func refusesExport(t *testing.T, s store.Store, p int) {
	t.Helper()
	called := false
	err := pstore(t, s).ExportPartition(ctx, p, 0, func(store.PartitionPos) error { called = true; return nil }, func(store.PartitionRecord) error { return nil })
	if !errors.Is(err, store.ErrImportUnfinished) || called {
		t.Fatalf("an export of a partition whose full import has not finished: %v (start called: %v)", err, called)
	}
}

// A full import that stopped between its reset (which removed records) and the write of its position refuses exports, in the
// crash image taken at that moment and after a restart, until an import finishes.
func testDurResetImport(t *testing.T, d *Durable) {
	ps := pstore(t, d.Store)
	interrupted := errors.New("interrupted")
	a, b, imp := resetImport(t, ps, 15, "og2", func() {
		if d.Crash != nil {
			c := d.Crash()
			defer c.Close()
			refusesExport(t, c, 15)
		}
		panic(interrupted)
	})
	func() {
		defer func() {
			if r := recover(); r != interrupted {
				t.Fatalf("the import was not interrupted: %v", r)
			}
		}()
		_ = imp()
	}()
	if st, _ := ps.PartitionState(ctx, 15); st.Committed != pos(1, 2) || !st.Importing {
		t.Fatalf("the position moved, or the import is not shown: %+v", st)
	}
	s := d.Reopen()
	defer s.Close()
	refusesExport(t, s, 15)
	ps = pstore(t, s)
	wantImporting(t, ps, 15, true) // the marker is durable
	// the import repeated (the next catch-up) completes it
	must(t, ps.ImportPartition(ctx, 15, []store.PartitionRecord{{Record: a, Seq: 1}}, pos(2, 5), whole))
	if got, at := exported(t, ps, 15, 0); at != pos(2, 5) || len(got) != 1 || got[rkey(a)].Seq != 1 {
		t.Fatalf("export after the import: %+v %v", at, keysOf(got))
	}
	if _, err := s.Lookup(ctx, model.KindUser, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the record the import did not bring: %v", err)
	}
}

// A full import that stopped after its reset and a batch, before its final call, refuses exports in the crash image and
// after a restart (the old position's data is gone and a record the import stored may lie below the position, so nothing
// else tells), and the import repeated from its First call completes with exactly the source's records: what the
// interrupted attempt stored and the source does not have is gone.
func testDurFullImportRepeated(t *testing.T, d *Durable) {
	ps := pstore(t, d.Store)
	const org = "og3"
	old1, old2 := urec(t, org, "fi-old1"), urec(t, org, "fi-old2")
	must(t, ps.ApplyPartition(ctx, 16, []*store.Record{old1, old2}, pos(1, 1)))
	x, y, z := urec(t, org, "fi-x"), urec(t, org, "fi-y"), urec(t, org, "fi-z")
	// the interrupted attempt brought x and z (below the new position)
	must(t, ps.ImportPartition(ctx, 16, []store.PartitionRecord{{Record: x, Seq: 1}, {Record: z, Seq: 2}}, pos(2, 3),
		store.ImportStep{Full: true, First: true}))
	if d.Crash != nil {
		c := d.Crash()
		refusesExport(t, c, 16)
		c.Close()
	}
	s := d.Reopen()
	defer s.Close()
	refusesExport(t, s, 16)
	if st, _ := pstore(t, s).PartitionState(ctx, 16); st.Committed != pos(1, 1) || !st.Importing {
		t.Fatalf("the position moved, or the import is not shown after the restart: %+v", st)
	}
	ps = pstore(t, s)
	// the source has x and y: the import again, from the start, in two calls
	must(t, ps.ImportPartition(ctx, 16, []store.PartitionRecord{{Record: x, Seq: 1}}, pos(2, 3), store.ImportStep{Full: true, First: true}))
	refusesExport(t, s, 16)
	must(t, ps.ImportPartition(ctx, 16, []store.PartitionRecord{{Record: y, Seq: 3}}, pos(2, 3), store.ImportStep{Full: true, Final: true}))
	wantImporting(t, ps, 16, false)
	got, at := exported(t, ps, 16, 0)
	if at != pos(2, 3) || len(got) != 2 || got[rkey(x)].Seq != 1 || got[rkey(y)].Seq != 3 {
		t.Fatalf("export after the import: %+v %v", at, keysOf(got))
	}
	for _, r := range []*store.Record{old1, old2, z} {
		if _, err := s.Lookup(ctx, model.KindUser, r.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s survived: %v", r.ID, err)
		}
	}
}
