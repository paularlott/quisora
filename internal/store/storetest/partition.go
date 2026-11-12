package storetest

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// RunPartition runs the conformance tests of store.PartitionStore (partition replication support) against stores that
// implement it. The factory returns an empty store, as for Run; tests that need a second store call it again.
func RunPartition(t *testing.T, f Factory) {
	tests := []struct {
		name string
		fn   func(*testing.T, Factory)
	}{
		{"State", testPartState},
		{"ApplyAsGiven", testPartApplyAsGiven},
		{"ApplyBehind", testPartApplyBehind},
		{"ApplyTombstones", testPartApplyTombstones},
		{"ApplyUnique", testPartApplyUnique},
		{"ApplyKinds", testPartApplyAtomic},
		{"KeyPreserved", testPartKeyPreserved},
		{"Export", testPartExport},
		{"ExportErrorStops", testPartExportError},
		{"ExportConsistentWhileApplying", testPartExportConsistent},
		{"ImportRoundTrip", testPartImportRoundTrip},
		{"ImportInvalid", testPartImportInvalid},
		{"ImportFull", testPartImportFull},
		{"ImportFullReleasesLongUnique", testPartImportFullLongUnique},
		{"ExportStartsWithThePosition", testPartExportStart},
		{"ImportInBatches", testPartImportBatches},
		{"ExportRefusedWhileAnImportIsUnfinished", testPartExportUnfinished},
		{"ImportFullInBatches", testPartImportFullBatches},
		{"ExportRefusedAfterAFullImportReset", testPartExportAfterReset},
		{"SnapshotRefusedWhileAnImportIsUnfinished", testPartSnapshotUnfinished},
		{"ImportFullRestartedAtTheSamePosition", testPartImportFullSamePosition},
		{"Purge", testPartPurge},
		{"Tombstones", testPartTombstones},
		{"PurgeKeepsTombstones", testPurgeKeepsPartitionTombstones},
		{"PartitionsIndependent", testPartIndependent},
		{"ConcurrentPartitions", testPartConcurrent},
		{"Wipe", testPartWipe},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, f) })
	}
}

// A full import's reset removes the partition's records and releases their unique values, however long (a long one is
// indexed by its hash): the value then finds nothing, even once the copy brings a record with the removed one's id.
func testPartImportFullLongUnique(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	link := func(hash string) *store.Record {
		r, err := store.Encode(&model.LinkToken{Meta: model.Meta{ID: "invite-u1"}, OrgID: "olong", UserID: "u1",
			TokenHash: hash, Expires: time.Now().Add(time.Hour)})
		must(t, err)
		return r
	}
	old, next := strings.Repeat("o", 600), strings.Repeat("n", 600)
	must(t, ps.ApplyPartition(ctx, 62, []*store.Record{link(old)}, pos(1, 1)))
	must(t, ps.ImportPartition(ctx, 62, []store.PartitionRecord{{Record: link(next), Seq: 2}}, pos(2, 2), whole))
	if _, err := s.GetByUnique(ctx, model.KindLink, model.LinkTokenKey(old)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the removed link's token: %v, want ErrNotFound (nil: it finds the imported link)", err)
	}
	if got, err := s.GetByUnique(ctx, model.KindLink, model.LinkTokenKey(next)); err != nil || got.ID != "invite-u1" {
		t.Fatalf("the imported link's token: %v %v", got, err)
	}
}

// pstore returns s as a PartitionStore, or skips the test.
func pstore(t *testing.T, s store.Store) store.PartitionStore {
	t.Helper()
	ps, ok := s.(store.PartitionStore)
	if !ok {
		t.Skip("the store does not implement store.PartitionStore")
	}
	return ps
}

func epoch(counter uint64, node byte) store.PartitionEpoch {
	e := store.PartitionEpoch{Counter: counter}
	e.Node[0] = node
	return e
}

func pos(counter uint64, seq uint64) store.PartitionPos {
	return store.PartitionPos{Epoch: epoch(counter, 1), Seq: seq}
}

// urec makes a live user record of org with the given name (its partition key is the org), at a fresh version.
func urec(t testing.TB, org, name string) *store.Record {
	t.Helper()
	r, err := store.Encode(newUser(org, name))
	must(t, err)
	r.Req = "req-" + name // the request id travels with the record through every partition path
	if r.Partition != org {
		t.Fatalf("a user of %q has partition key %q", org, r.Partition)
	}
	return r
}

// trec makes a tombstone of r: the writer of one sets the partition key from the record it deletes.
func trec(r *store.Record) *store.Record {
	d := store.Tombstone(r.Kind, r.ID)
	d.Partition = r.Partition
	return d
}

// final is the step of an import made in one call; whole the same for a full import.
var (
	final = store.ImportStep{First: true, Final: true}
	whole = store.ImportStep{Full: true, First: true, Final: true}
)

// exportAfter runs ExportPartition and returns the position it started with.
func exportAfter(s store.PartitionStore, p int, after uint64, fn func(store.PartitionRecord) error) (store.PartitionPos, error) {
	var pos store.PartitionPos
	err := s.ExportPartition(ctx, p, after, func(at store.PartitionPos) error { pos = at; return nil }, fn)
	return pos, err
}

func exported(t testing.TB, s store.PartitionStore, p int, after uint64) (map[string]store.PartitionRecord, store.PartitionPos) {
	t.Helper()
	out := map[string]store.PartitionRecord{}
	pos, err := exportAfter(s, p, after, func(r store.PartitionRecord) error {
		k := string(r.Kind) + "/" + r.ID
		if _, dup := out[k]; dup {
			t.Errorf("record %s exported twice", k)
		}
		out[k] = r
		return nil
	})
	must(t, err)
	return out, pos
}

func keysOf(m map[string]store.PartitionRecord) []string { return slices.Sorted(maps.Keys(m)) }

func rkey(r *store.Record) string { return string(r.Kind) + "/" + r.ID }

func sameRecord(t testing.TB, what string, got, want *store.Record) {
	t.Helper()
	if got.Kind != want.Kind || got.ID != want.ID || got.Version != want.Version || got.Epoch != want.Epoch ||
		got.Created != want.Created || got.Origin != want.Origin || got.Req != want.Req || got.Deleted != want.Deleted ||
		got.Scope != want.Scope || got.Partition != want.Partition || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("%s: got %+v, want %+v", what, got, want)
	}
}

func testPartState(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	st, err := ps.PartitionState(ctx, 7)
	must(t, err)
	if st.Promised != (store.PartitionEpoch{}) || st.Committed != (store.PartitionPos{}) || st.Pending != nil || st.PendingSeq != 0 || st.Purged != 0 {
		t.Fatalf("state of a partition never written: %+v", st)
	}
	must(t, ps.SetPartitionPromised(ctx, 7, epoch(3, 2)))
	must(t, ps.SetPartitionPromised(ctx, 7, epoch(3, 2))) // the same epoch again
	must(t, ps.SetPartitionPromised(ctx, 7, epoch(3, 9))) // same counter, higher node
	if err := ps.SetPartitionPromised(ctx, 7, epoch(3, 5)); !errors.Is(err, store.ErrPartitionRegress) {
		t.Fatalf("lowering the promise: %v", err)
	}
	if err := ps.SetPartitionPromised(ctx, 7, epoch(2, 200)); !errors.Is(err, store.ErrPartitionRegress) {
		t.Fatalf("lowering the counter: %v", err)
	}
	st, _ = ps.PartitionState(ctx, 7)
	if st.Promised != epoch(3, 9) {
		t.Fatalf("promised after refused lowerings: %+v", st.Promised)
	}
	other, _ := ps.PartitionState(ctx, 8)
	if other.Promised != (store.PartitionEpoch{}) {
		t.Fatalf("another partition's state changed: %+v", other)
	}

	must(t, ps.SetPartitionPending(ctx, 7, 4, []byte("write four")))
	st, _ = ps.PartitionState(ctx, 7)
	if string(st.Pending) != "write four" || st.PendingSeq != 4 || st.Promised != epoch(3, 9) {
		t.Fatalf("pending: %+v", st)
	}
	st.Pending[0] = 'X' // a returned copy: the store does not hold it
	if again, _ := ps.PartitionState(ctx, 7); string(again.Pending) != "write four" {
		t.Fatalf("the returned pending aliases the store's: %q", again.Pending)
	}
	// A commit below the pending write leaves it; the commit that reaches it clears it, in the same transaction.
	must(t, ps.ApplyPartition(ctx, 7, []*store.Record{urec(t, "o", "pend-a")}, pos(3, 3)))
	st, _ = ps.PartitionState(ctx, 7)
	if string(st.Pending) != "write four" || st.Committed != pos(3, 3) {
		t.Fatalf("after commit 3: %+v", st)
	}
	must(t, ps.ApplyPartition(ctx, 7, []*store.Record{urec(t, "o", "pend-b")}, pos(3, 4)))
	st, _ = ps.PartitionState(ctx, 7)
	if st.Pending != nil || st.PendingSeq != 0 || st.Committed != pos(3, 4) || st.Promised != epoch(3, 9) {
		t.Fatalf("after commit 4: %+v", st)
	}
	must(t, ps.SetPartitionPending(ctx, 7, 5, []byte{}))
	if st, _ = ps.PartitionState(ctx, 7); st.PendingSeq != 5 || len(st.Pending) != 0 {
		t.Fatalf("an empty (non-nil) pending write is a pending write: %+v", st)
	}
	must(t, ps.SetPartitionPending(ctx, 7, 0, nil))
	if st, _ = ps.PartitionState(ctx, 7); st.Pending != nil || st.PendingSeq != 0 {
		t.Fatalf("cleared pending: %+v", st)
	}
	// Setting the promise leaves the committed position and the other way round.
	must(t, ps.SetPartitionPromised(ctx, 7, epoch(4, 1)))
	if st, _ = ps.PartitionState(ctx, 7); st.Committed != pos(3, 4) || st.Promised != epoch(4, 1) {
		t.Fatalf("promise over committed: %+v", st)
	}
}

// Records are stored exactly as given: versions, generations and origins as the owner decided them, with no version
// comparison (an older version replaces a newer one) and no refusal over a tombstone.
func testPartApplyAsGiven(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	a, b := urec(t, "org1", "ag-a"), urec(t, "org1", "ag-b")
	a.Epoch, a.Created, a.Origin = a.Version-5, a.Version-3, "owner-node"
	b.Created = b.Version
	must(t, ps.ApplyPartition(ctx, 12, []*store.Record{a, b}, pos(1, 1)))
	got, err := s.Get(ctx, model.KindUser, a.ID)
	must(t, err)
	sameRecord(t, "applied record", got, a)
	if got.Scope != "org1" || len(got.Unique) != 2 || got.Fields["username"] != "ag-a" {
		t.Fatalf("index values not kept: %+v", got)
	}
	if st, _ := ps.PartitionState(ctx, 12); st.Committed != pos(1, 1) {
		t.Fatalf("committed: %+v", st.Committed)
	}
	// A record applied at a lower version than the stored one still replaces it.
	older := *a
	older.Version, older.Epoch, older.Created, older.Origin = a.Version-100, 0, 0, "other"
	older.Data = []byte("older data")
	must(t, ps.ApplyPartition(ctx, 12, []*store.Record{&older}, pos(1, 2)))
	got, err = s.Get(ctx, model.KindUser, a.ID)
	must(t, err)
	sameRecord(t, "older version applied over a newer one", got, &older)
	// The record is listed and counted like any other.
	res, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org1"})
	must(t, err)
	if res.Total != 2 {
		t.Fatalf("listed %d, want 2", res.Total)
	}
	// An expired record is stored as given too.
	e := urec(t, "org1", "ag-expired")
	e.Expires = time.Now().Add(-time.Hour)
	must(t, ps.ApplyPartition(ctx, 12, []*store.Record{e}, pos(1, 3)))
	if _, err := s.Get(ctx, model.KindUser, e.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired record is not visible: %v", err)
	}
	if lk, err := s.Lookup(ctx, model.KindUser, e.ID); err != nil || !lk.Expires.Equal(e.Expires) {
		t.Fatalf("an expired record is still stored: %v %+v", err, lk)
	}
	// The same record twice in one write: the later one applies.
	c1, c2 := urec(t, "org1", "ag-c"), urec(t, "org1", "ag-c")
	c2.ID, c2.Version = c1.ID, c1.Version+1
	c2.Data = []byte("second")
	must(t, ps.ApplyPartition(ctx, 12, []*store.Record{c1, c2}, pos(1, 4)))
	if got, _ = s.Get(ctx, model.KindUser, c1.ID); string(got.Data) != "second" {
		t.Fatalf("a record listed twice: %q", got.Data)
	}
	// An empty write moves the position.
	must(t, ps.ApplyPartition(ctx, 12, nil, pos(2, 5)))
	if st, _ := ps.PartitionState(ctx, 12); st.Committed != pos(2, 5) {
		t.Fatalf("committed after an empty write: %+v", st.Committed)
	}
}

func testPartApplyBehind(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	a := urec(t, "o", "bh-a")
	must(t, ps.ApplyPartition(ctx, 3, []*store.Record{a}, pos(1, 5)))
	b := urec(t, "o", "bh-b")
	for _, seq := range []uint64{5, 4, 1} {
		if err := ps.ApplyPartition(ctx, 3, []*store.Record{b}, pos(9, seq)); !errors.Is(err, store.ErrPartitionBehind) {
			t.Fatalf("apply at %d over 5: %v", seq, err)
		}
	}
	if err := ps.ApplyPartition(ctx, 3, nil, pos(9, 0)); err == nil {
		t.Fatal("apply at sequence 0")
	}
	if _, err := s.Get(ctx, model.KindUser, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a refused apply stored a record")
	}
	if st, _ := ps.PartitionState(ctx, 3); st.Committed != pos(1, 5) {
		t.Fatalf("a refused apply moved the position: %+v", st.Committed)
	}
	// A gap is fine: the sequence is the owner's, and this node may have been behind.
	must(t, ps.ApplyPartition(ctx, 3, []*store.Record{b}, pos(1, 9)))
}

func testPartApplyTombstones(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	a := urec(t, "org1", "tb-a")
	must(t, ps.ApplyPartition(ctx, 4, []*store.Record{a}, pos(1, 1)))
	d := trec(a)
	d.Epoch = 77
	must(t, ps.ApplyPartition(ctx, 4, []*store.Record{d}, pos(1, 2)))
	if _, err := s.Get(ctx, model.KindUser, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a tombstone hides the record: %v", err)
	}
	if _, err := s.GetByUnique(ctx, model.KindUser, model.UserEmailKey("org1", "tb-a@example.com")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a tombstone releases the unique values: %v", err)
	}
	tomb, err := s.Lookup(ctx, model.KindUser, a.ID)
	must(t, err)
	if !tomb.Deleted || tomb.Version != d.Version || tomb.Epoch != 77 || tomb.Partition != "org1" || tomb.Data != nil {
		t.Fatalf("stored as a tombstone: %+v", tomb)
	}
	if res, _ := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org1"}); res.Total != 0 {
		t.Fatalf("listed a deleted record: %d", res.Total)
	}
	if n, _ := s.Count(ctx, model.KindUser, "org1"); n != 0 {
		t.Fatalf("counted a deleted record: %d", n)
	}
	// A live record over the tombstone: no ErrDeleted, no generation check; it is what the owner decided.
	again := *a
	again.Version = d.Version + 1
	must(t, ps.ApplyPartition(ctx, 4, []*store.Record{&again}, pos(1, 3)))
	got, err := s.Get(ctx, model.KindUser, a.ID)
	must(t, err)
	sameRecord(t, "re-created", got, &again)
	// A tombstone of a record this node never held.
	must(t, ps.ApplyPartition(ctx, 4, []*store.Record{trec(urec(t, "org1", "tb-never"))}, pos(1, 4)))
}

// Unique values are updated as for a put: indexed under the record that lists them (whoever held them), released when the
// record drops them or is deleted; the order of records in one write does not matter.
func testPartApplyUnique(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	const org = "uorg"
	byEmail := func(addr string) (*store.Record, error) {
		return s.GetByUnique(ctx, model.KindUser, model.UserEmailKey(org, addr))
	}
	a, b := urec(t, org, "uq-a"), urec(t, org, "uq-b")
	must(t, ps.ApplyPartition(ctx, 9, []*store.Record{a, b}, pos(1, 1)))
	if r, err := byEmail("uq-a@example.com"); err != nil || r.ID != a.ID {
		t.Fatalf("unique lookup after apply: %v %v", err, r)
	}
	// b moves to a's address, a drops it, in one write, b listed first: the value ends with b whatever the order.
	var au, bu model.User
	must(t, store.Decode(a, &au))
	must(t, store.Decode(b, &bu))
	au.Email, au.Version = "uq-a2@example.com", a.Version+10
	bu.Email, bu.Version = "uq-a@example.com", b.Version+10
	ra, err := store.EncodeAsIs(&au)
	must(t, err)
	rb, err := store.EncodeAsIs(&bu)
	must(t, err)
	must(t, ps.ApplyPartition(ctx, 9, []*store.Record{rb, ra}, pos(1, 2)))
	if r, err := byEmail("uq-a@example.com"); err != nil || r.ID != b.ID {
		t.Fatalf("a value moved to b: %v %v", err, r)
	}
	if r, err := byEmail("uq-a2@example.com"); err != nil || r.ID != a.ID {
		t.Fatalf("a's new value: %v %v", err, r)
	}
	if _, err := byEmail("uq-b@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("b's old value is released: %v", err)
	}
	// A record that takes a value another live record holds, with no release of it: the new holder wins, the old
	// keeps its record and loses the index entry (the owner checked the partition: this is a repair, not a refusal).
	c := urec(t, org, "uq-c")
	var cu model.User
	must(t, store.Decode(c, &cu))
	cu.Email = "uq-a@example.com" // b holds it
	rc, err := store.EncodeAsIs(&cu)
	must(t, err)
	must(t, ps.ApplyPartition(ctx, 9, []*store.Record{rc}, pos(1, 3)))
	if r, err := byEmail("uq-a@example.com"); err != nil || r.ID != c.ID {
		t.Fatalf("the new holder wins: %v %v", err, r)
	}
	if _, err := s.Get(ctx, model.KindUser, b.ID); err != nil {
		t.Fatalf("the old holder keeps its record: %v", err)
	}
	// ... and b dropping the value later does not release c's.
	bu.Email, bu.Version = "uq-b-new@example.com", bu.Version+10
	rb2, err := store.EncodeAsIs(&bu)
	must(t, err)
	must(t, ps.ApplyPartition(ctx, 9, []*store.Record{rb2}, pos(1, 4)))
	if r, err := byEmail("uq-a@example.com"); err != nil || r.ID != c.ID {
		t.Fatalf("a record that no longer holds a value does not release it: %v %v", err, r)
	}
	// Deleting the holder frees the value.
	must(t, ps.ApplyPartition(ctx, 9, []*store.Record{trec(c)}, pos(1, 5)))
	if _, err := byEmail("uq-a@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted holder: %v", err)
	}
	// ... and a local put may then claim it (the index is consistent with what the partition applied).
	d := newUser(org, "uq-d")
	d.Email = "uq-a@example.com"
	must(t, users(s).Put(ctx, d))
	if r, err := byEmail("uq-a@example.com"); err != nil || r.ID != d.ID {
		t.Fatalf("claim after release: %v %v", err, r)
	}
}

// Records of several kinds go in one write, with the position.
func testPartApplyAtomic(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	good := urec(t, "o", "at-good")
	g := &model.Group{OrgID: "o", DisplayName: "grp"}
	gr, err := store.Encode(g)
	must(t, err)
	must(t, ps.ApplyPartition(ctx, 2, []*store.Record{good, gr}, pos(1, 1)))
	if _, err := s.Get(ctx, model.KindGroup, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, model.KindUser, good.ID); err != nil {
		t.Fatal(err)
	}
	if got, at := exported(t, ps, 2, 0); len(got) != 2 || at != pos(1, 1) {
		t.Fatalf("export: %v %+v", keysOf(got), at)
	}
}

// The partition key goes in and comes out of every read, whichever way the record was written, and a tombstone keeps it.
func testPartKeyPreserved(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	u := newUser("org-key", "key-a")
	must(t, users(s).Put(ctx, u))
	check := func(what string, r *store.Record, want string) {
		t.Helper()
		if r.Partition != want {
			t.Errorf("%s: partition key %q, want %q", what, r.Partition, want)
		}
	}
	r, err := s.Get(ctx, model.KindUser, u.ID)
	must(t, err)
	check("Get after Put", r, "org-key")
	r, err = s.GetByUnique(ctx, model.KindUser, model.UserEmailKey("org-key", "key-a@example.com"))
	must(t, err)
	check("GetByUnique", r, "org-key")
	r, err = s.Lookup(ctx, model.KindUser, u.ID)
	must(t, err)
	check("Lookup", r, "org-key")
	res, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org-key"})
	must(t, err)
	check("List", res.Records[0], "org-key")
	many, err := store.GetMany(ctx, s, model.KindUser, []string{u.ID})
	must(t, err)
	check("GetMany", many[0], "org-key")
	// Global data, and a record keyed by its own id.
	org := &model.Org{Name: "key-org"}
	or, err := store.Encode(org)
	must(t, err)
	lk := &model.Lock{Holder: "me"}
	lr, err := store.Encode(lk)
	must(t, err)
	check("an organization", or, "")
	check("a lock", lr, lk.ID)
	must(t, s.Put(ctx, or))
	must(t, s.Put(ctx, lr))
	for _, c := range []struct {
		kind model.Kind
		id   string
		want string
	}{{model.KindOrg, org.ID, ""}, {model.KindLock, lk.ID, lk.ID}} {
		got, err := s.Get(ctx, c.kind, c.id)
		must(t, err)
		check("Get "+string(c.kind), got, c.want)
	}
	// Every way of writing: replicated, applied; a tombstone keeps its key.
	v := urec(t, "org-key", "key-b")
	ok, err := s.PutReplicated(ctx, v)
	must(t, err)
	if !ok {
		t.Fatal("PutReplicated did not apply")
	}
	got, _ := s.Get(ctx, model.KindUser, v.ID)
	check("PutReplicated", got, "org-key")
	w := urec(t, "org-key", "key-c")
	must(t, ps.ApplyPartition(ctx, 21, []*store.Record{w}, pos(1, 1)))
	got, _ = s.Get(ctx, model.KindUser, w.ID)
	check("ApplyPartition", got, "org-key")
	must(t, ps.ApplyPartition(ctx, 21, []*store.Record{trec(w)}, pos(1, 2)))
	got, err = s.Lookup(ctx, model.KindUser, w.ID)
	must(t, err)
	check("an applied tombstone", got, "org-key")
	// The key a record has when it is replaced by one with another is the new one: it is the record's own property.
	w2 := *w
	w2.Version, w2.Partition = store.Clock.Now(), "other"
	must(t, ps.ApplyPartition(ctx, 21, []*store.Record{&w2}, pos(1, 3)))
	got, _ = s.Get(ctx, model.KindUser, w.ID)
	check("replaced", got, "other")
}

func testPartExport(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	if got, pos0 := exported(t, ps, 30, 0); len(got) != 0 || pos0 != (store.PartitionPos{}) {
		t.Fatalf("export of a partition never written: %v %+v", got, pos0)
	}
	a, b, c := urec(t, "oa", "ex-a"), urec(t, "oa", "ex-b"), urec(t, "oa", "ex-c")
	other := urec(t, "ob", "ex-other")
	must(t, ps.ApplyPartition(ctx, 30, []*store.Record{a, b}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, 31, []*store.Record{other}, pos(1, 1))) // another partition
	must(t, ps.ApplyPartition(ctx, 30, []*store.Record{c, trec(a)}, pos(1, 2)))
	b2 := *b
	b2.Version, b2.Data = b.Version+5, []byte("b again")
	grp, err := store.Encode(&model.Group{OrgID: "oa", DisplayName: "ex-grp"})
	must(t, err)
	must(t, ps.ApplyPartition(ctx, 30, []*store.Record{&b2, grp}, pos(2, 4)))
	must(t, s.Put(ctx, urec(t, "oa", "ex-plain"))) // a plain put belongs to no partition write
	if _, err := s.PutReplicated(ctx, urec(t, "oa", "ex-replicated")); err != nil {
		t.Fatal(err)
	}

	all, at := exported(t, ps, 30, 0)
	if at != pos(2, 4) {
		t.Fatalf("export position %+v", at)
	}
	if want := []string{rkey(a), rkey(&b2), rkey(c), rkey(grp)}; !slices.Equal(keysOf(all), slices.Sorted(slices.Values(want))) {
		t.Fatalf("exported %v, want %v", keysOf(all), want)
	}
	if r := all[rkey(a)]; !r.Deleted || r.Seq != 2 || r.Partition != "oa" {
		t.Fatalf("the tombstone: %+v seq %d", r.Record, r.Seq)
	}
	if all[rkey(&b2)].Seq != 4 || all[rkey(c)].Seq != 2 || all[rkey(grp)].Seq != 4 {
		t.Fatalf("sequences: b %d c %d grp %d", all[rkey(&b2)].Seq, all[rkey(c)].Seq, all[rkey(grp)].Seq)
	}
	sameRecord(t, "exported record", all[rkey(&b2)].Record, &b2)
	if len(all[rkey(c)].Unique) != 2 || all[rkey(c)].Fields["username"] != "ex-c" || all[rkey(c)].Scope != "oa" {
		t.Fatalf("an exported record has its index values: %+v", all[rkey(c)].Record)
	}
	got, _ := exported(t, ps, 30, 2)
	if want := []string{rkey(&b2), rkey(grp)}; !slices.Equal(keysOf(got), slices.Sorted(slices.Values(want))) {
		t.Fatalf("exported after 2: %v, want %v", keysOf(got), want)
	}
	if got, at := exported(t, ps, 30, 4); len(got) != 0 || at != pos(2, 4) {
		t.Fatalf("exported after the last: %v %+v", got, at)
	}
	if got, at := exported(t, ps, 30, 99); len(got) != 0 || at != pos(2, 4) {
		t.Fatalf("exported after beyond the last: %v %+v", got, at)
	}
	if got, at := exported(t, ps, 31, 0); len(got) != 1 || at != pos(1, 1) {
		t.Fatalf("the other partition: %v %+v", got, at)
	}
}

func testPartExportError(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	must(t, ps.ApplyPartition(ctx, 1, []*store.Record{urec(t, "o", "ee-a"), urec(t, "o", "ee-b"), urec(t, "o", "ee-c")}, pos(1, 1)))
	stop := errors.New("stop here")
	n := 0
	_, err := exportAfter(ps, 1, 0, func(store.PartitionRecord) error {
		n++
		return stop
	})
	if !errors.Is(err, stop) || n != 1 {
		t.Fatalf("an error from fn stops the export: %v after %d", err, n)
	}
	// The store is usable afterwards (the snapshot was released).
	must(t, ps.ApplyPartition(ctx, 1, []*store.Record{urec(t, "o", "ee-d")}, pos(1, 2)))
}

// An export reads one snapshot: every write sets two records to the same number, so a snapshot that shows them different, or
// a position that is not their number, mixed two states.
func testPartExportConsistent(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	a, b := urec(t, "oc", "cons-a"), urec(t, "oc", "cons-b")
	write := func(n uint64) {
		ra, rb := *a, *b
		ra.Version, rb.Version = a.Version+hlc.Timestamp(n), b.Version+hlc.Timestamp(n)
		ra.Data, rb.Data = []byte(strconv.FormatUint(n, 10)), []byte(strconv.FormatUint(n, 10))
		must(t, ps.ApplyPartition(ctx, 40, []*store.Record{&ra, &rb}, pos(1, n)))
	}
	write(1)
	const writes = 300
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for n := uint64(2); n <= writes; n++ {
			write(n)
		}
	}()
	exports := 0
	for {
		got, at := exported(t, ps, 40, 0)
		exports++
		ra, rb := got[rkey(a)], got[rkey(b)]
		if ra.Record == nil || rb.Record == nil || string(ra.Data) != string(rb.Data) || string(ra.Data) != strconv.FormatUint(at.Seq, 10) ||
			ra.Seq != at.Seq || rb.Seq != at.Seq {
			t.Fatalf("an export mixed states: position %d, a %q (seq %d), b %q (seq %d)", at.Seq, ra.Data, ra.Seq, rb.Data, rb.Seq)
		}
		select {
		case <-done:
			wg.Wait()
			if got, at := exported(t, ps, 40, 0); at.Seq != writes || string(got[rkey(a)].Data) != strconv.Itoa(writes) {
				t.Fatalf("final export: %+v", at)
			}
			t.Logf("%d exports while %d writes applied", exports, writes)
			return
		default:
		}
	}
}

func testPartImportRoundTrip(t *testing.T, f Factory) {
	src, dst := f(t), f(t)
	defer src.Close()
	defer dst.Close()
	sp, dp := pstore(t, src), pstore(t, dst)
	a, b, c := urec(t, "oi", "im-a"), urec(t, "oi", "im-b"), urec(t, "oi", "im-c")
	must(t, sp.ApplyPartition(ctx, 50, []*store.Record{a, b}, pos(1, 1)))
	must(t, sp.ApplyPartition(ctx, 50, []*store.Record{trec(b), c}, pos(1, 2)))
	must(t, sp.SetPartitionPromised(ctx, 50, epoch(5, 5)))

	var recs []store.PartitionRecord
	at, err := exportAfter(sp, 50, 0, func(r store.PartitionRecord) error { recs = append(recs, r); return nil })
	must(t, err)
	must(t, dp.SetPartitionPending(ctx, 50, 3, []byte("pending three")))
	must(t, dp.ImportPartition(ctx, 50, recs, at, final))
	st, _ := dp.PartitionState(ctx, 50)
	if st.Committed != at || st.PendingSeq != 3 || string(st.Pending) != "pending three" || st.Purged != 0 {
		t.Fatalf("state after import (a pending write beyond it stays): %+v", st)
	}
	if st.Promised != (store.PartitionEpoch{}) {
		t.Fatalf("an import does not set the promise: %+v", st.Promised)
	}
	for _, r := range []*store.Record{a, c} {
		got, err := dst.Get(ctx, model.KindUser, r.ID)
		must(t, err)
		sameRecord(t, "imported", got, r)
		if got.Fields["username"] == nil || len(got.Unique) != 2 {
			t.Fatalf("imported record lost its index values: %+v", got)
		}
	}
	if _, err := dst.Get(ctx, model.KindUser, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an imported tombstone shows the record")
	}
	if tomb, err := dst.Lookup(ctx, model.KindUser, b.ID); err != nil || !tomb.Deleted || tomb.Partition != "oi" {
		t.Fatalf("imported tombstone: %v %+v", err, tomb)
	}
	if r, err := dst.GetByUnique(ctx, model.KindUser, model.UserEmailKey("oi", "im-c@example.com")); err != nil || r.ID != c.ID {
		t.Fatalf("unique values of imported records: %v %v", err, r)
	}
	// What was imported exports again with the same sequences.
	back, bat := exported(t, dp, 50, 0)
	orig, _ := exported(t, sp, 50, 0)
	if bat != at || !slices.Equal(keysOf(back), keysOf(orig)) {
		t.Fatalf("re-export: %v %+v, want %v %+v", keysOf(back), bat, keysOf(orig), at)
	}
	for k, r := range orig {
		if back[k].Seq != r.Seq {
			t.Fatalf("%s: sequence %d after import, was %d", k, back[k].Seq, r.Seq)
		}
	}
	// A delta: more writes at the source, exported after the destination's position, imported.
	d := urec(t, "oi", "im-d")
	c2 := *c
	c2.Version, c2.Data = c.Version+9, []byte("c2")
	must(t, sp.ApplyPartition(ctx, 50, []*store.Record{d, &c2}, pos(2, 3)))
	var delta []store.PartitionRecord
	at2, err := exportAfter(sp, 50, at.Seq, func(r store.PartitionRecord) error { delta = append(delta, r); return nil })
	must(t, err)
	if len(delta) != 2 || at2 != pos(2, 3) {
		t.Fatalf("delta export: %d records %+v", len(delta), at2)
	}
	must(t, dp.ImportPartition(ctx, 50, delta, at2, final))
	if got, _ := dst.Get(ctx, model.KindUser, c.ID); string(got.Data) != "c2" {
		t.Fatalf("delta import did not update: %q", got.Data)
	}
	if _, err := dst.Get(ctx, model.KindUser, d.ID); err != nil {
		t.Fatal(err)
	}
	if st, _ = dp.PartitionState(ctx, 50); st.Committed != at2 || st.Pending != nil || st.PendingSeq != 0 {
		t.Fatalf("state after delta (the import that reaches the pending write clears it): %+v", st)
	}
	// An empty import still moves the position.
	must(t, dp.ImportPartition(ctx, 50, nil, pos(3, 7), final))
	if st, _ = dp.PartitionState(ctx, 50); st.Committed != pos(3, 7) {
		t.Fatalf("committed after an empty import: %+v", st.Committed)
	}
	// An import also feeds the unique index: a later apply conflicts with nothing stale.
	if _, err := dst.GetByUnique(ctx, model.KindUser, model.UserEmailKey("oi", "im-b@example.com")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a deleted record's value: %v", err)
	}
}

func testPartImportInvalid(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	a := urec(t, "o", "iv-a")
	must(t, ps.ApplyPartition(ctx, 6, []*store.Record{urec(t, "o", "iv-seed")}, pos(1, 5)))
	for _, c := range []struct {
		name string
		recs []store.PartitionRecord
		upTo store.PartitionPos
		want error
	}{
		{"not ahead", []store.PartitionRecord{{Record: a, Seq: 4}}, pos(1, 5), store.ErrPartitionBehind},
		{"behind", nil, pos(1, 2), store.ErrPartitionBehind},
		{"sequence 0", []store.PartitionRecord{{Record: a, Seq: 0}}, pos(1, 8), nil},
		{"sequence past the position", []store.PartitionRecord{{Record: a, Seq: 9}}, pos(1, 8), nil},
		{"no record", []store.PartitionRecord{{Seq: 7}}, pos(1, 8), nil},
		{"position 0", nil, pos(1, 0), nil},
	} {
		err := ps.ImportPartition(ctx, 6, c.recs, c.upTo, final)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, err := s.Get(ctx, model.KindUser, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s: a refused import stored a record", c.name)
		}
		if st, _ := ps.PartitionState(ctx, 6); st.Committed != pos(1, 5) || st.Purged != 0 {
			t.Fatalf("%s: a refused import changed the state: %+v", c.name, st)
		}
	}
	// A full import that is refused removes nothing.
	if err := ps.ImportPartition(ctx, 6, nil, pos(1, 5), whole); !errors.Is(err, store.ErrPartitionBehind) {
		t.Fatalf("full import behind: %v", err)
	}
	if got, _ := exported(t, ps, 6, 0); len(got) != 1 {
		t.Fatalf("a refused full import removed records: %v", keysOf(got))
	}
}

func testPartImportFull(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	const org = "ofull"
	x, y, z := urec(t, org, "fu-x"), urec(t, org, "fu-y"), urec(t, org, "fu-z")
	gone := urec(t, org, "fu-gone-tombstone")
	must(t, ps.ApplyPartition(ctx, 60, []*store.Record{x, y, gone}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, 60, []*store.Record{trec(gone)}, pos(1, 2)))
	must(t, ps.ApplyPartition(ctx, 61, []*store.Record{z}, pos(1, 1))) // another partition: untouched
	plain := newUser(org, "fu-plain")                                  // a plain write: belongs to no partition write
	must(t, users(s).Put(ctx, plain))
	if _, err := ps.PurgePartition(ctx, 60, 2); err != nil { // (nothing below 2 to remove: the purge point is 1)
		t.Fatal(err)
	}
	// The authoritative copy: y changed, q new, a tombstone, and x absent.
	y2 := *y
	y2.Version, y2.Data = y.Version+7, []byte("y2")
	q := urec(t, org, "fu-q")
	tq := trec(urec(t, org, "fu-tq"))
	recs := []store.PartitionRecord{{Record: &y2, Seq: 6}, {Record: q, Seq: 8}, {Record: tq, Seq: 7}}
	must(t, ps.ImportPartition(ctx, 60, recs, pos(4, 9), whole))

	if _, err := s.Lookup(ctx, model.KindUser, x.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("x is absent from the import: removed outright, not tombstoned: %v", err)
	}
	if _, err := s.GetByUnique(ctx, model.KindUser, model.UserEmailKey(org, "fu-x@example.com")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("x's unique values are released: %v", err)
	}
	if _, err := s.Lookup(ctx, model.KindUser, gone.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a tombstone absent from the import is removed too: %v", err)
	}
	if got, err := s.Get(ctx, model.KindUser, y.ID); err != nil || string(got.Data) != "y2" || got.Version != y2.Version {
		t.Fatalf("y replaced: %v %+v", err, got)
	}
	if _, err := s.Get(ctx, model.KindUser, q.ID); err != nil {
		t.Fatal(err)
	}
	if tomb, err := s.Lookup(ctx, model.KindUser, tq.ID); err != nil || !tomb.Deleted {
		t.Fatalf("the imported tombstone: %v %+v", err, tomb)
	}
	if _, err := s.Get(ctx, model.KindUser, z.ID); err != nil {
		t.Fatalf("another partition's record was touched: %v", err)
	}
	if _, err := s.Get(ctx, model.KindUser, plain.ID); err != nil {
		t.Fatalf("a record written without a partition was touched: %v", err)
	}
	got, at := exported(t, ps, 60, 0)
	if at != pos(4, 9) || !slices.Equal(keysOf(got), slices.Sorted(slices.Values([]string{rkey(&y2), rkey(q), rkey(tq)}))) {
		t.Fatalf("after a full import: %v %+v", keysOf(got), at)
	}
	if got[rkey(&y2)].Seq != 6 || got[rkey(q)].Seq != 8 || got[rkey(tq)].Seq != 7 {
		t.Fatal("imported records keep their own sequences")
	}
	// The purge point is the caller's (it purges to its source's, PurgePartition): a full import leaves it as it was.
	if st, _ := ps.PartitionState(ctx, 60); st.Purged != 1 {
		t.Fatalf("purge point after a full import: %d, want 1 (unchanged)", st.Purged)
	}
	if _, err := exportAfter(ps, 60, 9, func(store.PartitionRecord) error { return nil }); err != nil {
		t.Fatalf("a delta from the copy's own position: %v", err)
	}
	if _, err := exportAfter(ps, 60, 0, func(store.PartitionRecord) error { return nil }); err != nil {
		t.Fatalf("a full export is always allowed: %v", err)
	}
	// An import of nothing, full: the partition is emptied.
	must(t, ps.ImportPartition(ctx, 60, nil, pos(4, 10), whole))
	if got, _ := exported(t, ps, 60, 0); len(got) != 0 {
		t.Fatalf("a full import of nothing leaves %v", keysOf(got))
	}
	if _, err := s.Get(ctx, model.KindUser, z.ID); err != nil {
		t.Fatalf("another partition's record was removed: %v", err)
	}
}

func testPartPurge(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	const org = "opurge"
	r1, r2, r3 := urec(t, org, "pg-1"), urec(t, org, "pg-2"), urec(t, org, "pg-3")
	otherT := urec(t, org, "pg-other")
	must(t, ps.ApplyPartition(ctx, 70, []*store.Record{r1}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, 70, []*store.Record{trec(r1)}, pos(1, 2)))
	must(t, ps.ApplyPartition(ctx, 70, []*store.Record{r2}, pos(1, 3)))
	must(t, ps.ApplyPartition(ctx, 70, []*store.Record{trec(r2), r3}, pos(1, 4)))
	must(t, ps.ApplyPartition(ctx, 71, []*store.Record{otherT}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, 71, []*store.Record{trec(otherT)}, pos(1, 2)))

	n, err := ps.PurgePartition(ctx, 70, 3) // tombstones below sequence 3: r1's, at 2
	must(t, err)
	if n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
	if _, err := s.Lookup(ctx, model.KindUser, r1.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a purged tombstone is gone: %v", err)
	}
	if tomb, err := s.Lookup(ctx, model.KindUser, r2.ID); err != nil || !tomb.Deleted {
		t.Fatalf("a tombstone at sequence 4 stays: %v %+v", err, tomb)
	}
	if _, err := s.Get(ctx, model.KindUser, r3.ID); err != nil {
		t.Fatalf("a live record is never purged: %v", err)
	}
	if tomb, err := s.Lookup(ctx, model.KindUser, otherT.ID); err != nil || !tomb.Deleted {
		t.Fatalf("another partition's tombstone: %v %+v", err, tomb)
	}
	st, _ := ps.PartitionState(ctx, 70)
	if st.Purged != 2 || st.Committed != pos(1, 4) {
		t.Fatalf("state after purge: %+v", st)
	}
	if st, _ = ps.PartitionState(ctx, 71); st.Purged != 0 {
		t.Fatalf("another partition's purge point: %d", st.Purged)
	}
	// The history needed to catch up from sequence 1 is gone (the tombstone at 2); from 2 on it is complete.
	if _, err := exportAfter(ps, 70, 1, func(store.PartitionRecord) error { return nil }); !errors.Is(err, store.ErrPartitionPurged) {
		t.Fatalf("export after 1: want the sentinel, got %v", err)
	}
	got, _ := exported(t, ps, 70, 2)
	if want := []string{rkey(r2), rkey(r3)}; !slices.Equal(keysOf(got), slices.Sorted(slices.Values(want))) {
		t.Fatalf("export after 2: %v, want %v", keysOf(got), want)
	}
	got, _ = exported(t, ps, 70, 0)
	if len(got) != 2 {
		t.Fatalf("a full export is allowed and holds what is left: %v", keysOf(got))
	}
	// The point never goes down, and purging nothing is fine.
	if n, err := ps.PurgePartition(ctx, 70, 2); err != nil || n != 0 {
		t.Fatalf("purge below the point: %d %v", n, err)
	}
	if st, _ = ps.PartitionState(ctx, 70); st.Purged != 2 {
		t.Fatalf("the purge point went down: %d", st.Purged)
	}
	if n, err := ps.PurgePartition(ctx, 70, 5); err != nil || n != 1 {
		t.Fatalf("purge below 5: %d %v", n, err)
	}
	if st, _ = ps.PartitionState(ctx, 70); st.Purged != 4 {
		t.Fatalf("purge point after purging below 5: %d", st.Purged)
	}
	// A purge point of an untouched partition, and sequence 0 and 1 (nothing below).
	if n, err := ps.PurgePartition(ctx, 72, 1); err != nil || n != 0 {
		t.Fatalf("purge below 1: %d %v", n, err)
	}
	if st, _ = ps.PartitionState(ctx, 72); st.Purged != 0 {
		t.Fatalf("purge point after purging below 1: %d", st.Purged)
	}
}

// Partitions share no state: the position, the promise, the records.
func testPartIndependent(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	a, b := urec(t, "o1", "ind-a"), urec(t, "o1", "ind-b")
	must(t, ps.ApplyPartition(ctx, 0, []*store.Record{a}, pos(1, 3)))
	must(t, ps.ApplyPartition(ctx, 63, []*store.Record{b}, pos(1, 1)))
	must(t, ps.SetPartitionPromised(ctx, 0, epoch(9, 1)))
	s0, _ := ps.PartitionState(ctx, 0)
	s63, _ := ps.PartitionState(ctx, 63)
	if s0.Committed.Seq != 3 || s0.Promised != epoch(9, 1) || s63.Committed.Seq != 1 || s63.Promised != (store.PartitionEpoch{}) {
		t.Fatalf("states: %+v %+v", s0, s63)
	}
	if got, _ := exported(t, ps, 0, 0); len(got) != 1 || got[rkey(a)].Record == nil {
		t.Fatalf("partition 0: %v", keysOf(got))
	}
	// Partition 0 is a partition like another: a record written without a stamp is not in it.
	must(t, users(s).Put(ctx, newUser("o1", "ind-plain")))
	if got, _ := exported(t, ps, 0, 0); len(got) != 1 {
		t.Fatalf("a plain write is in partition 0: %v", keysOf(got))
	}
}

func testPartConcurrent(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	const parts, writes = 6, 25
	var wg sync.WaitGroup
	errs := make(chan error, parts)
	for p := range parts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := uint64(1); n <= writes; n++ {
				r := urec(t, fmt.Sprintf("conc-%d", p), fmt.Sprintf("c-%d-%d", p, n))
				if err := ps.ApplyPartition(ctx, 80+p, []*store.Record{r}, pos(1, n)); err != nil {
					errs <- err
					return
				}
				if n%5 == 0 {
					if err := ps.SetPartitionPending(ctx, 80+p, n+1, []byte("p")); err != nil {
						errs <- err
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for p := range parts {
		got, at := exported(t, ps, 80+p, 0)
		if len(got) != writes || at.Seq != writes {
			t.Fatalf("partition %d: %d records, position %d", 80+p, len(got), at.Seq)
		}
	}
}

func testPartWipe(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	must(t, ps.ApplyPartition(ctx, 5, []*store.Record{urec(t, "o", "wipe-a")}, pos(1, 1)))
	must(t, ps.SetPartitionPromised(ctx, 5, epoch(2, 2)))
	wiper, ok := s.(interface{ Wipe(context.Context) error })
	if !ok {
		t.Skip("the store has no Wipe")
	}
	must(t, wiper.Wipe(ctx))
	if st, _ := ps.PartitionState(ctx, 5); st.Committed.Seq != 0 || st.Promised.Counter != 0 || st.Purged != 0 {
		t.Fatalf("state after Wipe: %+v", st)
	}
	if got, _ := exported(t, ps, 5, 0); len(got) != 0 {
		t.Fatalf("records after Wipe: %v", keysOf(got))
	}
}

// start is called once, before any record, with the position the snapshot reflects; an error from it stops the export; a
// purged history is reported without calling it.
func testPartExportStart(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	must(t, ps.ApplyPartition(ctx, 80, []*store.Record{urec(t, "os", "es-a"), urec(t, "os", "es-b")}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, 80, []*store.Record{urec(t, "os", "es-c")}, pos(1, 2)))
	var order []string
	err := ps.ExportPartition(ctx, 80, 0, func(at store.PartitionPos) error {
		if at != pos(1, 2) {
			t.Errorf("start position %+v", at)
		}
		order = append(order, "start")
		return nil
	}, func(store.PartitionRecord) error { order = append(order, "record"); return nil })
	must(t, err)
	if len(order) != 4 || order[0] != "start" {
		t.Fatalf("calls: %v", order)
	}
	// an error from start: no record is delivered
	stop := errors.New("stop")
	n := 0
	err = ps.ExportPartition(ctx, 80, 0, func(store.PartitionPos) error { return stop }, func(store.PartitionRecord) error { n++; return nil })
	if !errors.Is(err, stop) || n != 0 {
		t.Fatalf("an error from start: %v after %d records", err, n)
	}
	// a partition never written reports the zero position, once
	calls := 0
	must(t, ps.ExportPartition(ctx, 81, 0, func(at store.PartitionPos) error {
		calls++
		if at != (store.PartitionPos{}) {
			t.Errorf("position of an empty partition %+v", at)
		}
		return nil
	}, func(store.PartitionRecord) error { return nil }))
	if calls != 1 {
		t.Fatalf("start called %d times", calls)
	}
	// purged: the sentinel, and start is not called
	_, err = ps.PurgePartition(ctx, 80, 3)
	must(t, err)
	called := false
	err = ps.ExportPartition(ctx, 80, 1, func(store.PartitionPos) error { called = true; return nil }, func(store.PartitionRecord) error { return nil })
	if !errors.Is(err, store.ErrPartitionPurged) || called {
		t.Fatalf("a purged history: %v (start called: %v)", err, called)
	}
}

// batches returns recs in slices of at most n.
func batches(recs []store.PartitionRecord, n int) [][]store.PartitionRecord {
	var out [][]store.PartitionRecord
	for len(recs) > n {
		out, recs = append(out, recs[:n]), recs[n:]
	}
	return append(out, recs)
}

// A partition imported in several calls: the records are in as the batches arrive, stamped with their own sequences, the
// position moves with the last one only, and what a crash leaves (the batches before the last) is committed data of the
// source above the position, which an export does not show; the same import repeated completes it.
func testPartImportBatches(t *testing.T, f Factory) {
	src, dst := f(t), f(t)
	defer src.Close()
	defer dst.Close()
	sp, dp := pstore(t, src), pstore(t, dst)
	var all []*store.Record
	for i := range 25 {
		all = append(all, urec(t, "ob", fmt.Sprintf("ib-%02d", i)))
	}
	for i := 0; i < len(all); i += 5 {
		must(t, sp.ApplyPartition(ctx, 82, all[i:i+5], pos(1, uint64(i/5+1))))
	}
	var recs []store.PartitionRecord
	at, err := exportAfter(sp, 82, 0, func(r store.PartitionRecord) error { recs = append(recs, r); return nil })
	must(t, err)
	if at != pos(1, 5) || len(recs) != 25 {
		t.Fatalf("source export: %+v, %d records", at, len(recs))
	}
	bs := batches(recs, 10)
	if len(bs) != 3 {
		t.Fatalf("test set-up: %d batches", len(bs))
	}
	// the first two batches only (the process stops here)
	must(t, dp.ImportPartition(ctx, 82, bs[0], at, store.ImportStep{First: true}))
	must(t, dp.ImportPartition(ctx, 82, bs[1], at, store.ImportStep{}))
	if st, _ := dp.PartitionState(ctx, 82); st.Committed != (store.PartitionPos{}) {
		t.Fatalf("the position moved before the last batch: %+v", st.Committed)
	}
	if n, _ := dst.Count(ctx, model.KindUser, ""); n != 20 {
		t.Fatalf("%d records stored after two batches, want 20", n)
	}
	if _, err := exportAfter(dp, 82, 0, func(store.PartitionRecord) error { return nil }); !errors.Is(err, store.ErrImportUnfinished) {
		t.Fatalf("an export with records above the committed position: %v", err)
	}
	// the import repeated from the start (what the next catch-up does) completes it
	for i, b := range bs {
		must(t, dp.ImportPartition(ctx, 82, b, at, store.ImportStep{First: i == 0, Final: i == len(bs)-1}))
	}
	st, _ := dp.PartitionState(ctx, 82)
	if st.Committed != at || st.Purged != 0 {
		t.Fatalf("state after the import: %+v", st)
	}
	back, bat := exported(t, dp, 82, 0)
	orig, _ := exported(t, sp, 82, 0)
	if bat != at || !slices.Equal(keysOf(back), keysOf(orig)) {
		t.Fatalf("re-export: %d records %+v, want %d", len(back), bat, len(orig))
	}
	for k, r := range orig {
		if back[k].Seq != r.Seq {
			t.Fatalf("%s: sequence %d, was %d", k, back[k].Seq, r.Seq)
		}
	}
	// a batch after the position has moved is refused
	if err := dp.ImportPartition(ctx, 82, bs[0], at, store.ImportStep{}); !errors.Is(err, store.ErrPartitionBehind) {
		t.Fatalf("a batch of a finished import: %v", err)
	}
}

// A full import in several calls resets the partition at its First call (every record of it removed, and told), stores
// what the batches bring, moves the position only with the Final call, and is not fooled by what an import that did not
// finish left behind: the partition ends up exactly as the source's records.
func testPartImportFullBatches(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	const org = "ofb"
	var keep, drop []*store.Record
	for i := range 12 {
		r := urec(t, org, fmt.Sprintf("fb-keep-%02d", i))
		keep = append(keep, r)
		d := urec(t, org, fmt.Sprintf("fb-drop-%02d", i))
		drop = append(drop, d)
	}
	must(t, ps.ApplyPartition(ctx, 83, append(slices.Clone(keep), drop...), pos(1, 1)))
	other := urec(t, "oother", "fb-other")
	must(t, ps.ApplyPartition(ctx, 84, []*store.Record{other}, pos(1, 1)))
	plain := newUser(org, "fb-plain")
	must(t, users(s).Put(ctx, plain)) // belongs to no partition write

	var recs []store.PartitionRecord
	for i, r := range keep {
		r2 := *r
		r2.Version, r2.Data = r.Version+3, []byte("new")
		recs = append(recs, store.PartitionRecord{Record: &r2, Seq: uint64(i%5) + 2})
	}
	nu := urec(t, org, "fb-new")
	recs = append(recs, store.PartitionRecord{Record: nu, Seq: 7})
	bs := batches(recs, 4)

	// report collects what an import tells it removed.
	var removed []string
	report := func(k model.Kind, id string) { removed = append(removed, string(k)+"/"+id) }
	sorted := func(rs ...*store.Record) []string {
		var out []string
		for _, r := range rs {
			out = append(out, rkey(r))
		}
		slices.Sort(out)
		return out
	}

	// An earlier import of the same partition that stopped after one batch, which brought a record the new one does not
	// (and one it does not bring back): its reset removed everything the partition held.
	stale := urec(t, org, "fb-stale")
	must(t, ps.ImportPartition(ctx, 83, []store.PartitionRecord{{Record: stale, Seq: 3}, {Record: drop[0], Seq: 3}}, pos(2, 8),
		store.ImportStep{Full: true, First: true, Removed: report}))
	slices.Sort(removed)
	if want := sorted(append(slices.Clone(keep), drop...)...); !slices.Equal(removed, want) {
		t.Fatalf("the first import's reset removed %v, want %v", removed, want)
	}
	removed = nil

	step := func(i int) store.ImportStep {
		return store.ImportStep{Full: true, First: i == 0, Final: i == len(bs)-1, Removed: report}
	}
	for i, b := range bs[:len(bs)-1] {
		must(t, ps.ImportPartition(ctx, 83, b, pos(3, 9), step(i)))
		if st, _ := ps.PartitionState(ctx, 83); st.Committed != pos(1, 1) || st.Purged != 0 {
			t.Fatalf("the position moved before the last batch: %+v", st)
		}
		wantImporting(t, ps, 83, true) // from the First call, whatever position it still shows
		if i == 0 {
			// the reset of this import removed what the earlier one left
			slices.Sort(removed)
			if want := sorted(stale, drop[0]); !slices.Equal(removed, want) {
				t.Fatalf("the reset removed %v, want %v", removed, want)
			}
			if _, err := s.Lookup(ctx, model.KindUser, stale.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a record of the earlier import survived the reset: %v", err)
			}
		}
		if err := ps.ExportPartition(ctx, 83, 0, func(store.PartitionPos) error { return nil }, func(store.PartitionRecord) error { return nil }); !errors.Is(err, store.ErrImportUnfinished) {
			t.Fatalf("an export before the last batch: %v", err)
		}
	}
	removed = removed[:0]
	must(t, ps.ImportPartition(ctx, 83, bs[len(bs)-1], pos(3, 9), step(len(bs)-1)))
	if len(removed) != 0 {
		t.Fatalf("records removed by the last batch: %v", removed)
	}
	wantImporting(t, ps, 83, false)
	got, at := exported(t, ps, 83, 0)
	var wantKeys []string
	for _, r := range recs {
		wantKeys = append(wantKeys, rkey(r.Record))
	}
	slices.Sort(wantKeys)
	if at != pos(3, 9) || !slices.Equal(keysOf(got), wantKeys) {
		t.Fatalf("after the import: %v %+v", keysOf(got), at)
	}
	if st, _ := ps.PartitionState(ctx, 83); st.Purged != 0 {
		t.Fatalf("purge point %d, want 0 (a full import leaves it to the caller)", st.Purged)
	}
	for _, d := range drop {
		if _, err := s.Lookup(ctx, model.KindUser, d.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s not removed: %v", d.ID, err)
		}
		if _, err := s.GetByUnique(ctx, model.KindUser, model.UserEmailKey(org, d.Fields["username"].(string)+"@example.com")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the unique values of %s not released: %v", d.ID, err)
		}
	}
	// the records it brought back hold their unique values again
	if u, err := s.GetByUnique(ctx, model.KindUser, model.UserEmailKey(org, keep[3].Fields["username"].(string)+"@example.com")); err != nil || u.ID != keep[3].ID {
		t.Fatalf("the unique value of a record brought back: %v %v", err, u)
	}
	if r, err := s.Get(ctx, model.KindUser, keep[3].ID); err != nil || string(r.Data) != "new" {
		t.Fatalf("a kept record: %v %+v", err, r)
	}
	if _, err := s.Get(ctx, model.KindUser, other.ID); err != nil {
		t.Fatalf("another partition's record: %v", err)
	}
	if _, err := s.Get(ctx, model.KindUser, plain.ID); err != nil {
		t.Fatalf("a record of no partition write: %v", err)
	}
	// another full import right after resets again, so it holds only what it brings
	must(t, ps.ImportPartition(ctx, 83, recs[:2], pos(4, 10), whole))
	if got, _ := exported(t, ps, 83, 0); len(got) != 2 {
		t.Fatalf("second full import left %v", keysOf(got))
	}
}

// A full import that starts again at the same position as one that did not finish (the next catch-up from the same
// source) is not fooled by what the first left behind: the reset removes it all, and only what the second brings is there.
func testPartImportFullSamePosition(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	const org = "ofs"
	kept, extra := urec(t, org, "fs-kept"), urec(t, org, "fs-extra")
	// the first import stops after one batch, which brought both
	must(t, ps.ImportPartition(ctx, 85, []store.PartitionRecord{{Record: kept, Seq: 1}, {Record: extra, Seq: 2}}, pos(1, 4),
		store.ImportStep{Full: true, First: true}))
	// the one that follows, at the same position, brings one of them
	var removed []string
	must(t, ps.ImportPartition(ctx, 85, []store.PartitionRecord{{Record: kept, Seq: 1}}, pos(1, 4),
		store.ImportStep{Full: true, First: true, Final: true, Removed: func(k model.Kind, id string) {
			removed = append(removed, string(k)+"/"+id)
		}}))
	want := []string{rkey(kept), rkey(extra)}
	slices.Sort(want)
	slices.Sort(removed)
	if !slices.Equal(removed, want) {
		t.Fatalf("removed %v, want %v", removed, want)
	}
	if _, err := s.Lookup(ctx, model.KindUser, extra.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a record only the unfinished import brought is still there: %v", err)
	}
	if _, err := s.Get(ctx, model.KindUser, kept.ID); err != nil {
		t.Fatalf("the record the import brought: %v", err)
	}
	if got, at := exported(t, ps, 85, 0); at != pos(1, 4) || len(got) != 1 || got[rkey(kept)].Seq != 1 {
		t.Fatalf("export after the import: %+v %v", at, keysOf(got))
	}
}

// wantImporting checks PartitionState(p).Importing: set between a full import's First and Final calls, not otherwise.
func wantImporting(t testing.TB, ps store.PartitionStore, p int, want bool) {
	t.Helper()
	if st, err := ps.PartitionState(ctx, p); err != nil || st.Importing != want {
		t.Fatalf("partition %d state after a full import's step: importing %v (%v), want %v", p, st.Importing, err, want)
	}
}

// tombstone is one entry PartitionTombstones lists.
type tombstone struct {
	seq     uint64
	version hlc.Timestamp
}

// tombstones collects PartitionTombstones, ordered by sequence then version (the order of the listing is free).
func tombstones(t testing.TB, ps store.PartitionStore, p int, after, upTo uint64) []tombstone {
	t.Helper()
	var out []tombstone
	must(t, ps.PartitionTombstones(ctx, p, after, upTo, func(seq uint64, v hlc.Timestamp) error {
		out = append(out, tombstone{seq, v})
		return nil
	}))
	slices.SortFunc(out, func(a, b tombstone) int {
		if a.seq != b.seq {
			return cmp.Compare(a.seq, b.seq)
		}
		return cmp.Compare(a.version, b.version)
	})
	return out
}

// Store.Purge leaves the tombstones of a partition alone, however old: PurgePartition removes them, on the partition's
// own schedule, and moves the purge point with them (store.Store).
func testPurgeKeepsPartitionTombstones(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	u := urec(t, "opurge", "keep-tomb")
	d := trec(u)
	must(t, ps.ApplyPartition(ctx, 82, []*store.Record{u}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, 82, []*store.Record{d}, pos(1, 2)))
	_, err := s.Purge(ctx, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	must(t, err)
	if got := tombstones(t, ps, 82, 0, 2); len(got) != 1 || got[0] != (tombstone{2, d.Version}) {
		t.Fatalf("tombstones after Purge: %v, want the partition's tombstone kept", got)
	}
}

// PartitionTombstones lists the tombstones of one partition by sequence (bounds included at the top, excluded at the
// bottom), whatever kind they are, and only those: not live records, not a record created again over a tombstone, not
// what a purge removed, not another partition's, and not what a crashed import left above the committed position.
func testPartTombstones(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	const org = "otomb"
	u1, u2, u3 := urec(t, org, "tb-1"), urec(t, org, "tb-2"), urec(t, org, "tb-3")
	sess, err := store.Encode(&model.Session{UserID: u1.ID, OrgID: org, Expires: time.Now().Add(time.Hour)})
	must(t, err)
	d1, d2, dSess := trec(u1), trec(u2), trec(sess)
	must(t, ps.ApplyPartition(ctx, 80, []*store.Record{u1, u2, u3, sess}, pos(1, 1)))
	if got := tombstones(t, ps, 80, 0, 1); len(got) != 0 {
		t.Fatalf("live records listed as tombstones: %v", got)
	}
	must(t, ps.ApplyPartition(ctx, 80, []*store.Record{d1}, pos(1, 2)))
	must(t, ps.ApplyPartition(ctx, 80, []*store.Record{d2, dSess}, pos(1, 3))) // two kinds in one write
	other := urec(t, "oother", "tb-other")
	must(t, ps.ApplyPartition(ctx, 81, []*store.Record{other}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, 81, []*store.Record{trec(other)}, pos(1, 2)))

	want := []tombstone{{2, d1.Version}, {3, d2.Version}, {3, dSess.Version}}
	slices.SortFunc(want, func(a, b tombstone) int {
		if a.seq != b.seq {
			return cmp.Compare(a.seq, b.seq)
		}
		return cmp.Compare(a.version, b.version)
	})
	if got := tombstones(t, ps, 80, 0, 3); !slices.Equal(got, want) {
		t.Fatalf("tombstones: %v, want %v", got, want)
	}
	// Bounds: above afterSeq, up to upTo.
	if got := tombstones(t, ps, 80, 2, 3); len(got) != 2 || got[0].seq != 3 {
		t.Fatalf("after 2: %v", got)
	}
	if got := tombstones(t, ps, 80, 0, 2); len(got) != 1 || got[0] != (tombstone{2, d1.Version}) {
		t.Fatalf("up to 2: %v", got)
	}
	if got := tombstones(t, ps, 80, 3, 9); len(got) != 0 {
		t.Fatalf("after the last: %v", got)
	}
	// Another partition's tombstone is not in it.
	if got := tombstones(t, ps, 81, 0, 2); len(got) != 1 || got[0].seq != 2 {
		t.Fatalf("partition 81: %v", got)
	}
	// A record created again over a tombstone is live: no longer listed.
	again := *u1
	again.Version = store.Clock.Now()
	must(t, ps.ApplyPartition(ctx, 80, []*store.Record{&again}, pos(1, 4)))
	if got := tombstones(t, ps, 80, 0, 4); len(got) != 2 || got[0].seq != 3 {
		t.Fatalf("after re-creating one: %v", got)
	}
	// A stop from the callback is returned as it is.
	stop := errors.New("stop")
	if err := ps.PartitionTombstones(ctx, 80, 0, 4, func(uint64, hlc.Timestamp) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("callback error: %v", err)
	}
	// An import that did not finish: its tombstone is above the committed position, which the caller bounds by.
	v := urec(t, org, "tb-import")
	must(t, ps.ImportPartition(ctx, 80, []store.PartitionRecord{{Record: trec(v), Seq: 7}}, pos(1, 8),
		store.ImportStep{First: true}))
	if got := tombstones(t, ps, 80, 0, 4); len(got) != 2 {
		t.Fatalf("an unfinished import's tombstone is listed: %v", got)
	}
	must(t, ps.ImportPartition(ctx, 80, nil, pos(1, 8), store.ImportStep{Final: true}))
	if got := tombstones(t, ps, 80, 0, 8); len(got) != 3 || got[2].seq != 7 {
		t.Fatalf("after the import finished: %v", got)
	}
	// Purged ones are gone.
	if _, err := ps.PurgePartition(ctx, 80, 4); err != nil {
		t.Fatal(err)
	}
	if got := tombstones(t, ps, 80, 0, 8); len(got) != 1 || got[0].seq != 7 {
		t.Fatalf("after the purge: %v", got)
	}
	// A full import replaces the partition: the tombstones are the source's.
	only := urec(t, org, "tb-full")
	must(t, ps.ImportPartition(ctx, 82, []store.PartitionRecord{{Record: only, Seq: 1}, {Record: trec(only), Seq: 2}}, pos(1, 2), whole))
	if got := tombstones(t, ps, 82, 0, 2); len(got) != 1 || got[0].seq != 2 {
		t.Fatalf("after a full import: %v", got)
	}
}

// unfinishedImport leaves partition p as a crash in the middle of an import does: r committed at 1, then a new version of
// it brought by a batch that is not the final one, so stored at 2 with the position still at 1. It returns the new version
// and the step that would finish the import.
func unfinishedImport(t testing.TB, ps store.PartitionStore, p int, org string) (*store.Record, store.ImportStep) {
	t.Helper()
	r := urec(t, org, "unf-a")
	must(t, ps.ApplyPartition(ctx, p, []*store.Record{r}, pos(1, 1)))
	r2 := *r
	r2.Version++
	must(t, ps.ImportPartition(ctx, p, []store.PartitionRecord{{Record: &r2, Seq: 2}}, pos(1, 2), store.ImportStep{First: true}))
	return &r2, store.ImportStep{Final: true}
}

// An export never shows a partition whose import has not finished: the record the import overwrote is above the committed
// position, so the export would miss it while advertising the position below it. start is not called.
func testPartExportUnfinished(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	r2, finish := unfinishedImport(t, ps, 83, "ou")
	called := false
	err := ps.ExportPartition(ctx, 83, 0, func(store.PartitionPos) error { called = true; return nil }, func(store.PartitionRecord) error { return nil })
	if !errors.Is(err, store.ErrImportUnfinished) || called {
		t.Fatalf("an export during an unfinished import: %v (start called: %v)", err, called)
	}
	// another partition is not affected
	must(t, ps.ApplyPartition(ctx, 84, []*store.Record{urec(t, "ou", "unf-b")}, pos(1, 1)))
	if got, _ := exported(t, ps, 84, 0); len(got) != 1 {
		t.Fatalf("another partition exports %d records", len(got))
	}
	// the import finished (the same batch again, as the next catch-up does)
	must(t, ps.ImportPartition(ctx, 83, []store.PartitionRecord{{Record: r2, Seq: 2}}, pos(1, 2), finish))
	got, at := exported(t, ps, 83, 0)
	if at != pos(1, 2) || len(got) != 1 || got[rkey(r2)].Seq != 2 || got[rkey(r2)].Version != r2.Version {
		t.Fatalf("export after the import: %+v %v", at, got)
	}
}

// resetImport sets up partition p for a full import whose reset removes records before the position moves: a and b
// committed at (1, 2), then a full import to (2, 5) that brings only a, at its old sequence, so that nothing it stored lies
// above the committed position. during is called after the reset's removal of each record has committed and before the
// position is written (the Removed step of the import, the only moment a test can reach). It returns the import's
// arguments.
func resetImport(t testing.TB, ps store.PartitionStore, p int, org string, during func()) (a, b *store.Record, imp func() error) {
	a, b = urec(t, org, "sw-a"), urec(t, org, "sw-b")
	must(t, ps.ApplyPartition(ctx, p, []*store.Record{a}, pos(1, 1)))
	must(t, ps.ApplyPartition(ctx, p, []*store.Record{b}, pos(1, 2)))
	step := whole
	step.Removed = func(model.Kind, string) { during() }
	imp = func() error {
		return ps.ImportPartition(ctx, p, []store.PartitionRecord{{Record: a, Seq: 1}}, pos(2, 5), step)
	}
	return a, b, imp
}

// While a full import's reset has removed records but the position has not moved (a crash here leaves the old position with
// records missing, and nothing above it), an export never advertises the old position: it is refused, or (a backend whose
// reset and position are one step) it already shows the new one.
func testPartExportAfterReset(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	calls := 0
	a, b, imp := resetImport(t, ps, 85, "osw", func() {
		calls++
		got, at, err := exportOf(ps, 85)
		if errors.Is(err, store.ErrImportUnfinished) {
			return
		}
		if err != nil || at != pos(2, 5) || len(got) != 1 {
			t.Errorf("an export between the reset and the position: %v %+v %v", err, at, got)
		}
	})
	must(t, imp())
	if calls != 2 {
		t.Fatalf("%d records reported removed, want 2", calls)
	}
	got, at := exported(t, ps, 85, 0)
	if at != pos(2, 5) || len(got) != 1 || got[rkey(a)].Seq != 1 {
		t.Fatalf("export after the import: %+v %v", at, keysOf(got))
	}
	if _, err := s.Lookup(ctx, model.KindUser, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the record the import did not bring: %v", err)
	}
	// A reset with nothing yet brought leaves nothing above the position either: only the marker says the import is
	// unfinished, until its Final call.
	c := urec(t, "osw", "sw-c")
	must(t, ps.ApplyPartition(ctx, 86, []*store.Record{c}, pos(1, 1)))
	must(t, ps.ImportPartition(ctx, 86, nil, pos(2, 5), store.ImportStep{Full: true, First: true}))
	refusesExport(t, s, 86)
	must(t, ps.ImportPartition(ctx, 86, []store.PartitionRecord{{Record: c, Seq: 1}}, pos(2, 5), store.ImportStep{Full: true, Final: true}))
	if got, at := exported(t, ps, 86, 0); at != pos(2, 5) || len(got) != 1 {
		t.Fatalf("export after the import: %+v %v", at, keysOf(got))
	}
}

// A snapshot whose view holds a partition part-way through a full import is refused (store.Snapshotter): the import's
// reset removed records, and a backup of the view would be complete, verifiable and short. Before the import and once
// it has finished, a snapshot is taken.
func testPartSnapshotUnfinished(t *testing.T, f Factory) {
	s := f(t)
	defer s.Close()
	ps := pstore(t, s)
	sn, ok := s.(store.Snapshotter)
	if !ok {
		t.Skip("no snapshots")
	}
	snap := func() error {
		v, err := sn.Snapshot(ctx)
		if err == nil {
			v.Close()
		}
		return err
	}
	if err := snap(); errors.Is(err, store.ErrNoSnapshot) {
		t.Skip("no snapshots")
	} else if err != nil {
		t.Fatalf("a snapshot before the import: %v", err)
	}
	c := urec(t, "osn", "sn-c")
	must(t, ps.ApplyPartition(ctx, 87, []*store.Record{c}, pos(1, 1)))
	must(t, ps.ImportPartition(ctx, 87, nil, pos(2, 5), store.ImportStep{Full: true, First: true}))
	if err := snap(); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a snapshot while a full import is unfinished: %v, want ErrUnavailable", err)
	}
	must(t, ps.ImportPartition(ctx, 87, []store.PartitionRecord{{Record: c, Seq: 1}}, pos(2, 5), store.ImportStep{Full: true, Final: true}))
	if err := snap(); err != nil {
		t.Fatalf("a snapshot once the import has finished: %v", err)
	}

	// An incremental import cut short leaves records above the committed position and no marker: a snapshot would hold
	// half of what the source committed in one write (a changed record next to one the same write changed and the import
	// did not reach yet). So does one into a partition that has never committed anything.
	for i, base := range []uint64{1, 0} {
		p := 88 + i
		if base > 0 {
			must(t, ps.ApplyPartition(ctx, p, []*store.Record{urec(t, "osn", fmt.Sprintf("sn-i%d", i))}, pos(1, base)))
		}
		r := urec(t, "osn", fmt.Sprintf("sn-j%d", i))
		must(t, ps.ImportPartition(ctx, p, []store.PartitionRecord{{Record: r, Seq: base + 2}}, pos(2, base+3), store.ImportStep{}))
		if err := snap(); !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("a snapshot while an incremental import is unfinished (committed %d): %v, want ErrUnavailable", base, err)
		}
		must(t, ps.ImportPartition(ctx, p, nil, pos(2, base+3), store.ImportStep{Final: true}))
		if err := snap(); err != nil {
			t.Fatalf("a snapshot once the incremental import has finished: %v", err)
		}
	}
}

// exportOf exports a whole partition, returning the records, the position the export started with and its error.
func exportOf(ps store.PartitionStore, p int) (map[string]store.PartitionRecord, store.PartitionPos, error) {
	out := map[string]store.PartitionRecord{}
	at, err := exportAfter(ps, p, 0, func(r store.PartitionRecord) error { out[rkey(r.Record)] = r; return nil })
	return out, at, err
}
