package storetest

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// The storage contract's cases (package store): retried requests, transactions, unique values per kind, and failed
// writes that leave the caller's record as it was.

// A write whose request is found stored is the retry of a write that was applied: it is answered as done, with the
// stored version, and nothing is written again. Another request is refused as usual; a write with no request id is
// given one.
func testRetries(t *testing.T, s store.Store) {
	u := newUser("org1", "rita")
	create, _ := store.Encode(u)
	create.Req = store.NewReq()
	must(t, s.CompareAndPut(ctx, create, 0))
	v1 := create.Version
	again, _ := store.EncodeAsIs(u)
	again.Req = create.Req
	if err := s.CompareAndPut(ctx, again, 0); err != nil {
		t.Fatalf("a retried create: %v", err)
	}
	if again.Version != v1 {
		t.Fatalf("a retried create was given version %d, the stored one is %d", again.Version, v1)
	}
	other, _ := store.EncodeAsIs(u)
	other.Req = store.NewReq()
	if err := s.CompareAndPut(ctx, other, 0); !errors.Is(err, store.ErrStale) {
		t.Fatalf("another request's create over a live record: want ErrStale, got %v", err)
	}

	// An update retried after it was applied: its expectation is now stale, and it is still answered as done.
	u.GivenName = "Updated"
	update, _ := store.Encode(u)
	update.Req = store.NewReq()
	must(t, s.CompareAndPut(ctx, update, v1))
	v2 := update.Version
	retry, _ := store.EncodeAsIs(u)
	retry.Req = update.Req
	if err := s.CompareAndPut(ctx, retry, v1); err != nil {
		t.Fatalf("a retried update: %v", err)
	}
	if retry.Version != v2 {
		t.Fatalf("a retried update was given version %d, the stored one is %d", retry.Version, v2)
	}

	// A put retried: nothing is written again.
	put, _ := store.EncodeAsIs(u)
	put.Req = store.NewReq()
	must(t, s.Put(ctx, put))
	v3 := put.Version
	putAgain, _ := store.EncodeAsIs(u)
	putAgain.Req = put.Req
	must(t, s.Put(ctx, putAgain))
	if putAgain.Version != v3 {
		t.Fatalf("a retried put was given version %d, the stored one is %d", putAgain.Version, v3)
	}
	if got, err := s.Get(ctx, model.KindUser, u.ID); err != nil || got.Version != v3 || got.Req != put.Req {
		t.Fatalf("after a retried put: %+v %v", got, err)
	}

	// A deletion retried.
	tomb := store.Tombstone(model.KindUser, u.ID)
	tomb.Req = store.NewReq()
	must(t, s.Put(ctx, tomb))
	tombAgain := store.Tombstone(model.KindUser, u.ID)
	tombAgain.Req = tomb.Req
	must(t, s.Put(ctx, tombAgain))
	if _, err := s.Get(ctx, model.KindUser, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after a retried deletion: %v", err)
	}

	// A write that names no request is given one, stored with it and not left on the writer's record: the record
	// changed and written again is another write, applied.
	plain, _ := store.Encode(newUser("org1", "sid"))
	must(t, s.Put(ctx, plain))
	if plain.Req != "" {
		t.Fatalf("the request id the store made was left on the writer's record: %q", plain.Req)
	}
	got, err := s.Get(ctx, model.KindUser, plain.ID)
	if err != nil || got.Req == "" {
		t.Fatalf("a write with no request id was not given one: %+v %v", got, err)
	}
	first := got.Version
	plain.Data = got.Data
	must(t, s.Put(ctx, plain))
	if again, err := s.Get(ctx, model.KindUser, plain.ID); err != nil || again.Version <= first || again.Req == got.Req {
		t.Fatalf("a record written again was taken for a retry: %+v %v", again, err)
	}
}

// A transaction applies all of its writes or none; uniqueness holds across them and against what is stored, as the
// earlier writes of the transaction leave it.
func testTx(t *testing.T, s store.Store) {
	tb := users(s)
	a := newUser("org1", "tx-a")
	must(t, tb.Put(ctx, a))
	va := a.Version
	stored := func(id string) *store.Record {
		t.Helper()
		r, err := s.Get(ctx, model.KindUser, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		must(t, err)
		return r
	}
	enc := func(u *model.User) *store.Record {
		t.Helper()
		r, err := store.Encode(u)
		must(t, err)
		return r
	}

	// All of it: an update and a create.
	a.GivenName = "Changed"
	ra := enc(a)
	b := newUser("org1", "tx-b")
	rb := enc(b)
	must(t, s.Tx(ctx, []store.Op{{Rec: ra, Match: true, Expect: va}, {Rec: rb, Match: true}}))
	if r := stored(a.ID); r == nil || r.Version != ra.Version || ra.Version <= va {
		t.Fatalf("the update: stored %+v, written %d over %d", r, ra.Version, va)
	}
	if r := stored(b.ID); r == nil || r.Version != rb.Version {
		t.Fatalf("the create: stored %+v", r)
	}
	if sa, sb := stored(a.ID), stored(b.ID); sa.Req == "" || sa.Req != sb.Req {
		t.Fatalf("a transaction's records share its request id: %q %q", sa.Req, sb.Req)
	}
	va = ra.Version

	// None of it: a write that refuses undoes the others.
	c := newUser("org1", "tx-c")
	a.GivenName = "Lost"
	if err := s.Tx(ctx, []store.Op{{Rec: enc(c)}, {Rec: enc(a), Match: true, Expect: va - 1}}); !errors.Is(err, store.ErrStale) {
		t.Fatalf("a transaction with a stale write: want ErrStale, got %v", err)
	}
	if stored(c.ID) != nil {
		t.Fatal("a refused transaction's create was stored")
	}
	if r := stored(a.ID); r == nil || r.Version != va {
		t.Fatal("a refused transaction changed a record")
	}
	missing := newUser("org1", "tx-missing")
	if err := s.Tx(ctx, []store.Op{{Rec: enc(c)}, {Rec: enc(missing), Match: true, Expect: va}}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a transaction updating a missing record: want ErrNotFound, got %v", err)
	}
	if stored(c.ID) != nil {
		t.Fatal("a refused transaction's create was stored")
	}

	// Uniqueness across the transaction, and against what is stored.
	d1, d2 := newUser("org1", "tx-d1"), newUser("org1", "tx-d2")
	d2.Email = d1.Email
	if err := s.Tx(ctx, []store.Op{{Rec: enc(d1)}, {Rec: enc(d2)}}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("two writes claiming one value: want ErrConflict, got %v", err)
	}
	if stored(d1.ID) != nil || stored(d2.ID) != nil {
		t.Fatal("a conflicting transaction stored a record")
	}
	e := newUser("org1", "tx-e")
	e.Email = b.Email
	if err := s.Tx(ctx, []store.Op{{Rec: enc(c)}, {Rec: enc(e)}}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a write claiming a stored record's value: want ErrConflict, got %v", err)
	}
	if stored(c.ID) != nil {
		t.Fatal("a conflicting transaction stored a record")
	}
	// A value released by an earlier write of the transaction may be claimed by a later one.
	bEmail := b.Email
	b.Email = "tx-b-moved@example.com"
	e.Email = bEmail
	cur := stored(b.ID)
	must(t, s.Tx(ctx, []store.Op{{Rec: enc(b), Match: true, Expect: cur.Version}, {Rec: enc(e), Match: true}}))
	if r, err := s.GetByUnique(ctx, model.KindUser, model.UserEmailKey("org1", bEmail)); err != nil || r.ID != e.ID {
		t.Fatalf("the value moved within the transaction: %+v %v", r, err)
	}

	// A deletion and a create together.
	f := newUser("org1", "tx-f")
	must(t, s.Tx(ctx, []store.Op{{Rec: store.Tombstone(model.KindUser, e.ID)}, {Rec: enc(f), Match: true}}))
	if stored(e.ID) != nil || stored(f.ID) == nil {
		t.Fatal("a transaction's deletion and create")
	}

	// What a transaction cannot be.
	if err := s.Tx(ctx, nil); !errors.Is(err, store.ErrBadTx) {
		t.Fatalf("an empty transaction: want ErrBadTx, got %v", err)
	}
	g := newUser("org1", "tx-g")
	if err := s.Tx(ctx, []store.Op{{Rec: enc(g)}, {Rec: enc(g)}}); !errors.Is(err, store.ErrBadTx) {
		t.Fatalf("one record written twice: want ErrBadTx, got %v", err)
	}
	if stored(g.ID) != nil {
		t.Fatal("an invalid transaction stored a record")
	}
}

// A transaction retried after it was applied (its request id is found stored) is answered as done, each record taking
// its stored version, and nothing is written again: its creates would otherwise be refused.
func testTxRetried(t *testing.T, s store.Store) {
	req := store.NewReq()
	mk := func() []store.Op {
		h, i := newUser("org1", "txr-h"), newUser("org1", "txr-i")
		h.ID, i.ID = "txr-h", "txr-i"
		rh, err := store.EncodeAsIs(h)
		must(t, err)
		ri, err := store.EncodeAsIs(i)
		must(t, err)
		rh.Req, ri.Req = req, req
		return []store.Op{{Rec: rh, Match: true}, {Rec: ri, Match: true}}
	}
	first := mk()
	must(t, s.Tx(ctx, first))
	again := mk()
	if err := s.Tx(ctx, again); err != nil {
		t.Fatalf("a retried transaction: %v", err)
	}
	for i := range first {
		if again[i].Rec.Version != first[i].Rec.Version {
			t.Fatalf("record %d of the retry: version %d, stored %d", i, again[i].Rec.Version, first[i].Rec.Version)
		}
	}
	other := mk()
	for _, op := range other {
		op.Rec.Req = store.NewReq()
	}
	if err := s.Tx(ctx, other); !errors.Is(err, store.ErrStale) {
		t.Fatalf("another request's transaction of the same creates: want ErrStale, got %v", err)
	}
}

// A unique value is unique among the records of one kind, in a transaction as anywhere: a group and a tenant of the same
// name (the same unique value, model.GroupNameKey and TenantNameKey) are created together, and a transaction that
// deletes a group does not free the same value for a second tenant while another tenant holds it.
func testTxUniquePerKind(t *testing.T, s store.Store) {
	g := &model.Group{OrgID: "org1", DisplayName: "same"}
	te := &model.Tenant{OrgID: "org1", Name: "same"}
	gr, _ := store.Encode(g)
	tr, _ := store.Encode(te)
	if err := s.Tx(ctx, []store.Op{{Rec: gr, Match: true}, {Rec: tr, Match: true}}); err != nil {
		t.Fatalf("a group and a tenant of the same name in one transaction: %v", err)
	}
	other, _ := store.Encode(&model.Tenant{OrgID: "org1", Name: "same"})
	err := s.Tx(ctx, []store.Op{{Rec: store.Tombstone(model.KindGroup, gr.ID)}, {Rec: other, Match: true}})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second tenant of a name another tenant holds, with a group of that name deleted: want ErrConflict, got %v", err)
	}
	if _, err := s.Get(ctx, model.KindGroup, gr.ID); err != nil {
		t.Fatalf("the group of the refused transaction: %v", err)
	}
}

// A write that fails leaves the caller's record as it was passed (version, unique values, partition, request id), so
// the same record written again is judged again in full: a tenant whose name or resource another tenant of its
// organization holds is refused every time it is tried, by Put, CompareAndPut and Tx alike.
func testFailedWriteLeavesRecord(t *testing.T, s store.Store) {
	holder, _ := store.Encode(&model.Tenant{OrgID: "org1", Name: "held", Resources: []string{"https://api.example.com/mcp"}})
	must(t, s.CompareAndPut(ctx, holder, 0))
	for _, c := range []struct {
		name  string
		write func(r *store.Record) error
	}{
		{"Put", func(r *store.Record) error { return s.Put(ctx, r) }},
		{"CompareAndPut", func(r *store.Record) error { return s.CompareAndPut(ctx, r, 0) }},
	} {
		for _, te := range []*model.Tenant{
			{OrgID: "org1", Name: "held"}, // the name
			{OrgID: "org1", Name: "free", Resources: []string{"https://api.example.com/mcp"}}, // the resource
		} {
			rec, _ := store.Encode(te)
			was := *rec
			was.Unique = slices.Clone(rec.Unique)
			for try := range 2 {
				if err := c.write(rec); !errors.Is(err, store.ErrConflict) {
					t.Fatalf("%s of %s, try %d: want ErrConflict, got %v", c.name, te.Name, try+1, err)
				}
				if rec.Version != was.Version || rec.Epoch != was.Epoch || rec.Created != was.Created || rec.Req != was.Req ||
					rec.Partition != was.Partition || rec.Scope != was.Scope || !slices.Equal(rec.Unique, was.Unique) {
					t.Fatalf("%s of %s, try %d: the record changed: %+v, was %+v", c.name, te.Name, try+1, rec, &was)
				}
			}
		}
	}
	rec, _ := store.Encode(&model.Tenant{OrgID: "org1", Name: "held"})
	was := *rec
	was.Unique = slices.Clone(rec.Unique)
	if err := s.Tx(ctx, []store.Op{{Rec: rec, Match: true}}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Tx: want ErrConflict, got %v", err)
	}
	if rec.Version != was.Version || rec.Req != was.Req || !slices.Equal(rec.Unique, was.Unique) {
		t.Fatalf("Tx: the record changed: %+v, was %+v", rec, &was)
	}
}

// A transaction's assertion (store.Op.Assert) holds while its record is live at the version it names, in its
// partition, and writes nothing; one that does not hold (the record changed, was deleted, or is a new generation)
// refuses the transaction with ErrStale, its writes not made. Transactions asserting the same record all commit. A
// retried transaction is answered by its writes, whatever its assertions now find.
func testTxAssert(t *testing.T, s store.Store) {
	locks := store.NewTable[model.Lock](s)
	guard := &model.Lock{Meta: model.Meta{ID: "org1"}}
	must(t, locks.Create(ctx, guard))
	v := guard.Version
	create := func(name string, assert hlc.Timestamp) ([]store.Op, error) {
		t.Helper()
		r, err := store.Encode(newUser("org1", name))
		must(t, err)
		ops := []store.Op{{Rec: r, Match: true}, store.AssertOp(model.KindLock, "org1", "org1", assert)}
		return ops, s.Tx(ctx, ops)
	}
	exists := func(ops []store.Op) bool {
		t.Helper()
		_, err := s.Get(ctx, model.KindUser, ops[0].Rec.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		return err == nil
	}
	unchanged := func(want hlc.Timestamp) {
		t.Helper()
		g, err := s.Lookup(ctx, model.KindLock, "org1")
		if err != nil || g.Version != want {
			t.Fatalf("an assertion changed the record it asserts: %+v %v, want version %d", g, err, want)
		}
	}

	for _, name := range []string{"as-a", "as-b"} { // two transactions asserting one record: both commit
		ops, err := create(name, v)
		if err != nil || !exists(ops) {
			t.Fatalf("a transaction whose assertion holds: %v", err)
		}
	}
	unchanged(v)

	guard.Holder = "changed"
	must(t, locks.Update(ctx, guard))
	if ops, err := create("as-c", v); !errors.Is(err, store.ErrStale) || exists(ops) {
		t.Fatalf("an assertion of a record changed since: want ErrStale and nothing written, got %v", err)
	}
	v = guard.Version
	if err := s.Tx(ctx, []store.Op{store.AssertOp(model.KindLock, "org1", "org1", v)}); !errors.Is(err, store.ErrBadTx) {
		t.Fatalf("a transaction of assertions alone: want ErrBadTx, got %v", err)
	}
	if _, err := create("as-d", 0); !errors.Is(err, store.ErrBadTx) {
		t.Fatalf("an assertion of version 0: want ErrBadTx, got %v", err)
	}
	gr, err := store.Encode(&model.Lock{Meta: model.Meta{ID: "org1"}})
	must(t, err)
	if err = s.Tx(ctx, []store.Op{{Rec: gr}, store.AssertOp(model.KindLock, "org1", "org1", v)}); !errors.Is(err, store.ErrBadTx) {
		t.Fatalf("a transaction writing and asserting one record: want ErrBadTx, got %v", err)
	}
	unchanged(v)

	// Disappeared, and appeared again: a deletion and a new generation are changes too.
	must(t, locks.DeleteIf(ctx, "org1", v))
	if ops, err := create("as-e", v); !errors.Is(err, store.ErrStale) || exists(ops) {
		t.Fatalf("an assertion of a deleted record: want ErrStale and nothing written, got %v", err)
	}
	again := &model.Lock{Meta: model.Meta{ID: "org1"}}
	must(t, locks.Create(ctx, again))
	if ops, err := create("as-f", v); !errors.Is(err, store.ErrStale) || exists(ops) {
		t.Fatalf("an assertion of a record deleted and created again: want ErrStale and nothing written, got %v", err)
	}
	ops, err := create("as-g", again.Version)
	if err != nil || !exists(ops) {
		t.Fatalf("an assertion of the new generation: %v", err)
	}

	// A retry of an applied transaction is answered as done by its writes, though its assertion no longer holds.
	again.Holder = "changed"
	must(t, locks.Update(ctx, again))
	retry := []store.Op{{Rec: ops[0].Rec, Match: true}, store.AssertOp(model.KindLock, "org1", "org1", ops[1].Expect)}
	first := retry[0].Rec.Version
	retry[0].Rec.Req = mustStored(t, s, model.KindUser, retry[0].Rec.ID).Req
	if err := s.Tx(ctx, retry); err != nil || retry[0].Rec.Version != first {
		t.Fatalf("a retried transaction whose assertion has changed since: %v (version %d, stored %d)", err,
			retry[0].Rec.Version, first)
	}
}

// Many transactions asserting one record at once all commit (they do not conflict with each other over it), and a
// write of the record decides between them: none asserting the version it replaced commits after it.
func testConcurrentTxAssert(t *testing.T, s store.Store) {
	locks := store.NewTable[model.Lock](s)
	guard := &model.Lock{Meta: model.Meta{ID: "org1"}}
	must(t, locks.Create(ctx, guard))
	v := guard.Version
	assertCreate := func(name string) error {
		r, err := store.Encode(newUser("org1", name))
		if err != nil {
			return err
		}
		return s.Tx(ctx, []store.Op{{Rec: r, Match: true}, store.AssertOp(model.KindLock, "org1", "org1", v)})
	}
	var wg sync.WaitGroup
	for w := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 8 {
				if err := assertCreate(fmt.Sprintf("ca-%d-%d", w, i)); err != nil {
					t.Errorf("a transaction asserting a record others assert too: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}

	// Creations asserting v run until refused; the guard is changed while they do.
	var made atomic.Int32
	for w := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				err := assertCreate(fmt.Sprintf("cb-%d-%d", w, i))
				if errors.Is(err, store.ErrStale) {
					return
				}
				if err != nil {
					t.Errorf("a transaction asserting a record: %v", err)
					return
				}
				made.Add(1)
			}
		}()
	}
	for made.Load() < 32 {
		time.Sleep(time.Millisecond)
	}
	guard.Holder = "changed"
	must(t, locks.Update(ctx, guard))
	// Counted from a copy that holds the change (a cluster node applies it as it can): every creation before it.
	for deadline := time.Now().Add(10 * time.Second); ; {
		g, err := locks.Get(ctx, "org1")
		if err == nil && g.Version == guard.Version {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the change of the record is not readable here: %+v %v", g, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	before, err := users(s).Count(ctx, "org1")
	must(t, err)
	wg.Wait()
	after, err := users(s).Count(ctx, "org1")
	must(t, err)
	if after != before {
		t.Fatalf("%d transactions asserting the version a write replaced committed after it", after-before)
	}
}

// mustStored returns the stored record kind/id, in any state.
func mustStored(t *testing.T, s store.Store, kind model.Kind, id string) *store.Record {
	t.Helper()
	r, err := s.Lookup(ctx, kind, id)
	must(t, err)
	return r
}
