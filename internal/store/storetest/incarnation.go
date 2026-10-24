package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Generations (store.Record.Epoch): a tombstone of a plainly replicated kind beats every write of a generation started
// before it, whatever that write's version; quorum kinds rank by version alone (store.Head.Rank). A record created again after a deletion takes the version of the tombstone its writer saw as its
// epoch, so it beats that tombstone but never a deletion its writer had not seen.

// A local update can never replace a tombstone (Put: ErrDeleted, CompareAndPut: ErrNotFound); a create can, as a new
// generation whose epoch is the tombstone's version, and later updates keep that generation.
func testLocalWriteOverTombstone(t *testing.T, s store.Store) {
	tb := users(s)
	u := newUser("org1", "inc-a")
	must(t, tb.Create(ctx, u))
	r, err := s.Get(ctx, model.KindUser, u.ID)
	must(t, err)
	if r.Epoch != 0 || r.Created != r.Version {
		t.Fatalf("a first create is generation 0, created at its version: epoch %d created %d version %d", r.Epoch,
			r.Created, r.Version)
	}
	created := r.Created
	u.GivenName = "updated"
	must(t, tb.Update(ctx, u))
	if r, _ = s.Get(ctx, model.KindUser, u.ID); r.Epoch != 0 || r.Created != created {
		t.Fatalf("an update keeps the generation: %+v", r)
	}
	must(t, tb.Put(ctx, u))
	if r, _ = s.Get(ctx, model.KindUser, u.ID); r.Epoch != 0 || r.Created != created {
		t.Fatalf("a put over a live record keeps the generation: %+v", r)
	}
	stale := *u // read before the deletion
	must(t, tb.Delete(ctx, u.ID))
	tomb, err := s.Lookup(ctx, model.KindUser, u.ID)
	if err != nil || !tomb.Deleted {
		t.Fatalf("Lookup returns the tombstone: %v %+v", err, tomb)
	}
	err = tb.Put(ctx, &stale)
	if !errors.Is(err, store.ErrDeleted) || !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("put over a tombstone: want ErrDeleted (an ErrNotFound), got %v", err)
	}
	if err := tb.Update(ctx, &stale); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update over a tombstone: want ErrNotFound, got %v", err)
	}
	if _, err := tb.Get(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a refused write brought the record back")
	}
	again := newUser("org1", "inc-a")
	again.ID = u.ID
	must(t, tb.Create(ctx, again))
	r, err = s.Get(ctx, model.KindUser, u.ID)
	must(t, err)
	if r.Epoch != tomb.Version || r.Created != r.Version {
		t.Fatalf("a create after a deletion starts a generation at the tombstone it saw: epoch %d (tombstone %d) "+
			"created %d version %d", r.Epoch, tomb.Version, r.Created, r.Version)
	}
	if _, err := s.Lookup(ctx, model.KindUser, "never-stored"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Lookup of nothing: %v", err)
	}
	// Short-lived node-local state is not replicated: a put over its tombstone is allowed.
	e := &model.Ephemeral{Meta: model.Meta{ID: "inc-eph"}, Value: []byte("x")}
	eph := store.NewTable[model.Ephemeral](s)
	must(t, eph.Put(ctx, e))
	must(t, eph.Delete(ctx, e.ID))
	must(t, eph.Put(ctx, e))
}

// Replicated (a kind written by plain replication, sessions here): a live write of a deleted generation loses to the
// tombstone even with a far newer version (the resurrection a last-writer-wins merge allows); a re-creation wins over
// the tombstone it saw, and loses to a deletion it had not seen even when its own version is newer (a re-creating node
// whose clock is fast): the causal rule, never wall-clock order. Epoch and Created are kept as sent.
func testReplicatedTombstoneDominates(t *testing.T, s store.Store) {
	id := model.NewID()
	sess := func(note string, version hlc.Timestamp, origin string) *store.Record {
		x := &model.Session{Meta: model.Meta{ID: id, Version: version}, UserID: "u-" + note, OrgID: "org1",
			Expires: time.Now().Add(time.Hour)}
		r, _ := store.EncodeAsIs(x)
		r.Origin, r.Created = origin, version
		return r
	}
	userOf := func() (string, error) {
		r, err := s.Get(ctx, model.KindSession, id)
		if err != nil {
			return "", err
		}
		var x model.Session
		if err := store.Decode(r, &x); err != nil {
			return "", err
		}
		return x.UserID, nil
	}
	v := store.Clock.Now() + 1000
	live := sess("first", v, "n1")
	if ok, _, err := s.PutReplicated(ctx, live); err != nil || !ok {
		t.Fatalf("first apply: %v %v", ok, err)
	}
	if r, _ := s.Get(ctx, model.KindSession, id); r == nil || r.Epoch != 0 || r.Created != v {
		t.Fatal("epoch and created not kept")
	}
	del := &store.Record{Kind: model.KindSession, ID: id, Version: v + 10, Origin: "n2", Deleted: true}
	if ok, _, _ := s.PutReplicated(ctx, del); !ok {
		t.Fatal("tombstone not applied")
	}
	upd := sess("update from a node that had not seen the deletion", v+1_000_000, "n3") // e.g. a fast clock
	upd.Created = v
	if ok, _, _ := s.PutReplicated(ctx, upd); ok {
		t.Fatal("an update of the deleted generation beat the tombstone")
	}
	if _, err := userOf(); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("record resurrected")
	}
	ch, _, _ := s.Changes(ctx, 0, 0) // (a backend without a feed returns an error and no changes)
	for _, c := range ch {
		if c.Record.ID == id && !c.Record.Deleted {
			t.Fatal("the feed carries the resurrected record")
		}
	}
	// Re-created by a writer that saw the deletion: epoch = the tombstone's version. It wins, and keeps winning over
	// writes of the deleted generation.
	re := sess("re-created", v+20, "n1")
	re.Epoch = del.Version
	if ok, _, _ := s.PutReplicated(ctx, re); !ok {
		t.Fatal("a re-creation lost to the tombstone it superseded")
	}
	if ok, _, _ := s.PutReplicated(ctx, upd); ok {
		t.Fatal("an update of the deleted generation beat the re-created record")
	}
	got, err := userOf()
	must(t, err)
	if got != "u-re-created" {
		t.Fatalf("got %q", got)
	}
	// Replaying the old tombstone changes nothing; a later deletion wins.
	if ok, _, _ := s.PutReplicated(ctx, del); ok {
		t.Fatal("the older tombstone deleted the re-created record")
	}
	del2 := &store.Record{Kind: model.KindSession, ID: id, Version: v + 30, Origin: "n2", Deleted: true}
	if ok, _, _ := s.PutReplicated(ctx, del2); !ok {
		t.Fatal("the re-created record's deletion was not applied")
	}
	// A re-creation from a node that had seen only the first deletion (epoch del), minted on a fast clock (version
	// far beyond del2): the deletion it had not seen still wins.
	fast := sess("re-added on a fast node", v+5_000_000, "n9")
	fast.Epoch = del.Version
	if ok, _, _ := s.PutReplicated(ctx, fast); ok {
		t.Fatal("a re-creation beat a deletion its writer had not seen (wall-clock order decided)")
	}
	if _, err := userOf(); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the later deletion was undone by an earlier re-creation")
	}
}

// Quorum kinds (users here) rank by version alone (store.Head.Rank): the voters order versions as writes are granted,
// and a confirmed deletion's quorum refuses later writes that had not seen it, so the rank settles only partial
// writes, and the later one wins — a deletion or not, whatever generation it belongs to.
func testQuorumTombstoneRanksByVersion(t *testing.T, s store.Store) {
	u := newUser("org1", "inc-q")
	u.ID = model.NewID()
	v := store.Clock.Now() + 1000
	live := replica(u, v, "n1")
	if ok, _, err := s.PutReplicated(ctx, live); err != nil || !ok {
		t.Fatalf("first apply: %v %v", ok, err)
	}
	del := &store.Record{Kind: model.KindUser, ID: u.ID, Version: v + 10, Origin: "n2", Deleted: true}
	if ok, _, _ := s.PutReplicated(ctx, del); !ok {
		t.Fatal("tombstone not applied")
	}
	earlier := replica(u, v+5, "n3")
	earlier.Created = v
	if ok, _, _ := s.PutReplicated(ctx, earlier); ok {
		t.Fatal("an earlier write beat a later deletion")
	}
	u.GivenName = "later confirmed"
	later := replica(u, v+20, "n3")
	later.Created = v
	if ok, _, _ := s.PutReplicated(ctx, later); !ok {
		t.Fatal("a later write lost to an earlier (partial) deletion")
	}
	got, err := users(s).Get(ctx, u.ID)
	must(t, err)
	if got.GivenName != "later confirmed" {
		t.Fatalf("got %q", got.GivenName)
	}
	again := &store.Record{Kind: model.KindUser, ID: u.ID, Version: v + 30, Origin: "n2", Deleted: true}
	if ok, _, _ := s.PutReplicated(ctx, again); !ok {
		t.Fatal("a later deletion did not outrank the record")
	}
	re := replica(u, v+25, "n9")
	re.Epoch = del.Version // a re-creation, earlier than the deletion above
	if ok, _, _ := s.PutReplicated(ctx, re); ok {
		t.Fatal("an earlier re-creation beat a later deletion")
	}
	// A deletion of an absent record (its own version as epoch) gives way to a later create of the id.
	w := newUser("org1", "inc-q2")
	w.ID = model.NewID()
	blind := &store.Record{Kind: model.KindUser, ID: w.ID, Version: v + 40, Origin: "n1", Deleted: true}
	if ok, _, _ := s.PutReplicated(ctx, blind); !ok {
		t.Fatal("blind tombstone not applied")
	}
	created := replica(w, v+50, "n2")
	if ok, _, _ := s.PutReplicated(ctx, created); !ok {
		t.Fatal("a later create lost to an earlier deletion of the absent record")
	}
}
