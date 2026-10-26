package storetest

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Generations (store.Record.Epoch): a record created again after a deletion takes the version of the tombstone its
// writer saw as its epoch (store.StampLocal).

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
