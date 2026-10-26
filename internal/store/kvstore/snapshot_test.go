package kvstore

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A Badger snapshot is fixed when Snapshot returns (a later write is invisible to it without a read before) and is
// read-only all the way down.
func TestSnapshotIsFixedAndReadOnly(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{})
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{}, "u")); err != nil {
		t.Fatal(err)
	}
	r, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, record(model.KindLink, "b", time.Time{})); err != nil {
		t.Fatal(err)
	}
	if n, err := r.Count(ctx, model.KindLink, "sc"); err != nil || n != 1 {
		t.Fatalf("snapshot count %d %v", n, err)
	}
	res, err := r.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"})
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("snapshot list %+v %v", res, err)
	}
	// The view is read-only all the way down.
	snap := r.(*Store)
	if err := snap.Wipe(ctx); !errors.Is(err, errReadOnly) {
		t.Fatalf("Wipe on a snapshot: %v", err)
	}
	if err := snap.Put(ctx, record(model.KindLink, "c", time.Time{})); !errors.Is(err, errReadOnly) {
		t.Fatalf("Put on a snapshot: %v", err)
	}
	if got, err := snap.Get(ctx, model.KindLink, "a"); err != nil || got.ID != "a" {
		t.Fatalf("snapshot get: %v", err)
	}
	if _, err := snap.Get(ctx, model.KindLink, "b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a later write is visible in the snapshot: %v", err)
	}
	if got, err := snap.eng.Range(ctx, allBucket(model.KindLink), "", "", 0); err != nil || len(got) != 1 {
		t.Fatalf("snapshot range: %v %v", got, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

// A snapshot's counts, the engine's own included, leave out expired records.
func TestSnapshotCountSkipsExpired(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{})
	for i, exp := range []time.Time{time.Now().Add(time.Hour), time.Now().Add(-time.Hour), {}} {
		if err := s.Put(ctx, record(model.KindLink, "r"+strconv.Itoa(i), exp)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if n, err := r.Count(ctx, model.KindLink, "sc"); err != nil || n != 2 {
		t.Fatalf("snapshot count: %d %v", n, err)
	}
	snap := r.(*Store).eng
	if n, err := snap.Count(ctx, listBucket(model.KindLink, "sc"), nowMs()); err != nil || n != 2 {
		t.Fatalf("engine count: %d %v", n, err)
	}
}
