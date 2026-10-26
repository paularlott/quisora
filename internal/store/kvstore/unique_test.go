package kvstore

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Tombstoning or purging a record releases only the unique values that still point at it.
func TestPurgeAndTombstoneReleaseOnlyTheirOwnUniqueValues(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{})
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{}, "shared")); err != nil {
		t.Fatal(err)
	}
	// The unique key is re-pointed at another id (as after a replicated takeover): purging a must not free it.
	err := s.eng.Update(ctx, func(tx txn) error { tx.Set(uqKey(model.KindLink, "shared"), []byte("other")); return nil })
	if err != nil {
		t.Fatal(err)
	}
	tomb := &store.Record{Kind: model.KindLink, ID: "a", Version: store.Clock.Now(), Origin: "n", Deleted: true}
	if err := s.Put(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.eng.Get(ctx, uqKey(model.KindLink, "shared")); string(b) != "other" {
		t.Fatalf("tombstoning freed another record's unique value: %q", b)
	}
	// An expired record is removed by Purge together with its entries.
	exp := record(model.KindLink, "e", time.Now().Add(-time.Minute), "ev")
	if err := s.Put(ctx, exp); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Purge(ctx, time.Time{}, time.Now()); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if b, _ := s.eng.Get(ctx, uqKey(model.KindLink, "ev")); b != nil {
		t.Fatal("unique entry of a purged record kept")
	}
}
