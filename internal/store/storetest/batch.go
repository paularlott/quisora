package storetest

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// RunBatch checks an optional store.BatchReplicator against the PutReplicated semantics. It skips backends that do
// not implement it.
func RunBatch(t *testing.T, f Factory) {
	mk := func(t *testing.T) (store.Store, store.BatchReplicator) {
		s := f(t)
		t.Cleanup(func() { s.Close() })
		b, ok := s.(store.BatchReplicator)
		if !ok {
			t.Skip("backend does not implement store.BatchReplicator")
		}
		return s, b
	}
	rec := func(id, origin, uniq string, v int) *store.Record {
		r := &store.Record{Kind: model.KindGroup, ID: id, Origin: origin, Scope: "o", Data: []byte(fmt.Sprint(v)),
			Version: store.Clock.Now(), Fields: map[string]any{"display_name": id, "created": time.Now().UTC()}}
		if uniq != "" {
			r.Unique = []string{uniq}
		}
		return r
	}
	t.Run("Batch/MatchesSequential", func(t *testing.T) {
		s, b := mk(t)
		var recs []*store.Record
		for i := range 700 { // more than one transaction group
			recs = append(recs, rec(fmt.Sprintf("g%04d", i), "n1", fmt.Sprintf("o|g%d", i), i))
		}
		applied, err := b.PutReplicatedBatch(ctx, recs)
		if err != nil {
			t.Fatal(err)
		}
		for i := range recs {
			if !applied[i] {
				t.Fatalf("record %d not applied", i)
			}
		}
		if n, _ := s.Count(ctx, model.KindGroup, ""); n != 700 {
			t.Fatalf("count %d", n)
		}
		// Replaying is a no-op.
		applied, err = b.PutReplicatedBatch(ctx, recs)
		if err != nil {
			t.Fatal(err)
		}
		for i := range applied {
			if applied[i] {
				t.Fatalf("replay applied record %d", i)
			}
		}
	})
	t.Run("Batch/SameRecordTwiceAndTombstone", func(t *testing.T) {
		s, b := mk(t)
		v1, v2 := rec("a", "n1", "o|a", 1), rec("a", "n1", "o|a", 2)
		del := &store.Record{Kind: model.KindGroup, ID: "b", Deleted: true, Origin: "n1", Version: store.Clock.Now()}
		b1 := rec("b", "n1", "", 1)
		b1.Version = del.Version - 5
		applied, err := b.PutReplicatedBatch(ctx, []*store.Record{v1, v2, b1, del})
		if err != nil {
			t.Fatal(err)
		}
		if !applied[0] || !applied[1] || !applied[2] || !applied[3] {
			t.Fatalf("applied %v", applied)
		}
		got, err := s.Get(ctx, model.KindGroup, "a")
		if err != nil || string(got.Data) != "2" {
			t.Fatalf("a: %v %v", got, err)
		}
		if _, err := s.Get(ctx, model.KindGroup, "b"); err != store.ErrNotFound {
			t.Fatalf("b should be deleted: %v", err)
		}
	})
	t.Run("Batch/EmptyAndOlderInBatch", func(t *testing.T) {
		s, b := mk(t)
		if applied, err := b.PutReplicatedBatch(ctx, nil); err != nil || len(applied) != 0 {
			t.Fatalf("empty batch: %v %v", applied, err)
		}
		// The same record twice and then an older copy of it: the older copy is not applied over the newer.
		r1, r1b := rec("a", "n1", "o|dup", 1), rec("a", "n1", "o|dup", 2)
		older := *r1
		applied, err := b.PutReplicatedBatch(ctx, []*store.Record{r1, r1b, &older})
		if err != nil {
			t.Fatal(err)
		}
		if !applied[0] || !applied[1] || applied[2] {
			t.Fatalf("applied %v", applied)
		}
		// A later claimant of the value is refused; the holder keeps it.
		if _, err := b.PutReplicatedBatch(ctx, []*store.Record{rec("b", "n2", "o|dup", 3)}); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("a second claimant of a unique value: %v", err)
		}
		if h, err := s.GetByUnique(ctx, model.KindGroup, "o|dup"); err != nil || h.ID != "a" || string(h.Data) != "2" {
			t.Fatalf("holder: %v %v", h, err)
		}
	})
	t.Run("Batch/UniqueClashInBatch", func(t *testing.T) {
		s, b := mk(t)
		first, second := rec("x1", "n1", "o|same", 1), rec("x2", "n2", "o|same", 2)
		// The clashing record is refused and the batch stops there (what the group it is in had applied may be undone:
		// the caller gives up on an error).
		if _, err := b.PutReplicatedBatch(ctx, []*store.Record{first, second}); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("a clash in a batch: %v", err)
		}
		if _, err := s.Get(ctx, model.KindGroup, "x2"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the clashing record was stored: %v", err)
		}
		if h, err := s.GetByUnique(ctx, model.KindGroup, "o|same"); err == nil && h.ID != "x1" {
			t.Fatalf("holder %v", h)
		}
	})
}
