package storetest

import (
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
		applied, losers, err := b.PutReplicatedBatch(ctx, recs)
		if err != nil {
			t.Fatal(err)
		}
		for i := range recs {
			if !applied[i] || len(losers[i]) != 0 {
				t.Fatalf("record %d applied=%v losers=%v", i, applied[i], losers[i])
			}
		}
		if n, _ := s.Count(ctx, model.KindGroup, ""); n != 700 {
			t.Fatalf("count %d", n)
		}
		// Replaying is a no-op, and the change feed holds each record once.
		applied, _, err = b.PutReplicatedBatch(ctx, recs)
		if err != nil {
			t.Fatal(err)
		}
		for i := range applied {
			if applied[i] {
				t.Fatalf("replay applied record %d", i)
			}
		}
		ch, _, _ := s.Changes(ctx, 0, 0)
		if len(ch) != 700 {
			t.Fatalf("feed has %d entries", len(ch))
		}
		for i := 1; i < len(ch); i++ {
			if ch[i].Seq <= ch[i-1].Seq {
				t.Fatal("feed not in seq order")
			}
		}
	})
	t.Run("Batch/SameRecordTwiceAndTombstone", func(t *testing.T) {
		s, b := mk(t)
		v1, v2 := rec("a", "n1", "o|a", 1), rec("a", "n1", "o|a", 2)
		del := &store.Record{Kind: model.KindGroup, ID: "b", Deleted: true, Origin: "n1", Version: store.Clock.Now()}
		b1 := rec("b", "n1", "", 1)
		b1.Version = del.Version - 5
		applied, _, err := b.PutReplicatedBatch(ctx, []*store.Record{v1, v2, b1, del})
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
	t.Run("Batch/UniqueClashInBatch", func(t *testing.T) {
		s, b := mk(t)
		first, second := rec("x1", "n1", "o|same", 1), rec("x2", "n2", "o|same", 2)
		applied, losers, err := b.PutReplicatedBatch(ctx, []*store.Record{second, first})
		if err != nil {
			t.Fatal(err)
		}
		if !applied[0] || !applied[1] {
			t.Fatalf("applied %v", applied)
		}
		// first has the lower version, so it keeps the value; second loses (reported with whichever record lost).
		all := append(append([]string{}, losers[0]...), losers[1]...)
		if len(all) != 1 || all[0] != "x2" {
			t.Fatalf("losers %v", losers)
		}
		h, err := s.GetByUnique(ctx, model.KindGroup, "o|same")
		if err != nil || h.ID != "x1" {
			t.Fatalf("holder %v %v", h, err)
		}
	})
}
