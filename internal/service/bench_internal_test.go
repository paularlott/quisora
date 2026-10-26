package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// Isolate owner collection with distinct owners absent locally, so no quorum
// reads or decoding obscure the deduplication work.
func BenchmarkFreshReviewSweepDistinctOwners(b *testing.B) {
	for _, n := range []int{2000, 20000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			st := memstore.New()
			defer st.Close()
			sealer, _ := secure.NewSealer(secure.RandomBytes(32))
			s := New(config.Default(), st, sealer)
			ents := make([]model.Entity, n)
			for i := range n {
				ents[i] = &model.Session{Meta: model.Meta{ID: model.NewID()}, UserID: model.NewID()}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := s.passedEpochs(context.Background(), ents); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// DeleteUser always calls clearManagerOf, even for an account with no reports.
func BenchmarkFreshReviewDeletedUserManagerCleanup(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			ctx := context.Background()
			st, err := kvstore.OpenBadger(ctx, b.TempDir(), kvstore.BadgerOptions{InMemory: true})
			if err != nil {
				b.Fatal(err)
			}
			defer st.Close()
			sealer, _ := secure.NewSealer(secure.RandomBytes(32))
			s := New(config.Default(), st, sealer)
			recs := make([]*store.Record, n)
			for i := range n {
				u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: fmt.Sprintf("user-%06d", i), Email: fmt.Sprintf("user-%06d@example.test", i)}
				recs[i], err = store.Encode(u)
				if err != nil {
					b.Fatal(err)
				}
			}
			if _, err := st.PutReplicatedBatch(ctx, recs); err != nil {
				b.Fatal(err)
			}
			deleted := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org"}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				s.clearManagerOf(ctx, deleted)
			}
		})
	}
}
