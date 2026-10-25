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
)

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
			if _, _, err := st.PutReplicatedBatch(ctx, recs); err != nil {
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
