package kvstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

type round3CountingReads struct {
	engine
	records int
}

func (e *round3CountingReads) MGet(ctx context.Context, keys []string) ([][]byte, error) {
	e.records += len(keys)
	return e.engine.MGet(ctx, keys)
}

// The visibility filter is present on ordinary administrators' user listings.
func BenchmarkRound3UserPageReadAmplification(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			ctx := context.Background()
			s, err := OpenBadger(ctx, b.TempDir(), BadgerOptions{InMemory: true})
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			recs := make([]*store.Record, 0, n)
			for i := range n {
				name := fmt.Sprintf("user-%06d", i)
				u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: name, Email: name + "@example.test", GivenName: name, Role: model.RoleUser, Active: true}
				r, err := store.Encode(u)
				if err != nil {
					b.Fatal(err)
				}
				recs = append(recs, r)
			}
			if _, _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
				b.Fatal(err)
			}
			counting := &round3CountingReads{engine: s.eng}
			s.eng = counting
			for _, filtered := range []bool{false, true} {
				label := "plain"
				q := store.ListQuery{Scope: "org", Limit: 25}
				if filtered {
					label = "admin-visibility"
					q.Filters = []store.Filter{{Field: "super_admin", Value: false}}
				}
				b.Run(label, func(b *testing.B) {
					counting.records = 0
					b.ReportAllocs()
					for b.Loop() {
						page, err := s.List(ctx, model.KindUser, q)
						if err != nil || len(page.Records) != 25 || page.Total != n {
							b.Fatalf("page: %+v %v", page, err)
						}
					}
					b.ReportMetric(float64(counting.records)/float64(b.N), "records-read/op")
				})
			}
		})
	}
}
