package kvstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Page still visits every index member to produce Total, even when it returns
// just 25 IDs. Index entries need no record bodies for this engine-level measure.
func BenchmarkFreshBadgerPageIndexScaling(b *testing.B) {
	for _, n := range []int{10000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			ctx := context.Background()
			s, err := OpenBadger(ctx, b.TempDir(), BadgerOptions{InMemory: true})
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			for start := 0; start < n; start += 1000 {
				if err := s.eng.Update(ctx, func(tx txn) error {
					for i := start; i < start+1000 && i < n; i++ {
						tx.SetAdd("fresh-page", fmt.Sprintf("user-%09d", i), 0)
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				ids, total, err := s.eng.Page(ctx, "fresh-page", pageQuery{Limit: 25}, nowMs())
				if err != nil || len(ids) != 25 || total != n {
					b.Fatalf("page ids=%d total=%d err=%v", len(ids), total, err)
				}
			}
		})
	}
}

// The actual users console requests username ordering, unlike the unsorted
// paging fast path exercised by the prior bounded-read benchmark.
func BenchmarkFreshDefaultAdminUserPage(b *testing.B) {
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
				rec, err := store.Encode(u)
				if err != nil {
					b.Fatal(err)
				}
				recs = append(recs, rec)
			}
			if _, _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
				b.Fatal(err)
			}
			counting := &countingReads{engine: s.eng}
			s.eng = counting
			query := store.ListQuery{Scope: "org", Sort: "username", Limit: 25, Filters: []store.Filter{{Field: "super_admin", Value: false}}}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				page, err := s.List(ctx, model.KindUser, query)
				if err != nil || len(page.Records) != 25 || page.Total != n {
					b.Fatalf("page: %+v %v", page, err)
				}
			}
			b.ReportMetric(float64(counting.records)/float64(b.N), "records-read/op")
		})
	}
}
