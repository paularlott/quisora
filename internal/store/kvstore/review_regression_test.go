package kvstore

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

type freshReviewHeapProbe struct {
	engine
	baseline, peak uint64
}

func (p *freshReviewHeapProbe) MGet(ctx context.Context, keys []string) ([][]byte, error) {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	if stats.HeapAlloc > p.peak {
		p.peak = stats.HeapAlloc
	}
	return p.engine.MGet(ctx, keys)
}

// Measure live memory after GC between record batches, rather than total
// allocations, to detect whether the supposedly streaming page retains records.
func TestFreshReviewDescendingFilteredPageRetainsScope(t *testing.T) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const n = 4096
	recs := make([]*store.Record, 0, n)
	for i := range n {
		u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: fmt.Sprintf("user-%06d", i), Role: model.RoleUser, Active: true}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if _, _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	recs = nil
	p := &freshReviewHeapProbe{engine: s.eng}
	s.eng = p
	for _, desc := range []bool{false, true} {
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		p.baseline, p.peak = stats.HeapAlloc, stats.HeapAlloc
		q := store.ListQuery{Scope: "org", Sort: "active", Desc: desc, Limit: 25, Filters: []store.Filter{{Field: "active", Value: true}}}
		page, err := s.List(ctx, model.KindUser, q)
		if err != nil || page.Total != n || len(page.Records) != 25 {
			t.Fatalf("page=%+v err=%v", page, err)
		}
		t.Logf("desc=%v records=%d page=25 peak retained heap growth after GC=%d bytes", desc, n, p.peak-p.baseline)
	}
}

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
