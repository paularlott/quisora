package kvstore

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
