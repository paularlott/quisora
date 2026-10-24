package kvstore

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A descending listing on a field with long runs of equal values (active) keeps only what its page needs of each
// run: its pages, at any offset, are those of the shared query evaluation (ties by id ascending), with the same total.
func TestDescendingTiesPages(t *testing.T) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var recs []*store.Record
	for i := range 1500 {
		u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: fmt.Sprintf("u%04d", i),
			Role: model.RoleUser, Active: i%3 != 0}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if _, _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	all, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org"})
	if err != nil {
		t.Fatal(err)
	}
	ids := func(rs []*store.Record) []string {
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = r.ID
		}
		return out
	}
	for _, q := range []store.ListQuery{
		{Sort: "active", Desc: true, Limit: 25},
		{Sort: "active", Desc: true, Offset: 990, Limit: 25}, // across the boundary of the two runs
		{Sort: "active", Desc: true, Offset: 1400, Limit: 200},
		{Sort: "active", Desc: true, Offset: 5000, Limit: 25},
		{Sort: "active", Desc: true},
		{Sort: "active", Desc: true, Limit: 25, Filters: []store.Filter{{Field: "active", Value: true}}},
		{Sort: "active", Desc: true, Offset: 30, Limit: 25, Filters: []store.Filter{{Field: "role", Value: "user"}}},
	} {
		q.Scope = "org"
		want, err := store.ApplyQuery(model.KindUser, all.Records, q)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.List(ctx, model.KindUser, q)
		if err != nil {
			t.Fatal(err)
		}
		if got.Total != want.Total || !slices.Equal(ids(got.Records), ids(want.Records)) {
			t.Fatalf("%+v: got %d records (total %d), want %d (total %d)", q, len(got.Records), got.Total,
				len(want.Records), want.Total)
		}
	}
}
