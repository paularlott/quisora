package kvstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

// A descending listing on a field with long runs of equal values (active) keeps only what its page needs of each
// run: its pages, at any offset, are those of the shared query evaluation (ties by id ascending), with the same total.
func TestDescendingTiesPages(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{InMemory: true})
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
	if _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
		t.Fatal(err)
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
		storetest.CheckAgainstApplyQuery(t, s, model.KindUser, q)
	}
}
