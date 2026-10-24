package sqlstore

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Word membership must agree with the shared query implementation, including
// when another tag is present and the SQL LIKE branches are exercised.
func TestFreshReviewTagCaseMatchesSharedQuery(t *testing.T) {
	s := factory("sqlite", "")(t)
	defer s.Close()
	ctx := context.Background()
	for _, tags := range [][]string{{"Staff"}, {"Staff", "other"}, {"other", "Staff"}} {
		u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: model.NewID(), Tags: tags}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org"})
	if err != nil {
		t.Fatal(err)
	}
	q := store.ListQuery{Scope: "org", Filters: []store.Filter{{Field: "tags", Value: "staff"}}}
	want, err := store.ApplyQuery(model.KindUser, all.Records, q)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx, model.KindUser, q)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != want.Total {
		t.Fatalf("SQLite tags=staff returned total %d; shared query returned %d", got.Total, want.Total)
	}
}
