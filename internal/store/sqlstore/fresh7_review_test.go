package sqlstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func TestFreshReviewUnicodePrefixMatchesSharedQuery(t *testing.T) {
	s := factory("sqlite", "")(t)
	defer s.Close()
	ctx := context.Background()
	u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: "emile", GivenName: "Émile"}
	r, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, r); err != nil {
		t.Fatal(err)
	}
	q := store.ListQuery{Scope: "org", Search: "é"}
	want, err := store.ApplyQuery(model.KindUser, []*store.Record{r}, q)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx, model.KindUser, q)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != want.Total {
		t.Fatalf("SQLite prefix returned %d matches, shared case-insensitive prefix returned %d", got.Total, want.Total)
	}
}

func TestFreshReviewSQLGetManyBatchOrdering(t *testing.T) {
	s := factory("sqlite", "")(t)
	defer s.Close()
	ctx := context.Background()
	const n = 1100
	recs := make([]*store.Record, n)
	for i := range n {
		u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: fmt.Sprintf("user-%04d", i)}
		var err error
		recs[i], err = store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, rec := range recs {
		if err := s.Put(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	ids := make([]string, 0, n+2)
	for i := n - 1; i >= 0; i-- {
		ids = append(ids, recs[i].ID)
	}
	ids = append(ids, "missing", recs[500].ID)
	got, err := s.(store.MultiGetter).GetMany(ctx, model.KindUser, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n+1 {
		t.Fatalf("got %d records, expected %d", len(got), n+1)
	}
	for i := range n {
		if got[i].ID != recs[n-1-i].ID {
			t.Fatalf("wrong record at input position %d", i)
		}
	}
	if got[n].ID != recs[500].ID {
		t.Fatal("duplicate ID not preserved across batches")
	}
}

// Folding is Go's on SQLite for filters and sorts too, not only search: a prefix filter and a case-insensitive sort
// treat "É" as "é", as the shared query code does.
func TestSQLiteFoldsUnicodeInFiltersAndSorts(t *testing.T) {
	s := factory("sqlite", "")(t)
	defer s.Close()
	ctx := context.Background()
	var recs []*store.Record
	for _, name := range []string{"Zoé", "Émile", "ella"} {
		r, err := store.Encode(&model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: name, GivenName: name})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	for _, q := range []store.ListQuery{
		{Scope: "org", Filters: []store.Filter{{Field: "username", Op: store.OpPrefix, Value: "émi"}}},
		{Scope: "org", Sort: "username"},
	} {
		want, err := store.ApplyQuery(model.KindUser, recs, q)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.List(ctx, model.KindUser, q)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Records) != len(want.Records) {
			t.Fatalf("%+v: %d items, want %d", q, len(got.Records), len(want.Records))
		}
		for i := range want.Records {
			if got.Records[i].ID != want.Records[i].ID {
				t.Fatalf("%+v: item %d is %s, want %s", q, i, got.Records[i].ID, want.Records[i].ID)
			}
		}
	}
}
