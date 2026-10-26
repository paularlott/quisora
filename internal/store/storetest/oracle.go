package storetest

import (
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// IDs returns the ids of recs, in order.
func IDs(recs []*store.Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.ID
	}
	return out
}

// CheckAgainstApplyQuery lists q from s and reports an error unless it gives what the shared query evaluation
// (store.ApplyQuery) gives over every live record of kind: the same records in the same order, and the same total. It
// returns what s listed.
func CheckAgainstApplyQuery(t testing.TB, s store.Store, kind model.Kind, q store.ListQuery) *store.ListResult {
	t.Helper()
	all, err := s.List(ctx, kind, store.ListQuery{})
	must(t, err)
	want, err := store.ApplyQuery(kind, all.Records, q)
	must(t, err)
	got, err := s.List(ctx, kind, q)
	must(t, err)
	if !slices.Equal(IDs(got.Records), IDs(want.Records)) || got.Total != want.Total {
		t.Errorf("%s %+v:\n got %d %v\nwant %d %v", kind, q, got.Total, IDs(got.Records), want.Total, IDs(want.Records))
	}
	return got
}
