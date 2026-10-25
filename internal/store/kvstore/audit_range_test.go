package kvstore

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Audit pages filtered by time range, action (exact or prefix) and outcome are served from the indexes (a range of the
// created sort index, the action and outcome field indexes, a range of the action sort index): their pages, at any
// offset and in either order, are those of the shared query evaluation, with the same total.
func TestAuditFilterPages(t *testing.T) {
	t.Run("Badger", func(t *testing.T) {
		s, err := OpenBadger(context.Background(), t.TempDir(), BadgerOptions{InMemory: true})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		auditFilterPages(t, s)
	})
	t.Run("Valkey", func(t *testing.T) {
		s := valkeyFactory(t).(*Store)
		defer s.Close()
		auditFilterPages(t, s)
	})
}

func auditFilterPages(t *testing.T, s *Store) {
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	actions := []string{"user.create", "user.update", "user.login.failure", "client.create", "org.signout"}
	var recs []*store.Record
	for i := range 1200 {
		a := &model.Audit{Meta: model.Meta{ID: model.NewID(), Created: base.Add(time.Duration(i/3) * time.Minute)}, // runs of equal times
			OrgID: "org", Action: actions[i%len(actions)], Actor: "admin", Expires: base.AddDate(5, 0, 0)}
		if i%7 == 0 {
			a.OrgID = "other"
		}
		r, err := store.Encode(a)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if _, _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	all, err := s.List(ctx, model.KindAudit, store.ListQuery{Scope: "org"})
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
	from, to := base.Add(30*time.Minute), base.Add(200*time.Minute)
	rng := []store.Filter{{Field: "created", Op: store.OpGTE, Value: from}, {Field: "created", Op: store.OpLT, Value: to}}
	for _, q := range []store.ListQuery{
		{Sort: "created", Desc: true, Limit: 50, Filters: rng},
		{Sort: "created", Desc: true, Offset: 100, Limit: 50, Filters: rng},
		{Sort: "created", Limit: 50, Filters: rng},
		{Sort: "created", Offset: 400, Limit: 50, Filters: rng},
		{Sort: "created", Desc: true, Limit: 50, Filters: rng[:1]},
		{Sort: "created", Desc: true, Limit: 50, Filters: rng[1:]},
		{Sort: "created", Desc: true, Limit: 50, Filters: []store.Filter{{Field: "created", Op: store.OpGTE, Value: to}, {Field: "created", Op: store.OpLT, Value: from}}}, // empty
		{Sort: "created", Desc: true, Limit: 50, Filters: append([]store.Filter{{Field: "action", Value: "user.update"}}, rng...)},
		{Sort: "created", Desc: true, Offset: 20, Limit: 50, Filters: []store.Filter{{Field: "outcome", Value: "failure"}}},
		{Sort: "created", Desc: true, Limit: 50, Filters: []store.Filter{{Field: "action", Op: store.OpPrefix, Value: "USER."}}},
		{Sort: "created", Limit: 50, Filters: append([]store.Filter{{Field: "action", Op: store.OpPrefix, Value: "user.login"}}, rng...)},
		{Sort: "action", Limit: 50, Filters: rng},
	} {
		q.Scope = "org"
		want, err := store.ApplyQuery(model.KindAudit, all.Records, q)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.List(ctx, model.KindAudit, q)
		if err != nil {
			t.Fatal(err)
		}
		if got.Total != want.Total || !slices.Equal(ids(got.Records), ids(want.Records)) {
			t.Fatalf("%+v: got %d records (total %d), want %d (total %d)", q, len(got.Records), got.Total,
				len(want.Records), want.Total)
		}
	}
}
