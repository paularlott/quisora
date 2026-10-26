package kvstore

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

// Audit pages filtered by time range, action (exact or prefix) and outcome are served from the indexes (a range of the
// created sort index, the action and outcome field indexes, a range of the action sort index): their pages, at any
// offset and in either order, are those of the shared query evaluation, with the same total.
func TestAuditFilterPages(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{InMemory: true})
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
	if _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
		t.Fatal(err)
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
		storetest.CheckAgainstApplyQuery(t, s, model.KindAudit, q)
	}
}
