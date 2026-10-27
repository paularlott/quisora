package kvstore

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A sorted listing on a SortIndex field, ascending or descending, at any offset, with or without the visibility
// exclusion, loads the records of its page (plus the excluded set, whose sort members come from the records) and
// nothing else, and never has the engine count a range: the total is a counter. It returns exactly what applying the
// query to every record of the scope returns, ties (equal values, even a scope made of a few of them) and empty
// values included. Counters and sort members follow updates and deletions.
func TestSortedPagesAreBounded(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{InMemory: true})
	const n = 400
	hidden := 0
	recs := make([]*store.Record, 0, n)
	us := make([]*model.User, 0, n)
	for i := range n {
		name := fmt.Sprintf("user-%04d", i)
		if i%3 == 0 {
			name = strings.ToUpper(name) // case folds: the order is the folded one
		}
		u := &model.User{Meta: model.Meta{ID: model.NewID(), Created: time.Unix(1_700_000_000+int64(i%50), int64(i%7)*1000)},
			OrgID: "org", Username: name, Email: name + "@example.test", GivenName: fmt.Sprintf("Name%d", i%5), Role: model.RoleUser, Active: i%4 != 0}
		if i%9 == 0 {
			u.GivenName = "" // the name falls back to the username
		}
		if i%11 == 0 {
			end := time.Unix(1_800_000_000+int64(i), 0)
			u.ValidUntil = &end // most users have no end date: empty values sort first, as one run
		}
		if i%37 == 5 {
			u.Role = model.RoleSuperAdmin
			hidden++
		}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
		us = append(us, u)
	}
	if _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	counting := &countingReads{engine: s.eng}
	s.eng = counting
	ids := func(recs []*store.Record) []string {
		out := make([]string, len(recs))
		for i, r := range recs {
			out[i] = r.ID
		}
		return out
	}
	oracle := func(q store.ListQuery) *store.ListResult {
		t.Helper()
		all, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org"})
		if err != nil {
			t.Fatal(err)
		}
		want, err := store.ApplyQuery(model.KindUser, all.Records, q)
		if err != nil {
			t.Fatal(err)
		}
		return want
	}
	agree := func(q store.ListQuery) *store.ListResult {
		t.Helper()
		want := oracle(q)
		counting.records, counting.counted = 0, 0
		got, err := s.List(ctx, model.KindUser, q)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(ids(got.Records), ids(want.Records)) || got.Total != want.Total {
			t.Errorf("%+v:\n got %d %v\nwant %d %v", q, got.Total, ids(got.Records), want.Total, ids(want.Records))
		}
		return got
	}
	bounded := func(q store.ListQuery, extra int) {
		t.Helper()
		got := agree(q)
		if counting.records != len(got.Records)+extra {
			t.Errorf("%+v: loaded %d records for a page of %d (+%d excluded)", q, counting.records, len(got.Records), extra)
		}
		if counting.counted != 0 {
			t.Errorf("%+v: %d ranges counted by the engine; the total should come from a counter", q, counting.counted)
		}
	}
	visibility := []store.Filter{{Field: "super_admin", Value: false}}
	for _, sort := range []string{"username", "name", "created", "active", "role", "email"} {
		for _, desc := range []bool{false, true} {
			for _, off := range []int{0, 7, 100, 393, 500} {
				bounded(store.ListQuery{Scope: "org", Sort: sort, Desc: desc, Offset: off, Limit: 25}, 0)
				bounded(store.ListQuery{Scope: "org", Sort: sort, Desc: desc, Offset: off, Limit: 25, Filters: visibility}, hidden)
			}
			bounded(store.ListQuery{Scope: "org", Sort: sort, Desc: desc}, 0) // everything, in order
		}
	}
	// The plain and the excluding pages take their totals from the counters too.
	bounded(store.ListQuery{Scope: "org", Offset: 30, Limit: 25}, 0)
	bounded(store.ListQuery{Scope: "org", Desc: true, Offset: 30, Limit: 25, Filters: visibility}, 0)
	bounded(store.ListQuery{Scope: "org", Limit: 3, Filters: []store.Filter{{Field: "super_admin", Value: true}}}, 0)

	// Updates move a record in the sort indexes; deletions leave the indexes and the counters.
	tb := store.NewTable[model.User](s)
	u, err := tb.Get(ctx, us[10].ID)
	if err != nil {
		t.Fatal(err)
	}
	u.Username, u.GivenName = "aaa-first", "Zed"
	if err := tb.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{1, 2, 3, 42} {
		if err := tb.Delete(ctx, us[i].ID); err != nil {
			t.Fatal(err)
		}
	}
	hidden-- // user 42 was a super admin
	bounded(store.ListQuery{Scope: "org", Sort: "username", Limit: 3}, 0)
	bounded(store.ListQuery{Scope: "org", Sort: "name", Desc: true, Limit: 3, Filters: visibility}, hidden)
	if got, _ := s.Count(ctx, model.KindUser, "org"); got != n-4 {
		t.Errorf("count after deletions: %d", got)
	}

	// The listings no index answers outright (a search, a filter on an unindexed field, a sort on an unindexed
	// field) stream the scope and agree with the oracle.
	for _, desc := range []bool{false, true} {
		for _, q := range []store.ListQuery{
			{Scope: "org", Sort: "username", Desc: desc, Search: "user-00", Offset: 3, Limit: 10},
			{Scope: "org", Sort: "name", Desc: desc, Filters: []store.Filter{{Field: "role", Value: "user"}}, Offset: 50, Limit: 25},
			{Scope: "org", Sort: "name", Desc: desc, Filters: []store.Filter{{Field: "role", Value: "user"}}},
			{Scope: "org", Desc: desc, Search: "USER-01", Limit: 10},
			{Scope: "org", Sort: "valid_until", Desc: desc, Search: "user-02", Limit: 10}, // no sort index: ordered in memory
			{Scope: "org", Sort: "name", Desc: desc, Filters: visibility, Search: "user-03"},
			{Scope: "", Sort: "username", Desc: desc, Limit: 10}, // a scoped kind without a scope: ordered in memory
		} {
			agree(q)
		}
	}
	got, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org", Search: "user-01", After: us[100].ID, Limit: 5})
	if err != nil || got.Total != len(got.Records) || len(got.Records) != 5 {
		t.Errorf("searched page by key: %+v %v", got, err)
	}
	// An indexed bool's false records are not indexed; its true records are.
	if m, _ := s.eng.Range(ctx, fieldBucket(model.KindUser, "super_admin", "false"), "", "", 1); len(m) != 0 {
		t.Errorf("a false bucket is written: %v", m)
	}
	if m, _ := s.eng.Range(ctx, fieldBucket(model.KindUser, "super_admin", "true"), "", "", 0); len(m) != hidden {
		t.Errorf("true bucket holds %d, want %d", len(m), hidden)
	}
}

// A kind whose records expire (grants) keeps exact totals: the engine counts its ranges, leaving out the expired
// members, and keeps no counters.
func TestExpiringRangesCountExactly(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{InMemory: true})
	grants := store.NewTable[model.Grant](s)
	for i := range 20 {
		g := &model.Grant{UserID: "u1", OrgID: "org", ClientID: "app", Expires: time.Now().Add(time.Hour)}
		if i%4 == 0 {
			g.Expires = time.Now().Add(-time.Minute) // expired, still stored
		}
		if err := grants.Put(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	counting := &countingReads{engine: s.eng}
	s.eng = counting
	res, err := s.List(ctx, model.KindGrant, store.ListQuery{Scope: "u1", Limit: 3})
	if err != nil || res.Total != 15 || len(res.Records) != 3 {
		t.Fatalf("expiring scope: %+v %v", res, err)
	}
	if counting.counted != 1 {
		t.Errorf("the engine counted %d ranges, want 1: the scope has expiring members", counting.counted)
	}
	if n, _ := s.Count(ctx, model.KindGrant, "u1"); n != 15 {
		t.Errorf("count %d", n)
	}
	if _, err := s.Purge(ctx, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Count(ctx, model.KindGrant, "u1"); n != 15 {
		t.Errorf("count after purge %d", n)
	}
	if n, x, _ := s.counts(ctx, scopeBucket(model.KindGrant, "u1")); n != 0 || x != 0 {
		t.Errorf("counters of grants: %d members, %d expiring", n, x)
	}
}

// The sort key orders values as store.CompareValues does.
func TestSortKeyOrder(t *testing.T) {
	str := model.Field{Name: "s", Type: model.FieldString}
	tm := model.Field{Name: "t", Type: model.FieldTime}
	bl := model.Field{Name: "b", Type: model.FieldBool}
	in := model.Field{Name: "i", Type: model.FieldInt}
	cases := []struct {
		f    model.Field
		a, b any
	}{
		{str, "", "a"}, {str, nil, "a"}, {str, "a", "ab"}, {str, "a", "B"}, {str, "Ab", "b"}, {str, "a\x00", "a\x01"},
		{str, "a", "a\x00"}, {str, "a\x01", "a\x02"}, {str, "é", "z"}, // (bytes of the lowered UTF-8, as strings.Compare)
		{tm, time.Time{}, time.Unix(0, 0)}, {tm, nil, time.Unix(1, 0)}, {tm, time.Unix(-5, 0), time.Unix(1, 0)},
		{tm, time.Unix(1, 5), time.Unix(1, 6)}, {tm, time.Unix(1, 999_999_999), time.Unix(2, 0)},
		{bl, false, true}, {bl, nil, true}, {bl, true, true},
		{in, int64(-3), int64(2)}, {in, nil, int64(1)}, {in, 7, int64(7)},
	}
	for _, c := range cases {
		ka, kb := string(appendSortKey(nil, c.f, c.a)), string(appendSortKey(nil, c.f, c.b))
		if want := store.CompareValues(c.a, c.b); strings.Compare(ka, kb) != want {
			t.Errorf("%v vs %v: keys compare %d, values %d", c.a, c.b, strings.Compare(ka, kb), want)
		}
		if strings.IndexByte(ka, 0) >= 0 || strings.IndexByte(kb, 0) >= 0 {
			t.Errorf("%v / %v: a sort key holds a NUL", c.a, c.b)
		}
	}
	m := sortMember("org/1", str, "x\x00y", "id-1")
	if sortMemberID(m) != "id-1" || !strings.HasPrefix(m, "org%2F1/") {
		t.Errorf("member %q: id %q", m, sortMemberID(m))
	}
}
