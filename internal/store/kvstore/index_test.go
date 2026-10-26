package kvstore

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A user listing that leaves the super admins out (every listing of an ordinary administrator) loads only the
// records of its page, whatever the organization's size and the page's position: the super admins are never in it
// and the total counts everyone else. Likewise a page of one indexed filter's records (a group's members).
func TestIndexedPagesLoadOnlyThePage(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{InMemory: true})
	const n, group = 400, "g1"
	var visible, hidden []string
	recs := make([]*store.Record, 0, n+n/2)
	for i := range n {
		name := fmt.Sprintf("user-%04d", i)
		u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: name, Email: name + "@example.test", Role: model.RoleUser, Active: true}
		if i%37 == 5 {
			u.Role = model.RoleSuperAdmin
			hidden = append(hidden, u.ID)
		} else {
			visible = append(visible, u.ID)
		}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
		if i%2 == 0 {
			m := &model.Member{Meta: model.Meta{ID: model.MemberID(group, u.ID)}, GroupID: group, UserID: u.ID, OrgID: "org"}
			r, err := store.Encode(m)
			if err != nil {
				t.Fatal(err)
			}
			recs = append(recs, r)
		}
	}
	if _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	slices.Sort(visible)
	counting := &countingReads{engine: s.eng}
	s.eng = counting
	page := func(kind model.Kind, q store.ListQuery, wantTotal int) []string {
		t.Helper()
		counting.records = 0
		res, err := s.List(ctx, kind, q)
		if err != nil {
			t.Fatal(err)
		}
		if counting.records != len(res.Records) {
			t.Errorf("%+v: loaded %d records for a page of %d", q, counting.records, len(res.Records))
		}
		if wantTotal < 0 { // paged by key: the page length
			wantTotal = len(res.Records)
		}
		if res.Total != wantTotal {
			t.Errorf("%+v: total %d, want %d", q, res.Total, wantTotal)
		}
		ids := make([]string, len(res.Records))
		for i, r := range res.Records {
			ids[i] = r.ID
			if kind == model.KindUser && q.Filters[0].Value == false && slices.Contains(hidden, r.ID) {
				t.Errorf("%+v: a super admin is listed", q)
			}
		}
		return ids
	}
	visibility := []store.Filter{{Field: "super_admin", Value: false}}
	var got []string
	for off := 0; off < len(visible); off += 25 {
		got = append(got, page(model.KindUser, store.ListQuery{Scope: "org", Filters: visibility, Offset: off, Limit: 25}, len(visible))...)
	}
	if !slices.Equal(got, visible) {
		t.Fatalf("offset pages: %d ids, want the %d visible users in id order", len(got), len(visible))
	}
	got = got[:0]
	for after, total := "", len(visible); ; total = -1 { // (the first page is an offset page: After "" is none)
		ids := page(model.KindUser, store.ListQuery{Scope: "org", Filters: visibility, After: after, Limit: 25}, total)
		if len(ids) == 0 {
			break
		}
		got = append(got, ids...)
		after = ids[len(ids)-1]
	}
	if !slices.Equal(got, visible) {
		t.Fatalf("key pages: %d ids, want the %d visible users in id order", len(got), len(visible))
	}
	desc := page(model.KindUser, store.ListQuery{Scope: "org", Filters: visibility, Desc: true, Offset: 10, Limit: 25}, len(visible))
	want := slices.Clone(visible[len(visible)-35 : len(visible)-10])
	slices.Reverse(want)
	if !slices.Equal(desc, want) {
		t.Fatalf("descending page: %v", desc)
	}
	// The whole organization in one call still loads only what it lists.
	page(model.KindUser, store.ListQuery{Scope: "org", Filters: visibility}, len(visible))
	// The super admins themselves, and a group's members, come from their index, a page at a time.
	page(model.KindUser, store.ListQuery{Scope: "org", Filters: []store.Filter{{Field: "super_admin", Value: true}}, Limit: 3}, len(hidden))
	members := page(model.KindMember, store.ListQuery{Scope: "org", Filters: []store.Filter{{Field: "group_id", Value: group}}, Offset: 50, Limit: 10}, n/2)
	if len(members) != 10 {
		t.Fatalf("members page: %d", len(members))
	}
	page(model.KindMember, store.ListQuery{Scope: "org", Filters: []store.Filter{{Field: "group_id", Value: group}}, Limit: 1}, n/2)
}
