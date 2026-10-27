package kvstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A sorted page of a large organization costs its page, not the organization (the console's default user listing).
func BenchmarkSortedUserPage(b *testing.B) {
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			ctx := context.Background()
			s, err := OpenBadger(ctx, b.TempDir(), BadgerOptions{InMemory: true})
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			recs := make([]*store.Record, 0, 1000)
			for i := range n {
				name := fmt.Sprintf("user-%06d", i)
				u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: name, Email: name + "@example.test", GivenName: name, Role: model.RoleUser, Active: true}
				if i%500 == 7 {
					u.Role = model.RoleSuperAdmin
				}
				rec, err := store.Encode(u)
				if err != nil {
					b.Fatal(err)
				}
				recs = append(recs, rec)
				if len(recs) == cap(recs) || i == n-1 {
					if _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
						b.Fatal(err)
					}
					recs = recs[:0]
				}
			}
			visibility := []store.Filter{{Field: "super_admin", Value: false}}
			for _, bc := range []struct {
				name string
				q    store.ListQuery
			}{
				{"username-asc", store.ListQuery{Scope: "org", Sort: "username", Limit: 25, Filters: visibility}},
				{"username-desc-offset", store.ListQuery{Scope: "org", Sort: "username", Desc: true, Offset: 200, Limit: 25, Filters: visibility}},
				{"active-desc-ties", store.ListQuery{Scope: "org", Sort: "active", Desc: true, Offset: 200, Limit: 25, Filters: visibility}},
				{"role-user-username", store.ListQuery{Scope: "org", Sort: "username", Limit: 25, Filters: append([]store.Filter{{Field: "role", Value: string(model.RoleUser)}}, visibility...)}},
				{"role-super-username", store.ListQuery{Scope: "org", Sort: "username", Limit: 25, Filters: []store.Filter{{Field: "role", Value: string(model.RoleSuperAdmin)}}}},
				{"plain", store.ListQuery{Scope: "org", Limit: 25}},
				{"plain-visibility", store.ListQuery{Scope: "org", Limit: 25, Filters: visibility}},
				{"search-username", store.ListQuery{Scope: "org", Sort: "username", Search: "user-0000", Limit: 25, Filters: visibility}},
			} {
				b.Run(bc.name, func(b *testing.B) {
					counting := &countingReads{engine: s.eng}
					s.eng = counting
					defer func() { s.eng = counting.engine }()
					b.ReportAllocs()
					for b.Loop() {
						page, err := s.List(ctx, model.KindUser, bc.q)
						if err != nil || len(page.Records) == 0 {
							b.Fatalf("page: %+v %v", page, err)
						}
					}
					b.ReportMetric(float64(counting.records)/float64(b.N), "records-read/op")
				})
			}
		})
	}
}

// Page still visits every index member to produce Total, even when it returns
// just 25 IDs. Index entries need no record bodies for this engine-level measure.
func BenchmarkEnginePageTotalScalesWithIndex(b *testing.B) {
	for _, n := range []int{10000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			ctx := context.Background()
			s, err := OpenBadger(ctx, b.TempDir(), BadgerOptions{InMemory: true})
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			for start := 0; start < n; start += 1000 {
				if err := s.eng.Update(ctx, func(tx txn) error {
					for i := start; i < start+1000 && i < n; i++ {
						tx.SetAdd("bench-page", fmt.Sprintf("user-%09d", i), 0)
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				ids, total, err := s.eng.Page(ctx, "bench-page", pageQuery{Limit: 25}, nowMs())
				if err != nil || len(ids) != 25 || total != n {
					b.Fatalf("page ids=%d total=%d err=%v", len(ids), total, err)
				}
			}
		})
	}
}

// The unlimited scope listings of every request: a user's sessions, a user's memberships (an indexed filter within the
// organization's scope), and the organization's groups with changes pending (none).
func BenchmarkScopeListings(b *testing.B) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, b.TempDir(), BadgerOptions{InMemory: true})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	var recs []*store.Record
	put := func(e model.Entity) {
		rec, err := store.Encode(e)
		if err != nil {
			b.Fatal(err)
		}
		recs = append(recs, rec)
		if len(recs) == 500 {
			if _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
				b.Fatal(err)
			}
			recs = recs[:0]
		}
	}
	for u := range 1000 {
		uid := fmt.Sprintf("user-%04d", u)
		for range 3 {
			put(&model.Session{Meta: model.Meta{ID: model.NewID()}, UserID: uid, OrgID: "org", Expires: time.Now().Add(time.Hour), IP: "10.0.0.1"})
		}
		for g := range 5 {
			put(&model.Member{Meta: model.Meta{ID: model.NewID()}, GroupID: fmt.Sprintf("group-%d", (u+g)%200), UserID: uid, OrgID: "org"})
		}
	}
	for g := range 200 {
		put(&model.Group{Meta: model.Meta{ID: fmt.Sprintf("group-%d", g)}, OrgID: "org", DisplayName: fmt.Sprintf("group %d", g)})
	}
	if _, err := s.PutReplicatedBatch(ctx, recs); err != nil {
		b.Fatal(err)
	}
	for _, bc := range []struct {
		name string
		kind model.Kind
		q    store.ListQuery
		want int
	}{
		{"user-sessions", model.KindSession, store.ListQuery{Scope: "user-0500"}, 3},
		{"user-memberships", model.KindMember, store.ListQuery{Scope: "org", Filters: []store.Filter{{Field: "user_id", Value: "user-0500"}}}, 5},
		{"pending-groups-none", model.KindGroup, store.ListQuery{Scope: "org", Filters: []store.Filter{{Field: "pending", Value: true}}}, 0},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				page, err := s.List(ctx, bc.kind, bc.q)
				if err != nil || len(page.Records) != bc.want || page.Total != bc.want {
					b.Fatalf("page: %+v %v", page, err)
				}
			}
		})
	}
}
