package store_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

var qt0 = time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)

func userRec(id, org, name, role string, active bool, tags string, created time.Time) *store.Record {
	return &store.Record{Kind: model.KindUser, ID: id, Scope: org, Fields: map[string]any{
		"username": name, "email": name + "@x.com", "name": name, "role": role, "active": active, "tags": tags,
		"created": created, "valid_until": created, "expiring": true,
	}}
}

func ids(recs []*store.Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.ID
	}
	return out
}

func TestValidateQuery(t *testing.T) {
	for _, c := range []struct {
		name string
		kind model.Kind
		q    store.ListQuery
		bad  bool
	}{
		{"empty", model.KindUser, store.ListQuery{}, false},
		{"unknown kind", "nope", store.ListQuery{}, true},
		{"sort ok", model.KindUser, store.ListQuery{Sort: "username"}, false},
		{"sort unknown", model.KindUser, store.ListQuery{Sort: "nope"}, true},
		{"sort not sortable", model.KindUser, store.ListQuery{Sort: "tags"}, true},
		{"after plain", model.KindUser, store.ListQuery{After: "x"}, false},
		{"after with sort", model.KindUser, store.ListQuery{After: "x", Sort: "username"}, true},
		{"after with desc", model.KindUser, store.ListQuery{After: "x", Desc: true}, true},
		{"equality", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "role", Value: "admin"}}}, false},
		{"filter unknown", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "nope", Value: 1}}}, true},
		{"prefix ok", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "username", Op: store.OpPrefix, Value: "a"}}}, false},
		{"prefix non-string value", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "username", Op: store.OpPrefix, Value: 1}}}, true},
		{"prefix non-string field", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "active", Op: store.OpPrefix, Value: "a"}}}, true},
		{"gte time", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "created", Op: store.OpGTE, Value: qt0}}}, false},
		{"lt on string", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "username", Op: store.OpLT, Value: "a"}}}, true},
		{"gte on bool", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "active", Op: store.OpGTE, Value: true}}}, true},
		{"unknown op", model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "role", Op: "like", Value: "a"}}}, true},
	} {
		err := store.ValidateQuery(c.kind, c.q)
		if (err != nil) != c.bad || (err != nil && !errors.Is(err, store.ErrBadQuery)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if !store.IsPlainScan(store.ListQuery{Scope: "o", Limit: 5, Offset: 2, Desc: true}) {
		t.Error("paging does not make a scan non-plain")
	}
	for _, q := range []store.ListQuery{{Sort: "x"}, {Search: "x"}, {Filters: []store.Filter{{}}}} {
		if store.IsPlainScan(q) {
			t.Errorf("%+v is plain", q)
		}
	}
}

func TestApplyQuery(t *testing.T) {
	recs := []*store.Record{
		userRec("4", "o", "delta", "user", true, "x y", qt0.Add(3*time.Hour)),
		userRec("1", "o", "Alpha", "admin", true, "x", qt0),
		userRec("3", "o", "charlie", "user", false, "Y", qt0.Add(2*time.Hour)),
		userRec("2", "o", "bravo", "user", true, "", qt0.Add(time.Hour)),
		userRec("5", "p", "echo", "admin", true, "x", qt0.Add(4*time.Hour)),
	}
	recs[3].Fields["email"] = "BRAVO@x.com"
	delete(recs[0].Fields, "valid_until") // a record without the field is outside every range filter
	run := func(q store.ListQuery) ([]string, int) {
		t.Helper()
		res, err := store.ApplyQuery(model.KindUser, recs, q)
		if err != nil {
			t.Fatal(err)
		}
		return ids(res.Records), res.Total
	}
	for _, c := range []struct {
		name  string
		q     store.ListQuery
		want  []string
		total int
	}{
		{"id order", store.ListQuery{}, []string{"1", "2", "3", "4", "5"}, 5},
		{"id order desc", store.ListQuery{Desc: true}, []string{"5", "4", "3", "2", "1"}, 5},
		{"scope", store.ListQuery{Scope: "o"}, []string{"1", "2", "3", "4"}, 4},
		{"sort case-insensitive", store.ListQuery{Scope: "o", Sort: "username"}, []string{"1", "2", "3", "4"}, 4},
		{"sort desc", store.ListQuery{Scope: "o", Sort: "username", Desc: true}, []string{"4", "3", "2", "1"}, 4},
		{"sort bool", store.ListQuery{Scope: "o", Sort: "active"}, []string{"3", "1", "2", "4"}, 4},
		{"sort time desc", store.ListQuery{Sort: "created", Desc: true}, []string{"5", "4", "3", "2", "1"}, 5},
		{"page", store.ListQuery{Sort: "created", Offset: 1, Limit: 2}, []string{"2", "3"}, 5},
		{"offset past end", store.ListQuery{Offset: 9}, []string{}, 5},
		{"negative offset", store.ListQuery{Offset: -3, Limit: 1}, []string{"1"}, 5},
		{"search prefix any field", store.ListQuery{Search: "BRA"}, []string{"2"}, 1},
		{"search email field", store.ListQuery{Search: "echo@"}, []string{"5"}, 1},
		{"search no match", store.ListQuery{Search: "zzz"}, []string{}, 0},
		{"equality", store.ListQuery{Filters: []store.Filter{{Field: "role", Value: "admin"}}}, []string{"1", "5"}, 2},
		{"equality bool", store.ListQuery{Filters: []store.Filter{{Field: "active", Value: false}}}, []string{"3"}, 1},
		{"words filter", store.ListQuery{Filters: []store.Filter{{Field: "tags", Value: "y"}}}, []string{"3", "4"}, 2},
		{"words filter no partial", store.ListQuery{Filters: []store.Filter{{Field: "tags", Value: "xy"}}}, []string{}, 0},
		{"prefix filter", store.ListQuery{Filters: []store.Filter{{Field: "username", Op: store.OpPrefix, Value: "AL"}}}, []string{"1"}, 1},
		{"gte", store.ListQuery{Filters: []store.Filter{{Field: "created", Op: store.OpGTE, Value: qt0.Add(2 * time.Hour)}}}, []string{"3", "4", "5"}, 3},
		{"lt", store.ListQuery{Filters: []store.Filter{{Field: "created", Op: store.OpLT, Value: qt0.Add(2 * time.Hour)}}}, []string{"1", "2"}, 2},
		{"range", store.ListQuery{Filters: []store.Filter{{Field: "created", Op: store.OpGTE, Value: qt0.Add(time.Hour)}, {Field: "created", Op: store.OpLT, Value: qt0.Add(3 * time.Hour)}}}, []string{"2", "3"}, 2},
		{"gte missing field", store.ListQuery{Filters: []store.Filter{{Field: "valid_until", Op: store.OpGTE, Value: qt0.Add(-time.Hour)}}}, []string{"1", "2", "3", "5"}, 4},
		{"after", store.ListQuery{After: "2", Limit: 2}, []string{"3", "4"}, 2},
		{"after ignores offset", store.ListQuery{After: "4", Offset: 7}, []string{"5"}, 1},
		{"filters and search", store.ListQuery{Scope: "o", Search: "a", Filters: []store.Filter{{Field: "active", Value: true}}}, []string{"1"}, 1},
	} {
		got, total := run(c.q)
		if !slices.Equal(got, c.want) || total != c.total {
			t.Errorf("%s: got %v (%d), want %v (%d)", c.name, got, total, c.want, c.total)
		}
	}
	if _, err := store.ApplyQuery(model.KindUser, recs, store.ListQuery{Sort: "nope"}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("bad query: %v", err)
	}
	if res, err := store.ApplyQuery(model.KindUser, nil, store.ListQuery{}); err != nil || res.Total != 0 || res.Records == nil {
		t.Errorf("empty input: %+v %v", res, err)
	}
}

// A collector offered records in many batches returns what ApplyQuery gives for the same records, while holding no
// more than a page's worth (checked through the result: the page and the total stay exact under heavy trimming).
func TestCollectorMatchesApplyQuery(t *testing.T) {
	var recs []*store.Record
	for i := range 100 {
		recs = append(recs, userRec(fmt.Sprintf("%03d", i), "o", fmt.Sprintf("u%03d", (i*37)%100), "user", i%3 != 0, "", qt0.Add(time.Duration(i)*time.Minute)))
	}
	for _, q := range []store.ListQuery{
		{Sort: "username", Limit: 5},
		{Sort: "username", Desc: true, Limit: 7, Offset: 10},
		{Limit: 3, Offset: 50},
		{Filters: []store.Filter{{Field: "active", Value: true}}, Sort: "created", Desc: true, Limit: 4},
		{After: "010", Limit: 5},
		{Sort: "username"},
	} {
		want, err := store.ApplyQuery(model.KindUser, recs, q)
		if err != nil {
			t.Fatal(err)
		}
		c, err := store.NewCollector(model.KindUser, q)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(recs); i += 9 {
			c.Add(recs[i:min(i+9, len(recs))])
		}
		got := c.Result()
		if !slices.Equal(ids(got.Records), ids(want.Records)) || got.Total != want.Total {
			t.Errorf("%+v: collector %v (%d), apply %v (%d)", q, ids(got.Records), got.Total, ids(want.Records), want.Total)
		}
	}
	if _, err := store.NewCollector(model.KindUser, store.ListQuery{Sort: "nope"}); !errors.Is(err, store.ErrBadQuery) {
		t.Error("NewCollector accepted a bad query")
	}
}

func TestMatchAndPage(t *testing.T) {
	r := userRec("1", "o", "alice", "user", true, "", qt0)
	if !store.Match(model.KindUser, r, store.ListQuery{Scope: "o", Search: "ALI"}) || store.Match(model.KindUser, r, store.ListQuery{Scope: "q"}) {
		t.Error("Match scope/search")
	}
	if store.Match(model.KindUser, r, store.ListQuery{Filters: []store.Filter{{Field: "role", Value: "admin"}}}) {
		t.Error("Match filter")
	}
	s := []*store.Record{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	for _, c := range []struct {
		off, lim int
		want     []string
	}{{0, 0, []string{"a", "b", "c"}}, {1, 0, []string{"b", "c"}}, {0, 2, []string{"a", "b"}}, {2, 5, []string{"c"}}, {3, 1, nil}, {-1, 1, []string{"a"}}} {
		if got := ids(store.Page(s, c.off, c.lim)); !slices.Equal(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("Page(%d,%d) = %v", c.off, c.lim, got)
		}
	}
}

func TestEqualAndCompareValues(t *testing.T) {
	later := qt0.In(time.FixedZone("x", 3600))
	for _, c := range []struct {
		a, b any
		eq   bool
	}{
		{"a", "a", true}, {"a", "A", false}, {int64(3), 3, true}, {int32(3), uint64(3), true}, {uint32(4), int(4), true}, {int64(3), int64(4), false},
		{int64(3), "3", false}, {true, true, true}, {true, false, false}, {nil, nil, true}, {nil, "", true}, {nil, "x", false},
		{qt0, later, true}, {qt0, qt0.Add(time.Second), false}, {qt0, "x", false}, {"a", 1, false},
	} {
		if store.EqualValues(c.a, c.b) != c.eq {
			t.Errorf("EqualValues(%v, %v) = %v", c.a, c.b, !c.eq)
		}
	}
	for _, c := range []struct {
		a, b any
		want int
	}{
		{"a", "B", -1}, {"B", "a", 1}, {"a", "A", 0}, {false, true, -1}, {true, false, 1}, {true, true, 0}, {false, false, 0},
		{qt0, qt0.Add(1), -1}, {qt0.Add(1), qt0, 1}, {qt0, later, 0}, {nil, nil, 0}, {nil, "a", -1},
		{int64(1), int64(2), -1}, {3, int64(2), 1}, {uint64(2), int32(2), 0}, {"a", nil, 1},
	} {
		if got := store.CompareValues(c.a, c.b); got != c.want {
			t.Errorf("CompareValues(%v, %v) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
