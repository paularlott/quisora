// Package storetest is the conformance suite every Store backend must pass.
//
//	func TestConformance(t *testing.T) { storetest.Run(t, func(t *testing.T) store.Store { return newTestStore(t) }) }
//
// The factory must return an empty store; the suite closes it.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"github.com/paularlott/quisora/internal/ephemeral"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Factory returns a new, empty store.
type Factory func(t testing.TB) store.Store

// Options relax the suite for stores configured without a change feed.
type Options struct {
	// NoFeed skips the tests that read the change feed (Changes, ChangesIncludeReplicated, ConcurrentChangesOrder).
	// Everything else, including the feed-free parts of Purge, still runs.
	NoFeed bool
}

// Run runs every conformance test.
func Run(t *testing.T, f Factory) { RunWithOptions(t, f, Options{}) }

// RunWithOptions runs the conformance tests with the given relaxations.
func RunWithOptions(t *testing.T, f Factory, opt Options) {
	tests := []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"PutGet", testPutGet},
		{"RoundTripTypes", testRoundTripTypes},
		{"Stale", testStale},
		{"Unique", testUnique},
		{"UniqueReleasedOnChange", testUniqueReleased},
		{"Tombstone", testTombstone},
		{"Create", testCreate},
		{"CompareAndPut", testCompareAndPut},
		{"Expiry", testExpiry},
		{"ListScopeAndTotal", testListScope},
		{"ListSearch", testListSearch},
		{"ListFilters", testListFilters},
		{"ListFilterOperators", testListFilterOps},
		{"ListIndexedFilters", testListIndexed},
		{"ListSortIndexes", testListSortIndexes},
		{"GetMany", testGetMany},
		{"RefreshFields", testRefreshFields},
		{"ListSort", testListSort},
		{"ListPaging", testListPaging},
		{"ListPlainScanLarge", testPlainScanLarge},
		{"ListAfter", testListAfter},
		{"WriteAfterFasterClock", testWriteAfterFasterClock},
		{"EphemeralShared", testEphemeralShared},
		{"ListBadQuery", testBadQuery},
		{"Count", testCount},
		{"ReplicatedLWW", testReplicatedLWW},
		{"ReplicatedTombstoneWinsTie", testReplicatedTombstoneTie},
		{"ReplicatedTombstoneDominates", testReplicatedTombstoneDominates},
		{"QuorumTombstoneRanksByVersion", testQuorumTombstoneRanksByVersion},
		{"LocalWriteOverTombstone", testLocalWriteOverTombstone},
		{"ReplicatedOriginTie", testReplicatedOriginTie},
		{"ReplicatedUniqueClash", testReplicatedUniqueClash},
		{"Changes", testChanges},
		{"ChangesIncludeReplicated", testChangesReplicated},
		{"FeedID", testFeedID},
		{"Purge", testPurge},
		{"ConcurrentCompareAndPut", testConcurrentCAS},
		{"ConcurrentChangesOrder", testConcurrentChanges},
		{"ConcurrentUniqueClaim", testConcurrentUniqueClaim},
		{"ConcurrentRewritesFeed", testConcurrentRewritesFeed},
		{"KindsIsolated", testKindsIsolated},
	}
	feedTests := map[string]bool{"Changes": true, "ChangesIncludeReplicated": true, "ConcurrentChangesOrder": true,
		"ConcurrentRewritesFeed": true}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if opt.NoFeed && feedTests[tc.name] {
				t.Skip("change feed disabled")
			}
			s := f(t)
			defer s.Close()
			tc.fn(t, s)
		})
	}
}

var ctx = context.Background()

func users(s store.Store) *store.Table[model.User, *model.User] {
	return store.NewTable[model.User](s)
}

func newUser(org, name string) *model.User {
	return &model.User{OrgID: org, Username: name, Email: name + "@example.com", GivenName: "User " + name,
		Role: model.RoleUser, Active: true}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func testPutGet(t *testing.T, s store.Store) {
	u := newUser("org1", "alice")
	tb := users(s)
	must(t, tb.Put(ctx, u))
	got, err := tb.Get(ctx, u.ID)
	must(t, err)
	if got.Username != "alice" || got.Email != "alice@example.com" || got.Version != u.Version || got.Version == 0 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	got, err = tb.GetByUnique(ctx, model.UserEmailKey("org1", "ALICE@example.com"))
	must(t, err)
	if got.ID != u.ID {
		t.Fatal("unique lookup returned wrong record")
	}
	if _, err := tb.Get(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := tb.GetByUnique(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	r, err := s.Get(ctx, model.KindUser, u.ID)
	must(t, err)
	if r.Scope != "org1" || r.Origin != store.Origin() || len(r.Unique) != 2 {
		t.Fatalf("record metadata not preserved: %+v", r)
	}
}

// Field values of every type survive storage and are returned in Fields with the documented Go types.
func testRoundTripTypes(t *testing.T, s store.Store) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	u := newUser("org1", "bob")
	u.ValidUntil = &now
	must(t, users(s).Put(ctx, u))
	r, err := s.Get(ctx, model.KindUser, u.ID)
	must(t, err)
	if v, ok := r.Fields["active"].(bool); !ok || !v {
		t.Fatalf("bool field: %#v", r.Fields["active"])
	}
	if v, ok := r.Fields["valid_until"].(time.Time); !ok || !v.Equal(now) {
		t.Fatalf("time field: %#v want %v", r.Fields["valid_until"], now)
	}
	if v, ok := r.Fields["username"].(string); !ok || v != "bob" {
		t.Fatalf("string field: %#v", r.Fields["username"])
	}
	k := &model.SigningKey{Alg: "ES256"}
	must(t, store.NewTable[model.SigningKey](s).Put(ctx, k))
	got, err := store.NewTable[model.SigningKey](s).Get(ctx, k.ID)
	must(t, err)
	if got.Alg != "ES256" {
		t.Fatal("key round trip")
	}
}

func testStale(t *testing.T, s store.Store) {
	u := newUser("org1", "carol")
	must(t, users(s).Put(ctx, u))
	r, _ := store.EncodeAsIs(u) // same version
	if err := s.Put(ctx, r); !errors.Is(err, store.ErrStale) {
		t.Fatalf("same version: want ErrStale, got %v", err)
	}
	r.Version--
	if err := s.Put(ctx, r); !errors.Is(err, store.ErrStale) {
		t.Fatalf("older version: want ErrStale, got %v", err)
	}
}

func testUnique(t *testing.T, s store.Store) {
	tb := users(s)
	must(t, tb.Put(ctx, newUser("org1", "dave")))
	dup := newUser("org1", "dave2")
	dup.Email = "DAVE@example.com" // case-insensitive clash on email
	if err := tb.Put(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if _, err := tb.Get(ctx, dup.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("conflicting record must not be written")
	}
	// Same name in another org is fine.
	must(t, tb.Put(ctx, newUser("org2", "dave")))
}

func testUniqueReleased(t *testing.T, s store.Store) {
	tb := users(s)
	u := newUser("org1", "erin")
	must(t, tb.Put(ctx, u))
	u.Email = "erin.new@example.com"
	must(t, tb.Put(ctx, u))
	if _, err := tb.GetByUnique(ctx, model.UserEmailKey("org1", "erin@example.com")); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("old unique value must be released")
	}
	other := newUser("org1", "erin2")
	other.Email = "erin@example.com"
	must(t, tb.Put(ctx, other))
	got, err := tb.GetByUnique(ctx, model.UserEmailKey("org1", "erin.new@example.com"))
	must(t, err)
	if got.ID != u.ID {
		t.Fatal("new unique value must point at the record")
	}
}

func testTombstone(t *testing.T, s store.Store) {
	tb := users(s)
	u := newUser("org1", "frank")
	must(t, tb.Put(ctx, u))
	must(t, tb.Delete(ctx, u.ID))
	if _, err := tb.Get(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("tombstoned record visible via Get")
	}
	if _, err := tb.GetByUnique(ctx, model.UserUsernameKey("org1", "frank")); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("tombstoned record visible via unique")
	}
	list, total, err := tb.List(ctx, store.ListQuery{Scope: "org1"})
	must(t, err)
	if total != 0 || len(list) != 0 {
		t.Fatal("tombstoned record listed")
	}
	// Unique values are free again.
	must(t, tb.Put(ctx, newUser("org1", "frank")))
	// A write older than the tombstone is stale.
	old, _ := store.EncodeAsIs(u)
	if err := s.Put(ctx, old); !errors.Is(err, store.ErrStale) {
		t.Fatalf("write older than tombstone: want ErrStale, got %v", err)
	}
	// Deleting a record that never existed is allowed (tombstone for replication).
	must(t, s.Put(ctx, store.Tombstone(model.KindUser, "never")))
}

func testCreate(t *testing.T, s store.Store) {
	tb := users(s)
	u := newUser("org1", "gina")
	must(t, tb.Create(ctx, u))
	again := *u
	if err := tb.Create(ctx, &again); !errors.Is(err, store.ErrStale) {
		t.Fatalf("create over live record: want ErrStale, got %v", err)
	}
	clash := newUser("org1", "gina")
	if err := tb.Create(ctx, clash); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("create with clashing unique: want ErrConflict, got %v", err)
	}
	must(t, tb.Delete(ctx, u.ID))
	re := *u
	re.Version = 0
	must(t, tb.Create(ctx, &re)) // re-create over a tombstone
}

func testCompareAndPut(t *testing.T, s store.Store) {
	tb := users(s)
	u := newUser("org1", "hank")
	must(t, tb.Put(ctx, u))
	a, _ := tb.Get(ctx, u.ID)
	b, _ := tb.Get(ctx, u.ID)
	a.GivenName = "A"
	must(t, tb.Update(ctx, a))
	b.GivenName = "B"
	if err := tb.Update(ctx, b); !errors.Is(err, store.ErrStale) {
		t.Fatalf("lost update not detected: %v", err)
	}
	got, _ := tb.Get(ctx, u.ID)
	if got.GivenName != "A" {
		t.Fatal("stale update applied")
	}
	missing := newUser("org1", "nobody")
	missing.ID = "missing"
	r, _ := store.Encode(missing)
	if err := s.CompareAndPut(ctx, r, 12345); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// Unique clash on update.
	other := newUser("org1", "ivy")
	must(t, tb.Put(ctx, other))
	got.Email = other.Email
	if err := tb.Update(ctx, got); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func testExpiry(t *testing.T, s store.Store) {
	st := store.NewTable[model.Session](s)
	gone := &model.Session{UserID: "u1", OrgID: "o1", Expires: time.Now().Add(-time.Second)}
	live := &model.Session{UserID: "u1", OrgID: "o1", Expires: time.Now().Add(time.Hour)}
	must(t, st.Put(ctx, gone))
	must(t, st.Put(ctx, live))
	if _, err := st.Get(ctx, gone.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired record visible")
	}
	list, total, err := st.List(ctx, store.ListQuery{Scope: "u1"})
	must(t, err)
	if total != 1 || len(list) != 1 || list[0].ID != live.ID {
		t.Fatalf("expired record listed: total=%d", total)
	}
	n, err := s.Count(ctx, model.KindSession, "u1")
	must(t, err)
	if n != 1 {
		t.Fatalf("count includes expired: %d", n)
	}
	// An expired record does not hold unique values.
	tok := &model.Passkey{UserID: "u1", OrgID: "o1", CredentialID: []byte("cred"), Name: "a"}
	must(t, store.NewTable[model.Passkey](s).Put(ctx, tok))
}

func seedUsers(t testing.TB, s store.Store, org string, n int) []*model.User {
	out := make([]*model.User, n)
	for i := range n {
		u := newUser(org, fmt.Sprintf("user%03d", i))
		u.GivenName = fmt.Sprintf("Name %03d", (n-i)%n)
		u.Active = i%2 == 0
		if i%3 == 0 {
			u.Role = model.RoleManager
		}
		must(t, users(s).Put(ctx, u))
		out[i] = u
	}
	return out
}

func testListScope(t *testing.T, s store.Store) {
	seedUsers(t, s, "org1", 5)
	seedUsers(t, s, "org2", 3)
	_, total, err := users(s).List(ctx, store.ListQuery{Scope: "org1"})
	must(t, err)
	if total != 5 {
		t.Fatalf("org1 total %d", total)
	}
	_, total, err = users(s).List(ctx, store.ListQuery{})
	must(t, err)
	if total != 8 {
		t.Fatalf("all total %d", total)
	}
}

func testListSearch(t *testing.T, s store.Store) {
	seedUsers(t, s, "org1", 20)
	seedUsers(t, s, "org2", 12) // another scope: never matched
	u := newUser("org1", "100%_x")
	u.GivenName, u.FamilyName = "Zebra", "O'Hara"
	must(t, users(s).Put(ctx, u))
	// A case-insensitive prefix of the username, the address, the full name or the family name; LIKE wildcards in
	// the search are literal characters.
	cases := map[string]int{"user01": 10, "USER01": 10, "user010@": 1, "name 00": 10, "zebra": 1, "zebra o'": 1,
		"o'hara": 1, "100%": 1, "100%_": 1, "%": 0, "_": 0, "100_": 0, "nothing": 0, "example.com": 0, "ser01": 0}
	for q, want := range cases {
		_, total, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Search: q})
		must(t, err)
		if total != want {
			t.Errorf("search %q: got %d want %d", q, total, want)
		}
	}
}

func testListFilters(t *testing.T, s store.Store) {
	seedUsers(t, s, "org1", 12)
	cases := []struct {
		f    []store.Filter
		want int
	}{
		{[]store.Filter{{Field: "active", Value: true}}, 6},
		{[]store.Filter{{Field: "active", Value: false}}, 6},
		{[]store.Filter{{Field: "role", Value: "manager"}}, 4},
		{[]store.Filter{{Field: "role", Value: "manager"}, {Field: "active", Value: true}}, 2},
		{[]store.Filter{{Field: "username", Value: "user003"}}, 1},
		{[]store.Filter{{Field: "external_id", Value: ""}}, 12},
	}
	for i, c := range cases {
		_, total, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Filters: c.f})
		must(t, err)
		if total != c.want {
			t.Errorf("case %d: got %d want %d", i, total, c.want)
		}
	}
	// A word of a word-list field (tags): exactly that word, wherever it is in the list.
	for i, u := range users3(t, s) {
		u.Tags = [][]string{{"red", "x/y"}, {"blue", "red"}, {"x/y"}}[i]
		must(t, users(s).Put(ctx, u))
	}
	for tag, want := range map[string]int{"red": 2, "x/y": 2, "blue": 1, "re": 0, "x": 0, "red x/y": 0} {
		_, total, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Filters: []store.Filter{{Field: "tags", Value: tag}}})
		must(t, err)
		if total != want {
			t.Errorf("tag %q: got %d want %d", tag, total, want)
		}
	}
	// Ids only (Table.IDs): the same matches.
	ids, total, err := users(s).IDs(ctx, store.ListQuery{Scope: "org1", Filters: []store.Filter{{Field: "tags", Value: "red"}}})
	must(t, err)
	if total != 2 || len(ids) != 2 {
		t.Errorf("ids only: %v (total %d)", ids, total)
	}
	// Filters combine with search.
	_, total, err = users(s).List(ctx, store.ListQuery{Scope: "org1", Search: "user00",
		Filters: []store.Filter{{Field: "active", Value: true}}})
	must(t, err)
	if total != 5 { // user000,002,004,006,008
		t.Errorf("search+filter: %d", total)
	}
}

// users3 returns the first three users of org1 (by id).
func users3(t testing.TB, s store.Store) []*model.User {
	l, _, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Limit: 3})
	must(t, err)
	return l
}

func audits(s store.Store) *store.Table[model.Audit, *model.Audit] {
	return store.NewTable[model.Audit](s)
}

// seedAudit writes n audit events of org one minute apart from base, cycling through three actions.
func seedAudit(t testing.TB, s store.Store, org string, base time.Time, n int) {
	actions := []string{"user.create", "user.update", "login.failure"}
	for i := range n {
		a := actions[i%3]
		e := &model.Audit{OrgID: org, Action: a, Actor: fmt.Sprintf("actor%d", i), Target: "t", IP: fmt.Sprintf("10.0.0.%d", i),
			Outcome: model.AuditOutcome(a)}
		e.Created = base.Add(time.Duration(i) * time.Minute)
		must(t, audits(s).Put(ctx, e))
	}
}

// Prefix (case-insensitive, LIKE wildcards literal) and time range filters, alone and with the others.
func testListFilterOps(t *testing.T, s store.Store) {
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	seedAudit(t, s, "org1", base, 12)
	cases := []struct {
		f    []store.Filter
		want int
	}{
		{[]store.Filter{{Field: "action", Op: store.OpPrefix, Value: "user."}}, 8},
		{[]store.Filter{{Field: "action", Op: store.OpPrefix, Value: "USER."}}, 8},
		{[]store.Filter{{Field: "action", Op: store.OpPrefix, Value: "user_"}}, 0},
		{[]store.Filter{{Field: "action", Op: store.OpPrefix, Value: "%"}}, 0},
		{[]store.Filter{{Field: "created", Op: store.OpGTE, Value: base.Add(5 * time.Minute)}}, 7},
		{[]store.Filter{{Field: "created", Op: store.OpLT, Value: base.Add(5 * time.Minute)}}, 5},
		{[]store.Filter{{Field: "created", Op: store.OpGTE, Value: base.Add(2 * time.Minute)},
			{Field: "created", Op: store.OpLT, Value: base.Add(8 * time.Minute)}}, 6},
		{[]store.Filter{{Field: "outcome", Value: "failure"}}, 4},
		{[]store.Filter{{Field: "outcome", Value: "success"}, {Field: "action", Op: store.OpPrefix, Value: "user."},
			{Field: "created", Op: store.OpGTE, Value: base.Add(6 * time.Minute)}}, 4},
	}
	for i, c := range cases {
		_, total, err := audits(s).List(ctx, store.ListQuery{Scope: "org1", Filters: c.f})
		must(t, err)
		if total != c.want {
			t.Errorf("case %d: got %d want %d", i, total, c.want)
		}
	}
	// with a search (the IP address is searchable) and a sort
	l, total, err := audits(s).List(ctx, store.ListQuery{Scope: "org1", Search: "10.0.0.1", Sort: "created", Desc: true,
		Filters: []store.Filter{{Field: "action", Op: store.OpPrefix, Value: "user."}}})
	must(t, err)
	if total != 2 || l[0].IP != "10.0.0.10" || l[1].IP != "10.0.0.1" { // 10.0.0.1, 10.0.0.10 (10.0.0.11 is login.failure)
		t.Errorf("search+prefix: %d %v", total, l)
	}
	for _, bad := range []store.Filter{{Field: "created", Op: store.OpPrefix, Value: "2026"},
		{Field: "action", Op: store.OpGTE, Value: "a"}, {Field: "action", Op: "like", Value: "a"}} {
		if _, _, err := audits(s).List(ctx, store.ListQuery{Filters: []store.Filter{bad}}); !errors.Is(err, store.ErrBadQuery) {
			t.Errorf("filter %+v: %v", bad, err)
		}
	}
}

// RefreshFields fills in index fields a record was written without (a field added to the schema since), from its
// data, without changing its version.
func testRefreshFields(t *testing.T, s store.Store) {
	fr, ok := s.(store.FieldRefresher)
	if !ok {
		t.Skip("no FieldRefresher")
	}
	e := &model.Audit{OrgID: "org1", Action: "login.failure", Actor: "old", IP: "192.0.2.7", Outcome: "failure"}
	rec, err := store.Encode(e)
	must(t, err)
	delete(rec.Fields, "outcome") // as written by a build that did not index them
	delete(rec.Fields, "ip")
	must(t, s.Put(ctx, rec))
	stale := store.ListQuery{Filters: []store.Filter{{Field: "outcome", Value: ""}}}
	if _, n, _ := audits(s).List(ctx, stale); n != 1 {
		t.Fatalf("records without an outcome: %d", n)
	}
	n, err := fr.RefreshFields(ctx, model.KindAudit, store.ListQuery{Filters: stale.Filters, Limit: 10})
	must(t, err)
	if n != 1 {
		t.Fatalf("refreshed %d", n)
	}
	if _, n, _ := audits(s).List(ctx, stale); n != 0 {
		t.Fatalf("still without an outcome: %d", n)
	}
	l, n, err := audits(s).List(ctx, store.ListQuery{Search: "192.0.2", Filters: []store.Filter{{Field: "outcome", Value: "failure"}}})
	must(t, err)
	if n != 1 || l[0].Version != rec.Version {
		t.Fatalf("after refreshing: %d records, version %v (was %v)", n, l, rec.Version)
	}
	if n, err := fr.RefreshFields(ctx, model.KindAudit, store.ListQuery{Filters: stale.Filters, Limit: 10}); err != nil || n != 0 {
		t.Fatalf("second refresh: %d %v", n, err)
	}
}

func testListSort(t *testing.T, s store.Store) {
	tb := users(s)
	for i, n := range []string{"bravo", "Alpha", "charlie", "alpha2", "Delta"} {
		u := newUser("org1", n)
		u.GivenName = n
		vu := time.Date(2026, 1, 10-i, 0, 0, 0, 0, time.UTC)
		u.ValidUntil = &vu
		must(t, tb.Put(ctx, u))
	}
	list, _, err := tb.List(ctx, store.ListQuery{Scope: "org1", Sort: "name"})
	must(t, err)
	got := names(list)
	want := "Alpha,alpha2,bravo,charlie,Delta"
	if got != want {
		t.Fatalf("case-insensitive sort: %s want %s", got, want)
	}
	list, _, err = tb.List(ctx, store.ListQuery{Scope: "org1", Sort: "name", Desc: true})
	must(t, err)
	if names(list) != "Delta,charlie,bravo,alpha2,Alpha" {
		t.Fatalf("desc sort: %s", names(list))
	}
	list, _, err = tb.List(ctx, store.ListQuery{Scope: "org1", Sort: "valid_until"})
	must(t, err)
	if names(list) != "Delta,alpha2,charlie,Alpha,bravo" {
		t.Fatalf("time sort: %s", names(list))
	}
	// Default order is ID (creation) order.
	list, _, err = tb.List(ctx, store.ListQuery{Scope: "org1"})
	must(t, err)
	if names(list) != "bravo,Alpha,charlie,alpha2,Delta" {
		t.Fatalf("id order: %s", names(list))
	}
	list, _, err = tb.List(ctx, store.ListQuery{Scope: "org1", Desc: true})
	must(t, err)
	if names(list) != "Delta,alpha2,charlie,Alpha,bravo" {
		t.Fatalf("id desc order: %s", names(list))
	}
	// Ties break by id ascending.
	list, _, err = tb.List(ctx, store.ListQuery{Scope: "org1", Sort: "role"})
	must(t, err)
	if names(list) != "bravo,Alpha,charlie,alpha2,Delta" {
		t.Fatalf("tie break: %s", names(list))
	}
}

func names(list []*model.User) string {
	s := ""
	for i, u := range list {
		if i > 0 {
			s += ","
		}
		s += u.GivenName
	}
	return s
}

func testListPaging(t *testing.T, s store.Store) {
	seedUsers(t, s, "org1", 25)
	seen := map[string]bool{}
	for off := 0; off < 30; off += 10 {
		list, total, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Sort: "username", Offset: off, Limit: 10})
		must(t, err)
		if total != 25 {
			t.Fatalf("total %d", total)
		}
		for _, u := range list {
			if seen[u.ID] {
				t.Fatal("duplicate across pages")
			}
			seen[u.ID] = true
		}
	}
	if len(seen) != 25 {
		t.Fatalf("paged %d of 25", len(seen))
	}
	list, _, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Offset: 100, Limit: 10})
	must(t, err)
	if len(list) != 0 {
		t.Fatal("offset past end")
	}
}

func testPlainScanLarge(t *testing.T, s store.Store) {
	at := store.NewTable[model.Audit](s)
	ids := make([]string, 0, 300)
	for i := range 300 {
		a := &model.Audit{OrgID: "org1", Action: "test", Actor: fmt.Sprint(i), Expires: time.Now().Add(time.Hour)}
		must(t, at.Put(ctx, a))
		ids = append(ids, a.ID)
	}
	list, total, err := at.List(ctx, store.ListQuery{Scope: "org1", Desc: true, Offset: 50, Limit: 25})
	must(t, err)
	if total != 300 || len(list) != 25 || list[0].ID != ids[249] || list[24].ID != ids[225] {
		t.Fatalf("plain desc scan: total=%d len=%d", total, len(list))
	}
}

// testListAfter pages by key through a scope that changes between pages: records deleted behind the cursor do not
// make the scan skip any, expired records are left out without ending a page early, and every record that existed
// throughout is seen exactly once, in ID order.
func testListAfter(t *testing.T, s store.Store) {
	at := store.NewTable[model.Audit](s)
	var ids []string
	for i := range 120 {
		exp := time.Now().Add(time.Hour)
		if i%7 == 3 {
			exp = time.Now().Add(-time.Minute) // already expired
		}
		a := &model.Audit{OrgID: "org1", Action: "test", Actor: fmt.Sprint(i), Expires: exp}
		must(t, at.Put(ctx, a))
		if i%7 != 3 {
			ids = append(ids, a.ID)
		}
	}
	var got []string
	after := ""
	for page := 0; ; page++ {
		res, err := s.List(ctx, model.KindAudit, store.ListQuery{Scope: "org1", After: after, Limit: 10})
		must(t, err)
		if len(res.Records) == 0 {
			break
		}
		for _, r := range res.Records {
			got = append(got, r.ID)
		}
		after = res.Records[len(res.Records)-1].ID
		if page == 1 { // delete records already read: offset paging would now skip ahead
			for _, id := range got[:5] {
				must(t, s.Put(ctx, store.Tombstone(model.KindAudit, id)))
			}
		}
	}
	if !slices.Equal(got, ids) {
		t.Fatalf("after-scan saw %d records, want %d (in order)", len(got), len(ids))
	}
	if _, err := s.List(ctx, model.KindAudit, store.ListQuery{After: "x", Desc: true}); !errors.Is(err, store.ErrBadQuery) {
		t.Fatalf("after with desc: %v", err)
	}
}

// testWriteAfterFasterClock: another node sharing the database, with a clock seconds ahead, wrote a record. This node
// reads it and must be able to update it (its next version is newer than the one it read).
func testWriteAfterFasterClock(t *testing.T, s store.Store) {
	u := &model.User{Meta: model.Meta{ID: model.NewID(), Version: hlc.FromTime(time.Now().Add(2 * time.Second))},
		OrgID: "org1", Username: "fast", Email: "fast@example.com"}
	rec, err := store.EncodeAsIs(u)
	must(t, err)
	rec.Origin = "other-node"
	must(t, s.Put(ctx, rec))
	got, err := users(s).Get(ctx, u.ID)
	must(t, err)
	got.GivenName = "Changed"
	if err := users(s).Update(ctx, got); err != nil {
		t.Fatalf("update after a faster clock's write: %v", err)
	}
}

// testEphemeralShared runs the database-backed ephemeral store (clusters on a shared database) over the backend:
// values, single use under concurrency, counters under concurrency, expiry.
func testEphemeralShared(t *testing.T, s store.Store) {
	a, b := ephemeral.NewShared(s), ephemeral.NewShared(s) // two nodes on one database
	id, err := a.New(ctx, "code", []byte("v1"), time.Minute)
	must(t, err)
	if v, err := b.Get(ctx, "code", id); err != nil || string(v) != "v1" {
		t.Fatalf("get from another node: %q %v", v, err)
	}
	if _, err := b.Get(ctx, "flow", id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("namespaces are separate: %v", err)
	}
	must(t, b.Set(ctx, "code", id, []byte("v2"), time.Minute))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := a
			if i%2 == 1 {
				n = b
			}
			if v, err := n.Take(ctx, "code", id); err == nil {
				if string(v) != "v2" {
					t.Errorf("took %q", v)
				}
				wins.Add(1)
			} else if !errors.Is(err, ephemeral.ErrNotFound) {
				t.Errorf("take: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d nodes took the same code", wins.Load())
	}
	if _, err := a.Get(ctx, "code", id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("taken value still there: %v", err)
	}
	// counters
	if n, err := a.Incr(ctx, "rate", "ip|1.2.3.4", 0, time.Minute); err != nil || n != 0 {
		t.Fatalf("read of a missing counter: %d %v", n, err)
	}
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := a
			if i%2 == 1 {
				n = b
			}
			if _, err := n.Incr(ctx, "rate", "ip|1.2.3.4", 1, time.Minute); err != nil {
				t.Errorf("incr: %v", err)
			}
		}()
	}
	wg.Wait()
	if n, err := b.Incr(ctx, "rate", "ip|1.2.3.4", 0, time.Minute); err != nil || n != 20 {
		t.Fatalf("counter after 20 increments on two nodes: %d %v", n, err)
	}
	// expiry and delete
	short, err := a.New(ctx, "flow", []byte("x"), 50*time.Millisecond)
	must(t, err)
	time.Sleep(120 * time.Millisecond)
	if _, err := b.Get(ctx, "flow", short); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("expired value: %v", err)
	}
	if n, err := a.Incr(ctx, "rate", "window", 5, 50*time.Millisecond); err != nil || n != 5 {
		t.Fatal(n, err)
	}
	time.Sleep(120 * time.Millisecond)
	if n, err := a.Incr(ctx, "rate", "window", 1, time.Minute); err != nil || n != 1 {
		t.Fatalf("counter did not restart after its window: %d %v", n, err)
	}
	gone, _ := a.New(ctx, "flow", []byte("y"), time.Minute)
	must(t, b.Delete(ctx, "flow", gone))
	if _, err := a.Get(ctx, "flow", gone); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("deleted value: %v", err)
	}
}

func testBadQuery(t *testing.T, s store.Store) {
	if _, err := s.List(ctx, model.KindUser, store.ListQuery{Sort: "password_hash"}); !errors.Is(err, store.ErrBadQuery) {
		t.Fatalf("bad sort: %v", err)
	}
	if _, err := s.List(ctx, model.KindUser, store.ListQuery{Sort: "external_id"}); !errors.Is(err, store.ErrBadQuery) {
		t.Fatalf("non-sortable: %v", err)
	}
	if _, err := s.List(ctx, model.KindUser, store.ListQuery{Filters: []store.Filter{{Field: "x; drop table", Value: 1}}}); !errors.Is(err, store.ErrBadQuery) {
		t.Fatalf("bad filter: %v", err)
	}
}

func testCount(t *testing.T, s store.Store) {
	seedUsers(t, s, "org1", 7)
	seedUsers(t, s, "org2", 2)
	n, err := s.Count(ctx, model.KindUser, "org1")
	must(t, err)
	if n != 7 {
		t.Fatalf("count %d", n)
	}
	n, _ = s.Count(ctx, model.KindUser, "")
	if n != 9 {
		t.Fatalf("count all %d", n)
	}
	n, _ = s.Count(ctx, model.KindGroup, "")
	if n != 0 {
		t.Fatal("count other kind")
	}
}

// testGetMany: the live entities among the ids, in the order asked, those missing or deleted left out.
func testGetMany(t *testing.T, s store.Store) {
	us := seedUsers(t, s, "org1", 5)
	must(t, users(s).Delete(ctx, us[1].ID))
	got, err := users(s).GetMany(ctx, []string{us[3].ID, "missing", us[1].ID, us[0].ID, us[3].ID})
	must(t, err)
	if want := names([]*model.User{us[3], us[0], us[3]}); names(got) != want {
		t.Fatalf("got %s, want %s", names(got), want)
	}
	if got, err := users(s).GetMany(ctx, nil); err != nil || len(got) != 0 {
		t.Fatalf("none: %v %v", got, err)
	}
}

// testListIndexed: filters on indexed fields (model.Field.Index), which the key-value stores answer from their field
// indexes in several ways (the records with the value, the scope less the records with true, one filter paged on its
// own, filters combined with others, with a sort or search, without a scope), give exactly what applying the query to
// every record gives: the same records in the same order, and the same total; expired records are left out of both.
func testListIndexed(t *testing.T, s store.Store) {
	for i, u := range seedUsers(t, s, "org1", 30) {
		switch {
		case i%11 == 4:
			u.Role = model.RoleSuperAdmin
		case i%5 == 2:
			u.Role = model.RoleAdmin
		}
		if u.Role != model.RoleUser {
			must(t, users(s).Update(ctx, u))
		}
	}
	for i, u := range seedUsers(t, s, "org2", 10) {
		if i == 3 {
			u.Role = model.RoleSuperAdmin
			must(t, users(s).Update(ctx, u))
		}
	}
	grants := store.NewTable[model.Grant](s)
	for i := range 40 {
		g := &model.Grant{UserID: fmt.Sprintf("u%d", i%4), OrgID: "org1", ClientID: "app-a", Expires: time.Now().Add(time.Hour)}
		if i%3 == 0 {
			g.ClientID = "app-b"
		}
		if i%7 == 2 {
			g.Expires = time.Now().Add(-time.Minute) // expired, still stored
		}
		must(t, grants.Put(ctx, g))
	}
	members := store.NewTable[model.Member](s)
	for i := range 12 {
		m := &model.Member{Meta: model.Meta{ID: model.MemberID(fmt.Sprintf("g%d", i%3), fmt.Sprintf("u%d", i%4))},
			GroupID: fmt.Sprintf("g%d", i%3), UserID: fmt.Sprintf("u%d", i%4), OrgID: "org1"}
		must(t, members.Put(ctx, m))
	}
	ids := func(recs []*store.Record) []string {
		out := make([]string, len(recs))
		for i, r := range recs {
			out[i] = r.ID
		}
		return out
	}
	check := func(kind model.Kind, q store.ListQuery) {
		t.Helper()
		all, err := s.List(ctx, kind, store.ListQuery{})
		must(t, err)
		want, err := store.ApplyQuery(kind, all.Records, q)
		must(t, err)
		got, err := s.List(ctx, kind, q)
		must(t, err)
		if !slices.Equal(ids(got.Records), ids(want.Records)) || got.Total != want.Total {
			t.Errorf("%s %+v:\n got %d %v\nwant %d %v", kind, q, got.Total, ids(got.Records), want.Total, ids(want.Records))
		}
	}
	f := func(field string, v any) store.Filter { return store.Filter{Field: field, Value: v} }
	org1, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org1"})
	must(t, err)
	after := org1.Records[12].ID
	for _, desc := range []bool{false, true} {
		for _, off := range []int{0, 7, 26, 40} {
			check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false)}, Desc: desc, Offset: off, Limit: 10})
			check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("admin_rank", true)}, Desc: desc, Offset: off, Limit: 3})
			check(model.KindUser, store.ListQuery{Scope: "", Filters: []store.Filter{f("super_admin", false)}, Desc: desc, Offset: off, Limit: 10})
		}
		check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false), f("admin_rank", false)}, Desc: desc})
		check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false), f("active", true)}, Desc: desc, Limit: 5})
		check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("admin_rank", true), f("active", true)}, Desc: desc})
		check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("admin_rank", true), f("super_admin", false)}, Desc: desc})
		check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false)}, Sort: "username", Desc: desc, Limit: 8})
		// Sorted pages (the sort indexes of the key-value stores): every sort field of the user console and of
		// SCIM, both directions, at offsets, with the visibility exclusions, with ties (role, active) and without.
		for _, sort := range []string{"username", "name", "email", "created", "role", "active", "department"} {
			for _, off := range []int{0, 5, 23, 30} {
				check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false)}, Sort: sort, Desc: desc, Offset: off, Limit: 7})
				check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Offset: off, Limit: 7})
			}
			check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false), f("admin_rank", false)}, Sort: sort, Desc: desc, Offset: 3, Limit: 4})
			check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false), f("active", true)}, Sort: sort, Desc: desc, Offset: 2, Limit: 5})
			check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("admin_rank", true)}, Sort: sort, Desc: desc, Limit: 3})
			check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false)}, Sort: sort, Desc: desc, Search: "user01", Offset: 1, Limit: 4})
			check(model.KindUser, store.ListQuery{Scope: "", Sort: sort, Desc: desc, Offset: 4, Limit: 9})
			check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc})
		}
		check(model.KindUser, store.ListQuery{Scope: "org1", Search: "user0", Desc: desc, Offset: 2, Limit: 5})
		check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("role", "manager")}, Desc: desc, Offset: 1, Limit: 3})
		check(model.KindGrant, store.ListQuery{Scope: "u1", Sort: "created", Desc: desc, Offset: 1, Limit: 3})
		check(model.KindMember, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("group_id", "g1")}, Sort: "created", Desc: desc, Limit: 2})
		check(model.KindUser, store.ListQuery{Scope: "", Filters: []store.Filter{f("admin_rank", true)}, Desc: desc, Limit: 4})
		check(model.KindGrant, store.ListQuery{Scope: "u1", Filters: []store.Filter{f("client_id", "app-a")}, Desc: desc, Offset: 1, Limit: 3})
		check(model.KindGrant, store.ListQuery{Scope: "u1", Filters: []store.Filter{f("client_id", "app-b")}, Desc: desc})
		check(model.KindGrant, store.ListQuery{Scope: "", Filters: []store.Filter{f("client_id", "app-a")}, Desc: desc, Limit: 6})
		check(model.KindMember, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("group_id", "g1")}, Desc: desc, Limit: 1})
		check(model.KindMember, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("user_id", "u2")}, Desc: desc})
	}
	check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false)}, Search: "user01"})
	check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", false)}, After: after, Limit: 6})
	check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("admin_rank", true)}, After: after, Limit: 2})
	check(model.KindUser, store.ListQuery{Scope: "org1", Filters: []store.Filter{f("super_admin", true)}})
	check(model.KindUser, store.ListQuery{Scope: "org2", Filters: []store.Filter{f("super_admin", false)}, Limit: 4})
	check(model.KindUser, store.ListQuery{Scope: "org3", Filters: []store.Filter{f("super_admin", false)}})
	check(model.KindGrant, store.ListQuery{Scope: "u9", Filters: []store.Filter{f("client_id", "app-a")}})
}

// testListSortIndexes: listings sorted on the fields the key-value stores keep sort indexes for (model.Field.SortIndex)
// give exactly what applying the query to every record gives, where the index order is put to the test: runs of
// equal values longer than a page (ties break by id ascending in both directions), empty and missing values (which
// sort first), case folding, a kind without scopes (organizations), time fields, and after the records move in the
// order (updates) or leave it (deletions).
func testListSortIndexes(t *testing.T, s store.Store) {
	ids := func(recs []*store.Record) []string {
		out := make([]string, len(recs))
		for i, r := range recs {
			out[i] = r.ID
		}
		return out
	}
	check := func(kind model.Kind, q store.ListQuery) {
		t.Helper()
		all, err := s.List(ctx, kind, store.ListQuery{})
		must(t, err)
		want, err := store.ApplyQuery(kind, all.Records, q)
		must(t, err)
		got, err := s.List(ctx, kind, q)
		must(t, err)
		if !slices.Equal(ids(got.Records), ids(want.Records)) || got.Total != want.Total {
			t.Errorf("%s %+v:\n got %d %v\nwant %d %v", kind, q, got.Total, ids(got.Records), want.Total, ids(want.Records))
		}
	}
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	us := make([]*model.User, 0, 40)
	for i := range 40 {
		u := newUser("org1", fmt.Sprintf("u%02d", i))
		if i%4 == 1 {
			u.Username = strings.ToUpper(u.Username) // folds to the same order as the others
		}
		u.GivenName, u.FamilyName = []string{"Ann", "bob", "Ann", ""}[i%4], "" // three runs of equal names; "" names fall back to the username
		u.Work.Department = ""
		if i%5 == 0 {
			u.Work.Department = "Ops" // most departments are empty: a long run of empty values first
		}
		u.Created = base.Add(time.Duration(i%6) * time.Minute).Add(time.Duration(i%3) * time.Nanosecond) // ties at the second, apart by nanoseconds
		u.Active = i%3 != 0
		switch {
		case i%13 == 2:
			u.Role = model.RoleSuperAdmin
		case i%7 == 3:
			u.Role = model.RoleAdmin
		}
		must(t, users(s).Put(ctx, u))
		us = append(us, u)
	}
	orgs := store.NewTable[model.Org](s)
	for i, n := range []string{"zeta", "Alpha", "beta", "alpha2", "Beta2", "gamma"} {
		o := &model.Org{Name: n, DisplayName: []string{"Same", "Same", "Other", "", "Same", "other"}[i]}
		o.Created = base.Add(time.Duration(i%2) * time.Hour)
		must(t, orgs.Put(ctx, o))
	}
	groups := store.NewTable[model.Group](s)
	for _, n := range []string{"Team", "alpha", "ZEBRA", "beta", "Crew", "delta", "Echo", "", "gamma"} { // (names are unique)
		must(t, groups.Put(ctx, &model.Group{OrgID: "org1", DisplayName: n}))
	}
	visible := []store.Filter{{Field: "super_admin", Value: false}}
	for _, desc := range []bool{false, true} {
		for _, sort := range []string{"username", "name", "department", "created", "active", "role", "email"} {
			for _, off := range []int{0, 3, 11, 38, 45} {
				check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Offset: off, Limit: 5})
				check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Offset: off, Limit: 5, Filters: visible})
			}
			check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Limit: 1})
			check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Filters: visible})
			check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Filters: []store.Filter{{Field: "active", Value: false}}, Offset: 2, Limit: 4})
		}
		for _, sort := range []string{"name", "display_name", "created"} {
			for _, off := range []int{0, 2, 5} {
				check(model.KindOrg, store.ListQuery{Sort: sort, Desc: desc, Offset: off, Limit: 2})
			}
			check(model.KindGroup, store.ListQuery{Scope: "org1", Sort: "display_name", Desc: desc, Offset: 1, Limit: 4})
			check(model.KindGroup, store.ListQuery{Scope: "org1", Sort: "created", Desc: desc, Limit: 3})
		}
	}
	// The order follows the records: a renamed user moves, a deleted one leaves.
	u := us[7]
	u.Username, u.GivenName = "aaa", "Zoe"
	must(t, users(s).Update(ctx, u))
	must(t, users(s).Delete(ctx, us[0].ID))
	must(t, users(s).Delete(ctx, us[2].ID)) // a super admin
	for _, desc := range []bool{false, true} {
		check(model.KindUser, store.ListQuery{Scope: "org1", Sort: "username", Desc: desc, Limit: 3})
		check(model.KindUser, store.ListQuery{Scope: "org1", Sort: "name", Desc: desc, Offset: 1, Limit: 6, Filters: visible})
	}
	if n, err := s.Count(ctx, model.KindUser, "org1"); err != nil || n != 38 {
		t.Errorf("count %d %v", n, err)
	}
}

// replica is u as another node would send it: written at version, by origin, created (generation 0) at version.
func replica(u *model.User, version hlc.Timestamp, origin string) *store.Record {
	u.Version = version
	r, _ := store.EncodeAsIs(u)
	r.Origin, r.Created = origin, version
	return r
}

func testReplicatedLWW(t *testing.T, s store.Store) {
	u := newUser("org1", "jack")
	u.ID = model.NewID()
	v := store.Clock.Now()
	u.GivenName = "v2"
	ok, _, err := s.PutReplicated(ctx, replica(u, v+10, "n1"))
	must(t, err)
	if !ok {
		t.Fatal("first apply rejected")
	}
	u.GivenName = "v1"
	ok, _, _ = s.PutReplicated(ctx, replica(u, v+5, "n1"))
	if ok {
		t.Fatal("older version applied")
	}
	ok, _, _ = s.PutReplicated(ctx, replica(u, v+10, "n1"))
	if ok {
		t.Fatal("identical replay applied")
	}
	got, _ := users(s).Get(ctx, u.ID)
	if got.GivenName != "v2" {
		t.Fatal("LWW violated")
	}
	// The local clock witnessed the remote version: the next local write dominates.
	if store.Clock.Now() <= v+10 {
		t.Fatal("clock did not witness")
	}
}

func testReplicatedTombstoneTie(t *testing.T, s store.Store) {
	u := newUser("org1", "kim")
	u.ID = model.NewID()
	v := store.Clock.Now() + 100
	_, _, err := s.PutReplicated(ctx, replica(u, v, "n1"))
	must(t, err)
	ok, _, _ := s.PutReplicated(ctx, &store.Record{Kind: model.KindUser, ID: u.ID, Version: v, Origin: "n0", Deleted: true})
	if !ok {
		t.Fatal("tombstone at equal version must win")
	}
	ok, _, _ = s.PutReplicated(ctx, replica(u, v, "n9"))
	if ok {
		t.Fatal("value must not beat tombstone at equal version")
	}
	if _, err := users(s).Get(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("record resurrected")
	}
}

func testReplicatedOriginTie(t *testing.T, s store.Store) {
	u := newUser("org1", "lee")
	u.ID = model.NewID()
	v := store.Clock.Now() + 100
	u.GivenName = "from-b"
	_, _, _ = s.PutReplicated(ctx, replica(u, v, "b"))
	u.GivenName = "from-a"
	if ok, _, _ := s.PutReplicated(ctx, replica(u, v, "a")); ok {
		t.Fatal("lower origin must lose a tie")
	}
	u.GivenName = "from-c"
	if ok, _, _ := s.PutReplicated(ctx, replica(u, v, "c")); !ok {
		t.Fatal("higher origin must win a tie")
	}
	got, _ := users(s).Get(ctx, u.ID)
	if got.GivenName != "from-c" {
		t.Fatal(got.GivenName)
	}
}

func testReplicatedUniqueClash(t *testing.T, s store.Store) {
	// Local record created first keeps the email; a record created later elsewhere loses it (and is kept).
	tb := users(s)
	first := newUser("org1", "mia")
	must(t, tb.Put(ctx, first))
	second := newUser("org1", "mia2")
	second.Email = first.Email
	second.ID = model.NewID()
	ok, losers, err := s.PutReplicated(ctx, replica(second, store.Clock.Now(), "zz"))
	must(t, err)
	if !ok || len(losers) != 1 || losers[0] != second.ID {
		t.Fatalf("newer clashing record must be stored and reported as loser: ok=%v losers=%v", ok, losers)
	}
	got, _ := tb.GetByUnique(ctx, model.UserEmailKey("org1", first.Email))
	if got == nil || got.ID != first.ID {
		t.Fatal("first writer must keep the unique value")
	}
	if _, err := tb.Get(ctx, second.ID); err != nil {
		t.Fatal("loser must still be stored")
	}
	// Its other unique values are still indexed.
	if g, _ := tb.GetByUnique(ctx, model.UserUsernameKey("org1", "mia2")); g == nil || g.ID != second.ID {
		t.Fatal("loser's non-clashing unique values must be indexed")
	}

	// A record created earlier elsewhere takes the value from one created later here.
	third := newUser("org1", "noah")
	must(t, tb.Put(ctx, third))
	older := newUser("org1", "noah-old")
	older.Email = third.Email
	older.ID = model.NewID()
	ok, losers, err = s.PutReplicated(ctx, replica(older, third.Version-1, "aa"))
	must(t, err)
	if !ok || len(losers) != 1 || losers[0] != third.ID {
		t.Fatalf("older record must win the value: ok=%v losers=%v", ok, losers)
	}
	got, _ = tb.GetByUnique(ctx, model.UserEmailKey("org1", third.Email))
	if got == nil || got.ID != older.ID {
		t.Fatal("unique value must move to the older record")
	}
	// A long-standing record updated now (newer version, created long ago) keeps its value against a record created
	// meanwhile: the first claim wins, not the last write.
	fourth := newUser("org1", "olive")
	must(t, tb.Put(ctx, fourth))
	fourth.GivenName = "signed in"
	must(t, tb.Update(ctx, fourth))
	scim := newUser("org1", "olive-scim")
	scim.Email = fourth.Email
	scim.ID = model.NewID()
	created := store.Clock.Now()
	rs := replica(scim, created, "zz")
	ok, losers, err = s.PutReplicated(ctx, rs)
	must(t, err)
	if !ok || len(losers) != 1 || losers[0] != scim.ID {
		t.Fatalf("a record created later must lose the value: ok=%v losers=%v", ok, losers)
	}
	fourth.GivenName = "updated again"
	must(t, tb.Update(ctx, fourth)) // newer than the clashing record: still keeps it
	if got, _ := tb.GetByUnique(ctx, model.UserEmailKey("org1", fourth.Email)); got == nil || got.ID != fourth.ID {
		t.Fatal("the long-standing record lost its unique value")
	}
	if _, err := tb.Get(ctx, scim.ID); err != nil {
		t.Fatal("the record that lost the value must be kept")
	}
	// The loser releasing the value later (tombstone) must not disturb the winner.
	must(t, tb.Delete(ctx, third.ID))
	got, _ = tb.GetByUnique(ctx, model.UserEmailKey("org1", third.Email))
	if got == nil || got.ID != older.ID {
		t.Fatal("tombstoning the loser removed the winner's unique value")
	}
}

func testChanges(t *testing.T, s store.Store) {
	tb := users(s)
	a := newUser("org1", "olga")
	b := newUser("org1", "pete")
	must(t, tb.Put(ctx, a))
	must(t, tb.Put(ctx, b))
	a.GivenName = "changed"
	must(t, tb.Put(ctx, a))
	must(t, tb.Delete(ctx, b.ID))

	ch, next, err := s.Changes(ctx, 0, 0)
	must(t, err)
	if len(ch) != 2 {
		t.Fatalf("latest change per record only: got %d", len(ch))
	}
	if ch[0].Record.ID != a.ID || ch[1].Record.ID != b.ID || !ch[1].Record.Deleted {
		t.Fatal("changes not in seq order or tombstone missing")
	}
	if ch[0].Seq >= ch[1].Seq || next != ch[1].Seq {
		t.Fatal("seq not increasing / next wrong")
	}
	if len(ch[0].Record.Data) == 0 || ch[0].Record.Version != a.Version || ch[0].Record.Origin == "" {
		t.Fatal("change record incomplete")
	}
	ch, next2, _ := s.Changes(ctx, next, 0)
	if len(ch) != 0 || next2 != next {
		t.Fatal("no new changes expected")
	}
	c := newUser("org1", "quin")
	must(t, tb.Put(ctx, c))
	ch, _, _ = s.Changes(ctx, next, 0)
	if len(ch) != 1 || ch[0].Record.ID != c.ID {
		t.Fatal("incremental change missing")
	}
	// Limit.
	seedUsers(t, s, "org2", 10)
	ch, n1, _ := s.Changes(ctx, 0, 4)
	if len(ch) != 4 {
		t.Fatalf("limit: %d", len(ch))
	}
	ch2, _, _ := s.Changes(ctx, n1, 4)
	if len(ch2) != 4 || ch2[0].Seq <= n1 {
		t.Fatal("paging changes")
	}
}

func testChangesReplicated(t *testing.T, s store.Store) {
	u := newUser("org1", "rita")
	u.ID = model.NewID()
	_, _, err := s.PutReplicated(ctx, replica(u, store.Clock.Now(), "n7"))
	must(t, err)
	ch, _, _ := s.Changes(ctx, 0, 0)
	if len(ch) != 1 || ch[0].Record.Origin != "n7" {
		t.Fatal("replicated applies must appear in the feed with their origin")
	}
}

func testFeedID(t *testing.T, s store.Store) {
	if s.FeedID() == "" || s.FeedID() != s.FeedID() {
		t.Fatal("feed id must be stable and non-empty")
	}
}

func testPurge(t *testing.T, s store.Store) {
	tb := users(s)
	a := newUser("org1", "sam")
	must(t, tb.Put(ctx, a))
	must(t, tb.Delete(ctx, a.ID))
	st := store.NewTable[model.Session](s)
	gone := &model.Session{UserID: "u1", Expires: time.Now().Add(-time.Minute)}
	keep := &model.Session{UserID: "u1", Expires: time.Now().Add(time.Hour)}
	must(t, st.Put(ctx, gone))
	must(t, st.Put(ctx, keep))
	// Nothing old enough yet.
	n, err := s.Purge(ctx, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	must(t, err)
	if n != 0 {
		t.Fatalf("purged %d too early", n)
	}
	n, err = s.Purge(ctx, time.Now().Add(time.Minute), time.Now()) // margin: an earlier test may have moved the clock ahead
	must(t, err)
	if n != 2 {
		t.Fatalf("purged %d want 2", n)
	}
	ch, _, _ := s.Changes(ctx, 0, 0)
	for _, c := range ch {
		if c.Record.ID == a.ID || c.Record.ID == gone.ID {
			t.Fatal("purged record still in feed")
		}
	}
	// A purged tombstone no longer blocks an older replicated write (the cluster layer guards that case).
	if _, err := st.Get(ctx, keep.ID); err != nil {
		t.Fatal("live record purged")
	}
}

func testConcurrentCAS(t *testing.T, s store.Store) {
	tb := users(s)
	u := newUser("org1", "tess")
	must(t, tb.Put(ctx, u))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := *u
			c.GivenName = fmt.Sprint(i)
			if err := tb.Update(ctx, &c); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, store.ErrStale) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("exactly one concurrent update must win, got %d", wins.Load())
	}
}

func testConcurrentChanges(t *testing.T, s store.Store) {
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				if err := users(s).Put(ctx, newUser(fmt.Sprintf("org%d", w), fmt.Sprintf("u%d", i))); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	// Concurrently follow the feed: every record must be seen exactly once, cursor never skipping.
	seen := map[string]bool{}
	var cursor uint64
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	follow := func() {
		for {
			ch, next, err := s.Changes(ctx, cursor, 7)
			must(t, err)
			for _, c := range ch {
				seen[c.Record.ID] = true
			}
			cursor = next
			if len(ch) == 0 {
				return
			}
		}
	}
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
			follow()
		}
	}
	follow()
	if len(seen) != 200 {
		t.Fatalf("feed follower saw %d of 200 records", len(seen))
	}
}

// Concurrent creates claiming one unique value: exactly one wins, every other fails with ErrConflict alone (a backend
// that commits writes together must fail only the conflicting write), and the index points at the winner.
func testConcurrentUniqueClaim(t *testing.T, s store.Store) {
	tb := users(s)
	var wg sync.WaitGroup
	var wins atomic.Int32
	others := make([]*model.User, 24)
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := newUser("org1", fmt.Sprintf("claim%d", i))
			u.Email = "same@example.com"
			if err := tb.Create(ctx, u); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, store.ErrConflict) {
				t.Error(err)
			}
			o := newUser("org1", fmt.Sprintf("free%d", i)) // an unrelated write alongside, always succeeds
			if err := tb.Create(ctx, o); err != nil {
				t.Error(err)
			}
			others[i] = o
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("exactly one claim must win, got %d", wins.Load())
	}
	h, err := tb.GetByUnique(ctx, model.UserEmailKey("org1", "same@example.com"))
	must(t, err)
	if h.Email != "same@example.com" {
		t.Fatalf("holder %+v", h)
	}
	n, err := tb.Count(ctx, "org1")
	must(t, err)
	if n != 25 {
		t.Fatalf("count %d, want 25 (one claim and 24 unrelated)", n)
	}
	for _, o := range others {
		if _, err := tb.Get(ctx, o.ID); err != nil {
			t.Fatalf("unrelated write lost: %v", err)
		}
	}
}

// Writers rewrite a few shared records while a follower reads the feed: sequence numbers are strictly increasing
// within and across pages, and the follower's last view of every record is the stored one (no change is skipped by
// the cursor).
func testConcurrentRewritesFeed(t *testing.T, s store.Store) {
	tb := users(s)
	shared := make([]*model.User, 6)
	for i := range shared {
		shared[i] = newUser("org1", fmt.Sprintf("hot%d", i))
		must(t, tb.Put(ctx, shared[i]))
	}
	var wg sync.WaitGroup
	for w := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 30 {
				u := *shared[(w+i)%len(shared)]
				u.GivenName = fmt.Sprintf("w%d-%d", w, i)
				var err error
				if i%2 == 0 {
					err = tb.Put(ctx, &u)
				} else {
					cur, gerr := tb.Get(ctx, u.ID)
					if gerr != nil {
						t.Error(gerr)
						return
					}
					cur.GivenName = u.GivenName
					err = tb.Update(ctx, cur)
				}
				if err != nil && !errors.Is(err, store.ErrStale) {
					t.Error(err)
				}
			}
		}()
	}
	last := map[string]hlc.Timestamp{}
	var cursor, prev uint64
	follow := func() {
		for {
			ch, next, err := s.Changes(ctx, cursor, 5)
			must(t, err)
			for _, c := range ch {
				if c.Seq <= prev {
					t.Fatalf("seq %d after %d", c.Seq, prev)
				}
				prev = c.Seq
				last[c.Record.ID] = c.Record.Version
			}
			if next < cursor {
				t.Fatalf("cursor went back from %d to %d", cursor, next)
			}
			cursor = next
			if len(ch) == 0 {
				return
			}
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
			follow()
		}
	}
	follow()
	for _, u := range shared {
		r, err := s.Lookup(ctx, model.KindUser, u.ID)
		must(t, err)
		if last[u.ID] != r.Version {
			t.Fatalf("follower last saw %s at %d, stored %d", u.ID, last[u.ID], r.Version)
		}
	}
	all, _, err := s.Changes(ctx, 0, 0)
	must(t, err)
	if len(all) != len(shared) {
		t.Fatalf("feed holds %d entries, want %d", len(all), len(shared))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Seq <= all[i-1].Seq {
			t.Fatal("feed not in seq order")
		}
	}
}

func testKindsIsolated(t *testing.T, s store.Store) {
	u := newUser("org1", "uma")
	must(t, users(s).Put(ctx, u))
	if _, err := s.Get(ctx, model.KindGroup, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("kind leak via Get")
	}
	g := &model.Group{OrgID: "org1", DisplayName: "uma"}
	must(t, store.NewTable[model.Group](s).Put(ctx, g))
	// Same unique string in a different kind does not clash.
	o := &model.Org{Name: "org1/u/uma", DisplayName: "x"}
	must(t, store.NewTable[model.Org](s).Put(ctx, o))
}
