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

// Options adjust the suite to a store that is not one database: a gossip cluster.
type Options struct {
	// NoReplicated skips the cases of PutReplicated: a gossip cluster's records arrive through its partitions, and
	// a restore loads a node before it starts.
	NoReplicated bool
}

// Run runs every conformance test.
func Run(t *testing.T, f Factory) { RunWith(t, f, Options{}) }

// RunWith runs every conformance test, as opt adjusts them.
func RunWith(t *testing.T, f Factory, opt Options) {
	tests := []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"PutGet", testPutGet},
		{"RoundTripTypes", testRoundTripTypes},
		{"VersionsStamped", testVersionsStamped},
		{"Retries", testRetries},
		{"Tx", testTx},
		{"TxRetried", testTxRetried},
		{"TxUniquePerKind", testTxUniquePerKind},
		{"TxAssert", testTxAssert},
		{"ConcurrentTxAssert", testConcurrentTxAssert},
		{"FailedWriteLeavesTheRecord", testFailedWriteLeavesRecord},
		{"Unique", testUnique},
		{"UniqueReleasedOnChange", testUniqueReleased},
		{"UniqueOfAnyLength", testUniqueLong},
		{"LongUniqueReleasedByPurge", testUniqueLongPurged},
		{"Limits", testLimits},
		{"Tombstone", testTombstone},
		{"DeleteNotLive", testDeleteNotLive},
		{"PutOverExpired", testPutOverExpired},
		{"RecordNeverMoves", testRecordNeverMoves},
		{"EndedContext", testEndedContext},
		{"Closed", testClosed},
		{"ExpiresToTheMicrosecond", testExpiresPrecision},
		{"Create", testCreate},
		{"CompareAndPut", testCompareAndPut},
		{"Expiry", testExpiry},
		{"ListScopeAndTotal", testListScope},
		{"ListSearch", testListSearch},
		{"ListFoldsUnicodeAndTags", testListFolding},
		{"ListFilters", testListFilters},
		{"ListFilterOperators", testListFilterOps},
		{"ListIndexedFilters", testListIndexed},
		{"ListSortIndexes", testListSortIndexes},
		{"GetMany", testGetMany},
		{"ListSort", testListSort},
		{"ListPaging", testListPaging},
		{"ListPlainScanLarge", testPlainScanLarge},
		{"ListPlainScanSkipsExpired", testPlainScanSkipsExpired},
		{"ListAfter", testListAfter},
		{"IDOrderIsCreationOrder", testIDOrderIsCreationOrder},
		{"IDsAreCaseSensitive", testIDsCaseSensitive},
		{"WriteAfterFasterClock", testWriteAfterFasterClock},
		{"EphemeralShared", testEphemeralShared},
		{"ListBadQuery", testBadQuery},
		{"Count", testCount},
		{"PutReplicated", testPutReplicated},
		{"PutReplicatedUnique", testPutReplicatedUnique},
		{"LocalWriteOverTombstone", testLocalWriteOverTombstone},
		{"FeedID", testFeedID},
		{"Purge", testPurge},
		{"ConcurrentCompareAndPut", testConcurrentCAS},
		{"ConcurrentUniqueClaim", testConcurrentUniqueClaim},
		{"KindsIsolated", testKindsIsolated},
		{"Wipe", testWipe},
		{"Snapshot", testSnapshot},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if opt.NoReplicated && strings.HasPrefix(tc.name, "PutReplicated") {
				t.Skip("this store takes no replicated writes")
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
	if r.Scope != "org1" || r.Origin == "" || r.Req == "" || len(r.Unique) != 2 {
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

// The store stamps every write's version, newer than the one stored: a caller's version is not used, so a write made
// with an old copy's version lands (as in any database), and only compare-and-put refuses an old copy.
func testVersionsStamped(t *testing.T, s store.Store) {
	u := newUser("org1", "carol")
	must(t, users(s).Put(ctx, u))
	first := u.Version
	same, _ := store.EncodeAsIs(u) // the stored version
	must(t, s.Put(ctx, same))
	if same.Version <= first {
		t.Fatalf("a write of the stored version was not stamped newer: %d after %d", same.Version, first)
	}
	old, _ := store.EncodeAsIs(u)
	old.Version = 1 // far older than anything stored
	must(t, s.Put(ctx, old))
	if old.Version <= same.Version {
		t.Fatalf("a write of an old version was not stamped newer: %d after %d", old.Version, same.Version)
	}
	got, err := s.Get(ctx, model.KindUser, u.ID)
	must(t, err)
	if got.Version != old.Version {
		t.Fatalf("stored version %d, the write was given %d", got.Version, old.Version)
	}
	stale, _ := store.EncodeAsIs(u)
	if err := s.CompareAndPut(ctx, stale, first); !errors.Is(err, store.ErrStale) {
		t.Fatalf("compare-and-put from an old copy: want ErrStale, got %v", err)
	}
	next, _ := store.EncodeAsIs(u)
	must(t, s.CompareAndPut(ctx, next, got.Version))
	if next.Version <= got.Version {
		t.Fatalf("compare-and-put not stamped newer: %d after %d", next.Version, got.Version)
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
	if _, err := s.Lookup(ctx, model.KindUser, dup.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("conflicting record must not be written: %v", err)
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

// A unique value of any length is indexed whole: two long values that share a long prefix are different values, and
// each finds its record.
func testUniqueLong(t *testing.T, s store.Store) {
	tb := store.NewTable[model.Identity](s)
	prefix := strings.Repeat("l", 600)
	ident := func(subject string) *model.Identity {
		return &model.Identity{UserID: "u-" + subject[len(subject)-1:], OrgID: "org1", ProviderID: "p1", Subject: subject}
	}
	a, b := ident(prefix+"a"), ident(prefix+"b")
	must(t, tb.Put(ctx, a))
	must(t, tb.Put(ctx, b))
	for _, i := range []*model.Identity{a, b} {
		got, err := tb.GetByUnique(ctx, model.IdentityKey("p1", i.Subject))
		if err != nil || got.ID != i.ID {
			t.Fatalf("a long unique value: %v %v", got, err)
		}
	}
	clash := ident(prefix + "a")
	if err := tb.Put(ctx, clash); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a clash on a long unique value: want ErrConflict, got %v", err)
	}
	a.Subject = "short"
	must(t, tb.Put(ctx, a))
	must(t, tb.Put(ctx, clash)) // released
	// longer than any engine's key (Badger's is 65,000 bytes)
	huge := ident(strings.Repeat("h", 70_000) + "z")
	must(t, tb.Put(ctx, huge))
	if got, err := tb.GetByUnique(ctx, model.IdentityKey("p1", huge.Subject)); err != nil || got.ID != huge.ID {
		t.Fatalf("a 70 KB unique value: %v %v", got, err)
	}
}

// A purged expired record releases its unique values, however long (a long one is indexed by its hash): the value
// then finds nothing, even once another record takes the purged one's id.
func testUniqueLongPurged(t *testing.T, s store.Store) {
	lt := store.NewTable[model.LinkToken](s)
	old := strings.Repeat("o", 600)
	link := &model.LinkToken{Meta: model.Meta{ID: "invite-u1"}, OrgID: "org1", UserID: "u1", TokenHash: old,
		Expires: time.Now().Add(-time.Minute)}
	must(t, lt.Put(ctx, link))
	// (A cluster purges each node's copy on its own: the count is the purging node's, and another node may still hold it.)
	if n, err := s.Purge(ctx, time.Now().Add(-time.Hour), time.Now()); err != nil || n < 1 {
		t.Fatalf("purged %d (%v), want the expired link", n, err)
	}
	next := &model.LinkToken{Meta: model.Meta{ID: link.ID}, OrgID: "org1", UserID: "u1", TokenHash: strings.Repeat("n", 600),
		Expires: time.Now().Add(time.Hour)}
	must(t, lt.Put(ctx, next))
	if _, err := lt.GetByUnique(ctx, model.LinkTokenKey(old)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the purged link's token: %v, want ErrNotFound (nil: it finds the new link)", err)
	}
	if got, err := lt.GetByUnique(ctx, model.LinkTokenKey(next.TokenHash)); err != nil || got.ID != next.ID {
		t.Fatalf("the new link's token: %v %v", got, err)
	}
}

// Every store takes the same records: an id or scope of MaxIDLength characters, a string field of MaxFieldLength (a
// Words field of model.MaxTagsText), and refuses one longer with ErrBadRecord, writing nothing.
func testLimits(t *testing.T, s store.Store) {
	tb := users(s)
	at := newUser("org1", "limits")
	at.ID = strings.Repeat("i", store.MaxIDLength)
	at.GivenName = strings.Repeat("é", store.MaxFieldLength)
	tags := make([]string, model.MaxTags)
	for i := range tags {
		tags[i] = fmt.Sprintf("t%02d%s", i, strings.Repeat("x", 61))
	}
	at.Tags = tags
	must(t, tb.Put(ctx, at))
	got, err := tb.Get(ctx, at.ID)
	must(t, err)
	if got.GivenName != at.GivenName || len(got.Tags) != model.MaxTags {
		t.Fatalf("a record at the limits came back changed")
	}
	for name, change := range map[string]func(u *model.User){
		"id":    func(u *model.User) { u.ID = strings.Repeat("i", store.MaxIDLength+1) },
		"field": func(u *model.User) { u.GivenName = strings.Repeat("é", store.MaxFieldLength+1) },
	} {
		u := newUser("org1", "over-"+name)
		change(u)
		if err := tb.Put(ctx, u); !errors.Is(err, store.ErrBadRecord) {
			t.Fatalf("a record over the %s limit: want ErrBadRecord, got %v", name, err)
		}
		if err := tb.Create(ctx, u); !errors.Is(err, store.ErrBadRecord) {
			t.Fatalf("a record over the %s limit, created: want ErrBadRecord, got %v", name, err)
		}
		r, _ := store.Encode(u)
		if err := s.Tx(ctx, []store.Op{{Rec: r}}); !errors.Is(err, store.ErrBadRecord) {
			t.Fatalf("a record over the %s limit, in a Tx: want ErrBadRecord, got %v", name, err)
		}
		if _, err := tb.GetByUnique(ctx, model.UserUsernameKey("org1", "over-"+name)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a refused record was written: %v", err)
		}
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
	// A live write over the tombstone (an update from a copy read before the deletion) does not bring it back.
	old, _ := store.EncodeAsIs(u)
	if err := s.Put(ctx, old); !errors.Is(err, store.ErrDeleted) {
		t.Fatalf("live write over a tombstone: want ErrDeleted, got %v", err)
	}
	// A tombstone keeps the partition key of the record it deleted.
	if r, err := s.Lookup(ctx, model.KindUser, u.ID); err != nil || !r.Deleted || r.Partition != u.OrgID {
		t.Fatalf("the tombstone: %+v %v, want its record's partition %q", r, err, u.OrgID)
	}
}

// A Put over an expired record continues its generation (its Epoch and Created are kept), as over a live one; only a
// create (CompareAndPut with expect 0) starts a new one.
func testPutOverExpired(t *testing.T, s store.Store) {
	u := newUser("org1", "lapsed")
	r, err := store.Encode(u)
	must(t, err)
	r.Expires = time.Now().Add(-time.Minute)
	must(t, s.Put(ctx, r))
	first, err := s.Lookup(ctx, model.KindUser, u.ID)
	must(t, err)
	put, err := store.Encode(u)
	must(t, err)
	must(t, s.Put(ctx, put))
	if put.Created != first.Created || put.Epoch != first.Epoch {
		t.Fatalf("a put over an expired record: created %d epoch %d, want %d %d (its generation)", put.Created, put.Epoch,
			first.Created, first.Epoch)
	}
	r2, err := store.Encode(newUser("org1", "lapsed2"))
	must(t, err)
	r2.Expires = time.Now().Add(-time.Minute)
	must(t, s.Put(ctx, r2))
	created, err := store.EncodeAsIs(&model.User{Meta: model.Meta{ID: r2.ID}, OrgID: "org1", Username: "lapsed2"})
	must(t, err)
	must(t, s.CompareAndPut(ctx, created, 0))
	if created.Created != created.Version {
		t.Fatalf("a create over an expired record: created %d, want its own version %d (a new generation)", created.Created, created.Version)
	}
}

// A record never changes its partition key: a write that would is refused (ErrBadRecord), whatever the store, and its
// tombstone keeps the key.
func testRecordNeverMoves(t *testing.T, s store.Store) {
	u := newUser("org1", "stays")
	must(t, users(s).Put(ctx, u))
	moved := *u
	moved.OrgID = "org2"
	r, err := store.Encode(&moved)
	must(t, err)
	if err := s.Put(ctx, r); !errors.Is(err, store.ErrBadRecord) {
		t.Fatalf("a write moving a record to another partition: want ErrBadRecord, got %v", err)
	}
	if err := s.Tx(ctx, []store.Op{{Rec: r}}); !errors.Is(err, store.ErrBadRecord) {
		t.Fatalf("a transaction moving a record to another partition: want ErrBadRecord, got %v", err)
	}
	got, err := users(s).Get(ctx, u.ID)
	must(t, err)
	if got.OrgID != "org1" {
		t.Fatalf("the record moved: %q", got.OrgID)
	}
}

// A write whose context has ended before it begins is refused with ErrUnavailable and writes nothing, whatever the
// store; a read may complete, and fails, if it fails, with ErrUnavailable.
func testEndedContext(t *testing.T, s store.Store) {
	tb := users(s)
	keep := newUser("org1", "kept")
	must(t, tb.Put(ctx, keep))
	for name, c := range map[string]context.Context{"cancelled": cancelled(), "past its deadline": pastDeadline()} {
		u := newUser("org1", "ended-"+strings.ReplaceAll(name, " ", "-"))
		r, err := store.Encode(u)
		must(t, err)
		for op, write := range map[string]func() error{
			"put":    func() error { return s.Put(c, r) },
			"create": func() error { return s.CompareAndPut(c, r, 0) },
			"tx":     func() error { return s.Tx(c, []store.Op{{Rec: r}}) },
		} {
			if err := write(); !errors.Is(err, store.ErrUnavailable) {
				t.Fatalf("%s with a context %s: want ErrUnavailable, got %v", op, name, err)
			}
		}
		if _, err := s.Lookup(ctx, model.KindUser, u.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a write with a context %s was written: %v", name, err)
		}
		if _, err := s.Get(c, model.KindUser, keep.ID); err != nil && !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("a read with a context %s: want it answered or ErrUnavailable, got %v", name, err)
		}
		if _, err := s.List(c, model.KindUser, store.ListQuery{Scope: "org1"}); err != nil && !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("a listing with a context %s: want it answered or ErrUnavailable, got %v", name, err)
		}
	}
}

// A closed store answers every call with ErrUnavailable, whatever the store (and closing it again is harmless).
func testClosed(t *testing.T, s store.Store) {
	u := newUser("org1", "closing")
	must(t, users(s).Put(ctx, u))
	must(t, s.Close())
	r, err := store.Encode(newUser("org1", "after-close"))
	must(t, err)
	for name, call := range map[string]func() error{
		"get": func() error { _, err := s.Get(ctx, model.KindUser, u.ID); return err },
		"unique": func() error {
			_, err := s.GetByUnique(ctx, model.KindUser, model.UserUsernameKey("org1", "closing"))
			return err
		},
		"lookup": func() error { _, err := s.Lookup(ctx, model.KindUser, u.ID); return err },
		"list":   func() error { _, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org1"}); return err },
		"count":  func() error { _, err := s.Count(ctx, model.KindUser, "org1"); return err },
		"put":    func() error { return s.Put(ctx, r) },
		"create": func() error { return s.CompareAndPut(ctx, r, 0) },
		"tx":     func() error { return s.Tx(ctx, []store.Op{{Rec: r}}) },
		"snapshot": func() error {
			sn, ok := s.(store.Snapshotter)
			if !ok {
				return store.ErrUnavailable
			}
			v, err := sn.Snapshot(ctx)
			if err == nil {
				v.Close()
			}
			if errors.Is(err, store.ErrNoSnapshot) {
				return store.ErrUnavailable
			}
			return err
		},
	} {
		if err := call(); !errors.Is(err, store.ErrUnavailable) {
			t.Errorf("%s on a closed store: want ErrUnavailable, got %v", name, err)
		}
	}
}

// An expiry comes back to the microsecond, in UTC, whatever the store and whatever zone it was written in.
func testExpiresPrecision(t *testing.T, s store.Store) {
	at := time.Date(2099, 1, 2, 3, 4, 5, 123456789, time.FixedZone("x", 3600))
	r, err := store.Encode(newUser("org1", "expiring"))
	must(t, err)
	r.Expires = at
	must(t, s.Put(ctx, r))
	got, err := s.Get(ctx, model.KindUser, r.ID)
	must(t, err)
	if want := at.UTC().Truncate(time.Microsecond); !got.Expires.Equal(want) || got.Expires.Location() != time.UTC ||
		got.Expires.Nanosecond() != want.Nanosecond() {
		t.Fatalf("expires %v, want %v", got.Expires, want)
	}
}

func cancelled() context.Context {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	return c
}

func pastDeadline() context.Context {
	c, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	_ = cancel // (ended already; released with the test)
	return c
}

// A deletion of a record that is not live (none stored, deleted, or expired) writes nothing and succeeds, whatever the
// store: a later live write of the same id is a write like any other, not one over a tombstone. One expecting a version
// finds nothing (ErrNotFound).
func testDeleteNotLive(t *testing.T, s store.Store) {
	tb := users(s)
	gone := newUser("org1", "expired")
	r, err := store.Encode(gone)
	must(t, err)
	r.Expires = time.Now().Add(-time.Minute)
	must(t, s.Put(ctx, r))
	for _, id := range []string{"never", gone.ID} {
		for name, del := range map[string]func() error{
			"put":    func() error { return s.Put(ctx, store.Tombstone(model.KindUser, id)) },
			"create": func() error { return s.CompareAndPut(ctx, store.Tombstone(model.KindUser, id), 0) },
			"tx":     func() error { return s.Tx(ctx, []store.Op{{Rec: store.Tombstone(model.KindUser, id)}}) },
		} {
			if err := del(); err != nil {
				t.Fatalf("%s: a deletion of %s, not live: %v", name, id, err)
			}
			if got, err := s.Lookup(ctx, model.KindUser, id); err == nil && got.Deleted {
				t.Fatalf("%s: a deletion of %s, not live, wrote a tombstone", name, id)
			}
		}
		if err := tb.DeleteIf(ctx, id, 1); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a deletion expecting a version of %s, not live: want ErrNotFound, got %v", id, err)
		}
	}
	again := newUser("org1", "never-again")
	again.ID = "never"
	must(t, tb.Put(ctx, again)) // no tombstone stands in its way
	// A deletion expecting no live record does not delete a live one.
	if err := s.CompareAndPut(ctx, store.Tombstone(model.KindUser, again.ID), 0); !errors.Is(err, store.ErrStale) {
		t.Fatalf("a deletion with expect 0 of a live record: want ErrStale, got %v", err)
	}
	if _, err := tb.Get(ctx, again.ID); err != nil {
		t.Fatalf("the live record was deleted: %v", err)
	}
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
	a, err := tb.Get(ctx, u.ID)
	must(t, err)
	b, err := tb.Get(ctx, u.ID)
	must(t, err)
	a.GivenName = "A"
	must(t, tb.Update(ctx, a))
	b.GivenName = "B"
	if err := tb.Update(ctx, b); !errors.Is(err, store.ErrStale) {
		t.Fatalf("lost update not detected: %v", err)
	}
	got, err := tb.Get(ctx, u.ID)
	must(t, err)
	if got.GivenName != "A" {
		t.Fatal("stale update applied")
	}
	missing := newUser("org1", "nobody")
	missing.ID = "missing"
	r, _ := store.Encode(missing)
	if err := s.CompareAndPut(ctx, r, 12345); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// An expectation ahead of the stored version is stale.
	cur, err := s.Get(ctx, model.KindUser, u.ID)
	must(t, err)
	c := *got
	next, _ := store.Encode(&c)
	if err := s.CompareAndPut(ctx, next, cur.Version+1); !errors.Is(err, store.ErrStale) {
		t.Fatalf("expectation ahead of the stored version: want ErrStale, got %v", err)
	}
	if now, err := s.Get(ctx, model.KindUser, u.ID); err != nil || now.Version != cur.Version {
		t.Fatalf("a refused CompareAndPut changed the record: version %d, was %d", now.Version, cur.Version)
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
	// An expired record does not hold its unique values: another record may claim them.
	link := func(id string, expires time.Time) *store.Record {
		return &store.Record{Kind: model.KindLink, ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "u1",
			Unique: []string{"exp/token"}, Data: []byte("x"), Expires: expires}
	}
	must(t, s.Put(ctx, link("old", time.Now().Add(-time.Second))))
	must(t, s.Put(ctx, link("new", time.Time{})))
	if h, err := s.GetByUnique(ctx, model.KindLink, "exp/token"); err != nil || h.ID != "new" {
		t.Fatalf("holder of an expired record's unique value: %v %v", h, err)
	}
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

// testListFolding: searches, prefix filters and sorts fold case beyond ASCII ("É" as "é"), and a word of a word-list
// field matches whatever its case and wherever it is in the list, as the shared query evaluation does.
func testListFolding(t *testing.T, s store.Store) {
	for _, name := range []string{"Zoé", "Émile", "ella"} {
		u := newUser("org1", name)
		u.GivenName = name
		must(t, users(s).Put(ctx, u))
	}
	for i, tags := range [][]string{{"Staff"}, {"Staff", "other"}, {"other", "Staff"}, {"other"}} {
		u := newUser("org1", fmt.Sprintf("tagged%d", i))
		u.Tags = tags
		must(t, users(s).Put(ctx, u))
	}
	for _, q := range []store.ListQuery{
		{Scope: "org1", Search: "é"},
		{Scope: "org1", Search: "ÉMI"},
		{Scope: "org1", Filters: []store.Filter{{Field: "username", Op: store.OpPrefix, Value: "émi"}}},
		{Scope: "org1", Sort: "username"},
		{Scope: "org1", Sort: "name", Desc: true},
		{Scope: "org1", Filters: []store.Filter{{Field: "tags", Value: "staff"}}},
	} {
		got := CheckAgainstApplyQuery(t, s, model.KindUser, q)
		if got.Total == 0 {
			t.Errorf("%+v matched nothing", q)
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
		{[]store.Filter{{Field: "manager_id", Value: ""}}, 12},
	}
	for i, c := range cases {
		_, total, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Filters: c.f})
		must(t, err)
		if total != c.want {
			t.Errorf("case %d: got %d want %d", i, total, c.want)
		}
	}
	// A word of a word-list field (tags): that word, ignoring case, wherever it is in the list.
	for i, u := range users3(t, s) {
		u.Tags = [][]string{{"red", "x/y"}, {"blue", "Red"}, {"x/y"}}[i]
		must(t, users(s).Put(ctx, u))
	}
	for tag, want := range map[string]int{"red": 2, "RED": 2, "x/y": 2, "blue": 1, "re": 0, "x": 0, "red x/y": 0} {
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

// testPlainScanSkipsExpired: expired records still stored are left out of offsets, limits and totals in both directions
// (in a scope with LIKE wildcards, which are literal), and Purge removes them without changing the count.
func testPlainScanSkipsExpired(t *testing.T, s store.Store) {
	tb := store.NewTable[model.Session](s)
	var live []string
	for i := range 8 {
		ss := &model.Session{UserID: "u/1%", OrgID: "o", Expires: time.Now().Add(time.Hour)}
		if i == 1 || i == 4 || i == 5 {
			ss.Expires = time.Now().Add(-time.Minute)
		}
		must(t, tb.Put(ctx, ss))
		if ss.Expires.After(time.Now()) {
			live = append(live, ss.ID)
		}
	}
	must(t, tb.Put(ctx, &model.Session{UserID: "u/10", OrgID: "o", Expires: time.Now().Add(time.Hour)})) // matched by the wildcard
	for _, desc := range []bool{false, true} {
		list, total, err := tb.List(ctx, store.ListQuery{Scope: "u/1%", Desc: desc, Offset: 1, Limit: 3})
		must(t, err)
		want := live[1:4]
		if desc {
			want = []string{live[3], live[2], live[1]}
		}
		got := make([]string, len(list))
		for i, ss := range list {
			got[i] = ss.ID
		}
		if total != 5 || !slices.Equal(got, want) {
			t.Fatalf("desc=%v: %v (total %d), want %v (total 5)", desc, got, total, want)
		}
	}
	if n, err := s.Count(ctx, model.KindSession, ""); err != nil || n != 6 {
		t.Fatalf("count all %d %v", n, err)
	}
	if n, err := s.Purge(ctx, time.Now(), time.Now()); err != nil || n != 3 {
		t.Fatalf("purge %d %v", n, err)
	}
	if n, err := s.Count(ctx, model.KindSession, "u/1%"); err != nil || n != 5 {
		t.Fatalf("count after purge %d %v", n, err)
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
		if page == 0 && res.Total != len(ids) {
			t.Fatalf("an after-page's total is %d, want every match (%d)", res.Total, len(ids))
		}
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

// testIDOrderIsCreationOrder: ids made one after another (model.NewID), across millisecond boundaries, list in the
// order they were made: a scope's default order, its after-paging and its descending order are creation order, as a
// backend that compares ids byte-wise gives them.
func testIDOrderIsCreationOrder(t *testing.T, s store.Store) {
	var ids []string
	for i := range 40 {
		u := newUser("org1", fmt.Sprintf("ord%02d", 39-i)) // names in the reverse order: only the ids give the order
		must(t, users(s).Put(ctx, u))
		ids = append(ids, u.ID)
		if i%10 == 9 {
			time.Sleep(2 * time.Millisecond) // the next ids are of a later millisecond
		}
	}
	if ids[0][:9] == ids[len(ids)-1][:9] { // a millisecond (2^80) is more than the ninth digit's 62^13
		t.Fatal("setup: the ids did not cross a millisecond boundary")
	}
	listed, _, err := users(s).IDs(ctx, store.ListQuery{Scope: "org1"})
	must(t, err)
	if !slices.Equal(listed, ids) {
		t.Fatalf("default order is not creation order:\n got %v\nwant %v", listed, ids)
	}
	var paged []string
	for after := ""; ; {
		res, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org1", After: after, Limit: 7})
		must(t, err)
		if len(res.Records) == 0 {
			break
		}
		for _, r := range res.Records {
			paged = append(paged, r.ID)
		}
		after = paged[len(paged)-1]
	}
	if !slices.Equal(paged, ids) {
		t.Fatalf("after-paging is not creation order:\n got %v\nwant %v", paged, ids)
	}
	desc, _, err := users(s).IDs(ctx, store.ListQuery{Scope: "org1", Desc: true})
	must(t, err)
	slices.Reverse(desc)
	if !slices.Equal(desc, ids) {
		t.Fatalf("descending order is not reverse creation order: %v", desc)
	}
}

// testIDsCaseSensitive: two ids that differ only in the case of one letter are two records, each read back as itself and
// listed in its own scope, and the unique values that hold them (a user's username key starts with its organization's
// id) are two values. A backend comparing ids or unique values regardless of case (a case-insensitive collation) would
// merge them.
func testIDsCaseSensitive(t *testing.T, s store.Store) {
	a, b := caseTwins()
	ua, ub := newUser(a, "twin"), newUser(b, "twin")
	ua.ID, ub.ID = a, b
	must(t, users(s).Create(ctx, ua))
	must(t, users(s).Create(ctx, ub))
	for _, id := range []string{a, b} {
		u, err := users(s).Get(ctx, id)
		must(t, err)
		if u.ID != id || u.OrgID != id {
			t.Errorf("Get(%s) = %s of %s", id, u.ID, u.OrgID)
		}
		listed, _, err := users(s).IDs(ctx, store.ListQuery{Scope: id})
		must(t, err)
		if !slices.Equal(listed, []string{id}) {
			t.Errorf("scope %s lists %v", id, listed)
		}
		byName, err := users(s).GetByUnique(ctx, model.UserUsernameKey(id, "twin"))
		must(t, err)
		if byName.ID != id {
			t.Errorf("unique value of %s names %s", id, byName.ID)
		}
	}
	if n, err := users(s).Count(ctx, ""); err != nil || n != 2 {
		t.Fatalf("%d records, want 2: %v", n, err)
	}
}

// caseTwins returns two ids that differ only in the case of one letter.
func caseTwins() (string, string) {
	for {
		a := []byte(model.NewID())
		for i, c := range a {
			if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' {
				b := slices.Clone(a)
				b[i] ^= 0x20
				if model.IsID(string(b)) {
					return string(a), string(b)
				}
			}
		}
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
	short, err := a.New(ctx, "flow", []byte("x"), 20*time.Millisecond)
	must(t, err)
	time.Sleep(60 * time.Millisecond)
	if _, err := b.Get(ctx, "flow", short); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("expired value: %v", err)
	}
	if n, err := a.Incr(ctx, "rate", "window", 5, 20*time.Millisecond); err != nil || n != 5 {
		t.Fatal(n, err)
	}
	time.Sleep(60 * time.Millisecond)
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
	if _, err := s.List(ctx, model.KindUser, store.ListQuery{Sort: "manager_id"}); !errors.Is(err, store.ErrBadQuery) {
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
	check := func(kind model.Kind, q store.ListQuery) {
		t.Helper()
		CheckAgainstApplyQuery(t, s, kind, q)
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
		for _, sort := range []string{"username", "name", "email", "created", "role", "active", "valid_until"} {
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
	check := func(kind model.Kind, q store.ListQuery) {
		t.Helper()
		CheckAgainstApplyQuery(t, s, kind, q)
	}
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	us := make([]*model.User, 0, 40)
	for i := range 40 {
		u := newUser("org1", fmt.Sprintf("u%02d", i))
		if i%4 == 1 {
			u.Username = strings.ToUpper(u.Username) // folds to the same order as the others
		}
		u.GivenName, u.FamilyName = []string{"Ann", "bob", "Ann", ""}[i%4], "" // three runs of equal names; "" names fall back to the username
		if i%5 == 0 {
			end := base.Add(time.Duration(i) * time.Hour)
			u.ValidUntil = &end // most users have no end date: a long run of empty values first
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
	role := func(r model.Role, more ...store.Filter) []store.Filter {
		return append([]store.Filter{{Field: "role", Value: string(r)}}, more...)
	}
	for _, desc := range []bool{false, true} {
		for _, sort := range []string{"username", "name", "valid_until", "created", "active", "role", "email"} {
			for _, off := range []int{0, 3, 11, 38, 45} {
				check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Offset: off, Limit: 5})
				check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Offset: off, Limit: 5, Filters: visible})
				// An indexed equality filter, alone and with the visibility exclusion, that selects most of the
				// scope (the key-value stores page the sort index keeping its matches) and few of it.
				check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Offset: off, Limit: 5, Filters: role(model.RoleUser)})
				check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Offset: off, Limit: 5, Filters: role(model.RoleUser, visible...)})
				check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Offset: off, Limit: 2, Filters: role(model.RoleAdmin, visible...)})
			}
			check(model.KindUser, store.ListQuery{Scope: "org1", Sort: sort, Desc: desc, Filters: role(model.RoleUser)})
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
	// The order follows the records: a renamed user moves, a deleted one leaves, as does one whose role changes from
	// the role filtered on.
	u := us[7]
	u.Username, u.GivenName, u.Role = "aaa", "Zoe", model.RoleAdmin
	must(t, users(s).Update(ctx, u))
	must(t, users(s).Delete(ctx, us[0].ID))
	must(t, users(s).Delete(ctx, us[2].ID)) // a super admin
	for _, desc := range []bool{false, true} {
		check(model.KindUser, store.ListQuery{Scope: "org1", Sort: "username", Desc: desc, Limit: 3})
		check(model.KindUser, store.ListQuery{Scope: "org1", Sort: "name", Desc: desc, Offset: 1, Limit: 6, Filters: visible})
		check(model.KindUser, store.ListQuery{Scope: "org1", Sort: "username", Desc: desc, Limit: 4, Filters: role(model.RoleUser, visible...)})
		check(model.KindUser, store.ListQuery{Scope: "org1", Sort: "active", Desc: desc, Offset: 9, Limit: 6, Filters: role(model.RoleUser)})
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

func testPutReplicated(t *testing.T, s store.Store) {
	u := newUser("org1", "jack")
	u.ID = model.NewID()
	v := store.Clock.Now() + 1000
	u.GivenName = "v2"
	r := replica(u, v+10, "n1")
	r.Epoch = v - 3 // a generation: kept as sent
	ok, err := s.PutReplicated(ctx, r)
	must(t, err)
	if !ok {
		t.Fatalf("first apply: %v", ok)
	}
	got, err := s.Get(ctx, model.KindUser, u.ID)
	must(t, err)
	if got.Version != v+10 || got.Origin != "n1" || got.Epoch != v-3 || got.Created != v+10 || got.Partition != "org1" {
		t.Fatalf("stored as sent: %+v", got)
	}
	// The same or an older version is not applied; a newer one is.
	u.GivenName = "v1"
	if ok, err := s.PutReplicated(ctx, replica(u, v+5, "n1")); err != nil || ok {
		t.Fatalf("older version: %v %v", ok, err)
	}
	if ok, err := s.PutReplicated(ctx, replica(u, v+10, "n2")); err != nil || ok {
		t.Fatalf("the same version: %v %v", ok, err)
	}
	if g, err := users(s).Get(ctx, u.ID); err != nil || g.GivenName != "v2" {
		t.Fatalf("an older record replaced a newer one: %q", g.GivenName)
	}
	u.GivenName = "v3"
	if ok, err := s.PutReplicated(ctx, replica(u, v+20, "n1")); err != nil || !ok {
		t.Fatalf("newer version: %v %v", ok, err)
	}
	// The local clock witnessed the version: the next local write is above it.
	if store.Clock.Now() <= v+20 {
		t.Fatal("clock did not witness")
	}
	// A newer tombstone replaces it, and then an older record is not applied over it (tombstones count).
	del := &store.Record{Kind: model.KindUser, ID: u.ID, Version: v + 30, Origin: "n2", Deleted: true}
	if ok, err := s.PutReplicated(ctx, del); err != nil || !ok {
		t.Fatalf("tombstone: %v %v", ok, err)
	}
	if ok, err := s.PutReplicated(ctx, replica(u, v+25, "n1")); err != nil || ok {
		t.Fatalf("a record older than the tombstone: %v %v", ok, err)
	}
	if _, err := users(s).Get(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("record resurrected")
	}
	if ok, err := s.PutReplicated(ctx, replica(u, v+40, "n1")); err != nil || !ok {
		t.Fatalf("a record newer than the tombstone: %v %v", ok, err)
	}
	if _, err := users(s).Get(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
}

// A unique value another live record holds is refused (ErrConflict) and nothing of the record is stored; a deleted
// record, or one that no longer lists the value, holds nothing.
func testPutReplicatedUnique(t *testing.T, s store.Store) {
	tb := users(s)
	first := newUser("org1", "mia")
	must(t, tb.Put(ctx, first))
	second := newUser("org1", "mia2")
	second.Email = first.Email
	second.ID = model.NewID()
	ok, err := s.PutReplicated(ctx, replica(second, store.Clock.Now(), "zz"))
	if !errors.Is(err, store.ErrConflict) || ok {
		t.Fatalf("a clashing record: ok=%v err=%v", ok, err)
	}
	if _, err := tb.Get(ctx, second.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a refused record was stored")
	}
	if got, _ := tb.GetByUnique(ctx, model.UserEmailKey("org1", first.Email)); got == nil || got.ID != first.ID {
		t.Fatal("the holder lost its value")
	}
	if _, err := tb.GetByUnique(ctx, model.UserUsernameKey("org1", "mia2")); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a refused record's other unique values were indexed")
	}
	// Once the holder is deleted the value is free.
	must(t, tb.Delete(ctx, first.ID))
	if ok, err := s.PutReplicated(ctx, replica(second, store.Clock.Now(), "zz")); err != nil || !ok {
		t.Fatalf("a value its holder released: %v %v", ok, err)
	}
	if got, _ := tb.GetByUnique(ctx, model.UserEmailKey("org1", first.Email)); got == nil || got.ID != second.ID {
		t.Fatal("the value did not move to the new holder")
	}
	// A record keeps its own values when it is applied again at a newer version.
	second.GivenName = "again"
	if ok, err := s.PutReplicated(ctx, replica(second, store.Clock.Now(), "zz")); err != nil || !ok {
		t.Fatalf("a newer version of the holder: %v %v", ok, err)
	}
}

func testFeedID(t *testing.T, s store.Store) {
	if s.FeedID() == "" || s.FeedID() != s.FeedID() {
		t.Fatal("the store's identity must be stable and non-empty")
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
	// The expired record goes; the tombstone goes too, unless the store purges its tombstones itself (store.Store).
	_, terr := s.Lookup(ctx, model.KindUser, a.ID)
	switch {
	case n == 2 && errors.Is(terr, store.ErrNotFound):
	case n == 1 && terr == nil:
	default:
		t.Fatalf("purged %d (the tombstone: %v), want the expired record and perhaps the tombstone", n, terr)
	}
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
