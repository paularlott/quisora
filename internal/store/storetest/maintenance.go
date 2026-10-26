package storetest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// testWipe: a wiped store (a backend with a Wipe method; a restore starts with it) holds no records and no unique values
// any more, and has a new identity.
func testWipe(t *testing.T, s store.Store) {
	w, ok := s.(interface{ Wipe(context.Context) error })
	if !ok {
		t.Skip("the store has no Wipe")
	}
	tb := users(s)
	u := newUser("org1", "wiped")
	must(t, tb.Put(ctx, u))
	must(t, store.NewTable[model.Session](s).Put(ctx, &model.Session{UserID: "u", Expires: time.Now().Add(time.Hour)}))
	feed := s.FeedID()
	must(t, w.Wipe(ctx))
	if s.FeedID() == feed || s.FeedID() == "" {
		t.Fatalf("feed id %q after a wipe, was %q", s.FeedID(), feed)
	}
	if _, err := s.Lookup(ctx, model.KindUser, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a record survived the wipe: %v", err)
	}
	if _, err := tb.GetByUnique(ctx, model.UserEmailKey("org1", u.Email)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a unique value survived the wipe: %v", err)
	}
	for kind, scope := range map[model.Kind]string{model.KindUser: "", model.KindSession: "u"} {
		if n, err := s.Count(ctx, kind, scope); err != nil || n != 0 {
			t.Fatalf("%s count after the wipe: %d %v", kind, n, err)
		}
	}
	if _, total, err := tb.List(ctx, store.ListQuery{}); err != nil || total != 0 {
		t.Fatalf("list after the wipe: %d %v", total, err)
	}
	must(t, tb.Put(ctx, newUser("org1", "wiped"))) // its unique values are free again
}

// testSnapshot: a snapshot (store.Snapshotter) is a point-in-time view: writes after its first read are invisible to it,
// and its counts and lists leave out expired records as the store's own do. (On SQLite and Badger the view is fixed
// when Snapshot returns; PostgreSQL, MySQL and MariaDB fix a transaction's snapshot at its first read.)
func testSnapshot(t *testing.T, s store.Store) {
	sn, ok := s.(store.Snapshotter)
	if !ok {
		t.Skip("the store does not implement store.Snapshotter")
	}
	put := func(id string, expires time.Time) {
		t.Helper()
		must(t, s.Put(ctx, &store.Record{Kind: model.KindLink, ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "sc",
			Data: []byte("d"), Expires: expires}))
	}
	put("a", time.Time{})
	put("f", time.Now().Add(time.Hour))
	put("x", time.Now().Add(-time.Hour))
	view, err := sn.Snapshot(ctx)
	if errors.Is(err, store.ErrNoSnapshot) {
		t.Skip("no point-in-time view")
	}
	must(t, err)
	t.Cleanup(func() { view.Close() }) // an open view would keep a server database from being dropped
	// The view is fixed when Snapshot returns: a write before its first read is not in it.
	put("b", time.Time{})
	if n, err := view.Count(ctx, model.KindLink, "sc"); err != nil || n != 2 {
		t.Fatalf("snapshot count after a later write: %d %v", n, err)
	}
	res, err := view.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"})
	if err != nil || res.Total != 2 || !slices.Equal(IDs(res.Records), []string{"a", "f"}) {
		t.Fatalf("snapshot list: %+v %v", res, err)
	}
	must(t, view.Close())
	if n, err := s.Count(ctx, model.KindLink, "sc"); err != nil || n != 3 {
		t.Fatalf("live count: %d %v", n, err)
	}
}
