package kvstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

var bg = context.Background()

func engines() map[string]func(testing.TB) store.Store {
	return map[string]func(testing.TB) store.Store{"badger": badgerFactory, "valkey": valkeyFactory}
}

// Expired-but-unpurged records must be skipped by offsets, limits and totals in both directions.
func TestPlainScanSkipsExpired(t *testing.T) {
	for name, f := range engines() {
		t.Run(name, func(t *testing.T) {
			s := f(t)
			defer s.Close()
			tb := store.NewTable[model.Session](s)
			var liveIDs []string
			for i := range 8 {
				ss := &model.Session{UserID: "u/1%", OrgID: "o"}
				if i%8 == 1 || i%8 == 4 || i%8 == 5 {
					ss.Expires = time.Now().Add(-time.Minute)
				} else {
					ss.Expires = time.Now().Add(time.Hour)
				}
				if err := tb.Put(bg, ss); err != nil {
					t.Fatal(err)
				}
				if ss.Expires.After(time.Now()) {
					liveIDs = append(liveIDs, ss.ID)
				}
			}
			for _, desc := range []bool{false, true} {
				list, total, err := tb.List(bg, store.ListQuery{Scope: "u/1%", Desc: desc, Offset: 1, Limit: 3})
				if err != nil || total != 5 || len(list) != 3 {
					t.Fatalf("desc=%v total=%d len=%d err=%v", desc, total, len(list), err)
				}
				for i, ss := range list {
					want := liveIDs[1+i]
					if desc {
						want = liveIDs[3-i]
					}
					if ss.ID != want {
						t.Fatalf("desc=%v pos %d: got %s want %s", desc, i, ss.ID, want)
					}
				}
			}
			if n, _ := s.Count(bg, model.KindSession, ""); n != 5 {
				t.Fatalf("count all %d", n)
			}
			n, err := s.Purge(bg, time.Now(), time.Now())
			if err != nil || n != 3 {
				t.Fatalf("purge %d %v", n, err)
			}
			if n, _ := s.Count(bg, model.KindSession, "u/1%"); n != 5 {
				t.Fatalf("count after purge %d", n)
			}
		})
	}
}

func TestBadgerReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenBadger(bg, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	feed := s.FeedID()
	u := &model.User{OrgID: "o", Username: "a", Email: "a@x", Role: model.RoleUser}
	if err := store.NewTable[model.User](s).Put(bg, u); err != nil {
		t.Fatal(err)
	}
	ch, last, _ := s.Changes(bg, 0, 0)
	if len(ch) != 1 {
		t.Fatal("feed")
	}
	s.Close()
	s, err = OpenBadger(bg, dir, BadgerOptions{Compression: "zstd"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.FeedID() != feed {
		t.Fatal("feed id not persisted")
	}
	u2 := &model.User{OrgID: "o", Username: "b", Email: "b@x", Role: model.RoleUser}
	if err := store.NewTable[model.User](s).Put(bg, u2); err != nil {
		t.Fatal(err)
	}
	ch, _, _ = s.Changes(bg, last, 0)
	if len(ch) != 1 || ch[0].Seq != last+1 {
		t.Fatalf("seq did not continue: %v", ch)
	}
	if _, err := store.NewTable[model.User](s).Get(bg, u.ID); err != nil {
		t.Fatal(err)
	}
}

// Purge only touches the exp and tomb indexes: seed many live records, one tombstone and one expired record.
func TestPurgeLargeStore(t *testing.T) {
	for name, f := range engines() {
		t.Run(name, func(t *testing.T) {
			s := f(t)
			defer s.Close()
			tb := store.NewTable[model.Session](s)
			for i := range 300 {
				_ = i
				if err := tb.Put(bg, &model.Session{UserID: fmt.Sprint("u", i%7), Expires: time.Now().Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			dead := &model.Session{UserID: "u1", Expires: time.Now().Add(-time.Hour)}
			_ = tb.Put(bg, dead)
			n, err := s.Purge(bg, time.Now(), time.Now())
			if err != nil || n != 1 {
				t.Fatalf("purge %d %v", n, err)
			}
			if c, _ := s.Count(bg, model.KindSession, ""); c != 300 {
				t.Fatalf("count %d", c)
			}
		})
	}
}

func TestWipe(t *testing.T) {
	for name, f := range engines() {
		t.Run(name, func(t *testing.T) {
			s := f(t)
			defer s.Close()
			w := s.(*Store)
			tb := store.NewTable[model.User](s)
			u := &model.User{OrgID: "o", Username: "a", Email: "a@x", Role: model.RoleUser}
			if err := tb.Put(bg, u); err != nil {
				t.Fatal(err)
			}
			ses := &model.Session{UserID: "u", Expires: time.Now().Add(time.Hour)}
			if err := store.NewTable[model.Session](s).Put(bg, ses); err != nil {
				t.Fatal(err)
			}
			old := s.FeedID()
			if err := w.Wipe(bg); err != nil {
				t.Fatal(err)
			}
			if s.FeedID() == old || s.FeedID() == "" {
				t.Fatal("feed id not renewed")
			}
			if _, err := tb.Get(bg, u.ID); err == nil {
				t.Fatal("record survived")
			}
			if _, err := tb.GetByUnique(bg, model.UserEmailKey("o", "a@x")); err == nil {
				t.Fatal("unique survived")
			}
			if n, _ := s.Count(bg, model.KindUser, ""); n != 0 {
				t.Fatalf("count %d", n)
			}
			if n, _ := s.Count(bg, model.KindSession, "u"); n != 0 {
				t.Fatalf("scope count %d", n)
			}
			if _, tot, _ := tb.List(bg, store.ListQuery{}); tot != 0 {
				t.Fatal("list not empty")
			}
			if ch, _, _ := s.Changes(bg, 0, 0); len(ch) != 0 {
				t.Fatal("feed not empty")
			}
			u2 := &model.User{OrgID: "o", Username: "a", Email: "a@x", Role: model.RoleUser}
			if err := tb.Put(bg, u2); err != nil {
				t.Fatalf("unique not free: %v", err)
			}
			if ch, _, _ := s.Changes(bg, 0, 0); len(ch) != 1 || ch[0].Seq != 1 {
				t.Fatalf("feed after wipe: %v", ch)
			}
		})
	}
}

// Kinds and fields live in the record itself: a kind first written after a restart works on an existing Badger DB,
// and records written before a field existed read back with its zero value.
func TestLaterKindOnExistingBadger(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenBadger(bg, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	old := &store.Record{Kind: model.KindClient, ID: "c-old", Version: store.Clock.Now(), Origin: "n", Scope: "o", Data: []byte("x"),
		Fields: map[string]any{"name": "old"}} // written before tenant_id existed
	if err := s.Put(bg, old); err != nil {
		t.Fatal(err)
	}
	feed := s.FeedID()
	s.Close()

	s, err = OpenBadger(bg, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.FeedID() != feed {
		t.Fatal("feed id changed")
	}
	rec := func(kind model.Kind, id string, f map[string]any) *store.Record {
		return &store.Record{Kind: kind, ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "o", Data: []byte("x"), Fields: f}
	}
	if err := s.Put(bg, rec(model.KindTenant, "t1", map[string]any{"name": "apps"})); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(bg, rec(model.KindClient, "c-new", map[string]any{"name": "new", "tenant_id": "t1"})); err != nil {
		t.Fatal(err)
	}
	res, err := s.List(bg, model.KindClient, store.ListQuery{Scope: "o", Filters: []store.Filter{{Field: "tenant_id", Value: "t1"}}})
	if err != nil || len(res.Records) != 1 || res.Records[0].ID != "c-new" {
		t.Fatalf("filter: %v %+v", err, res)
	}
	res, err = s.List(bg, model.KindClient, store.ListQuery{Scope: "o", Filters: []store.Filter{{Field: "tenant_id", Value: ""}}})
	if err != nil || len(res.Records) != 1 || res.Records[0].ID != "c-old" {
		t.Fatalf("old record: %v %+v", err, res)
	}
	if n, _ := s.Count(bg, model.KindTenant, "o"); n != 1 {
		t.Fatalf("tenants %d", n)
	}
}

// A12: a Badger snapshot is a point-in-time view of the whole store; a store written by an earlier pre-release
// format is refused at open rather than read wrongly.
func TestBadgerSnapshotAndFormat(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenBadger(ctx, dir, BadgerOptions{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	put := func(id string) {
		if err := s.Put(ctx, &store.Record{Kind: model.KindGroup, ID: id, Version: store.Clock.Now(), Scope: "o",
			Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	put("before")
	view, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	put("after")
	res, err := view.List(ctx, model.KindGroup, store.ListQuery{})
	if err != nil || len(res.Records) != 1 || res.Records[0].ID != "before" {
		t.Fatalf("the snapshot sees later writes: %v %+v", err, res)
	}
	view.Close()
	// an earlier build's store: data, but no format marker
	if err := s.eng.Update(ctx, func(tx txn) error { tx.Delete(metaFormat); return nil }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := OpenBadger(ctx, dir, BadgerOptions{NoSync: true}); err == nil {
		t.Fatal("a store in an earlier format was opened")
	}
}
