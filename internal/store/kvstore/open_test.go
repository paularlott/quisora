package kvstore

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A store opens and works with each option, and refuses an unknown compression or a key of the wrong length.
func TestOpenAcceptsEveryOptionCombination(t *testing.T) {
	ctx := context.Background()
	for _, o := range []BadgerOptions{
		{Compression: "snappy"},
		{Compression: "zstd"},
		{Compression: "none"},
		{InMemory: true},
		{NoSync: true, Group: GroupOptions{Disabled: true}, GCInterval: time.Hour},
		{NoSync: true, SyncInterval: time.Millisecond},
		{BlockCacheMB: 8, IndexCacheMB: 8, ValueLogFileSizeMB: 16},
		{Logger: quietLogger{}},
	} {
		s := openBadger(t, o)
		if err := s.Put(ctx, record(model.KindLink, "a", time.Time{}, "u")); err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		if got, err := s.GetByUnique(ctx, model.KindLink, "u"); err != nil || got.ID != "a" {
			t.Fatalf("%+v: %v", o, err)
		}
	}
	if _, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{Compression: "lz4"}); err == nil || !strings.Contains(err.Error(), "unknown compression") {
		t.Fatalf("unknown compression: %v", err)
	}
	if _, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{EncryptionKey: []byte("short")}); err == nil {
		t.Fatal("a key of the wrong length was accepted")
	}
}

func TestOpenRefusesAPathUnderAFile(t *testing.T) {
	// A path under a regular file cannot be a database directory.
	dir := t.TempDir()
	f := dir + "/file"
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBadger(context.Background(), f+"/sub", BadgerOptions{}); err == nil || !strings.Contains(err.Error(), "open badger") {
		t.Fatalf("open under a file: %v", err)
	}
}

// A reopened store keeps its data and identity, also with another compression; and kinds and fields live in the record
// itself, so a kind first written after a restart works, and a record written before a field existed reads it as zero.
func TestReopen(t *testing.T) {
	t.Run("KeepsDataAndFeedIDWithAnotherCompression", func(t *testing.T) {
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
		if _, err := store.NewTable[model.User](s).Get(bg, u.ID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("KindAndFieldAddedLater", func(t *testing.T) {
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
	})
}

// Every operation on a closed store fails with an error instead of panicking or returning data.
func TestOperationsOnClosedStoreFail(t *testing.T) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{}, "u")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rec := record(model.KindLink, "b", time.Time{}, "u2")
	checks := map[string]func() error{
		"Get":      func() error { _, err := s.Get(ctx, model.KindLink, "a"); return err },
		"Lookup":   func() error { _, err := s.Lookup(ctx, model.KindLink, "a"); return err },
		"ByUnique": func() error { _, err := s.GetByUnique(ctx, model.KindLink, "u"); return err },
		"GetMany":  func() error { _, err := s.GetMany(ctx, model.KindLink, []string{"a"}); return err },
		"List":     func() error { _, err := s.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"}); return err },
		"ListAll":  func() error { _, err := s.List(ctx, model.KindLink, store.ListQuery{}); return err },
		"Count":    func() error { _, err := s.Count(ctx, model.KindLink, "sc"); return err },
		"Put":      func() error { return s.Put(ctx, rec) },
		"CAS":      func() error { return s.CompareAndPut(ctx, rec, 0) },
		"Repl":     func() error { _, err := s.PutReplicated(ctx, rec); return err },
		"ReplB":    func() error { _, err := s.PutReplicatedBatch(ctx, []*store.Record{rec}); return err },
		"Purge":    func() error { _, err := s.Purge(ctx, time.Now(), time.Now()); return err },
		"Wipe":     func() error { return s.Wipe(ctx) },
		"Due":      func() error { _, err := s.ListDue(ctx, model.KindUser, time.Now(), 10); return err },
	}
	for name, f := range checks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s on a closed store panicked: %v", name, r)
				}
			}()
			if err := f(); err == nil {
				t.Errorf("%s on a closed store succeeded", name)
			}
		}()
	}
}

// Wipe puts the format marker back (storetest's Wipe checks the rest): the wiped store is not taken for an earlier
// build's when it reopens.
func TestWipeRestoresFormatMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenBadger(ctx, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{}, "u")); err != nil {
		t.Fatal(err)
	}
	if err := s.Wipe(ctx); err != nil {
		t.Fatal(err)
	}
	if b, err := s.eng.Get(ctx, metaFormat); err != nil || string(b) != strconv.Itoa(currentFormat()) {
		t.Fatalf("format marker: %q %v", b, err)
	}
	s.Close()
	s, err = OpenBadger(ctx, dir, BadgerOptions{})
	if err != nil {
		t.Fatalf("reopen after a wipe: %v", err)
	}
	s.Close()
}

// With NoSync and a SyncInterval the store syncs in the background while it is written, and closes (stopping the
// sync) with everything written there to read again.
func TestSyncIntervalStoreKeepsItsWrites(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenBadger(ctx, dir, BadgerOptions{NoSync: true, SyncInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 200 {
		if err := s.Put(ctx, record(model.KindLink, "id"+strconv.Itoa(i), time.Time{})); err != nil {
			t.Fatal(err)
		}
		if i%50 == 0 {
			time.Sleep(3 * time.Millisecond) // let a sync run between writes
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenBadger(ctx, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n, err := s.Count(ctx, model.KindLink, "sc"); err != nil || n != 200 {
		t.Fatalf("count after reopen: %d %v", n, err)
	}
}
