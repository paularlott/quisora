package kvstore

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A store at an older format is migrated at open, once, step by step; one from a newer build, or from before
// formatBase, is refused. (This test adds two migrations after the real ones.)
func TestFormatMigrations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	open := func() (*Store, error) { return OpenBadger(ctx, dir, BadgerOptions{}) }
	s, err := open()
	if err != nil {
		t.Fatal(err)
	}
	set := func(v string) {
		t.Helper()
		if err := s.eng.Update(ctx, func(tx txn) error { tx.Set(metaFormat, []byte(v)); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	set("0") // a pre-release format older than formatBase
	s.Close()
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "pre-release") {
		t.Fatalf("an old pre-release store: %v", err)
	}
	s, _ = OpenBadger(ctx, t.TempDir(), BadgerOptions{}) // (the refused one stays refused; carry on with a new one)
	dir = s.eng.(*badgerEngine).db.Opts().Dir

	saved := formatMigrations
	t.Cleanup(func() { formatMigrations = saved })
	var ran []string
	failOnce := true
	formatMigrations = append(slices.Clone(saved), []formatMigration{
		{"first", func(ctx context.Context, s *Store) error { ran = append(ran, "first"); return nil }},
		{"second", func(ctx context.Context, s *Store) error {
			if failOnce {
				failOnce = false
				return errors.New("interrupted")
			}
			ran = append(ran, "second")
			return nil
		}},
	}...)
	s.Close()
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("an interrupted migration: %v", err)
	}
	s, err = open() // resumes at the second migration
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ran, ",") != "first,second" {
		t.Fatalf("migrations run: %v", ran)
	}
	if b, _ := s.eng.Get(ctx, metaFormat); string(b) != strconv.Itoa(formatBase+len(saved)+2) {
		t.Fatalf("format after migrating: %s", b)
	}
	s.Close()
	if s, err = open(); err != nil || len(ran) != 2 {
		t.Fatalf("reopened: %v (%v)", err, ran)
	}
	s.Close()

	formatMigrations = saved // a build that knows fewer formats: the store is newer than it
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "newer build") {
		t.Fatalf("a store from a newer build: %v", err)
	}
}

// A store is marked with its format when it is made; one without a marker (empty or not) or with a garbled one was made by
// an earlier pre-release build and is refused.
func TestFormatMarkerChecks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenBadger(ctx, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, record(model.KindLink, "a", time.Time{})); err != nil {
		t.Fatal(err)
	}
	// Data present but the format marker gone: an unmarked store is not trusted.
	if err := s.eng.Update(ctx, func(tx txn) error { tx.Delete(metaFormat); return nil }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := OpenBadger(ctx, dir, BadgerOptions{}); err == nil || !strings.Contains(err.Error(), "pre-release") {
		t.Fatalf("unmarked store with data: %v", err)
	}
	// A marker that is not a number.
	dir2 := t.TempDir()
	s, _ = OpenBadger(ctx, dir2, BadgerOptions{})
	_ = s.eng.Update(ctx, func(tx txn) error { tx.Set(metaFormat, []byte("abc")); return nil })
	s.Close()
	if _, err := OpenBadger(ctx, dir2, BadgerOptions{}); err == nil || !strings.Contains(err.Error(), "pre-release") {
		t.Fatalf("garbled marker: %v", err)
	}
	// A store is marked when it is made, and a store without a marker, empty or not, was made by an earlier build.
	dir3 := t.TempDir()
	s, _ = OpenBadger(ctx, dir3, BadgerOptions{})
	if b, _ := s.eng.Get(ctx, metaFormat); string(b) != strconv.Itoa(currentFormat()) {
		t.Fatalf("a new store is marked with the current format: %q", b)
	}
	_ = s.eng.Update(ctx, func(tx txn) error { tx.Delete(metaFormat); return nil })
	s.Close()
	if _, err = OpenBadger(ctx, dir3, BadgerOptions{}); err == nil || !strings.Contains(err.Error(), "pre-release") {
		t.Fatalf("empty store without marker: %v", err)
	}
}

// The migration lock: a lock another process holds blocks, an expired or unreadable one is taken over, and releasing
// leaves another holder's lock alone.
func TestMigrationLock(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{})
	other := func(exp time.Time) {
		t.Helper()
		err := s.eng.Update(ctx, func(tx txn) error {
			tx.Set(metaMigrate, []byte("someone "+strconv.FormatInt(exp.UnixMilli(), 10)))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A lock another process holds blocks until the caller gives up.
	other(time.Now().Add(time.Hour))
	cctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err := s.lockMigration(cctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held lock: %v", err)
	}
	// A lock whose holder died (expired) is taken over.
	other(time.Now().Add(-time.Minute))
	release, err := s.lockMigration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := s.eng.Get(ctx, metaMigrate); len(b) == 0 || strings.HasPrefix(string(b), "someone") {
		t.Fatalf("lock not taken: %q", b)
	}
	release()
	if b, _ := s.eng.Get(ctx, metaMigrate); b != nil {
		t.Fatalf("lock not released: %q", b)
	}
	// A lock with an unparsable expiry counts as free.
	_ = s.eng.Update(ctx, func(tx txn) error { tx.Set(metaMigrate, []byte("x notanumber")); return nil })
	release, err = s.lockMigration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Releasing must not delete a lock another holder has taken meanwhile.
	other(time.Now().Add(time.Hour))
	release()
	if b, _ := s.eng.Get(ctx, metaMigrate); !strings.HasPrefix(string(b), "someone") {
		t.Fatalf("release removed another holder's lock: %q", b)
	}
}

// rewriteRecords rewrites the records fn changes, keeping their versions and leaving tombstones alone; fn's error and a
// canceled context stop it.
func TestRewriteRecordsKeepsVersionAndSkipsTombstones(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{})
	put := func(id, purpose string) {
		t.Helper()
		rec, err := store.Encode(&model.LinkToken{Meta: model.Meta{ID: id}, UserID: "sc", Purpose: purpose, TokenHash: "h-" + id})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	put("a", "old")
	put("b", "old")
	put("c", "keep")
	// A tombstone is left alone.
	put("d", "old")
	tomb := &store.Record{Kind: model.KindLink, ID: "d", Version: store.Clock.Now(), Origin: "n", Deleted: true}
	if err := s.Put(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Get(ctx, model.KindLink, "a")

	n, err := s.rewriteRecords(ctx, model.KindLink, func(r *store.Record) (bool, error) {
		var l model.LinkToken
		if err := store.Decode(r, &l); err != nil {
			return false, err
		}
		if l.Purpose != "old" {
			return false, nil
		}
		l.Purpose = "new"
		enc, err := store.Encode(&l)
		if err != nil {
			return false, err
		}
		r.Data = enc.Data
		return true, nil
	})
	if err != nil || n != 2 {
		t.Fatalf("rewrite: %d %v", n, err)
	}
	after, err := s.Get(ctx, model.KindLink, "a")
	if err != nil || after.Version != before.Version || after.Fields["purpose"] != "new" {
		t.Fatalf("after: %+v %v", after, err)
	}
	res, err := s.List(ctx, model.KindLink, store.ListQuery{Scope: "sc", Filters: []store.Filter{{Field: "purpose", Value: "new"}}})
	if err != nil || len(res.Records) != 2 {
		t.Fatalf("filter on rewritten field: %d %v", len(res.Records), err)
	}
	// The error of fn aborts and is returned.
	boom := errors.New("boom")
	if _, err := s.rewriteRecords(ctx, model.KindLink, func(*store.Record) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Fatalf("fn error: %v", err)
	}
	// Nothing to rewrite in another kind.
	if n, err := s.rewriteRecords(ctx, model.KindUser, func(*store.Record) (bool, error) { return true, nil }); err != nil || n != 0 {
		t.Fatalf("empty kind: %d %v", n, err)
	}
	// A canceled context stops it.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.rewriteRecords(cctx, model.KindLink, func(*store.Record) (bool, error) { return false, nil }); err == nil {
		t.Fatal("canceled context")
	}
}
