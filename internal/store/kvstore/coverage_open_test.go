package kvstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func covRecord(kind model.Kind, id string, expires time.Time, uniq ...string) *store.Record {
	return &store.Record{Kind: kind, ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "sc", Unique: uniq,
		Data: []byte("d"), Expires: expires}
}

func covBadger(t *testing.T, o BadgerOptions) *Store {
	t.Helper()
	s, err := OpenBadger(context.Background(), t.TempDir(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCoverageOpenOptions(t *testing.T) {
	ctx := context.Background()
	for _, o := range []BadgerOptions{
		{Compression: "snappy"},
		{Compression: "zstd"},
		{Compression: "none"},
		{InMemory: true},
		{NoSync: true, Group: GroupOptions{Disabled: true}, GCInterval: time.Hour},
		{BlockCacheMB: 8, IndexCacheMB: 8, ValueLogFileSizeMB: 16},
		{Logger: quietLogger{}},
	} {
		s := covBadger(t, o)
		if err := s.Put(ctx, covRecord(model.KindLink, "a", time.Time{}, "u")); err != nil {
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

func TestCoverageQuietLogger(t *testing.T) {
	var l quietLogger
	l.Errorf("e %d", 1)
	l.Warningf("w %d", 1)
	l.Infof("i %d", 1)
	l.Debugf("d %d", 1)
}

func TestCoverageOpenBadDirectory(t *testing.T) {
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

func TestCoverageEncryptedWrongKeyMessage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{1}, 32)
	s, err := OpenBadger(ctx, dir, BadgerOptions{EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = OpenBadger(ctx, dir, BadgerOptions{})
	if err == nil || !strings.Contains(err.Error(), "encryption_key") {
		t.Fatalf("the error should name the setting: %v", err)
	}
}

func TestCoverageDflt(t *testing.T) {
	if dflt(0, 5) != 5 || dflt(-1, 5) != 5 || dflt(3, 5) != 3 {
		t.Fatal("dflt")
	}
}

func TestCoverageClosedBadger(t *testing.T) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, covRecord(model.KindLink, "a", time.Time{}, "u")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rec := covRecord(model.KindLink, "b", time.Time{}, "u2")
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
		"Repl":     func() error { _, _, err := s.PutReplicated(ctx, rec); return err },
		"ReplB":    func() error { _, _, err := s.PutReplicatedBatch(ctx, []*store.Record{rec}); return err },
		"Changes":  func() error { _, _, err := s.Changes(ctx, 0, 0); return err },
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

func TestCoverageSnapshotReadOnly(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	if err := s.Put(ctx, covRecord(model.KindLink, "a", time.Time{}, "u")); err != nil {
		t.Fatal(err)
	}
	r, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, covRecord(model.KindLink, "b", time.Time{})); err != nil {
		t.Fatal(err)
	}
	if n, err := r.Count(ctx, model.KindLink, "sc"); err != nil || n != 1 {
		t.Fatalf("snapshot count %d %v", n, err)
	}
	res, err := r.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"})
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("snapshot list %+v %v", res, err)
	}
	// The view is read-only all the way down.
	snap := r.(*Store)
	if err := snap.Wipe(ctx); !errors.Is(err, errReadOnly) {
		t.Fatalf("Wipe on a snapshot: %v", err)
	}
	if err := snap.Put(ctx, covRecord(model.KindLink, "c", time.Time{})); !errors.Is(err, errReadOnly) {
		t.Fatalf("Put on a snapshot: %v", err)
	}
	if got, err := snap.Get(ctx, model.KindLink, "a"); err != nil || got.ID != "a" {
		t.Fatalf("snapshot get: %v", err)
	}
	if _, err := snap.Get(ctx, model.KindLink, "b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a later write is visible in the snapshot: %v", err)
	}
	if got, err := snap.eng.Range(ctx, allBucket(model.KindLink), "", "", 0); err != nil || len(got) != 1 {
		t.Fatalf("snapshot range: %v %v", got, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageWipe(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	if err := s.Put(ctx, covRecord(model.KindLink, "a", time.Time{}, "u")); err != nil {
		t.Fatal(err)
	}
	old := s.FeedID()
	if err := s.Wipe(ctx); err != nil {
		t.Fatal(err)
	}
	if s.FeedID() == old {
		t.Fatal("feed id kept")
	}
	if _, err := s.GetByUnique(ctx, model.KindLink, "u"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unique survived: %v", err)
	}
	if ch, next, err := s.Changes(ctx, 0, 0); err != nil || len(ch) != 0 || next != 0 {
		t.Fatalf("feed after wipe: %v %d %v", ch, next, err)
	}
	// The format marker is back: the wiped store reopens.
	if b, err := s.eng.Get(ctx, metaFormat); err != nil || string(b) == "" {
		t.Fatalf("format marker: %q %v", b, err)
	}
	if err := s.Put(ctx, covRecord(model.KindLink, "b", time.Time{}, "u")); err != nil {
		t.Fatal(err)
	}
	if ch, _, _ := s.Changes(ctx, 0, 0); len(ch) != 1 || ch[0].Seq != 1 {
		t.Fatalf("seq restarts: %+v", ch)
	}
}

func TestCoverageUpdateConflictRetry(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{Group: GroupOptions{Disabled: true}})
	// An error from the transaction body is returned unchanged and nothing is written.
	boom := errors.New("boom")
	err := s.eng.Update(ctx, func(tx txn) error { tx.Set("k", []byte("v")); return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("Update: %v", err)
	}
	if b, _ := s.eng.Get(ctx, "k"); b != nil {
		t.Fatal("an aborted transaction wrote")
	}
	// retry gives up after maxRetries conflicts, reports a canceled context, and passes other errors through.
	calls := 0
	err = retry(ctx, func() error { calls++; return errConflict })
	if !errors.Is(err, store.ErrStale) || calls != maxRetries {
		t.Fatalf("retry exhaustion: %v after %d calls", err, calls)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	calls = 0
	if err := retry(cctx, func() error { calls++; return errConflict }); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("retry canceled: %v after %d calls", err, calls)
	}
	if err := retry(ctx, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatal("retry swallowed an error")
	}
	n := 0
	if err := retry(ctx, func() error {
		if n++; n < 3 {
			return errConflict
		}
		return nil
	}); err != nil || n != 3 {
		t.Fatalf("retry success: %v %d", err, n)
	}
}

func TestCoverageGroupFalls(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{Group: GroupOptions{Disabled: true}})
	e := s.eng.(*badgerEngine)
	boom := errors.New("boom")
	if err := e.Group(ctx, "k", "i", func(tx txn) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("ungrouped Group: %v", err)
	}
	if err := e.Group(ctx, "k", "i", func(tx txn) error { tx.Set("x", []byte("1")); return nil }); err != nil {
		t.Fatal(err)
	}
	if b, _ := e.Get(ctx, "x"); string(b) != "1" {
		t.Fatal("write lost")
	}
}
