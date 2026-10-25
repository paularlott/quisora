package kvstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func TestCoverageCodecRoundTrip(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 6789, time.UTC)
	in := &store.Record{Kind: model.KindUser, ID: "u1", Version: store.Clock.Now(), Epoch: store.Clock.Now(), Created: store.Clock.Now(),
		Origin: "n", Scope: "o", Unique: []string{"a", "b"}, Data: []byte("data"), Expires: at,
		Fields: map[string]any{"s": "str", "b": true, "t": at, "i": 7, "i32": int32(8), "i64": int64(9), "u32": uint32(10), "u64": uint64(11), "nil": nil}}
	b, err := encodeRecord(in)
	if err != nil {
		t.Fatal(err)
	}
	st, err := decodeRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	out := st.rec
	if out.ID != in.ID || out.Kind != in.Kind || out.Version != in.Version || out.Epoch != in.Epoch || out.Created != in.Created ||
		out.Origin != "n" || out.Scope != "o" || string(out.Data) != "data" || !out.Expires.Equal(at) || len(out.Unique) != 2 {
		t.Fatalf("round trip: %+v", out)
	}
	want := map[string]any{"s": "str", "b": true, "t": at, "i": int64(7), "i32": int64(8), "i64": int64(9), "u32": int64(10), "u64": int64(11), "nil": nil}
	for k, w := range want {
		got, ok := out.Fields[k]
		if !ok {
			t.Errorf("field %s lost", k)
			continue
		}
		if tw, isT := w.(time.Time); isT {
			if gt, _ := got.(time.Time); !gt.Equal(tw) {
				t.Errorf("field %s: %v != %v", k, got, w)
			}
		} else if got != w {
			t.Errorf("field %s: %#v != %#v", k, got, w)
		}
	}
	if _, err := encodeRecord(&store.Record{Kind: model.KindUser, ID: "x", Fields: map[string]any{"bad": 1.5}}); err == nil || !strings.Contains(err.Error(), "unsupported field type") {
		t.Fatalf("float field: %v", err)
	}
	// A tombstone: no data, no expiry.
	b, _ = encodeRecord(&store.Record{Kind: model.KindUser, ID: "x", Version: 5, Deleted: true})
	if st, err := decodeRecord(b); err != nil || !st.rec.Deleted || !st.rec.Expires.IsZero() || st.rec.Fields != nil {
		t.Fatalf("tombstone: %+v %v", st, err)
	}
}

func TestCoverageDecodeCorrupt(t *testing.T) {
	if _, err := decodeRecord(nil); err == nil || !strings.Contains(err.Error(), "corrupt record") {
		t.Fatalf("empty: %v", err)
	}
	if _, err := decodeRecord([]byte{1, 2, 3}); err == nil {
		t.Fatal("short header")
	}
	b := append(make([]byte, seqHeader), []byte("\xc1\xc1\xc1not msgpack")...)
	if _, err := decodeRecord(b); err == nil || !strings.Contains(err.Error(), "decode record") {
		t.Fatalf("garbage body: %v", err)
	}
	// A header alone: an empty array body does not decode into the record.
	if _, err := decodeRecord(make([]byte, seqHeader)); err == nil {
		t.Fatal("headerless body decoded")
	}
}

// A record that no longer decodes (bit rot, a foreign writer) is an error to every reader, never a silent skip
// and never a panic.
func TestCoverageCorruptStoredRecord(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	good := covRecord(model.KindLink, "good", time.Time{}, "u-good")
	if err := s.Put(ctx, good); err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored bytes in place; the indexes still point at the record.
	err := s.eng.Update(ctx, func(tx txn) error {
		b, err := tx.Get(recKey(model.KindLink, "good"))
		if err != nil {
			return err
		}
		bad := append([]byte(nil), b[:seqHeader]...)
		tx.Set(recKey(model.KindLink, "good"), append(bad, 0xc1, 0xc1, 0xc1))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]func() error{
		"Get":      func() error { _, err := s.Get(ctx, model.KindLink, "good"); return err },
		"Lookup":   func() error { _, err := s.Lookup(ctx, model.KindLink, "good"); return err },
		"ByUnique": func() error { _, err := s.GetByUnique(ctx, model.KindLink, "u-good"); return err },
		"GetMany":  func() error { _, err := s.GetMany(ctx, model.KindLink, []string{"good"}); return err },
		"List":     func() error { _, err := s.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"}); return err },
		"Changes":  func() error { _, _, err := s.Changes(ctx, 0, 0); return err },
		"Put":      func() error { return s.Put(ctx, covRecord(model.KindLink, "good", time.Time{})) },
		"Repl": func() error {
			_, _, err := s.PutReplicated(ctx, covRecord(model.KindLink, "good", time.Time{}))
			return err
		},
		"ReplB": func() error {
			_, _, err := s.PutReplicatedBatch(ctx, []*store.Record{covRecord(model.KindLink, "good", time.Time{})})
			return err
		},
		"CAS": func() error { return s.CompareAndPut(ctx, covRecord(model.KindLink, "good", time.Time{}), 1) },
	}
	for name, f := range checks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked on a corrupt record: %v", name, r)
				}
			}()
			if err := f(); err == nil || errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s over a corrupt record: %v", name, err)
			}
		}()
	}
}

func TestCoverageCorruptTombstoneAndExpiryIndex(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Add(time.Hour)
	// An index entry that is not kind/id.
	for _, bucket := range []string{"tomb", "exp"} {
		s := covBadger(t, BadgerOptions{})
		err := s.eng.Update(ctx, func(tx txn) error { tx.SetAdd(bucket, "0000/notenough", 0); return nil })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Purge(ctx, now, now); err == nil || !strings.Contains(err.Error(), "corrupt "+bucket+" index entry") {
			t.Fatalf("%s: %v", bucket, err)
		}
	}
}

func TestCoverageCorruptFeedEntry(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	for _, m := range []string{"notanumber/link/x", "00000000000000000001"} {
		s := covBadger(t, BadgerOptions{})
		err := s.eng.Update(ctx, func(tx txn) error { tx.SetAdd(feedBkt, m, 0); return nil })
		if err != nil {
			t.Fatal(err)
		}
		if _, next, err := s.Changes(ctx, 0, 0); err == nil || !strings.Contains(err.Error(), "corrupt feed entry") || next != 0 {
			t.Fatalf("%q: next=%d %v", m, next, err)
		}
	}
	_ = s
}

func TestCoverageFeedEntryWithoutRecordIsSkipped(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	if err := s.Put(ctx, covRecord(model.KindLink, "a", time.Time{})); err != nil {
		t.Fatal(err)
	}
	err := s.eng.Update(ctx, func(tx txn) error { tx.SetAdd(feedBkt, seqMember(5, "link/ghost"), 0); return nil })
	if err != nil {
		t.Fatal(err)
	}
	ch, next, err := s.Changes(ctx, 0, 0)
	if err != nil || len(ch) != 1 || next != 5 {
		t.Fatalf("changes: %d next=%d %v", len(ch), next, err)
	}
}

func TestCoverageFormatChecks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenBadger(ctx, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, covRecord(model.KindLink, "a", time.Time{})); err != nil {
		t.Fatal(err)
	}
	// Data present but the format marker gone: an unmarked store is not trusted as a new one.
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
	// An empty store without a marker is new: marked and usable.
	dir3 := t.TempDir()
	s, _ = OpenBadger(ctx, dir3, BadgerOptions{})
	_ = s.eng.Update(ctx, func(tx txn) error { tx.Delete(metaFormat); return nil })
	s.Close()
	s, err = OpenBadger(ctx, dir3, BadgerOptions{})
	if err != nil {
		t.Fatalf("empty store without marker: %v", err)
	}
	if b, _ := s.eng.Get(ctx, metaFormat); string(b) == "" {
		t.Fatal("marker not written")
	}
	s.Close()
}

func TestCoverageLockMigration(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	other := func(exp time.Time) {
		t.Helper()
		err := s.eng.Update(ctx, func(tx txn) error {
			tx.Set(metaMigrate, []byte("someone "+itoa64(exp.UnixMilli())))
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

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestCoverageRewriteRecords(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
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
	_, feedBefore, _ := s.Changes(ctx, 0, 0)
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
	if _, feedAfter, _ := s.Changes(ctx, 0, 0); feedAfter != feedBefore {
		t.Fatalf("the feed moved: %d -> %d", feedBefore, feedAfter)
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

func TestCoverageHelpers(t *testing.T) {
	if got := appendOnce([]string{"a"}, "a"); len(got) != 1 {
		t.Fatal(got)
	}
	if got := appendOnce([]string{"a"}, "b"); len(got) != 2 {
		t.Fatal(got)
	}
	for in, want := range map[any]string{"x": "x", true: "true", false: "false", int64(-4): "-4", 12: "12"} {
		if got, ok := fieldKey(in); !ok || got != want {
			t.Errorf("fieldKey(%#v) = %q, %v", in, got, ok)
		}
	}
	for _, v := range []any{nil, 1.5, time.Now(), uint32(1), int32(1)} {
		if _, ok := fieldKey(v); ok {
			t.Errorf("fieldKey(%T) indexed", v)
		}
	}
	if seqOf(nil) != 0 || seqOf([]byte("42")) != 0 || seqOf([]byte{0, 0, 0, 0, 0, 0, 1, 0}) != 256 {
		t.Fatal("seqOf")
	}
	if !errors.Is(errReadOnly, errReadOnly) || currentFormat() < formatBase {
		t.Fatal("format constants")
	}
	_ = hlc.Timestamp(0)
}

// Replication applies in groups: a batch with the same record twice and with two claimants of one unique value
// resolves as if applied one by one, and an oversized batch is split.
func TestCoverageReplicatedBatch(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	if a, l, err := s.PutReplicatedBatch(ctx, nil); err != nil || len(a) != 0 || len(l) != 0 {
		t.Fatalf("empty batch: %v %v %v", a, l, err)
	}
	r1 := covRecord(model.KindLink, "a", time.Time{}, "dup")
	r1b := covRecord(model.KindLink, "a", time.Time{}, "dup") // newer version of the same record
	r2 := covRecord(model.KindLink, "b", time.Time{}, "dup")  // a second claimant, newer than r1
	older := *r1
	applied, losers, err := s.PutReplicatedBatch(ctx, []*store.Record{r1, r1b, &older, r2})
	if err != nil {
		t.Fatal(err)
	}
	if !applied[0] || !applied[1] || applied[2] {
		t.Fatalf("applied: %v", applied)
	}
	if len(losers[2]) != 0 {
		t.Fatalf("a stale record has no losers: %v", losers[2])
	}
	// One of the two claimants holds the unique value, whichever the rule picks, and exactly one record answers it.
	got, err := s.GetByUnique(ctx, model.KindLink, "dup")
	if err != nil || (got.ID != "a" && got.ID != "b") {
		t.Fatalf("holder: %v %v", got, err)
	}
	// Larger than one group.
	var many []*store.Record
	for i := range batchGroup + 5 {
		many = append(many, covRecord(model.KindLink, "m"+itoa64(int64(i)), time.Time{}))
	}
	applied, _, err = s.PutReplicatedBatch(ctx, many)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range applied {
		if !a {
			t.Fatalf("record %d not applied", i)
		}
	}
	if n, _ := s.Count(ctx, model.KindLink, "sc"); n < batchGroup+5 {
		t.Fatalf("count %d", n)
	}
}

func TestCoverageRemoveReleasesOnlyOwnUnique(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	if err := s.Put(ctx, covRecord(model.KindLink, "a", time.Time{}, "shared")); err != nil {
		t.Fatal(err)
	}
	// The unique key is re-pointed at another id (as after a replicated takeover): purging a must not free it.
	err := s.eng.Update(ctx, func(tx txn) error { tx.Set(uqKey(model.KindLink, "shared"), []byte("other")); return nil })
	if err != nil {
		t.Fatal(err)
	}
	tomb := &store.Record{Kind: model.KindLink, ID: "a", Version: store.Clock.Now(), Origin: "n", Deleted: true}
	if err := s.Put(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.eng.Get(ctx, uqKey(model.KindLink, "shared")); string(b) != "other" {
		t.Fatalf("tombstoning freed another record's unique value: %q", b)
	}
	// An expired record is removed by Purge together with its entries.
	exp := covRecord(model.KindLink, "e", time.Now().Add(-time.Minute), "ev")
	if err := s.Put(ctx, exp); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Purge(ctx, time.Time{}, time.Now()); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if b, _ := s.eng.Get(ctx, uqKey(model.KindLink, "ev")); b != nil {
		t.Fatal("unique entry of a purged record kept")
	}
}

func TestCoverageSnapshotCountSkipsExpired(t *testing.T) {
	ctx := context.Background()
	s := covBadger(t, BadgerOptions{})
	for i, exp := range []time.Time{time.Now().Add(time.Hour), time.Now().Add(-time.Hour), {}} {
		if err := s.Put(ctx, covRecord(model.KindLink, "r"+itoa64(int64(i)), exp)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if n, err := r.Count(ctx, model.KindLink, "sc"); err != nil || n != 2 {
		t.Fatalf("snapshot count: %d %v", n, err)
	}
	snap := r.(*Store).eng
	if n, err := snap.Count(ctx, listBucket(model.KindLink, "sc"), nowMs()); err != nil || n != 2 {
		t.Fatalf("engine count: %d %v", n, err)
	}
}
