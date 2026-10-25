package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

var ctx = context.Background()

func groups() *store.Table[model.Group, *model.Group] {
	return store.NewTable[model.Group](memstore.New())
}

func TestDurableContext(t *testing.T) {
	if store.IsDurable(ctx) {
		t.Error("plain context is durable")
	}
	d := store.WithDurable(ctx)
	if !store.IsDurable(d) {
		t.Error("WithDurable")
	}
	if store.IsDurable(store.WithoutDurable(d)) {
		t.Error("WithoutDurable")
	}
}

func TestApplied(t *testing.T) {
	for _, c := range []struct {
		err error
		ok  bool
	}{{nil, true}, {store.ErrNotReplicated, true}, {errors.Join(store.ErrNotReplicated, errors.New("x")), true},
		{store.ErrUnconfirmed, false}, {store.ErrConflict, false}} {
		if store.Applied(c.err) != c.ok {
			t.Errorf("Applied(%v) = %v", c.err, !c.ok)
		}
	}
	if !errors.Is(store.ErrDeleted, store.ErrNotFound) {
		t.Error("ErrDeleted must match ErrNotFound")
	}
}

func TestRecordLiveAndHead(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		r    store.Record
		ok   bool
	}{
		{"plain", store.Record{}, true},
		{"deleted", store.Record{Deleted: true}, false},
		{"expired", store.Record{Expires: now}, false},
		{"future", store.Record{Expires: now.Add(time.Second)}, true},
	} {
		if c.r.Live(now) != c.ok {
			t.Errorf("%s: Live = %v", c.name, !c.ok)
		}
	}
	r := store.Record{Kind: model.KindSession, Version: 5, Epoch: 3, Created: 2, Origin: "n", Deleted: true}
	h := r.Head()
	if *h != (store.Head{Kind: model.KindSession, Version: 5, Epoch: 3, Created: 2, Origin: "n", Deleted: true}) {
		t.Errorf("Head %+v", h)
	}
}

func TestRankOrdering(t *testing.T) {
	a, b := store.Rank{Epoch: 1, Version: 9}, store.Rank{Epoch: 2, Version: 1}
	if !a.Less(b) || b.Less(a) || a.Less(a) {
		t.Error("epoch dominates")
	}
	if !(store.Rank{Epoch: 1, Version: 1}).Less(store.Rank{Epoch: 1, Version: 2}) {
		t.Error("version breaks epoch ties")
	}
	// A live record's rank is (epoch, version); a tombstone's epoch is its own version; a quorum kind ranks by version.
	live := &store.Record{Kind: model.KindSession, Version: 7, Epoch: 4}
	if live.Rank() != (store.Rank{Epoch: 4, Version: 7}) {
		t.Errorf("live rank %+v", live.Rank())
	}
	tomb := &store.Record{Kind: model.KindSession, Version: 9, Deleted: true}
	if tomb.Rank() != (store.Rank{Epoch: 9, Version: 9}) {
		t.Errorf("tombstone rank %+v", tomb.Rank())
	}
	q := &store.Record{Kind: model.KindUser, Version: 7, Epoch: 4, Deleted: true}
	if q.Rank() != (store.Rank{Version: 7}) {
		t.Errorf("quorum rank %+v", q.Rank())
	}
}

func TestNewerTieBreaks(t *testing.T) {
	k := model.KindSession
	a := &store.Record{Kind: k, Version: 5, Origin: "a"}
	b := &store.Record{Kind: k, Version: 5, Origin: "b"}
	if store.Newer(a, b) || !store.Newer(b, a) {
		t.Error("equal versions: the higher origin wins")
	}
	if store.Newer(a, a) {
		t.Error("a record is not newer than itself")
	}
	// A tombstone and a live record of one version have equal rank only when the live epoch is that version.
	tomb := &store.Record{Kind: k, Version: 5, Deleted: true, Origin: "a"}
	live := &store.Record{Kind: k, Version: 5, Epoch: 5, Origin: "z"}
	if !store.Newer(tomb, live) || store.Newer(live, tomb) {
		t.Error("at equal rank the tombstone wins, whatever the origin")
	}
	if !store.Newer(&store.Record{Kind: k, Version: 6}, &store.Record{Kind: k, Version: 5, Origin: "z"}) {
		t.Error("a higher version beats a higher origin")
	}
	if !store.Newer(&store.Record{Kind: k, Version: 1, Epoch: 2}, &store.Record{Kind: k, Version: 9, Epoch: 1}) {
		t.Error("a later generation beats a later version")
	}
}

func TestStampLocal(t *testing.T) {
	tomb := &store.Head{Kind: model.KindSession, Version: 50, Deleted: true}
	live := &store.Head{Kind: model.KindSession, Version: 60, Epoch: 11, Created: 22}
	for _, c := range []struct {
		name           string
		rec            store.Record
		old            *store.Head
		create         bool
		err            error
		epoch, created hlc.Timestamp
	}{
		{"delete clears", store.Record{Kind: model.KindSession, Version: 70, Deleted: true, Epoch: 1, Created: 2}, live, false, nil, 0, 0},
		{"create over nothing", store.Record{Kind: model.KindSession, Version: 70}, nil, true, nil, 0, 70},
		{"write over nothing", store.Record{Kind: model.KindSession, Version: 70}, nil, false, nil, 0, 70},
		{"live over tombstone refused", store.Record{Kind: model.KindSession, Version: 70}, tomb, false, store.ErrDeleted, 0, 0},
		{"create over tombstone", store.Record{Kind: model.KindSession, Version: 70}, tomb, true, nil, 50, 70},
		{"ephemeral over tombstone", store.Record{Kind: model.KindEphemeral, Version: 70}, &store.Head{Kind: model.KindEphemeral, Version: 50, Deleted: true}, false, nil, 50, 70},
		{"create over expired", store.Record{Kind: model.KindSession, Version: 70}, live, true, nil, 11, 70},
		{"update continues", store.Record{Kind: model.KindSession, Version: 70}, live, false, nil, 11, 22},
	} {
		rec := c.rec
		err := store.StampLocal(&rec, c.old, c.create)
		if !errors.Is(err, c.err) || (c.err == nil && err != nil) {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		if err == nil && (rec.Epoch != c.epoch || rec.Created != c.created) {
			t.Errorf("%s: epoch %d created %d, want %d %d", c.name, rec.Epoch, rec.Created, c.epoch, c.created)
		}
	}
}

func TestKeepsUnique(t *testing.T) {
	old, young := &store.Head{Created: 10}, &store.Head{Created: 20}
	if !store.KeepsUnique(old, young, "z", "a") || store.KeepsUnique(young, old, "a", "z") {
		t.Error("the record created first keeps the value, whatever the ids")
	}
	same := &store.Head{Created: 10}
	if !store.KeepsUnique(old, same, "a", "b") || store.KeepsUnique(old, same, "b", "a") {
		t.Error("ties break by id")
	}
}

func TestWitnessAndOrigin(t *testing.T) {
	before := store.SkewRefused()
	next := store.Clock.Now()
	store.Witness(next) // a version the clock itself minted is never refused
	if store.SkewRefused() != before {
		t.Error("a local version was refused")
	}
	if store.Ahead(next) > store.MaxSkew {
		t.Errorf("a fresh version is %v ahead", store.Ahead(next))
	}
	// A version minutes ahead of this machine is refused and counted, and the clock does not follow it.
	ahead := hlc.Timestamp(uint64(next) + uint64(10*time.Minute/time.Microsecond)<<hlc.CounterBits)
	if store.Ahead(ahead) < 5*time.Minute {
		t.Skipf("timestamp layout differs: only %v ahead", store.Ahead(ahead))
	}
	store.Witness(ahead)
	if store.SkewRefused() != before+1 {
		t.Error("a version far ahead was not counted")
	}
	if store.Clock.Now() >= ahead {
		t.Error("the clock followed a version far ahead")
	}

	prev := store.Origin()
	t.Cleanup(func() { store.SetOrigin(prev) })
	store.SetOrigin("node-7")
	if store.Origin() != "node-7" {
		t.Error("SetOrigin")
	}
	rec := store.Tombstone(model.KindGroup, "g")
	if rec.Origin != "node-7" || !rec.Deleted || rec.ID != "g" || rec.Version == 0 {
		t.Errorf("tombstone %+v", rec)
	}
}

func TestEncodeDecode(t *testing.T) {
	g := &model.Group{OrgID: "o", DisplayName: "Eng", Tags: []string{"a"}}
	rec, err := store.Encode(g)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID == "" || g.Created.IsZero() || g.Updated.IsZero() || g.Version == 0 || rec.Version != g.Version {
		t.Errorf("Encode did not stamp meta: %+v", g.Meta)
	}
	if rec.Kind != model.KindGroup || rec.ID != g.ID || rec.Scope != "o" || rec.Origin != store.Origin() ||
		rec.Fields["display_name"] != "Eng" || !slices.Equal(rec.Unique, []string{"o/n/eng"}) || len(rec.Data) == 0 {
		t.Errorf("record %+v", rec)
	}
	var out model.Group
	rec.Version = 12345
	if err := store.Decode(rec, &out); err != nil {
		t.Fatal(err)
	}
	if out.DisplayName != "Eng" || out.ID != g.ID || out.Version != 12345 || !slices.Equal(out.Tags, []string{"a"}) {
		t.Errorf("decoded %+v", out)
	}
	if err := store.Decode(&store.Record{Data: []byte{0xc1}}, &out); err == nil {
		t.Error("garbage decoded")
	}

	// Encode keeps a given id and creation time but always moves Updated and Version on.
	created := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	g2 := &model.Group{Meta: model.Meta{ID: "fixed", Created: created, Version: 1}, OrgID: "o", DisplayName: "x"}
	if _, err := store.Encode(g2); err != nil || g2.ID != "fixed" || !g2.Created.Equal(created) || g2.Version <= 1 || !g2.Updated.After(created) {
		t.Errorf("g2 %+v %v", g2.Meta, err)
	}
	// EncodeAsIs leaves the metadata alone.
	g3 := &model.Group{Meta: model.Meta{ID: "as-is", Version: 77}, OrgID: "o", DisplayName: "y"}
	r3, err := store.EncodeAsIs(g3)
	if err != nil || r3.Version != 77 || r3.ID != "as-is" || !g3.Updated.IsZero() {
		t.Errorf("EncodeAsIs %+v %v", r3, err)
	}
}

func TestIndexFields(t *testing.T) {
	g := &model.Group{OrgID: "o", DisplayName: "Eng", Tags: []string{"a", "b"}}
	rec, err := store.Encode(g)
	if err != nil {
		t.Fatal(err)
	}
	f, err := store.IndexFields(rec)
	if err != nil || f["display_name"] != "Eng" || f["tags"] != "a b" || f["pending"] != false {
		t.Errorf("IndexFields = %v %v", f, err)
	}
	if _, err := store.IndexFields(&store.Record{Kind: "nope"}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("unknown kind: %v", err)
	}
	if _, err := store.IndexFields(&store.Record{Kind: model.KindGroup, Data: []byte{0xc1}}); err == nil {
		t.Error("undecodable data accepted")
	}
}

func TestTableCRUD(t *testing.T) {
	tb := groups()
	g := &model.Group{OrgID: "o", DisplayName: "Eng"}
	if err := tb.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	if g.ID == "" || g.Version == 0 {
		t.Fatalf("create did not stamp %+v", g.Meta)
	}
	if err := tb.Create(ctx, &model.Group{Meta: model.Meta{ID: g.ID}, OrgID: "o", DisplayName: "Other"}); !errors.Is(err, store.ErrStale) {
		t.Errorf("duplicate id: %v", err)
	}
	if err := tb.Create(ctx, &model.Group{OrgID: "o", DisplayName: "ENG"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("unique clash: %v", err)
	}

	got, err := tb.Get(ctx, g.ID)
	if err != nil || got.DisplayName != "Eng" || got.Version != g.Version {
		t.Fatalf("Get %+v %v", got, err)
	}
	byName, err := tb.GetByUnique(ctx, model.GroupNameKey("o", "eng"))
	if err != nil || byName.ID != g.ID {
		t.Errorf("GetByUnique %v", err)
	}
	if _, err := tb.GetByUnique(ctx, "o/n/none"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByUnique missing: %v", err)
	}
	if _, err := tb.Get(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get missing: %v", err)
	}

	// Update is optimistic: a stale copy is refused and keeps its own version.
	stale := *got
	got.DisplayName = "Eng2"
	old := got.Version
	if err := tb.Update(ctx, got); err != nil || got.Version <= old {
		t.Fatalf("Update %v (version %d -> %d)", err, old, got.Version)
	}
	stale.DisplayName = "Eng3"
	sv := stale.Version
	if err := tb.Update(ctx, &stale); !errors.Is(err, store.ErrStale) || stale.Version != sv {
		t.Errorf("stale update: %v version %d (want %d)", err, stale.Version, sv)
	}
	if err := tb.Update(ctx, &model.Group{Meta: model.Meta{ID: "nope", Version: 5}, OrgID: "o", DisplayName: "z"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("update of missing: %v", err)
	}

	// Put replaces unconditionally, and stamps the version it wrote.
	got.DisplayName = "Eng4"
	if err := tb.Put(ctx, got); err != nil {
		t.Fatal(err)
	}
	if r, _ := tb.Get(ctx, g.ID); r.DisplayName != "Eng4" || r.Version != got.Version {
		t.Errorf("Put not stored: %+v", r)
	}
	if err := tb.Put(ctx, &model.Group{OrgID: "o", DisplayName: "eng4"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("Put clash: %v", err)
	}

	// DeleteIf refuses a stale expectation, then Delete tombstones; a later Put of an old copy cannot revive it.
	if err := tb.DeleteIf(ctx, g.ID, 1); !errors.Is(err, store.ErrStale) {
		t.Errorf("DeleteIf stale: %v", err)
	}
	if err := tb.DeleteIf(ctx, g.ID, got.Version); err != nil {
		t.Fatalf("DeleteIf: %v", err)
	}
	if _, err := tb.Get(ctx, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after DeleteIf: %v", err)
	}
	if err := tb.Put(ctx, got); !errors.Is(err, store.ErrDeleted) {
		t.Errorf("revive by Put: %v", err)
	}
	if err := tb.Delete(ctx, "never-existed"); err != nil {
		t.Errorf("Delete of absent: %v", err)
	}
}

func TestTableUpdateRestoresVersionOnFailure(t *testing.T) {
	tb := groups()
	g := &model.Group{OrgID: "o", DisplayName: "a"}
	if err := tb.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	// A clash fails the write: the entity keeps the version it was read at, so the caller can retry.
	other := &model.Group{OrgID: "o", DisplayName: "b"}
	if err := tb.Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	v := other.Version
	other.DisplayName = "A"
	if err := tb.Update(ctx, other); !errors.Is(err, store.ErrConflict) || other.Version != v {
		t.Errorf("conflict update: %v version %d want %d", err, other.Version, v)
	}
}

func TestTableListing(t *testing.T) {
	tb := groups()
	var ids []string
	for _, n := range []string{"delta", "Alpha", "charlie", "bravo"} {
		g := &model.Group{OrgID: "o", DisplayName: n}
		if err := tb.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, g.ID)
	}
	if err := tb.Create(ctx, &model.Group{OrgID: "p", DisplayName: "elsewhere"}); err != nil {
		t.Fatal(err)
	}
	if n, err := tb.Count(ctx, "o"); err != nil || n != 4 {
		t.Errorf("Count = %d %v", n, err)
	}
	if n, _ := tb.Count(ctx, ""); n != 5 {
		t.Errorf("Count all = %d", n)
	}
	all, err := tb.All(ctx, "o")
	if err != nil || len(all) != 4 {
		t.Fatalf("All = %d %v", len(all), err)
	}
	names := func(gs []*model.Group) []string {
		var out []string
		for _, g := range gs {
			out = append(out, g.DisplayName)
		}
		return out
	}
	page, total, err := tb.List(ctx, store.ListQuery{Scope: "o", Sort: "display_name", Limit: 2, Offset: 1})
	if err != nil || total != 4 || !slices.Equal(names(page), []string{"bravo", "charlie"}) {
		t.Errorf("List = %v total %d %v", names(page), total, err)
	}
	if _, _, err := tb.List(ctx, store.ListQuery{Sort: "nope"}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("bad sort: %v", err)
	}
	gotIDs, total, err := tb.IDs(ctx, store.ListQuery{Scope: "o"})
	if err != nil || total != 4 || !slices.Equal(gotIDs, ids) {
		t.Errorf("IDs = %v total %d %v (want %v)", gotIDs, total, err, ids)
	}
	if _, _, err := tb.IDs(ctx, store.ListQuery{Sort: "nope"}); !errors.Is(err, store.ErrBadQuery) {
		t.Errorf("IDs bad sort: %v", err)
	}
}

// multi wraps a store with a batch reader, as the key-value backends have.
type multi struct {
	store.Store
	calls int
	err   error
}

func (m *multi) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	var out []*store.Record
	for _, id := range ids {
		if r, err := m.Get(ctx, kind, id); err == nil {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestTableGetMany(t *testing.T) {
	for _, batch := range []bool{false, true} {
		var s store.Store = memstore.New()
		m := &multi{Store: s}
		if batch {
			s = m
		}
		tb := store.NewTable[model.Group](s)
		var ids []string
		for _, n := range []string{"a", "b", "c"} {
			g := &model.Group{OrgID: "o", DisplayName: n}
			if err := tb.Create(ctx, g); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, g.ID)
		}
		got, err := tb.GetMany(ctx, []string{ids[2], "missing", ids[0]})
		if err != nil || len(got) != 2 || got[0].DisplayName != "c" || got[1].DisplayName != "a" {
			t.Errorf("batch=%v GetMany = %v %v", batch, got, err)
		}
		if (m.calls == 1) != batch {
			t.Errorf("batch=%v: MultiGetter used %d times", batch, m.calls)
		}
		if got, err := tb.GetMany(ctx, nil); err != nil || len(got) != 0 {
			t.Errorf("empty GetMany = %v %v", got, err)
		}
	}
	boom := errors.New("boom")
	tb := store.NewTable[model.Group](&multi{Store: memstore.New(), err: boom})
	if _, err := tb.GetMany(ctx, []string{"x"}); !errors.Is(err, boom) {
		t.Errorf("batch error: %v", err)
	}
}

// A record whose stored data cannot be decoded surfaces the decode error on every read path.
func TestTableDecodeErrors(t *testing.T) {
	s := memstore.New()
	bad := &store.Record{Kind: model.KindGroup, ID: "bad", Version: store.Clock.Now(), Origin: "x", Scope: "o",
		Unique: []string{"o/n/bad"}, Data: []byte{0xc1}}
	if err := s.Put(ctx, bad); err != nil {
		t.Fatal(err)
	}
	tb := store.NewTable[model.Group](s)
	if _, err := tb.Get(ctx, "bad"); err == nil {
		t.Error("Get decoded garbage")
	}
	if _, err := tb.GetByUnique(ctx, "o/n/bad"); err == nil {
		t.Error("GetByUnique decoded garbage")
	}
	if _, _, err := tb.List(ctx, store.ListQuery{Scope: "o"}); err == nil {
		t.Error("List decoded garbage")
	}
	if _, err := tb.GetMany(ctx, []string{"bad"}); err == nil {
		t.Error("GetMany decoded garbage")
	}
	if _, err := tb.GetMany(ctx, []string{"bad"}); err == nil {
		t.Error("GetMany (batch) decoded garbage")
	}
	m := store.NewTable[model.Group](&multi{Store: s})
	if _, err := m.GetMany(ctx, []string{"bad"}); err == nil {
		t.Error("GetMany via MultiGetter decoded garbage")
	}
	if _, err := tb.Get(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Error(err)
	}
}
