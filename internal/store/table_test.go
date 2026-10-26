package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

var ctx = context.Background()

func groups() *store.Table[model.Group, *model.Group] {
	return store.NewTable[model.Group](memstore.New())
}

// Create, Get, GetByUnique, Update (optimistic), Put, DeleteIf and Delete through a Table.
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
	// A clash fails the write too: the entity keeps the version it was read at, so the caller can retry.
	other := &model.Group{OrgID: "o", DisplayName: "other"}
	if err := tb.Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	ov := other.Version
	other.DisplayName = "ENG2"
	if err := tb.Update(ctx, other); !errors.Is(err, store.ErrConflict) || other.Version != ov {
		t.Errorf("conflict update: %v version %d (want %d)", err, other.Version, ov)
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

// Count, All, List and IDs through a Table: scope, order, paging, total, and a bad sort refused.
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

// GetMany uses a backend's batch reader (MultiGetter) once, or one Get per id without one, and passes its error on.
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
	m := store.NewTable[model.Group](&multi{Store: s})
	if _, err := m.GetMany(ctx, []string{"bad"}); err == nil {
		t.Error("GetMany via MultiGetter decoded garbage")
	}
	if _, err := tb.Get(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Error(err)
	}
}
