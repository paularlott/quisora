package store_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Encode stamps the entity's metadata (a given id and creation time are kept, Updated and Version always move on) and
// fills the record; Decode restores the entity with the record's version; EncodeAsIs leaves the metadata alone.
func TestEncodeStampsMetaAndDecodeRestoresIt(t *testing.T) {
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

// IndexFields returns the record's indexed field values, decoding its data.
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
