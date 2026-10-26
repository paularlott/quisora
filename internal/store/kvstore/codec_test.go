package kvstore

import (
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A stored record keeps its generation (Epoch) and creation version (Created).
func TestRecordKeepsEpochAndCreated(t *testing.T) {
	b, err := encodeRecord(&store.Record{Kind: "group", ID: "g2", Version: 50, Epoch: 30, Created: 45, Data: []byte("y")}, pstamp{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRecord(b)
	if err != nil || got.rec.Epoch != 30 || got.rec.Created != 45 || got.rec.Version != 50 {
		t.Fatalf("decoded: %v %+v", err, got)
	}
}

// A stored record keeps its partition key and its partition stamp.
func TestRecordKeepsPartition(t *testing.T) {
	b, err := encodeRecord(&store.Record{Kind: "user", ID: "u", Version: 5, Partition: "org-7", Data: []byte("x")}, pstamp{num: 12, seq: 345})
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRecord(b)
	if err != nil || got.rec.Partition != "org-7" || got.ps != (pstamp{12, 345}) {
		t.Fatalf("decoded: %v %+v", err, got)
	}
	// a tombstone keeps both too
	b, _ = encodeRecord(&store.Record{Kind: "user", ID: "u", Version: 6, Deleted: true, Partition: "org-7"}, pstamp{12, 346})
	if got, err = decodeRecord(b); err != nil || got.rec.Partition != "org-7" || got.ps.seq != 346 {
		t.Fatalf("tombstone: %v %+v", err, got)
	}
	if _, _, _, err := psMember("garbage"); err == nil {
		t.Fatal("a corrupt partition index entry was accepted")
	}
	if _, err := decodeState([]byte{0xc1}); err == nil {
		t.Fatal("a corrupt partition state was accepted")
	}
}

// Every field type survives encoding (integers as int64), an unsupported one is refused, and a tombstone keeps no data or
// expiry.
func TestRecordRoundTripKeepsAllFieldTypes(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 6789, time.UTC)
	in := &store.Record{Kind: model.KindUser, ID: "u1", Version: store.Clock.Now(), Epoch: store.Clock.Now(), Created: store.Clock.Now(),
		Origin: "n", Scope: "o", Unique: []string{"a", "b"}, Data: []byte("data"), Expires: at,
		Fields: map[string]any{"s": "str", "b": true, "t": at, "i": 7, "i32": int32(8), "i64": int64(9), "u32": uint32(10), "u64": uint64(11), "nil": nil}}
	b, err := encodeRecord(in, pstamp{})
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
	if _, err := encodeRecord(&store.Record{Kind: model.KindUser, ID: "x", Fields: map[string]any{"bad": 1.5}}, pstamp{}); err == nil || !strings.Contains(err.Error(), "unsupported field type") {
		t.Fatalf("float field: %v", err)
	}
	// A tombstone: no data, no expiry.
	b, _ = encodeRecord(&store.Record{Kind: model.KindUser, ID: "x", Version: 5, Deleted: true}, pstamp{})
	if st, err := decodeRecord(b); err != nil || !st.rec.Deleted || !st.rec.Expires.IsZero() || st.rec.Fields != nil {
		t.Fatalf("tombstone: %+v %v", st, err)
	}
}

func TestDecodeRejectsCorruptBodies(t *testing.T) {
	if _, err := decodeRecord(nil); err == nil || !strings.Contains(err.Error(), "decode record") {
		t.Fatalf("empty: %v", err)
	}
	if _, err := decodeRecord([]byte{1, 2, 3}); err == nil {
		t.Fatal("a short body decoded")
	}
	if _, err := decodeRecord([]byte("\xc1\xc1\xc1not msgpack")); err == nil || !strings.Contains(err.Error(), "decode record") {
		t.Fatalf("garbage body: %v", err)
	}
}

// Only string, bool and int64 values (and int, as stored) are indexed by value.
func TestFieldKeyIndexesOnlyStringBoolInt64(t *testing.T) {
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
}
