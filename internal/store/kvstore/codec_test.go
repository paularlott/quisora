package kvstore

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/shamaton/msgpack/v3"
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

// A stored record keeps its request id; one stored before the field existed (an array one element short) still
// decodes, with Req "".
func TestRecordKeepsReq(t *testing.T) {
	b, err := encodeRecord(&store.Record{Kind: "user", ID: "u", Version: 5, Req: "r-1", Data: []byte("x")}, pstamp{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeRecord(b); err != nil || got.rec.Req != "r-1" {
		t.Fatalf("decoded: %v %+v", err, got)
	}
	var w wireRecord
	if err := msgpack.UnmarshalAsArray(b, &w); err != nil {
		t.Fatal(err)
	}
	old, err := msgpack.MarshalAsArray(&struct { // the layout before Req
		Kind, ID  string
		Version   uint64
		Origin    string
		Deleted   bool
		Scope     string
		Unique    []string
		Fields    []wireField
		Data      []byte
		Expires   int64
		Epoch     uint64
		Created   uint64
		Partition string
		PNum      uint32
		PSeq      uint64
	}{Kind: w.Kind, ID: w.ID, Version: w.Version, Data: w.Data, PSeq: 9})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeRecord(old); err != nil || got.rec.Req != "" || got.rec.ID != "u" || got.ps.seq != 9 {
		t.Fatalf("a record stored before Req: %v %+v", err, got)
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

// referenceDecode is what decodeRecord replaced: the msgpack library's reflecting decoder.
func referenceDecode(b []byte) (*stored, error) {
	var w wireRecord
	if err := msgpack.UnmarshalAsArray(b, &w); err != nil {
		return nil, err
	}
	r := &store.Record{Kind: model.Kind(w.Kind), ID: w.ID, Version: hlc.Timestamp(w.Version), Origin: w.Origin,
		Deleted: w.Deleted, Scope: w.Scope, Unique: w.Unique, Data: w.Data, Epoch: hlc.Timestamp(w.Epoch),
		Created: hlc.Timestamp(w.Created), Partition: w.Partition, Req: w.Req}
	if w.Expires != 0 {
		r.Expires = time.Unix(0, w.Expires)
	}
	if len(w.Fields) > 0 {
		r.Fields = make(map[string]any, len(w.Fields))
		for _, f := range w.Fields {
			switch f.Type {
			case ftNil:
				r.Fields[f.Name] = nil
			case ftString:
				r.Fields[f.Name] = f.Str
			case ftInt:
				r.Fields[f.Name] = f.Int
			case ftBool:
				r.Fields[f.Name] = f.Bool
			case ftTime:
				r.Fields[f.Name] = time.Unix(f.Int, int64(f.Nano)).UTC()
			}
		}
	}
	return &stored{rec: r, ps: pstamp{w.PNum, w.PSeq}}, nil
}

// decodeRecord reads every record the msgpack library writes as the library's own decoder does: strings and blobs of every
// length class, integers of every width, empty and absent values, a record from before Req.
func TestDecodeRecordMatchesReflectingDecoder(t *testing.T) {
	rnd := rand.New(rand.NewPCG(1, 2))
	str := func() string {
		n := []int{0, 1, 31, 32, 255, 256, 70000}[rnd.IntN(7)]
		return strings.Repeat("é", n/2) + strings.Repeat("x", n%2)
	}
	i64 := func() int64 {
		return []int64{0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 32, 1<<63 - 1, -1, -32, -33, -128, -129, -32768, -32769, -1 << 31, -1<<31 - 1, -1 << 63}[rnd.IntN(20)]
	}
	u64 := func() uint64 {
		return []uint64{0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 32, 1<<64 - 1}[rnd.IntN(10)]
	}
	for range 3000 {
		w := wireRecord{Kind: str(), ID: str(), Version: u64(), Origin: str(), Deleted: rnd.IntN(2) == 0, Scope: str(),
			Expires: i64(), Epoch: u64(), Created: u64(), Partition: str(), PNum: uint32(u64()), PSeq: u64(), Req: str()}
		for range []int{0, 0, 1, 15, 16, 20}[rnd.IntN(6)] {
			w.Unique = append(w.Unique, str())
		}
		for range []int{0, 0, 1, 15, 16, 20}[rnd.IntN(6)] {
			w.Fields = append(w.Fields, wireField{Name: str(), Type: uint8(rnd.IntN(5)), Int: i64(), Nano: int32(i64()), Str: str(), Bool: rnd.IntN(2) == 0})
		}
		if n := []int{-1, 0, 5, 255, 256, 70000}[rnd.IntN(6)]; n >= 0 {
			w.Data = bytes.Repeat([]byte{byte(rnd.IntN(256))}, n)
		}
		body, err := msgpack.MarshalAsArray(&w)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeRecord(body)
		want, werr := referenceDecode(body)
		if err != nil || werr != nil {
			t.Fatalf("decode: %v, reference: %v", err, werr)
		}
		got.rec.Data, want.rec.Data = nilIfEmpty(got.rec.Data), nilIfEmpty(want.rec.Data)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("record %+v\n decoded %+v\n   want %+v", w, got.rec, want.rec)
		}
	}
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// Truncating a stored record anywhere, or garbling a byte of its header, is an error, never a panic.
func TestDecodeRecordRefusesDamage(t *testing.T) {
	b, err := encodeRecord(&store.Record{Kind: "user", ID: "u", Version: 5, Scope: "s", Unique: []string{"a"}, Data: []byte("xyz"),
		Fields: map[string]any{"f": "v", "t": time.Now()}}, pstamp{num: 1, seq: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := range len(b) {
		if _, err := decodeRecord(b[:i]); err == nil {
			t.Fatalf("a record cut at %d of %d bytes decoded", i, len(b))
		}
	}
	for i := range b {
		for _, c := range []byte{0xc1, 0xff, 0x00} {
			g := slices.Clone(b)
			g[i] = c
			decodeRecord(g) // (may decode to something else, must not panic)
		}
	}
}
