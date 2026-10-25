package cluster

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/store"
	"github.com/shamaton/msgpack/v3"
)

// failWriter fails the write numbered failAt (1 is the first) and every one after it.
type covFailWriter struct{ failAt, n int }

func (f *covFailWriter) Write(p []byte) (int, error) {
	f.n++
	if f.n >= f.failAt {
		return 0, errors.New("injected: write failed")
	}
	return len(p), nil
}

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	for _, p := range []string{"one", "", "three"} {
		if err := writeFrame(&buf, []byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"one", "", "three"} {
		got, err := readFrame(&buf)
		if err != nil || string(got) != want {
			t.Fatalf("%q %v, want %q", got, err, want)
		}
	}
	if _, err := readFrame(&buf); err != io.EOF {
		t.Fatalf("end of a complete stream: %v", err)
	}
	for failAt := 1; failAt <= 2; failAt++ { // the length prefix, then the body
		if err := writeFrame(&covFailWriter{failAt: failAt}, []byte("x")); err == nil {
			t.Fatalf("write %d failure ignored", failAt)
		}
	}
	huge := []byte{0xff, 0xff, 0xff, 0xff}
	if _, err := readFrame(bytes.NewReader(huge)); err == nil || !strings.Contains(err.Error(), "frame of") {
		t.Fatalf("oversize frame: %v", err)
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 9, 'a'})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("cut frame: %v", err)
	}
}

func TestRecordFieldTypesRoundTrip(t *testing.T) {
	when := time.Date(2026, 3, 4, 5, 6, 7, 890, time.UTC)
	rec := &store.Record{Kind: dataKind, ID: "r1", Version: 100, Epoch: 50, Created: 60, Origin: "n1", Scope: "s",
		Unique: []string{"u1"}, Data: []byte("d"), Expires: time.Unix(1000, 5),
		Fields: map[string]any{"nil": nil, "str": "s", "bool": true, "time": when, "int": 1, "i32": int32(2),
			"i64": int64(3), "u32": uint32(4), "u64": uint64(5)}}
	b, err := encodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"nil": nil, "str": "s", "bool": true, "time": when, "int": int64(1), "i32": int64(2),
		"i64": int64(3), "u32": int64(4), "u64": int64(5)}
	for k, v := range want {
		if g, ok := got.Fields[k]; !ok || g != v {
			t.Errorf("field %s: %v (%T), want %v", k, g, g, v)
		}
	}
	if got.Epoch != 50 || got.Created != 60 || got.Version != 100 || !got.Expires.Equal(rec.Expires) || got.Scope != "s" {
		t.Errorf("record: %+v", got)
	}
	if _, err := encodeRecord(&store.Record{Kind: dataKind, ID: "x", Version: 5, Fields: map[string]any{"f": 1.5}}); err == nil ||
		!strings.Contains(err.Error(), "unsupported field type") {
		t.Errorf("float field: %v", err)
	}
	// A tombstone carries no fields, scope or data, only its generation.
	tb, err := encodeRecord(&store.Record{Kind: dataKind, ID: "x", Version: 9, Epoch: 9, Deleted: true, Scope: "s",
		Fields: map[string]any{"f": 1.5}})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := decodeRecord(tb); err != nil || !d.Deleted || d.Scope != "" || d.Fields != nil || d.Created != 0 {
		t.Fatalf("tombstone: %+v %v", d, err)
	}
}

func TestDecodeRecordRefusesMalformed(t *testing.T) {
	enc := func(w wireRecord) []byte {
		b, err := msgpack.MarshalAsArray(&w)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := decodeRecord([]byte("not msgpack")); err == nil {
		t.Error("garbage decoded")
	}
	v := uint64(hlc.FromTime(time.Now()))
	for name, w := range map[string]wireRecord{
		"epoch at version":       {Kind: "k", ID: "i", Version: v, Epoch: v},
		"created after version":  {Kind: "k", ID: "i", Version: v, Created: v + 1},
		"tombstone epoch beyond": {Kind: "k", ID: "i", Version: v, Epoch: v + 1, Deleted: true},
	} {
		if _, err := decodeRecord(enc(w)); err == nil || !strings.Contains(err.Error(), "bad generation") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r, err := decodeRecord(enc(wireRecord{Kind: "k", ID: "i", Version: v, Epoch: v - 1, Created: v})); err != nil || r.Epoch != hlc.Timestamp(v-1) {
		t.Errorf("a well-formed generation: %v %v", r, err)
	}
	if r, err := decodeRecord(enc(wireRecord{Kind: "k", ID: "i", Version: v, Epoch: v, Deleted: true, Created: 3})); err != nil || r.Created != 0 {
		t.Errorf("a tombstone at its own version: %v %v", r, err)
	}
}

func TestMergeAuditOrders(t *testing.T) {
	at := func(s int) time.Time { return time.Unix(int64(s), 0).UTC() }
	rec := func(id, action string, sec int) *store.Record {
		return &store.Record{ID: id, Fields: map[string]any{"action": action, "created": at(sec)}}
	}
	mk := func() []*store.Record {
		return []*store.Record{rec("c", "User.Update", 3), rec("a", "user.create", 1), rec("b", "user.create", 1),
			rec("d", "audit.read", 2)}
	}
	ids := func(rs []*store.Record) string {
		var s []string
		for _, r := range rs {
			s = append(s, r.ID)
		}
		return strings.Join(s, "")
	}
	if got := ids(mergeAudit(mk(), store.ListQuery{})); got != "abdc" { // time, then id
		t.Errorf("by time: %s", got)
	}
	if got := ids(mergeAudit(mk(), store.ListQuery{Desc: true})); got != "cdba" {
		t.Errorf("by time, newest first: %s", got)
	}
	if got := ids(mergeAudit(mk(), store.ListQuery{Sort: "action"})); got != "dabc" { // case-insensitive action
		t.Errorf("by action: %s", got)
	}
	if got := ids(mergeAudit(mk(), store.ListQuery{Sort: "action", Desc: true, Limit: 2})); got != "cb" {
		t.Errorf("by action, descending, limited: %s", got)
	}
}

func TestAuditFiltersWireRoundTrip(t *testing.T) {
	when := time.Date(2026, 1, 2, 3, 4, 5, 6000, time.UTC)
	in := []store.Filter{{Field: "action", Op: "=", Value: "a"}, {Field: "created", Op: ">=", Value: when}, {Field: "n", Op: "=", Value: 5}}
	out := fromAuditFilters(toAuditFilters(in))
	if len(out) != 3 || out[0].Value != "a" || !out[1].Value.(time.Time).Equal(when) || out[2].Value != "" {
		t.Fatalf("%+v", out)
	}
}

func TestDecodeClusterKeysAndLoadNodeID(t *testing.T) {
	good := testKey()
	if k, prev, err := decodeClusterKeys(good, []string{testKey()}); err != nil || len(k) != 32 || len(prev) != 1 {
		t.Fatalf("%v", err)
	}
	for _, key := range []string{"", "!!!", "AAAA"} {
		if _, _, err := decodeClusterKeys(key, nil); err == nil || !strings.Contains(err.Error(), "cluster.key") {
			t.Errorf("key %q: %v", key, err)
		}
	}
	if _, _, err := decodeClusterKeys(good, []string{testKey(), "short"}); err == nil || !strings.Contains(err.Error(), "previous_keys[1]") {
		t.Errorf("previous key: %v", err)
	}

	dir := t.TempDir()
	if id, err := loadNodeID(dir, "0198f0e0-0000-7000-8000-000000000001"); err != nil || id != "0198f0e0-0000-7000-8000-000000000001" {
		t.Errorf("configured: %v %v", id, err)
	}
	if _, err := loadNodeID(dir, "not-a-uuid"); err == nil || !strings.Contains(err.Error(), "node_id must be a UUID") {
		t.Errorf("bad configured id: %v", err)
	}
	if id, err := loadNodeID("", ""); err != nil || id == "" {
		t.Errorf("no directory: %v %v", id, err)
	}
	first, err := loadNodeID(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := loadNodeID(dir, ""); again != first {
		t.Errorf("the persisted id changed: %s %s", first, again)
	}
	// A damaged file is replaced by a new id.
	if err := os.WriteFile(filepath.Join(dir, "node_id"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fresh, err := loadNodeID(dir, ""); err != nil || fresh == first {
		t.Errorf("after damage: %v %v", fresh, err)
	}
	if _, err := loadNodeID(filepath.Join(dir, "missing"), ""); err == nil || !strings.Contains(err.Error(), "persist node id") {
		t.Errorf("unwritable directory: %v", err)
	}
}
