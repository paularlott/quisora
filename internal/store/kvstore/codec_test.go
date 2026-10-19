package kvstore

import (
	"testing"

	"github.com/paularlott/quisora/internal/store"
)

// A stored record keeps its generation (Epoch) and creation version (Created).
func TestRecordKeepsEpochAndCreated(t *testing.T) {
	b, err := encodeRecord(&store.Record{Kind: "group", ID: "g2", Version: 50, Epoch: 30, Created: 45, Data: []byte("y")})
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRecord(b)
	if err != nil || got.rec.Epoch != 30 || got.rec.Created != 45 || got.rec.Version != 50 {
		t.Fatalf("decoded: %v %+v", err, got)
	}
}
