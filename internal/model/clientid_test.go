package model

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Client IDs: fixed width, the prefix, and the same byte-wise order as the UUIDs they encode (clients list and page
// by ID in creation order).
func TestClientID(t *testing.T) {
	if got := ClientIDFromUUID(uuid.UUID{}); got != "c_0000000000000000000000" {
		t.Fatalf("zero UUID = %q", got)
	}
	var max uuid.UUID
	for i := range max {
		max[i] = 0xff
	}
	if got := ClientIDFromUUID(max); len(got) != 24 || got[2] > '9' {
		t.Fatalf("max UUID = %q (22 base-62 characters fit 128 bits with room to spare)", got)
	}
	ids := map[string]bool{}
	for range 2000 {
		var a, b uuid.UUID
		_, _ = rand.Read(a[:])
		_, _ = rand.Read(b[:])
		ca, cb := ClientIDFromUUID(a), ClientIDFromUUID(b)
		if len(ca) != 24 || !strings.HasPrefix(ca, ClientIDPrefix) || strings.ContainsAny(ca[2:], "-_") {
			t.Fatalf("bad shape %q", ca)
		}
		if (bytes.Compare(a[:], b[:]) < 0) != (ca < cb) {
			t.Fatalf("order differs: %s %s -> %s %s", a, b, ca, cb)
		}
		ids[ca] = true
	}
	if len(ids) != 2000 {
		t.Fatalf("collisions: %d distinct of 2000", len(ids))
	}
	n1, n2 := NewClientID(), NewClientID()
	if n1 == n2 || !strings.HasPrefix(n1, ClientIDPrefix) {
		t.Fatalf("NewClientID: %q %q", n1, n2)
	}
}
