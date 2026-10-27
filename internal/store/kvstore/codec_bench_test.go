package kvstore

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func benchUserRecord(b testing.TB) []byte {
	u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: "alice.example", Email: "alice@example.test", GivenName: "Alice",
		FamilyName: "Example", Role: model.RoleUser, Active: true, Tags: []string{"a", "b", "c"}}
	rec, err := store.Encode(u)
	if err != nil {
		b.Fatal(err)
	}
	rec.Origin, rec.Created, rec.Epoch, rec.Expires = "node-1", store.Clock.Now(), 0, time.Time{}
	body, err := encodeRecord(rec, pstamp{})
	if err != nil {
		b.Fatal(err)
	}
	return body
}

func BenchmarkDecodeRecord(b *testing.B) {
	body := benchUserRecord(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := decodeRecord(body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeRecord(b *testing.B) {
	st, _ := decodeRecord(benchUserRecord(b))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := encodeRecord(st.rec, st.ps); err != nil {
			b.Fatal(err)
		}
	}
}
