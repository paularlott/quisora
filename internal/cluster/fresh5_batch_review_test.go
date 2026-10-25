package cluster

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossip/compression/snappy"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func TestFreshReviewQuorumBatchFitsDefaultTransport(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	randomText := func(n int) string {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)[:n]
	}
	const n = 6000 // below the production orphan sweep's 20,000-record batch
	ids := make([]string, 0, n)
	resp := &struct{ Recs [][]byte }{} // the size the reply would have as one packet
	for i := range n {
		u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: fmt.Sprintf("user-%06d", i), Email: fmt.Sprintf("user-%06d@example.test", i), GivenName: randomText(100), FamilyName: randomText(100), ExternalID: randomText(255), Active: true}
		u.Work.Title = randomText(255)
		u.Work.Department = randomText(255)
		u.Work.Organization = randomText(255)
		u.Work.Division = randomText(255)
		u.Work.CostCenter = randomText(255)
		u.Work.EmployeeNumber = randomText(255)
		rec, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
		b, err := encodeRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		resp.Recs = append(resp.Recs, b)
		for _, tn := range c.nodes {
			if err := tn.st().inner.Put(bg, rec); err != nil {
				t.Fatal(err)
			}
		}
	}
	encoded, err := shamaton.New().Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := snappy.New().Compress(encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("users=%d raw response=%d compressed response=%d default TCPMaxPacketSize=%d", n, len(encoded), len(compressed), gossip.DefaultConfig().TCPMaxPacketSize)
	if _, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids[:100]); err != nil {
		t.Fatalf("small read failed: %v", err)
	}
	if got, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids); err != nil {
		t.Fatalf("supported sweep-sized batch failed (received %d users): %v", len(got), err)
	}
}
