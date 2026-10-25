package cluster

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// Counting IDs cannot bound the encoded reply: a client's inline JWKS can fit
// within a normal JSON request while sixteen such clients exceed one packet.
func TestFresh7SmallQuorumReadFallsBackWhenReplyExceedsPacket(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Default(), c.nodes[0].st(), sealer)
	orgName := "pooled-reply"
	org, err := svc.CreateOrg(bg, service.System, service.OrgInput{Name: &orgName})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, readFew+1)
	for range readFew + 1 {
		b := make([]byte, 350_000)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		jwks := `{"keys":[],"padding":"` + base64.RawURLEncoding.EncodeToString(b) + `"}`
		name := "Large JWKS"
		redirects := []string{"https://example.test/callback"}
		client, _, err := svc.CreateClient(bg, service.System, org.ID, service.ClientInput{Name: &name, JWKS: &jwks, RedirectURIs: &redirects})
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.nodes[0].st().inner.Lookup(bg, model.KindClient, client.ID)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, client.ID)
		for _, tn := range c.nodes {
			if _, _, err := tn.st().inner.PutReplicated(bg, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got, err := c.nodes[0].st().Fresh(bg, model.KindClient, ids); err != nil || len(got) != len(ids) {
		t.Fatalf("stream read failed: records=%d err=%v", len(got), err)
	}
	if got, err := c.nodes[0].st().Fresh(bg, model.KindClient, ids[:readFew]); err != nil || len(got) != readFew {
		t.Fatalf("smaller read failed despite successful larger stream: records=%d err=%v", len(got), err)
	}
}

func TestFresh7PartialLargeStreamDoesNotCountAsQuorumAnswer(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	fault := &fresh6PartialReadFailure{Store: memstore.New()}
	c.mks = map[int]backend{2: func(testing.TB, string) store.Store { return fault }}
	c.startAll()
	c.waitReady()
	ids := []string{"stream-first", "stream-fault"}
	for i := range readFew {
		ids = append(ids, fmt.Sprintf("missing-%d", i))
	}
	for _, id := range ids[:2] {
		u := &model.User{Meta: model.Meta{ID: id}, OrgID: "org", Username: id, Active: true, GivenName: strings.Repeat("a", 100_000)}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		for _, tn := range c.nodes {
			if err := tn.st().inner.Put(bg, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	fault.fail.Store(true)
	defer fault.fail.Store(false)
	c.drop(0, 1, true, msgRead, msgReadFew)
	if _, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids); !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("partial stream certified a read: %v", err)
	}
	c.drop(0, 1, false, msgRead, msgReadFew)
	got, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids)
	if err != nil || len(got) != 2 {
		t.Fatalf("healthy peer could not supply quorum after partial-stream failure: records=%d err=%v", len(got), err)
	}
}
