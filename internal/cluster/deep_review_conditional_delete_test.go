package cluster

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/store"
)

func TestDeepReviewConditionalDeleteChecksExpectedVersion(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	table := users(c.nodes[0])
	u := newUser("org1", "conditional-delete")
	if err := table.Create(bg, u); err != nil {
		t.Fatal(err)
	}
	expected := u.Version
	u.GivenName = "Changed after decision"
	if err := table.Update(bg, u); err != nil {
		t.Fatal(err)
	}
	if err := table.DeleteIf(bg, u.ID, expected); !errors.Is(err, store.ErrStale) {
		t.Fatalf("conditional deletion ignored stale expected version: got %v, want ErrStale", err)
	}
}
