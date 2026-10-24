package cluster

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A blind deletion of a record absent on the writer carries its own Version as
// Epoch. The scalar quorum high-water mark cannot make a later create outrank it.
func TestFreshPartialBlindDeletionCannotEraseConfirmedCreate(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	failing := &deepDesignDeleteFailure{Store: memstore.New()}
	c.mks = map[int]backend{1: func(testing.TB, string) store.Store { return failing }}
	c.startAll()
	c.waitReady()
	u := newUser("org1", "create-after-partial-blind-delete")
	u.ID = model.NewID()
	c.drop(0, 2, true, msgPrepare)
	for _, i := range []int{1, 2} {
		c.drop(0, i, true, msgRecord, msgPush)
		c.drop(i, 0, true, msgFeed)
	}
	failing.fail.Store(true)
	err := users(c.nodes[0]).Delete(bg, u.ID) // absent everywhere
	failing.fail.Store(false)
	if !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("partial blind deletion: %v", err)
	}
	partial, err := c.nodes[0].st().Lookup(bg, model.KindUser, u.ID)
	if err != nil || !partial.Deleted {
		t.Fatalf("partial deletion missing: %v %+v", err, partial)
	}
	c.drop(2, 0, true, msgPrepare)
	if err := users(c.nodes[2]).Create(bg, u); err != nil {
		t.Fatalf("later quorum create failed: %v", err)
	}
	if u.Version <= partial.Version {
		t.Fatal("create version did not advance past deletion")
	}
	for _, i := range []int{1, 2} {
		if _, err := users(c.nodes[i]).Get(bg, u.ID); err != nil {
			t.Fatalf("confirmed create absent before healing: %v", err)
		}
	}
	for _, i := range []int{1, 2} {
		if _, err := c.nodes[i].st().applyReplica(bg, partial); err != nil {
			t.Fatal(err)
		}
		if _, err := users(c.nodes[i]).Get(bg, u.ID); err != nil {
			t.Fatalf("older partial blind deletion erased later quorum-confirmed create on node%d: %v", i, err)
		}
	}
}
