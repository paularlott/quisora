package cluster

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

type deepDesignDeleteFailure struct {
	store.Store
	fail atomic.Bool
}

func (s *deepDesignDeleteFailure) PutReplicated(ctx context.Context, rec *store.Record) (bool, []string, error) {
	if rec.Deleted && s.fail.Load() {
		return false, nil, errors.New("review: deletion commit storage failure")
	}
	return s.Store.PutReplicated(ctx, rec)
}

// A deletion prepares A/B but only commits A. A subsequent update succeeds at
// B/C with a higher Version. B retained its high-water mark throughout, without
// restarting. The documented partial-write recovery guarantee requires that the
// confirmed update rank above the earlier partial deletion when A reconnects.
func TestDeepDesignPartialDeletionCannotEraseLaterConfirmedUpdate(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	failing := &deepDesignDeleteFailure{Store: memstore.New()}
	c.mks = map[int]backend{1: func(testing.TB, string) store.Store { return failing }}
	c.startAll()
	c.waitReady()
	u := newUser("org1", "partial-deletion")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(x *model.User) bool { return x.Version == u.Version })
	later, err := users(c.nodes[2]).Get(bg, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Only B may join A's prepare quorum; broadcasts and anti-entropy must not
	// deliver A's partial deletion to B/C before the subsequent update.
	c.drop(0, 2, true, msgPrepare)
	for _, i := range []int{1, 2} {
		c.drop(0, i, true, msgRecord, msgPush)
		c.drop(i, 0, true, msgFeed)
	}
	failing.fail.Store(true)
	err = users(c.nodes[0]).Delete(bg, u.ID)
	failing.fail.Store(false)
	if !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("partial deletion: %v, want ErrUnconfirmed", err)
	}
	partial, err := c.nodes[0].st().Lookup(bg, model.KindUser, u.ID)
	if err != nil || !partial.Deleted {
		t.Fatalf("A must hold the partial tombstone: %v, %#v", err, partial)
	}
	// The later caller starts after the deletion already returned failure.
	// Only B may join C's quorum; B holds the old base and the deletion's hw.
	c.drop(2, 0, true, msgPrepare)
	later.GivenName = "confirmed after partial deletion"
	if err := users(c.nodes[2]).Update(bg, later); err != nil {
		t.Fatalf("later update should be confirmed at B/C: %v", err)
	}
	if later.Version <= partial.Version {
		t.Fatalf("later version %d did not exceed partial deletion %d", later.Version, partial.Version)
	}
	for _, i := range []int{1, 2} {
		got, err := users(c.nodes[i]).Get(bg, u.ID)
		if err != nil || got.Version != later.Version {
			t.Fatalf("node %d must hold confirmed update: %v, %#v", i, err, got)
		}
	}
	// Deliver precisely the record A's normal anti-entropy would send upon heal.
	for _, i := range []int{1, 2} {
		if _, err := c.nodes[i].st().applyReplica(bg, partial); err != nil {
			t.Fatal(err)
		}
		if _, err := users(c.nodes[i]).Get(bg, u.ID); errors.Is(err, store.ErrNotFound) {
			t.Fatalf("old partial deletion erased later quorum-confirmed update on node %d despite retained high-water mark and higher update version", i)
		} else if err != nil {
			t.Fatal(err)
		}
	}
}
