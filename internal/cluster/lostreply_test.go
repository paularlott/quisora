//go:build faults

package cluster

import (
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

// The tests of lost replies inject them (faultHooks.loseReply), so they are built with the faults tag only:
//
//	go test -tags faults ./internal/cluster/

// The conformance suite's lost replies variant (TestConformance): three nodes through node 0, and every third partition
// write lands and then reports an unknown outcome below the store's settling (the reply lost), which the store must
// settle: its caller never sees it.
func TestConformanceLostReplies(t *testing.T) {
	if os.Getenv("QUISORA_CONFORMANCE") == "" && !namedRun("TestConformanceLostReplies") {
		t.Skip("set QUISORA_CONFORMANCE=1 to run the store conformance suite against cluster.Store")
	}
	for _, b := range localBackends() {
		t.Run(b.name, func(t *testing.T) {
			storetest.RunWith(t, func(tb testing.TB) store.Store {
				c := conformClusterWith(tb, 3, b, steady)
				var n atomic.Int64
				c.nodes[0].n.faults.loseReply = func() bool { return n.Add(1)%3 == 0 }
				return noClose{c.nodes[0].st()}
			}, storetest.Options{NoReplicated: true})
		})
	}
}

// A write whose reply was lost, and whose record another write changed before its resubmission reached the owner,
// cannot be told apart from one that never landed: the record no longer carries its request id. Its resubmission is
// refused as stale, which its own landing may have caused, so the store answers that the outcome is unknown
// (unavailable, unconfirmed), never that the write was refused: a caller that audits by outcome then records it as
// unknown instead of leaving out a change that was made.
func TestOverwrittenWriteWithALostReplyIsUnknownNotStale(t *testing.T) {
	c := started(t, badgerBackend())
	org, _ := c.orgNotOwnedBy(0)
	tb := store.NewTable[model.User](c.nodes[0].st())
	u := &model.User{OrgID: org, Username: "lost", Email: "lost@example.com", Active: true}
	if err := tb.Create(bg, u); err != nil {
		t.Fatal(err)
	}
	other := store.NewTable[model.User](c.nodes[1].st())
	var lost atomic.Bool
	c.nodes[0].n.faults.loseReply = func() bool {
		if !lost.CompareAndSwap(false, true) {
			return false
		}
		// The first write landed; another, from a node that has it, changes the record before the first's
		// resubmission.
		var cur *model.User
		waitFor(t, 5*time.Second, "the other node to have the first write", func() bool {
			got, err := other.Get(bg, u.ID)
			cur = got
			return err == nil && got.GivenName == "first"
		})
		cur.GivenName = "intervening"
		if err := other.Update(bg, cur); err != nil {
			t.Errorf("the intervening write: %v", err)
		}
		return true
	}
	u.GivenName = "first"
	err := tb.Update(bg, u)
	if !lost.Load() {
		t.Fatal("test set-up: no reply was lost")
	}
	if errors.Is(err, store.ErrStale) || !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("a write that landed, was changed and lost its reply: %v, want unavailable and unconfirmed, not stale", err)
	}
	if got, err := other.Get(bg, u.ID); err != nil || got.GivenName != "intervening" {
		t.Fatalf("the intervening write was undone: %+v %v", got, err)
	}
}

// An unconditional write (a Put, a plain deletion) that landed and lost its reply, and that another writer changed
// before the store submitted it again, is never replayed over that successor: the replay is conditional on the version
// the write was based on (change.Base), refused, and the write is reported unknown, the successor kept.
func TestReplayedUnconditionalWriteKeepsTheSuccessor(t *testing.T) {
	for _, tc := range []struct {
		name string
		// write is the first write, through node 0; change, the successor through node 1 once it holds that write
		write  func(s *Store, u *model.User) error
		change func(t *testing.T, other *store.Table[model.User, *model.User], u *model.User)
		// kept checks the successor survived
		kept func(t *testing.T, other *store.Table[model.User, *model.User], u *model.User)
	}{
		{
			name: "put",
			write: func(s *Store, u *model.User) error {
				u.GivenName = "first"
				r, err := store.Encode(u)
				if err != nil {
					return err
				}
				return s.Put(bg, r)
			},
			change: func(t *testing.T, other *store.Table[model.User, *model.User], u *model.User) {
				var cur *model.User
				waitFor(t, 5*time.Second, "the other node to have the first write", func() bool {
					got, err := other.Get(bg, u.ID)
					cur = got
					return err == nil && got.GivenName == "first"
				})
				cur.GivenName = "successor"
				if err := other.Update(bg, cur); err != nil {
					t.Errorf("the successor: %v", err)
				}
			},
			kept: func(t *testing.T, other *store.Table[model.User, *model.User], u *model.User) {
				if got, err := other.Get(bg, u.ID); err != nil || got.GivenName != "successor" {
					t.Fatalf("the successor was overwritten by the replay: %+v %v", got, err)
				}
			},
		},
		{
			name:  "delete",
			write: func(s *Store, u *model.User) error { return store.NewTable[model.User](s).Delete(bg, u.ID) },
			change: func(t *testing.T, other *store.Table[model.User, *model.User], u *model.User) {
				waitFor(t, 5*time.Second, "the other node to have the deletion", func() bool {
					_, err := other.Get(bg, u.ID)
					return errors.Is(err, store.ErrNotFound)
				})
				again := &model.User{Meta: model.Meta{ID: u.ID}, OrgID: u.OrgID, Username: "again", Active: true}
				if err := other.Create(bg, again); err != nil {
					t.Errorf("the successor (created again): %v", err)
				}
			},
			kept: func(t *testing.T, other *store.Table[model.User, *model.User], u *model.User) {
				if got, err := other.Get(bg, u.ID); err != nil || got.Username != "again" {
					t.Fatalf("the record created again was deleted by the replay: %+v %v", got, err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := started(t, badgerBackend())
			org, _ := c.orgNotOwnedBy(0)
			tb := store.NewTable[model.User](c.nodes[0].st())
			u := &model.User{OrgID: org, Username: "replayed-" + tc.name, Active: true}
			if err := tb.Create(bg, u); err != nil {
				t.Fatal(err)
			}
			c.waitVersion(t, model.KindUser, u.ID, u.Version)
			other := store.NewTable[model.User](c.nodes[1].st())
			var lost atomic.Bool
			c.nodes[0].n.faults.loseReply = func() bool {
				if !lost.CompareAndSwap(false, true) {
					return false
				}
				tc.change(t, other, u)
				return true
			}
			err := tc.write(c.nodes[0].st(), u)
			if !lost.Load() {
				t.Fatal("test set-up: no reply was lost")
			}
			if !errors.Is(err, store.ErrUnconfirmed) {
				t.Fatalf("a write that landed, was succeeded and lost its reply: %v, want unknown (unconfirmed)", err)
			}
			tc.kept(t, other, u)
		})
	}
}
