package cluster

import (
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A crash can occur before the ten-second prune loop saves an unapplied deletion.
// Waiting out a restart pause raises versions, but cannot recover its lost epoch.
func TestRound3PartialDeletionMarkSurvivesImmediateVoterRestart(t *testing.T) {
	var nodes []*Node
	for range 3 {
		n, err := New(tempConfig(t), memstore.New(), Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		n.voter = newVoter(n)
		nodes = append(nodes, n)
	}
	u := newUser("org1", "immediate-voter-restart")
	initial, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	initial.Created = initial.Version
	for _, n := range nodes {
		if _, _, err := n.st.inner.PutReplicated(bg, initial); err != nil {
			t.Fatal(err)
		}
	}
	deletion := store.Tombstone(model.KindUser, u.ID)
	for _, i := range []int{0, 1} {
		if r := nodes[i].voter.prepare(bg, "partial-delete", deletion, modeBlind, initial.Rank()); r.St != stGrant {
			t.Fatalf("prepare deletion node%d: %+v", i, r)
		}
	}
	if st := nodes[0].voter.commit(bg, "partial-delete", deletion, true); st != stGrant {
		t.Fatalf("partial commit: %d", st)
	}
	// Restart before intentTTL; the store and directory survive, RAM does not.
	previousPause := restartPause
	restartPause = 25 * time.Millisecond
	nodes[1].voter = newVoter(nodes[1])
	restartPause = previousPause
	time.Sleep(30 * time.Millisecond)
	changed := *u
	changed.GivenName = "Later confirmed profile"
	encoded, err := store.Encode(&changed)
	if err != nil {
		t.Fatal(err)
	}
	later := *encoded
	later.Created = initial.Created
	// A voter may answer low (its floor is past every version it granted before its restart); the writer then
	// stamps past the floor and prepares again, as quorumWrite does.
	for attempt := 0; ; attempt++ {
		var floor uint64
		for _, i := range []int{1, 2} {
			switch r := nodes[i].voter.prepare(bg, "later-confirmed", &later, modeMatch, initial.Rank()); r.St {
			case stGrant:
			case stLow:
				floor = max(floor, r.Floor)
			default:
				t.Fatalf("later prepare node%d: %+v", i, r)
			}
		}
		if floor == 0 {
			break
		}
		if attempt > 0 {
			t.Fatalf("later prepare still low after re-stamping past floor %d", floor)
		}
		later.Version = hlc.Timestamp(floor) + 1
	}
	for _, i := range []int{1, 2} {
		if st := nodes[i].voter.commit(bg, "later-confirmed", &later, true); st != stGrant {
			t.Fatalf("later commit node%d: %d", i, st)
		}
	}
	if _, err := nodes[1].st.applyReplica(bg, deletion); err != nil {
		t.Fatal(err)
	}
	if _, err := nodes[1].st.Get(bg, model.KindUser, u.ID); err != nil {
		t.Fatalf("unsaved deletion mark vanished on restart; old partial deletion erased later quorum-confirmed write: %v", err)
	}
}
