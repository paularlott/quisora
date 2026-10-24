package cluster

import (
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func voterNode(t *testing.T) *Node {
	t.Helper()
	n, err := New(tempConfig(t), memstore.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	if !n.votes() {
		t.Fatal("test set-up: the node does not vote anyway")
	}
	return n
}

func mustEncode(t *testing.T, u *model.User) *store.Record {
	t.Helper()
	r, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A voter grants no version further ahead of its clock than voteAhead: a restart then needs nothing on disk.
func TestVoterRefusesVersionsFarAhead(t *testing.T) {
	v := newVoter(voterNode(t))
	rec := mustEncode(t, newUser("org1", "ahead"))
	rec.Version = hlc.FromTime(time.Now().Add(voteAhead + time.Second))
	if r := v.prepare(bg, "op", rec, modeMatch, store.Rank{}); r.St == stGrant {
		t.Fatal("granted a version further ahead than voteAhead")
	}
	rec.Version = store.Clock.Now()
	if r := v.prepare(bg, "op2", rec, modeMatch, store.Rank{}); r.St != stGrant {
		t.Fatalf("a current version: %d", r.St)
	}
}

// A voter that has just started takes part in no quorum write until restartPause has passed.
func TestVoterPausesAfterStart(t *testing.T) {
	defer func(d time.Duration) { restartPause = d }(restartPause)
	restartPause = 300 * time.Millisecond
	v := newVoter(voterNode(t))
	rec := mustEncode(t, newUser("org1", "paused"))
	if r := v.prepare(bg, "op", rec, modeMatch, store.Rank{}); r.St != stNotReady {
		t.Fatalf("just started: %d, want not ready", r.St)
	}
	time.Sleep(restartPause + 10*time.Millisecond)
	rec.Version = store.Clock.Now()
	if r := v.prepare(bg, "op", rec, modeMatch, store.Rank{}); r.St != stGrant {
		t.Fatalf("after the pause: %d", r.St)
	}
}
