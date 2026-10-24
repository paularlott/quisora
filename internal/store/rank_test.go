package store

import (
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
)

// A tombstone of a plainly replicated kind outranks every write of the generation it deleted, whatever its version;
// one of a quorum kind ranks by version within that generation, so a later (confirmed) write outranks it, and a
// re-creation (a new generation, epoch = the tombstone's version) outranks it either way. A quorum deletion of nothing
// live deletes whatever generation there may be: it outranks every generation created before it.
func TestTombstoneRank(t *testing.T) {
	gen, del, later := hlc.Timestamp(100), hlc.Timestamp(200), hlc.Timestamp(300)
	for _, tc := range []struct {
		kind      model.Kind
		laterWins bool
	}{
		{model.KindSession, false}, // plain replication: a deletion always wins over its generation
		{model.KindUser, true},     // quorum kind: the later write wins
	} {
		tomb := &Record{Kind: tc.kind, ID: "x", Version: del, Deleted: true}
		if err := StampLocal(tomb, &Head{Kind: tc.kind, Version: 150, Epoch: gen}, false); err != nil {
			t.Fatal(err)
		}
		live := &Record{Kind: tc.kind, ID: "x", Version: later, Epoch: gen}
		if got := Newer(live, tomb); got != tc.laterWins {
			t.Errorf("%s: a later write of the deleted generation outranks the tombstone: %v, want %v", tc.kind, got, tc.laterWins)
		}
		if Newer(&Record{Kind: tc.kind, ID: "x", Version: 150, Epoch: gen}, tomb) {
			t.Errorf("%s: an earlier write of the deleted generation outranks the tombstone", tc.kind)
		}
		again := &Record{Kind: tc.kind, ID: "x", Version: later, Epoch: del} // re-created over the tombstone
		if !Newer(again, tomb) {
			t.Errorf("%s: a re-creation does not outrank the tombstone it was created over", tc.kind)
		}
	}

	blind := &Record{Kind: model.KindMember, ID: "m", Version: 500, Deleted: true}
	if err := StampLocal(blind, &Head{Kind: model.KindMember, Version: 200, Deleted: true}, false); err != nil {
		t.Fatal(err)
	}
	readd := &Record{Kind: model.KindMember, ID: "m", Version: 900, Epoch: 200} // re-created elsewhere, unseen
	if Newer(readd, blind) {
		t.Error("a re-creation the deletion had not seen outranks a later deletion over a tombstone")
	}
}
