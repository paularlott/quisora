package store

import (
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
)

// A plainly replicated kind ranks by generation, then version: a tombstone outranks every write of the generation it
// deleted, whatever that write's version, and a re-creation over it (epoch = its version) outranks it. A quorum kind
// ranks by version alone (the voters order versions as writes are granted): the later write wins, a deletion or not,
// whatever generation it belongs to — a confirmed create over a partial deletion of an absent record included.
func TestRank(t *testing.T) {
	gen, del, later := hlc.Timestamp(100), hlc.Timestamp(200), hlc.Timestamp(300)
	tomb := func(k model.Kind) *Record {
		r := &Record{Kind: k, ID: "x", Version: del, Deleted: true}
		if err := StampLocal(r, &Head{Kind: k, Version: 150, Epoch: gen}, false); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// plain replication
	pt := tomb(model.KindSession)
	if Newer(&Record{Kind: model.KindSession, ID: "x", Version: later, Epoch: gen}, pt) {
		t.Error("session: a later write of the deleted generation outranks the tombstone")
	}
	if !Newer(&Record{Kind: model.KindSession, ID: "x", Version: later, Epoch: del}, pt) {
		t.Error("session: a re-creation does not outrank the tombstone it was created over")
	}
	// quorum kinds
	qt := tomb(model.KindUser)
	if !Newer(&Record{Kind: model.KindUser, ID: "x", Version: later, Epoch: gen}, qt) {
		t.Error("user: a later write does not outrank an earlier deletion")
	}
	if Newer(&Record{Kind: model.KindUser, ID: "x", Version: 150, Epoch: gen}, qt) {
		t.Error("user: an earlier write outranks a later deletion")
	}
	blind := &Record{Kind: model.KindUser, ID: "y", Version: del, Deleted: true} // deleted where absent
	if err := StampLocal(blind, nil, false); err != nil {
		t.Fatal(err)
	}
	if !Newer(&Record{Kind: model.KindUser, ID: "y", Version: later}, blind) {
		t.Error("user: a later create does not outrank an earlier deletion of the absent record")
	}
	readd := &Record{Kind: model.KindMember, ID: "m", Version: later, Epoch: 150}  // re-created, earlier than...
	again := &Record{Kind: model.KindMember, ID: "m", Version: 400, Deleted: true} // ...a later deletion
	if Newer(readd, again) || !Newer(again, readd) {
		t.Error("member: a re-creation outranks a later deletion")
	}
}
