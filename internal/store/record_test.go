package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A record is live unless deleted or expired.
func TestRecordLiveHonoursDeletedAndExpiry(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		r    store.Record
		ok   bool
	}{
		{"plain", store.Record{}, true},
		{"deleted", store.Record{Deleted: true}, false},
		{"expired", store.Record{Expires: now}, false},
		{"future", store.Record{Expires: now.Add(time.Second)}, true},
	} {
		if c.r.Live(now) != c.ok {
			t.Errorf("%s: Live = %v", c.name, !c.ok)
		}
	}
}

// Head copies the record's identity and state.
func TestRecordHeadCopiesIdentity(t *testing.T) {
	r := store.Record{Kind: model.KindSession, Version: 5, Epoch: 3, Created: 2, Origin: "n", Deleted: true}
	h := r.Head()
	if *h != (store.Head{Kind: model.KindSession, Version: 5, Epoch: 3, Created: 2, Origin: "n", Deleted: true}) {
		t.Errorf("Head %+v", h)
	}
}

// StampLocal sets a local write's generation (Epoch) and creation version (Created) from what it replaces, and refuses a
// live write over a tombstone.
func TestStampLocalGenerations(t *testing.T) {
	tomb := &store.Head{Kind: model.KindSession, Version: 50, Deleted: true}
	live := &store.Head{Kind: model.KindSession, Version: 60, Epoch: 11, Created: 22}
	for _, c := range []struct {
		name           string
		rec            store.Record
		old            *store.Head
		create         bool
		err            error
		epoch, created hlc.Timestamp
	}{
		{"delete clears", store.Record{Kind: model.KindSession, Version: 70, Deleted: true, Epoch: 1, Created: 2}, live, false, nil, 0, 0},
		{"create over nothing", store.Record{Kind: model.KindSession, Version: 70}, nil, true, nil, 0, 70},
		{"write over nothing", store.Record{Kind: model.KindSession, Version: 70}, nil, false, nil, 0, 70},
		{"live over tombstone refused", store.Record{Kind: model.KindSession, Version: 70}, tomb, false, store.ErrDeleted, 0, 0},
		{"create over tombstone", store.Record{Kind: model.KindSession, Version: 70}, tomb, true, nil, 50, 70},
		{"ephemeral over tombstone", store.Record{Kind: model.KindEphemeral, Version: 70}, &store.Head{Kind: model.KindEphemeral, Version: 50, Deleted: true}, false, nil, 50, 70},
		{"create over expired", store.Record{Kind: model.KindSession, Version: 70}, live, true, nil, 11, 70},
		{"update continues", store.Record{Kind: model.KindSession, Version: 70}, live, false, nil, 11, 22},
	} {
		rec := c.rec
		err := store.StampLocal(&rec, c.old, c.create)
		if !errors.Is(err, c.err) || (c.err == nil && err != nil) {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		if err == nil && (rec.Epoch != c.epoch || rec.Created != c.created) {
			t.Errorf("%s: epoch %d created %d, want %d %d", c.name, rec.Epoch, rec.Created, c.epoch, c.created)
		}
	}
}

// Witness lets the clock follow versions it sees, but a version minutes ahead of this machine is refused and counted.
func TestWitnessRefusesFarAheadVersionsAndCountsThem(t *testing.T) {
	before := store.SkewRefused()
	next := store.Clock.Now()
	store.Witness(next) // a version the clock itself minted is never refused
	if store.SkewRefused() != before {
		t.Error("a local version was refused")
	}
	if store.Ahead(next) > store.MaxSkew {
		t.Errorf("a fresh version is %v ahead", store.Ahead(next))
	}
	// A version minutes ahead of this machine is refused and counted, and the clock does not follow it.
	ahead := hlc.Timestamp(uint64(next) + uint64(10*time.Minute/time.Microsecond)<<hlc.CounterBits)
	if store.Ahead(ahead) < 5*time.Minute {
		t.Fatalf("a version 10 minutes ahead is only %v ahead", store.Ahead(ahead))
	}
	store.Witness(ahead)
	if store.SkewRefused() != before+1 {
		t.Error("a version far ahead was not counted")
	}
	if store.Clock.Now() >= ahead {
		t.Error("the clock followed a version far ahead")
	}
}

// SetOrigin names the node in the records it writes, tombstones included.
func TestOriginStampsTombstones(t *testing.T) {
	prev := store.Origin()
	t.Cleanup(func() { store.SetOrigin(prev) })
	store.SetOrigin("node-7")
	if store.Origin() != "node-7" {
		t.Error("SetOrigin")
	}
	rec := store.Tombstone(model.KindGroup, "g")
	if rec.Origin != "node-7" || !rec.Deleted || rec.ID != "g" || rec.Version == 0 {
		t.Errorf("tombstone %+v", rec)
	}
}
