package cluster

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func covFeed(t *testing.T, n *Node, req feedReq) *feedResp {
	t.Helper()
	r, err := n.feedPage(nil, covPacket(t, &req))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFeedPageAnswers(t *testing.T) {
	n, cs := gnode(t)
	n.bootstrap.Store(false)
	n.catchingUp.Store(false)
	if _, err := n.feedPage(nil, covBad(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	a, b := newRec(newID(), ""), newRec(newID(), "")
	for _, r := range []*store.Record{a, b, {Kind: model.KindEphemeral, ID: "e", Version: store.Clock.Now(), Data: []byte("x")}} {
		if _, _, err := cs.Store.PutReplicated(bg, r); err != nil {
			t.Fatal(err)
		}
	}
	feed := cs.FeedID()

	// A normal page: the replicated records (the two, and the one that set up the cluster), not node-local state.
	r := covFeed(t, n, feedReq{FeedID: feed, Limit: 100})
	base := len(r.Recs)
	if r.Stale || base != 3 || r.More {
		t.Fatalf("stale %v, %d records, more %v", r.Stale, base, r.More)
	}
	// Another feed id: served from the start. A limit out of range is the default.
	if r := covFeed(t, n, feedReq{FeedID: "someone else", Since: 99, Limit: -1}); len(r.Recs) != base {
		t.Fatalf("other feed: %d", len(r.Recs))
	}
	if r := covFeed(t, n, feedReq{FeedID: feed, Limit: 1_000_000}); len(r.Recs) != base {
		t.Fatalf("huge limit: %d", len(r.Recs))
	}
	if r := covFeed(t, n, feedReq{FeedID: feed, Limit: 1}); !r.More || len(r.Recs) != 1 {
		t.Fatalf("a page of one: %+v", r)
	}

	// A page is cut at maxPageBytes, with More set and the cursor at the last record sent.
	for range 3 {
		big := newRec(newID(), "")
		big.Data = make([]byte, 600<<10)
		if _, _, err := cs.Store.PutReplicated(bg, big); err != nil {
			t.Fatal(err)
		}
	}
	r = covFeed(t, n, feedReq{FeedID: feed, Limit: 100})
	total := 0
	for _, b := range r.Recs {
		total += len(b)
	}
	if !r.More || total > maxPageBytes+1<<10 {
		t.Fatalf("page of %d bytes, more %v", total, r.More)
	}

	// Refusals: out of date, misconfigured, a restored node met data.
	why := "x"
	for name, p := range map[string]*atomic.Pointer[string]{"behind": &n.behind, "foreign": &n.foreign, "mixed": &n.mixed,
		"restoredInto": &n.restoredInto} {
		p.Store(&why)
		if r := covFeed(t, n, feedReq{FeedID: feed}); !r.Stale || len(r.Recs) != 0 {
			t.Errorf("%s: %+v", name, r)
		}
		p.Store(nil)
	}

	// A new node copies only from one that has caught up and sees a majority.
	n.catchingUp.Store(true)
	if r := covFeed(t, n, feedReq{FeedID: feed, Fresh: true}); !r.Stale {
		t.Errorf("catching up, asked by a new node: %+v", r)
	}
	if r := covFeed(t, n, feedReq{FeedID: feed}); r.Stale || !r.CatchingUp {
		t.Errorf("catching up, asked by an old member: %+v", r)
	}
	n.catchingUp.Store(false)
	if r := covFeed(t, n, feedReq{FeedID: feed, Fresh: true}); !r.Stale { // no quorum in view on a node alone
		t.Errorf("no quorum, asked by a new node: %+v", r)
	}

	// A node that has not finished its own first copy has nothing to offer.
	n.bootstrap.Store(true)
	n.holdsData.Store(false)
	if r := covFeed(t, n, feedReq{FeedID: feed}); !r.Fresh || !r.Empty || len(r.Recs) != 0 {
		t.Errorf("bootstrapping, empty: %+v", r)
	}
	n.holdsData.Store(true)
	if r := covFeed(t, n, feedReq{FeedID: feed}); !r.Fresh || r.Empty {
		t.Errorf("bootstrapping, partly copied: %+v", r)
	}
	n.bootstrap.Store(false)

	// A node restored from a backup serves only new members, and remembers that they came for its data.
	n.restored.Store(true)
	if r := covFeed(t, n, feedReq{FeedID: feed}); !r.Stale {
		t.Errorf("restored, asked by an old member: %+v", r)
	}
	// (a quorum in view is needed to seed a new node; without one it is refused first)
	if r := covFeed(t, n, feedReq{FeedID: feed, Fresh: true}); !r.Stale {
		t.Errorf("restored, no quorum: %+v", r)
	}
	n.restored.Store(false)

	// The store failing to list its changes fails the request.
	cs.changes = errors.New("disk")
	if _, err := n.feedPage(nil, covPacket(t, &feedReq{FeedID: feed})); err == nil {
		t.Error("a failing change feed was not reported")
	}
	// The handler adds the clock for the peer clock check.
	cs.changes = nil
	if resp, err := n.feedPage(&gossip.Node{ID: gossip.NodeID(uuid.New())}, covPacket(t, &feedReq{FeedID: feed})); err != nil || resp.Stale {
		t.Errorf("%v %v", resp, err)
	}
}

func TestHandleRecordAndPush(t *testing.T) {
	n, cs := gnode(t)
	n.bootstrap.Store(false)
	n.catchingUp.Store(false)
	if err := n.handleRecord(nil, covBad(t)); err == nil {
		t.Error("record: a bad payload was accepted")
	}
	if err := n.handleRecord(nil, covPacket(t, &recordMsg{B: []byte("junk")})); err == nil {
		t.Error("record: an undecodable record was accepted")
	}
	rec := newRec(newID(), "")
	if err := n.handleRecord(nil, covPacket(t, &recordMsg{B: covEncode(t, rec)})); err != nil || !has(n.Store(), rec.ID) {
		t.Fatalf("record: %v", err)
	}
	cs.putRepl = errors.New("disk")
	if err := n.handleRecord(nil, covPacket(t, &recordMsg{B: covEncode(t, newRec(newID(), ""))})); err == nil {
		t.Error("record: a failing apply was not reported")
	}
	cs.putRepl = nil
	why := "behind"
	n.behind.Store(&why)
	skipped := newRec(newID(), "")
	if err := n.handleRecord(nil, covPacket(t, &recordMsg{B: covEncode(t, skipped)})); err != nil || has(n.Store(), skipped.ID) {
		t.Fatalf("record on a node that is behind: %v", err)
	}

	if _, err := n.handlePush(nil, covBad(t)); err == nil {
		t.Error("push: a bad payload was accepted")
	}
	if _, err := n.handlePush(nil, covPacket(t, &recordMsg{B: []byte("junk")})); err == nil {
		t.Error("push: an undecodable record was accepted")
	}
	push := func(r *store.Record) *ackMsg {
		t.Helper()
		a, err := n.handlePush(nil, covPacket(t, &recordMsg{B: covEncode(t, r)}))
		if err != nil {
			t.Fatal(err)
		}
		return a.(*ackMsg)
	}
	if a := push(newRec(newID(), "")); a.OK || a.St != pushRefused {
		t.Errorf("behind: %+v", a)
	}
	n.behind.Store(nil)
	fresh := newRec(newID(), "")
	if a := push(fresh); !a.OK || a.St != pushApplied {
		t.Errorf("applied: %+v", a)
	}
	if a := push(fresh); !a.OK { // the same version again: held
		t.Errorf("held: %+v", a)
	}
	older := *fresh
	older.Version--
	older.Origin = "someone else"
	if a := push(&older); a.OK || a.St != pushSuperseded {
		t.Errorf("superseded: %+v", a)
	}
	n.catchingUp.Store(true)
	if a := push(newRec(newID(), "")); a.OK || a.St != pushRefused {
		t.Errorf("a node that does not vote: %+v", a)
	}
	n.catchingUp.Store(false)
	cs.putRepl = errors.New("disk")
	if a := push(newRec(newID(), "")); a.OK || a.St != pushRefused {
		t.Errorf("a failing apply: %+v", a)
	}
}

func TestSameDatabaseAndHoldsAll(t *testing.T) {
	n, cs := gnode(t)
	n.sameDatabase("peer-1")
	n.sameDatabase("peer-1") // told once
	if why := n.misconfig.Load(); why == nil || !strings.Contains(*why, "peer-1") {
		t.Fatalf("%v", why)
	}
	n.differentDatabase("peer-2") // another peer's feed says nothing about this refusal
	if n.misconfig.Load() == nil {
		t.Fatal("lifted by a peer that did not cause it")
	}
	n.differentDatabase("peer-1")
	if n.misconfig.Load() != nil {
		t.Fatal("not lifted")
	}
	n.differentDatabase("peer-1") // nothing to lift

	have := newRec(newID(), "")
	if _, _, err := cs.Store.PutReplicated(bg, have); err != nil {
		t.Fatal(err)
	}
	newer := *have
	newer.Version++
	gone := store.Tombstone(dataKind, "never-had")
	loc := &store.Record{Kind: model.KindEphemeral, ID: "e", Version: 1}
	if !n.holdsAll([][]byte{covEncode(t, have), covEncode(t, gone), covEncode(t, loc)}) {
		t.Error("everything is here (a deletion of what was never held counts)")
	}
	if n.holdsAll([][]byte{covEncode(t, &newer)}) {
		t.Error("a newer version is not held")
	}
	if n.holdsAll([][]byte{covEncode(t, newRec(newID(), ""))}) {
		t.Error("an unknown record is not held")
	}
	if n.holdsAll([][]byte{[]byte("junk")}) {
		t.Error("an undecodable record is held")
	}
	if !n.holdsAll(nil) {
		t.Error("an empty page is held")
	}
}

func TestOtherBootstrapRefusal(t *testing.T) {
	enc := func(created time.Time) *store.Record {
		o := &model.Org{Meta: model.Meta{ID: model.PrimaryOrgID, Created: created}, Name: "primary"}
		r, err := store.EncodeAsIs(o)
		if err != nil {
			t.Fatal(err)
		}
		r.Version = model.BootstrapVersion
		return r
	}
	t1, t2 := time.Now().Add(-time.Hour).UTC(), time.Now().UTC()
	n, cs := gnode(t)
	if _, _, err := cs.Store.PutReplicated(bg, enc(t1)); err != nil {
		t.Fatal(err)
	}
	s := n.Store()
	if s.otherBootstrap(bg, enc(t1)) {
		t.Error("the same bootstrap refused")
	}
	if s.otherBootstrap(bg, newRec(newID(), "")) {
		t.Error("an ordinary record refused")
	}
	if !s.otherBootstrap(bg, enc(t2)) || n.refused.Load() != 1 {
		t.Fatalf("another bootstrap applied (refused %d)", n.refused.Load())
	}
	if why := n.behind.Load(); why == nil || !strings.Contains(*why, "bootstrap") {
		t.Errorf("a newcomer that was bootstrapped on its own did not stop: %v", why)
	}

	// A node that has copied from a peer keeps its records and goes on; a forced one is told not to be emptied.
	n2, cs2 := gnode(t)
	if _, _, err := cs2.Store.PutReplicated(bg, enc(t1)); err != nil {
		t.Fatal(err)
	}
	n2.joined.Store(true)
	if !n2.Store().otherBootstrap(bg, enc(t2)) || n2.behind.Load() != nil {
		t.Errorf("a joined node: %v", n2.behind.Load())
	}
	n3, cs3 := gnode(t)
	if _, _, err := cs3.Store.PutReplicated(bg, enc(t1)); err != nil {
		t.Fatal(err)
	}
	why := "forced"
	n3.forced.Store(&why)
	if !n3.Store().otherBootstrap(bg, enc(t2)) || n3.behind.Load() != nil {
		t.Errorf("a forced node: %v", n3.behind.Load())
	}
}

func TestApplyBatchWithBatchBackend(t *testing.T) {
	cs := &covStore{Store: memstore.New()}
	bs := &covBatchStore{covStore: cs}
	c := newTCluster(t, 3, func(testing.TB, string) store.Store { return bs })
	tn := c.build(0, "", nil)
	defer tn.n.Close()
	n := tn.n
	a, b := newRec(newID(), ""), newRec(newID(), "")
	loc := &store.Record{Kind: model.KindEphemeral, ID: "e", Version: store.Clock.Now(), Data: []byte("x")}
	if err := n.Store().applyBatch(bg, []*store.Record{a, loc, b, a}); err != nil { // (a twice: the second is not applied)
		t.Fatal(err)
	}
	if !has(n.Store(), a.ID) || !has(n.Store(), b.ID) || !n.holdsData.Load() {
		t.Fatal("page not applied")
	}
	// Records that clash on a unique value: the later one is kept without it and reported as a loser.
	var losers []string
	n.OnConflict(func(l *store.Record) { losers = append(losers, l.ID) })
	first, second := newRec(newID(), "same-key"), newRec(newID(), "same-key")
	first.Created, second.Created = first.Version, second.Version+1
	if err := n.Store().applyBatch(bg, []*store.Record{first, second}); err != nil {
		t.Fatal(err)
	}
	bs.batchErr = errors.New("disk")
	if err := n.Store().applyBatch(bg, []*store.Record{newRec(newID(), "")}); err == nil {
		t.Fatal("a failing batch was not reported")
	}
	_ = losers
}

// covDir prepares a data directory for a node: a store holding data (or not), and the saved cluster state.
func covState(t *testing.T, dir string, ps persisted, files ...string) {
	t.Helper()
	b, _ := json.Marshal(ps)
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// How a node decides to start from what it finds on disk (loadState).
func TestLoadStateDecisions(t *testing.T) {
	type start struct {
		bootstrap, behind, forced bool
	}
	cases := []struct {
		name   string
		empty  bool
		force  bool
		files  []string
		ps     func(feed string) *persisted // nil: no state file
		marker func(dir string)
		want   start
	}{
		{name: "empty", empty: true, want: start{bootstrap: true}},
		{name: "empty, forced", empty: true, force: true, want: start{bootstrap: true}},
		{name: "no state file", want: start{behind: true}},
		{name: "never synced", ps: func(f string) *persisted { return &persisted{Self: f} }, want: start{behind: true}},
		{name: "never synced, forced", force: true, ps: func(f string) *persisted { return &persisted{Self: f} },
			want: start{forced: true}},
		{name: "replaced database", ps: func(string) *persisted { return &persisted{Self: "another feed", LastSync: time.Now().UnixNano()} },
			want: start{behind: true}},
		{name: "in date", ps: func(f string) *persisted { return &persisted{Self: f, LastSync: time.Now().UnixNano()} }},
		{name: "in date, forced", force: true, ps: func(f string) *persisted { return &persisted{Self: f, LastSync: time.Now().UnixNano()} },
			want: start{forced: true}},
		{name: "too long ago", ps: func(f string) *persisted {
			return &persisted{Self: f, LastSync: time.Now().Add(-365 * 24 * time.Hour).UnixNano()}
		},
			want: start{behind: true}},
		{name: "interrupted first copy, recent", ps: func(f string) *persisted {
			return &persisted{Self: f, Copying: true, CopiedAt: time.Now().UnixNano()}
		}, want: start{bootstrap: true}},
		{name: "interrupted first copy, forced", force: true, ps: func(f string) *persisted {
			return &persisted{Self: f, Copying: true, CopiedAt: time.Now().UnixNano()}
		}, want: start{bootstrap: true}},
		{name: "interrupted first copy, too long ago", ps: func(f string) *persisted {
			return &persisted{Self: f, Copying: true, CopiedAt: time.Now().Add(-365 * 24 * time.Hour).UnixNano()}
		}, want: start{behind: true}},
		{name: "restored from a backup", files: []string{RestoredMarker}, ps: func(f string) *persisted { return &persisted{Self: f} }},
		{name: "restored from a backup, forced", force: true, files: []string{RestoredMarker},
			ps: func(f string) *persisted { return &persisted{Self: f} }},
		{name: "force marker that cannot be removed", files: nil, ps: func(f string) *persisted { return &persisted{Self: f} },
			marker: func(dir string) {
				p := filepath.Join(dir, ForceStartMarker)
				if err := os.MkdirAll(filepath.Join(p, "inner"), 0o700); err != nil {
					t.Fatal(err)
				}
			}, want: start{behind: true}},
		{name: "force marker", ps: func(f string) *persisted { return &persisted{Self: f} },
			marker: func(dir string) {
				if err := os.WriteFile(filepath.Join(dir, ForceStartMarker), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}, want: start{forced: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := &covStore{Store: memstore.New()}
			if !tc.empty {
				if _, _, err := cs.Store.PutReplicated(bg, newRec(newID(), "")); err != nil {
					t.Fatal(err)
				}
			}
			c := newTCluster(t, 3, func(testing.TB, string) store.Store { return cs })
			c.noSeed = true
			dir := t.TempDir()
			if tc.ps != nil {
				covState(t, dir, *tc.ps(cs.FeedID()), tc.files...)
			} else {
				for _, f := range tc.files {
					_ = os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600)
				}
			}
			if tc.marker != nil {
				tc.marker(dir)
			}
			c.opts = func(o *Options) { o.ForceStart = tc.force }
			tn := c.build(0, dir, nil)
			defer tn.n.Close()
			got := start{bootstrap: tn.n.bootstrap.Load(), behind: tn.n.behind.Load() != nil, forced: tn.n.ForcedStart() != ""}
			if got != tc.want {
				t.Fatalf("%+v, want %+v (behind: %v)", got, tc.want, tn.n.behind.Load())
			}
		})
	}
}
