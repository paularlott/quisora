package cluster

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func TestStandaloneEphemeralDirect(t *testing.T) {
	n, _ := hnode(t)
	e := n.Ephemeral()
	id, err := e.New(bg, "ns", []byte("a"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Set(bg, "ns", id, []byte("b"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, err := e.Get(bg, "ns", id); err != nil || string(v) != "b" {
		t.Fatalf("%q %v", v, err)
	}
	if err := e.Delete(bg, "ns", id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Get(bg, "ns", id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if !n.ServesTokens() {
		t.Fatal("a standalone node serves tokens")
	}
	n.rebuild() // nothing to rebuild without gossip
	n.publishReady()
	if n.peersExpected() {
		t.Fatal("a standalone node expects no peers")
	}
}

func TestStandaloneFreshAndStamp(t *testing.T) {
	n, cs := hnode(t)
	s := n.Store()
	u := mustEncode(t, newUser("org1", "fresh"))
	if err := cs.Store.Put(bg, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.Fresh(bg, model.KindUser, []string{u.ID, "missing"})
	if err != nil || len(got) != 1 || got[u.ID] == nil {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := s.Fresh(bg, model.KindUser, nil); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	cs.lookup = errors.New("disk")
	if _, err := s.Fresh(bg, model.KindUser, []string{u.ID}); err == nil {
		t.Fatal("a store error was swallowed")
	}
	if _, err := s.stamp(bg, mustEncode(t, newUser("org1", "x")), modeMatch, 0); err == nil {
		t.Fatal("a store error was swallowed by stamp")
	}
	cs.lookup = nil

	// The local precondition of a compare-and-swap.
	if _, err := s.stamp(bg, mustEncode(t, newUser("org1", "x")), modeMatch, 0); err != nil {
		t.Fatalf("a create: %v", err)
	}
	same := *u
	if _, err := s.stamp(bg, &same, modeMatch, 0); !errors.Is(err, store.ErrStale) {
		t.Fatalf("a create over a live record: %v", err)
	}
	if _, err := s.stamp(bg, &same, modeMatch, u.Version+1); !errors.Is(err, store.ErrStale) {
		t.Fatalf("an update of another version: %v", err)
	}
	if _, err := s.stamp(bg, &same, modeMatch, u.Version); err != nil {
		t.Fatalf("an update of the version held: %v", err)
	}
}

func TestGossipNodeFreshAndQuorumWriteRefused(t *testing.T) {
	n, _ := gnode(t)
	n.catchingUp.Store(true)
	if _, err := n.Store().Fresh(bg, model.KindUser, []string{"x"}); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("a node that has not caught up: %v", err)
	}
	// Without a quorum in view a quorum kind is not written at all.
	if err := n.Store().Put(bg, mustEncode(t, newUser("org1", "refused"))); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("%v", err)
	}
	// A durable write with fewer peers than a majority needs is not confirmed.
	if err := n.canConfirm(); err == nil {
		t.Fatal("a node alone can confirm")
	}
	if err := n.ackPeers(bg, nil); !errors.Is(err, ErrNotReplicated) {
		t.Fatalf("%v", err)
	}
	if ms := n.members(true); len(ms) != 1 || !ms[0].Self || !ms[0].Ready || ms[0].Address == "" {
		t.Fatalf("%+v", ms)
	}
}

func TestHandleReadLargeAndUnencodable(t *testing.T) {
	n, cs := hnode(t)
	big := covRec(model.KindUser, "big", store.Clock.Now())
	big.Data = make([]byte, 32<<10)
	odd := covRec(model.KindUser, "odd", store.Clock.Now())
	odd.Fields = map[string]any{"f": 1.5}
	for _, r := range []*store.Record{big, odd} {
		if _, _, err := cs.Store.PutReplicated(bg, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.handleRead(covPacket(t, &readReq{Kind: "user", IDs: []string{"big"}}), &covFailWriter{failAt: 1}); err == nil {
		t.Error("a failing stream was not reported while writing a frame")
	}
	if err := n.handleRead(covPacket(t, &readReq{Kind: "user", IDs: []string{"odd"}}), &covFailWriter{failAt: 1 << 30}); err == nil {
		t.Error("a record that cannot be encoded was served")
	}
	if _, err := n.feedPage(nil, covPacket(t, &feedReq{FeedID: cs.FeedID()})); err == nil {
		t.Error("a feed page with a record that cannot be encoded was served")
	}
}

func TestClockReadings(t *testing.T) {
	n, _ := gnode(t)
	now := time.Now()
	n.clockReading("p1", now, now, 0) // a reply with no time says nothing
	if len(n.clocks.last) != 0 {
		t.Fatal("a reading without a time was kept")
	}
	// A peer whose clock is hours behind this one's: this node's is ahead of the cluster's, and it stops serving.
	n.clockReading("p1", now, now, now.Add(-2*time.Hour).UnixNano())
	if why := n.clockOff.Load(); why == nil || !strings.Contains(*why, "ahead of") {
		t.Fatalf("%v", why)
	}
	n.clockReading("p1", now, now, now.UnixNano())
	if n.clockOff.Load() != nil {
		t.Fatal("not serving again once the clocks agree")
	}
	n.clockReading("p1", now, now, now.Add(2*time.Hour).UnixNano())
	if why := n.clockOff.Load(); why == nil || !strings.Contains(*why, "behind") {
		t.Fatalf("%v", why)
	}
}

func TestCheckSkewWarnsOncePerOrigin(t *testing.T) {
	n, _ := hnode(t)
	rec := newRec(newID(), "")
	rec.Origin = "far-ahead-node"
	rec.Version = hlc.FromTime(time.Now().Add(2 * time.Hour))
	n.checkSkew(rec)
	n.checkSkew(rec)
	if n.skewed.Load() != 2 {
		t.Fatalf("counted %d", n.skewed.Load())
	}
	if _, ok := n.skewWarned.Load("far-ahead-node"); !ok {
		t.Fatal("not noted")
	}
}

func TestSaveStateAndMarkSyncedFailures(t *testing.T) {
	n, _ := gnode(t)
	n.stateFile = filepath.Join(t.TempDir(), "missing", "cluster-state.json")
	n.dirty.Store(true)
	n.saveState() // logged; the state stays dirty for the next try
	if !n.dirty.Load() {
		t.Fatal("a failed save lost the dirty flag")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MarkSynced(filepath.Join(file, "dir"), "feed"); err == nil {
		t.Fatal("a directory under a file was made")
	}
}

func TestStartWithoutOtherPeers(t *testing.T) {
	n, _ := gnode(t)
	n.seedMu.Lock()
	n.seeds, n.seedsSet = nil, true
	n.seedMu.Unlock()
	if err := n.Start(bg); err == nil || !strings.Contains(err.Error(), "names no other node") {
		t.Fatalf("%v", err)
	}
}

// A shared-database node whose database does not answer says so, and keeps trying.
func TestSharedNodeStartsWithoutDatabase(t *testing.T) {
	saved := leaseRenew
	leaseRenew = 20 * time.Millisecond
	t.Cleanup(func() { leaseRenew = saved })
	cs := &covStore{Store: memstore.New()}
	n := snode(t, cs)
	cs.get = errors.New("db down")
	if err := n.Start(bg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the lease to be tried again", func() bool { return cs.gets.Load() >= 4 })
	if n.IsLeader() {
		t.Fatal("a node without its database leads")
	}
}

// A durable write that peers refuse is not confirmed, whichever way they refuse it; one the caller abandons is not
// either.
func TestDurablePushRefusedAndAbandoned(t *testing.T) {
	c := covStarted(t)
	a := c.nodes[0].n
	why := "behind"
	c.nodes[1].n.behind.Store(&why)
	c.nodes[2].n.behind.Store(&why)
	rec := newRec(newID(), "")
	b := covEncode(t, rec)
	if err := a.ackPeers(bg, b); !errors.Is(err, ErrNotReplicated) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("peers that refuse: %v", err)
	}
	c.nodes[1].n.behind.Store(nil)
	c.nodes[2].n.behind.Store(nil)

	ns := c.net(0)
	ns.mu.Lock()
	ns.slowMsg, ns.slowBy = msgPush, 30*time.Second
	ns.mu.Unlock()
	defer func() { ns.mu.Lock(); ns.slowBy = 0; ns.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	if err := a.ackPeers(ctx, b); !errors.Is(err, ErrNotReplicated) {
		t.Fatalf("an abandoned write: %v", err)
	}
	// A record that cannot be put on the wire fails the write after it was applied here.
	bad := newRec(newID(), "")
	bad.Fields["f"] = 1.5
	if err := c.nodes[0].st().Put(bg, bad); err == nil {
		t.Fatal("an unencodable record was reported replicated")
	}
}

// A quorum read counts the nodes that answer: it needs one peer besides this node.
func TestFreshQuorumReads(t *testing.T) {
	c := covStarted(t)
	tn := c.nodes[0]
	u := newUser("org1", "fresh-read")
	if err := users(tn).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(*model.User) bool { return true })
	got, err := tn.st().Fresh(bg, model.KindUser, []string{u.ID, "missing"})
	if err != nil || len(got) != 1 || got[u.ID] == nil {
		t.Fatalf("%v %v", got, err)
	}
	// One peer cannot be opened a stream to: the other makes the quorum.
	c.drop(0, 1, true, msgRead, msgReadFew)
	if got, err := tn.st().Fresh(bg, model.KindUser, []string{u.ID}); err != nil || len(got) != 1 {
		t.Fatalf("one peer cut off: %v %v", got, err)
	}
	// Both cut off: not a quorum.
	c.drop(0, 2, true, msgRead, msgReadFew)
	if _, err := tn.st().Fresh(bg, model.KindUser, []string{u.ID}); !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("no peer: %v", err)
	}
	c.drop(0, 1, false, msgRead, msgReadFew)
	c.drop(0, 2, false, msgRead, msgReadFew)
}

// A whole-record write made from a copy that has fallen behind re-bases on the newer copy and goes through.
func TestUpsertFromStaleCopyRebases(t *testing.T) {
	c := covStarted(t)
	u := newUser("org1", "stale-upsert")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(*model.User) bool { return true })
	c.lagBehind(0, true)
	defer c.lagBehind(0, false)
	newer, err := users(c.nodes[1]).Get(bg, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	newer.Email = "changed-on-1@example.com"
	if err := users(c.nodes[1]).Update(bg, newer); err != nil {
		t.Fatal(err)
	}
	stale, err := users(c.nodes[0]).Get(bg, u.ID)
	if err != nil || stale.Email == newer.Email {
		t.Fatalf("test set-up: node 0 is not behind (%v)", err)
	}
	stale.GivenName = "from-the-stale-copy"
	if err := users(c.nodes[0]).Put(bg, stale); err != nil {
		t.Fatalf("an upsert from a stale copy: %v", err)
	}
	got, err := users(c.nodes[0]).Get(bg, u.ID)
	if err != nil || got.GivenName != "from-the-stale-copy" {
		t.Fatalf("%v %v", got, err)
	}
}
