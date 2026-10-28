package cluster

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

func TestLeaseTickOutcomes(t *testing.T) {
	cs := &failStore{Store: memstore.New()}
	n := snode(t, cs)
	l := n.lease
	if l.reachable() {
		t.Fatal("reachable before any answer")
	}
	if ok, why := n.Ready(); ok || !strings.Contains(why, "not answering") {
		t.Fatalf("a shared node that has not reached its database: %v %q", ok, why)
	}

	// The database fails: no lease, not reachable, the error is reported.
	cs.get = errors.New("db down")
	if err := l.tick(bg); err == nil || l.until.Load() != 0 || l.reachable() {
		t.Fatalf("db down: %v until %d reachable %v", err, l.until.Load(), l.reachable())
	}
	cs.get = nil

	// Another node got there first (the create loses), which is not an error and shows the database answers.
	cs.cas = store.ErrConflict
	if err := l.tick(bg); err != nil || l.held() || !l.reachable() {
		t.Fatalf("lost the race: %v held %v reachable %v", err, l.held(), l.reachable())
	}
	// Any other failure of the write is an error.
	cs.cas = errors.New("disk full")
	if err := l.tick(bg); err == nil {
		t.Fatal("a failing lease write was not reported")
	}
	cs.cas = nil

	// Free: this node takes it, with a fencing token; renewing keeps the token.
	if err := l.tick(bg); err != nil || !l.held() || l.token.Load() == 0 {
		t.Fatalf("take: %v held %v token %d", err, l.held(), l.token.Load())
	}
	token := l.token.Load()
	if !n.IsLeader() {
		t.Fatal("the holder is not the leader")
	}
	if err := l.tick(bg); err != nil || l.token.Load() != token {
		t.Fatalf("renew: %v token %d (was %d)", err, l.token.Load(), token)
	}
	// A renewal that loses to a write by another node is not an error either.
	cs.cas = store.ErrStale
	if err := l.tick(bg); err != nil || l.held() {
		t.Fatalf("stale renewal: %v held %v", err, l.held())
	}
	cs.cas = nil
	if err := l.tick(bg); err != nil || !l.held() {
		t.Fatalf("take again: %v", err)
	}

	// Someone else holds it: this node leads no more.
	e, err := l.st.Get(bg, leaseID)
	if err != nil {
		t.Fatal(err)
	}
	e.Value = []byte("another-node")
	if err := l.st.Update(bg, e); err != nil {
		t.Fatal(err)
	}
	if err := l.tick(bg); err != nil || l.held() || !l.reachable() {
		t.Fatalf("another holder: %v held %v", err, l.held())
	}
	if n.IsLeader() {
		t.Fatal("a node without the lease leads")
	}
}

// A lease record this node cannot read back (or one without a creation version) gives no fencing token, so no lease.
func TestLeaseTickWithoutToken(t *testing.T) {
	cs := &failStore{Store: memstore.New()}
	n := snode(t, cs)
	calls := 0
	cs.getHook = func(r *store.Record, err error) (*store.Record, error) {
		calls++
		if calls == 2 { // the read of the record just created
			cp := *r
			cp.Created = 0
			return &cp, nil
		}
		return r, err
	}
	if err := n.lease.tick(bg); err != nil || n.lease.held() || n.lease.token.Load() != 0 {
		t.Fatalf("%v held %v token %d", err, n.lease.held(), n.lease.token.Load())
	}
}

func TestLeaseReleaseAndFence(t *testing.T) {
	shared := memstore.New()
	a, b := snode(t, shared), snode(t, shared)
	// Not held: nothing to release.
	a.lease.release(bg)
	if err := a.lease.tick(bg); err != nil || !a.IsLeader() {
		t.Fatal(err)
	}
	ctx := a.fence(bg)
	if err := a.fenced(ctx); err != nil {
		t.Fatalf("the holder: %v", err)
	}
	if err := a.fenced(bg); err != nil {
		t.Fatalf("an unfenced context: %v", err)
	}
	a.lease.release(bg)
	if a.IsLeader() {
		t.Fatal("still leader after releasing")
	}
	if err := a.fenced(ctx); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a fenced write after the release: %v", err)
	}
	// The other node takes over at once.
	if err := b.lease.tick(bg); err != nil || !b.IsLeader() {
		t.Fatalf("b: %v", err)
	}
	// A node that is not the holder keeps its hands off housekeeping: purging is the leader's.
	old := store.Tombstone(dataKind, "t")
	old.Version = store.Clock.Now() - 1
	if _, err := shared.PutReplicated(bg, old); err != nil {
		t.Fatal(err)
	}
	a.purgeOnce(bg, time.Now().Add(48*time.Hour))
	if _, err := shared.Lookup(bg, dataKind, "t"); err != nil {
		t.Fatalf("a node without the lease purged: %v", err)
	}
	// A leader whose lease record was taken over since is fenced out of purging too.
	e, _ := b.lease.st.Get(bg, leaseID)
	e.Value = []byte("another-node")
	if err := b.lease.st.Update(bg, e); err != nil {
		t.Fatal(err)
	}
	b.purgeOnce(bg, time.Now().Add(48*time.Hour))
	if _, err := shared.Lookup(bg, dataKind, "t"); err != nil {
		t.Fatalf("a fenced-out leader purged: %v", err)
	}
	// The real holder purges (tombstones are kept an hour on a shared database).
	c := snode(t, shared)
	e.Value = []byte(c.ID())
	if err := b.lease.st.Update(bg, e); err != nil {
		t.Fatal(err)
	}
	if err := c.lease.tick(bg); err != nil || !c.IsLeader() {
		t.Fatalf("c: %v", err)
	}
	c.purgeOnce(bg, time.Now().Add(48*time.Hour))
	if _, err := shared.Lookup(bg, dataKind, "t"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the holder did not purge: %v", err)
	}
}

// Nodes sharing one database without gossip elect a housekeeper with a lease. A node that lost the lease (it
// stalled past its expiry and another node took over) has its housekeeping writes refused: the lease generation it
// started under is no longer the current one.
func TestHousekeepingFencedAfterLeaseLoss(t *testing.T) {
	saved := [3]time.Duration{leaseTTL, leaseRenew, leaseMargin}
	leaseTTL, leaseRenew, leaseMargin = 600*time.Millisecond, time.Hour, 100*time.Millisecond
	t.Cleanup(func() { leaseTTL, leaseRenew, leaseMargin = saved[0], saved[1], saved[2] })
	shared := memstore.New()
	mk := func() *Node {
		cfg := config.Default()
		cfg.Server.DataDir = t.TempDir()
		cfg.Storage.Backend = "postgres" // a database server the nodes share (not opened: the store is given)
		n, err := New(cfg, shared, Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		return n
	}
	a, b := mk(), mk()
	if err := a.lease.tick(bg); err != nil || !a.IsLeader() {
		t.Fatalf("a takes the lease: %v", err)
	}
	ctx := a.fence(bg)
	if err := a.Store().Put(ctx, newRec(model.NewID(), "")); err != nil {
		t.Fatalf("the holder's housekeeping write: %v", err)
	}
	time.Sleep(700 * time.Millisecond) // a stalls past its lease
	if err := b.lease.tick(bg); err != nil || !b.IsLeader() {
		t.Fatalf("b takes over: %v", err)
	}
	a.lease.until.Store(time.Now().Add(time.Hour).UnixNano()) // a's clock (or pause) makes it believe it still leads
	if err := a.Store().Put(ctx, newRec(model.NewID(), "")); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a housekeeping write after the lease passed on: %v", err)
	}
	if err := b.Store().Put(b.fence(bg), newRec(model.NewID(), "")); err != nil {
		t.Fatalf("the new holder's housekeeping write: %v", err)
	}
	if err := a.Store().Put(bg, newRec(model.NewID(), "")); err != nil {
		t.Fatalf("an ordinary (unfenced) write: %v", err)
	}
}

// A shared-database node whose database does not answer says so, and keeps trying.
func TestSharedNodeStartsWithoutDatabase(t *testing.T) {
	saved := leaseRenew
	leaseRenew = 20 * time.Millisecond
	t.Cleanup(func() { leaseRenew = saved })
	cs := &failStore{Store: memstore.New()}
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

// clockedStore is a shared database whose server clock is off from this machine's by off, and whose reading takes rtt.
type clockedStore struct {
	*memstore.Store
	off, rtt atomic.Int64 // nanoseconds
	reads    atomic.Int64
}

func (s *clockedStore) ServerTime(context.Context) (time.Time, error) {
	s.reads.Add(1)
	time.Sleep(time.Duration(s.rtt.Load()) / 2)
	now := time.Now().Add(time.Duration(s.off.Load()))
	time.Sleep(time.Duration(s.rtt.Load()) / 2)
	return now, nil
}

// startClocked starts a shared-database node over a store with a skewed server clock; the lease (and with it the
// clock reading) ticks every 20 ms.
func startClocked(t *testing.T, off, rtt time.Duration) (*Node, *clockedStore) {
	t.Helper()
	saved := leaseRenew
	leaseRenew = 20 * time.Millisecond
	t.Cleanup(func() { leaseRenew = saved })
	cs := &clockedStore{Store: memstore.New()}
	cs.off.Store(int64(off))
	cs.rtt.Store(int64(rtt))
	n := snode(t, cs)
	if err := n.Start(bg); err != nil {
		t.Fatal(err)
	}
	return n, cs
}

// Nodes sharing a database stamp expiries with their own clocks, so one whose clock is off from the database server's
// refuses to serve, as a gossip node does when it is off from its peers, and serves again once it is within half the
// bound. /readyz (Status) reports the offset.
func TestSharedDatabaseClockRefusesToServe(t *testing.T) {
	n, cs := startClocked(t, 3*time.Second, 0) // within the bound
	if ok, why := n.Ready(); !ok {
		t.Fatalf("a node 3 s off its database's clock is not ready: %s", why)
	}
	if ms := n.Status().ClockOffsetMs; ms == nil || *ms < 2900 || *ms > 3100 {
		t.Fatalf("the offset in the status: %v", ms)
	}
	notReady := func(what, dir string) {
		t.Helper()
		waitFor(t, 5*time.Second, what, func() bool {
			ok, why := n.Ready()
			return !ok && strings.Contains(why, dir+" the database server's")
		})
	}

	cs.off.Store(int64(time.Minute)) // the database's clock a minute ahead: this node's is behind
	notReady("not ready a minute behind", "behind")
	if ms := n.Status().ClockOffsetMs; ms == nil || *ms < 59000 {
		t.Fatalf("the offset in the status: %v", ms)
	}
	cs.off.Store(int64(-time.Minute))
	notReady("not ready a minute ahead", "ahead of")

	// Within the bound but not within half of it: it keeps refusing (no flapping at the edge).
	cs.off.Store(int64(4 * time.Second))
	reads := cs.reads.Load()
	waitFor(t, 5*time.Second, "a reading", func() bool { return cs.reads.Load() >= reads+3 })
	if ok, _ := n.Ready(); ok {
		t.Fatal("a node 4 s off served again before it was within 2.5 s")
	}
	cs.off.Store(int64(time.Second))
	waitFor(t, 5*time.Second, "serving again", func() bool { ok, _ := n.Ready(); return ok })
}

// A reading whose round trip was long says nothing about the offset (the midpoint is a guess), however far off it
// looks: it is ignored, neither refusing nor lifting a refusal, and the next quick one decides.
func TestSharedDatabaseClockIgnoresSlowReadings(t *testing.T) {
	saved := dbClockRTT
	dbClockRTT = 50 * time.Millisecond
	t.Cleanup(func() { dbClockRTT = saved })
	reads := func(cs *clockedStore, n int64) {
		t.Helper()
		from := cs.reads.Load()
		waitFor(t, 10*time.Second, "more readings", func() bool { return cs.reads.Load() >= from+n })
	}
	n, cs := startClocked(t, time.Hour, 200*time.Millisecond)
	reads(cs, 3)
	if ok, why := n.Ready(); !ok || n.Status().ClockOffsetMs != nil {
		t.Fatalf("slow readings an hour off refused a node (%s) or showed an offset: %v", why, n.Status().ClockOffsetMs)
	}

	cs.rtt.Store(0)
	waitFor(t, 5*time.Second, "not ready an hour off", func() bool { ok, _ := n.Ready(); return !ok })

	cs.off.Store(0)
	cs.rtt.Store(int64(200 * time.Millisecond))
	reads(cs, 3)
	if ok, _ := n.Ready(); ok {
		t.Fatal("slow readings lifted the refusal")
	}
	cs.rtt.Store(0)
	waitFor(t, 5*time.Second, "serving again", func() bool { ok, _ := n.Ready(); return ok })
}

// Two nodes on one database with the notice gossip (cluster.notify): a write on one runs the other's change hooks
// within moments; the writer's own hooks run once, for its own write. Without cluster.notify there is no gossip.
func TestSharedDatabaseNoticeGossip(t *testing.T) {
	shared, err := sqlstore.Open(bg, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "shared.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shared.Close() })
	key := testKey()
	addrs := []string{clustertest.FreeAddr(t), clustertest.FreeAddr(t)}
	mk := func(i int) *Node {
		cfg := config.Default()
		cfg.Server.DataDir = t.TempDir()
		cfg.Storage.Backend = "postgres" // a database server the nodes share (not opened: the store is given)
		cfg.Cluster.Notify = config.Notify{Bind: addrs[i], Peers: addrs, Key: key}
		n, err := New(cfg, shared, Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		return n
	}
	a, b := mk(0), mk(1)
	if a.ngc == nil || !a.SharedDatabase() {
		t.Fatal("no notice gossip")
	}
	var mu sync.Mutex
	got := map[*Node][]string{}
	for _, n := range []*Node{a, b} {
		n.OnChange(func(rec *store.Record, local bool) {
			mu.Lock()
			defer mu.Unlock()
			tag := "remote"
			if local {
				tag = "local"
			}
			del := ""
			if rec.Deleted {
				del = ":deleted"
			}
			got[n] = append(got[n], string(rec.Kind)+":"+rec.ID+":"+rec.Scope+del+":"+tag)
		})
	}
	for _, n := range []*Node{a, b} {
		if err := n.Start(bg); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 5*time.Second, "notice gossip joined", func() bool { return a.ngc.NumAliveNodes() >= 2 && b.ngc.NumAliveNodes() >= 2 })
	rec := newRec(model.NewID(), "")
	if err := a.st.Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	gone := newRec(model.NewID(), "")
	gone.Kind, gone.Deleted = model.KindUser, true
	if err := a.st.Put(bg, gone); err != nil {
		t.Fatal(err)
	}
	// Notices are gossiped: they may arrive in either order, and a node hears of other writes too (its id's lease
	// renewed, say), so what a node heard of these two records is compared as a set. (Under mu.)
	of := func(n *Node, ids ...string) []string {
		var out []string
		for _, g := range got[n] {
			for _, id := range ids {
				if strings.Contains(g, ":"+id+":") {
					out = append(out, g)
				}
			}
		}
		slices.Sort(out)
		return out
	}
	waitFor(t, 5*time.Second, "b hears of both", func() bool { mu.Lock(); defer mu.Unlock(); return len(of(b, rec.ID, gone.ID)) >= 2 })
	mu.Lock()
	defer mu.Unlock()
	want := []string{string(dataKind) + ":" + rec.ID + ":org1:remote", "user:" + gone.ID + ":org1:deleted:remote"}
	slices.Sort(want)
	if g := of(b, rec.ID, gone.ID); !slices.Equal(g, want) {
		t.Errorf("b got %v, want %v", g, want)
	}
	if g := of(a, rec.ID, gone.ID); len(g) != 2 || !slices.Contains(g, string(dataKind)+":"+rec.ID+":org1:local") {
		t.Errorf("a (the writer) got %v", g)
	}

	// a real deletion (store.Tombstone: no scope) still tells both nodes' hooks the scope of what it removed
	mu.Unlock()
	if err := a.st.Put(bg, store.Tombstone(rec.Kind, rec.ID)); err != nil {
		t.Fatal(err)
	}
	deleted := string(dataKind) + ":" + rec.ID + ":org1:deleted:"
	waitFor(t, 5*time.Second, "b hears of the deletion", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Contains(got[b], deleted+"remote")
	})
	mu.Lock()
	if !slices.Contains(got[a], deleted+"local") {
		t.Errorf("a got %v, no local notice of its deletion", got[a])
	}

	// without cluster.notify: no notice gossip
	cfg := config.Default()
	cfg.Server.DataDir = t.TempDir()
	cfg.Storage.Backend = "postgres"
	plain, err := New(cfg, shared, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if plain.ngc != nil {
		t.Error("notice gossip without cluster.notify")
	}
}

// A configuration reload reaches every node sharing the database through the notice gossip, in the same two phases
// as a gossip cluster: one node that cannot apply it stops it everywhere. Without cluster.notify only the node asked
// reloads, and the error says so.
func TestSharedDatabaseReloadOverNoticeGossip(t *testing.T) {
	shared, err := sqlstore.Open(bg, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "shared.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shared.Close() })
	key := testKey()
	addrs := []string{clustertest.FreeAddr(t), clustertest.FreeAddr(t)}
	var mu sync.Mutex
	applied := map[string]int{}
	refuse := map[string]bool{}
	mk := func(i int) *Node {
		cfg := config.Default()
		cfg.Server.DataDir = t.TempDir()
		cfg.Storage.Backend = "postgres"
		cfg.Cluster.Notify = config.Notify{Bind: addrs[i], Peers: addrs, Key: key}
		n, err := New(cfg, shared, Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		n.SetReloader(func(_ context.Context, apply bool, _ int) ReloadReport {
			mu.Lock()
			defer mu.Unlock()
			if refuse[n.ID()] {
				return ReloadReport{Error: "master keys: not base64"}
			}
			if apply {
				applied[n.ID()]++
			}
			return ReloadReport{}
		})
		return n
	}
	a, b := mk(0), mk(1)
	for _, n := range []*Node{a, b} {
		if err := n.Start(bg); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 5*time.Second, "notice gossip joined", func() bool { return a.ngc.NumAliveNodes() >= 2 && b.ngc.NumAliveNodes() >= 2 })

	reports, err := a.ReloadCluster(bg)
	if err != nil || len(reports) != 2 {
		t.Fatalf("reload: %v %+v", err, reports)
	}
	mu.Lock()
	if applied[a.ID()] != 1 || applied[b.ID()] != 1 {
		t.Fatalf("applied %v", applied)
	}
	refuse[b.ID()] = true
	mu.Unlock()
	if _, err := a.ReloadCluster(bg); err == nil {
		t.Fatal("a node that cannot apply the configuration did not stop the reload")
	}
	mu.Lock()
	if applied[a.ID()] != 1 {
		t.Fatalf("applied on a although b refused: %v", applied)
	}
	mu.Unlock()

	// without cluster.notify: this node only, and the error says so
	cfg := config.Default()
	cfg.Server.DataDir = t.TempDir()
	cfg.Storage.Backend = "postgres"
	plain, err := New(cfg, shared, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	plain.SetReloader(func(context.Context, bool, int) ReloadReport { return ReloadReport{} })
	if _, err := plain.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "cluster.notify") {
		t.Fatalf("shared database without notify: %v", err)
	}
}

func TestHandleNotice(t *testing.T) {
	n, _ := hnode(t)
	var got []*store.Record
	n.OnChange(func(r *store.Record, local bool) {
		if local {
			t.Error("a notice is not a local change")
		}
		got = append(got, r)
	})
	n.OnChange(func(*store.Record, bool) {}) // a second hook: both are kept
	if err := n.handleNotice(nil, badPacket(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	for _, m := range []noticeMsg{{}, {K: "user"}, {I: "x"}} {
		if err := n.handleNotice(nil, packetOf(t, &m)); err != nil {
			t.Error(err)
		}
	}
	if len(got) != 0 {
		t.Fatalf("an incomplete notice ran the hooks: %v", got)
	}
	if err := n.handleNotice(nil, packetOf(t, &noticeMsg{K: "user", I: "u1", S: "org", D: true})); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != model.KindUser || got[0].ID != "u1" || got[0].Scope != "org" || !got[0].Deleted {
		t.Fatalf("%+v", got)
	}
	n.notice(got[0]) // no notice gossip: nothing to send
	if noticeWorthy(model.KindEphemeral) || noticeWorthy(model.KindLock) || noticeWorthy(model.KindQueue) || !noticeWorthy(model.KindUser) {
		t.Error("noticeWorthy")
	}
}

func TestReloadClusterSharedDatabaseWithoutNotify(t *testing.T) {
	cfg := tempConfig(t)
	cfg.Storage.Backend = "postgres" // shared, not opened: the store is given
	n, err := New(cfg, memstore.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.SetReloader(func(context.Context, bool, int) ReloadReport { return ReloadReport{} })
	if reps, err := n.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "this node only") || len(reps) != 1 {
		t.Fatalf("%v %v", reps, err)
	}
	if n.EphemeralStore() == ephemeral.Store(n.Ephemeral()) {
		t.Error("a node sharing a database keeps ephemeral state in it")
	}
}
