package cluster

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
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
	if err := a.Store().Put(ctx, newRec(newID(), "")); err != nil {
		t.Fatalf("the holder's housekeeping write: %v", err)
	}
	time.Sleep(700 * time.Millisecond) // a stalls past its lease
	if err := b.lease.tick(bg); err != nil || !b.IsLeader() {
		t.Fatalf("b takes over: %v", err)
	}
	a.lease.until.Store(time.Now().Add(time.Hour).UnixNano()) // a's clock (or pause) makes it believe it still leads
	if err := a.Store().Put(ctx, newRec(newID(), "")); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a housekeeping write after the lease passed on: %v", err)
	}
	if err := b.Store().Put(b.fence(bg), newRec(newID(), "")); err != nil {
		t.Fatalf("the new holder's housekeeping write: %v", err)
	}
	if err := a.Store().Put(bg, newRec(newID(), "")); err != nil {
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
	rec := newRec(newID(), "")
	if err := a.st.Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	gone := newRec(newID(), "")
	gone.Kind, gone.Deleted = model.KindUser, true
	if err := a.st.Put(bg, gone); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "b hears of both", func() bool { mu.Lock(); defer mu.Unlock(); return len(got[b]) >= 2 })
	mu.Lock()
	defer mu.Unlock()
	want := []string{string(dataKind) + ":" + rec.ID + ":org1:remote", "user:" + gone.ID + ":org1:deleted:remote"}
	if len(got[b]) != 2 || got[b][0] != want[0] || got[b][1] != want[1] {
		t.Errorf("b got %v, want %v", got[b], want)
	}
	if len(got[a]) != 2 || got[a][0] != string(dataKind)+":"+rec.ID+":org1:local" {
		t.Errorf("a (the writer) got %v", got[a])
	}

	// a real deletion (store.Tombstone: no scope) still tells both nodes' hooks the scope of what it removed
	mu.Unlock()
	if err := a.st.Put(bg, store.Tombstone(rec.Kind, rec.ID)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "b hears of the deletion", func() bool { mu.Lock(); defer mu.Unlock(); return len(got[b]) >= 3 })
	mu.Lock()
	if g := got[b][2]; g != string(dataKind)+":"+rec.ID+":org1:deleted:remote" {
		t.Errorf("b got %q for the deletion", g)
	}
	if g := got[a][2]; g != string(dataKind)+":"+rec.ID+":org1:deleted:local" {
		t.Errorf("a got %q for its deletion", g)
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
