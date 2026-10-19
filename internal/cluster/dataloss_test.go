package cluster

import (
	"errors"
	"os"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

// The reviewer's scenarios that used to lose data. Each one checks that every record written before is still there.

func writeN(t *testing.T, tn *tnode, n int) []string {
	t.Helper()
	ids := make([]string, n)
	for i := range ids {
		ids[i] = newID()
		if err := tn.st().Put(bg, newRec(ids[i], "")); err != nil {
			t.Fatal(err)
		}
	}
	return ids
}

func holdsAll(tn *tnode, ids []string) bool {
	for _, id := range ids {
		if !has(tn.st(), id) {
			return false
		}
	}
	return true
}

// restart stops every node and starts them again on the same data directories, all at once.
func (c *tcluster) restartAll(t *testing.T, between func()) {
	t.Helper()
	dirs := make([]string, len(c.nodes))
	for i, tn := range c.nodes {
		dirs[i] = tn.dir
		stop(tn)
	}
	if between != nil {
		between()
	}
	for i := range c.nodes {
		c.nodes[i] = c.build(i, dirs[i], nil)
	}
	c.start(c.nodes...)
}

// HIGH: a node whose id changes on restart (its data directory was not kept, its database was). It refuses to
// serve and wipes nothing; with its id back it serves its data. A whole-cluster restart that loses every id loses
// nothing either.
func TestLostNodeIDNeverWipes(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 100)
	waitFor(t, 15*time.Second, "replicated", func() bool { return holdsAll(c.nodes[1], ids) && holdsAll(c.nodes[2], ids) })
	time.Sleep(time.Second)
	c.restartAll(t, func() {
		for _, tn := range c.nodes {
			_ = os.Remove(filepath.Join(tn.dir, "node_id")) // every node comes back with a new id
			_ = os.Remove(filepath.Join(tn.dir, "cluster-state.json"))
		}
	})
	time.Sleep(2 * time.Second)
	for i, tn := range c.nodes {
		if ok, why := tn.n.Ready(); ok || !strings.Contains(why, "belongs to node") {
			t.Errorf("node %d with a new id: ready=%v %s", i, ok, why)
		}
		if !holdsAll(tn, ids) {
			t.Fatalf("node %d wiped its database after its id changed: %d of %d", i, countAll(tn.st()), len(ids))
		}
	}
}

// HIGH: two gossip nodes misconfigured to share one database; stopping one wipes nothing.
func TestStoppingASharingNodeWipesNothing(t *testing.T) {
	oldTTL, oldRenew, oldMargin := leaseTTL, leaseRenew, leaseMargin
	leaseTTL, leaseRenew, leaseMargin = time.Second, 100*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { leaseTTL, leaseRenew, leaseMargin = oldTTL, oldRenew, oldMargin })
	shared := memstore.New()
	c := newTCluster(t, 2, func(testing.TB, string) store.Store { return shared })
	c.startAll()
	var ids []string
	for range 30 {
		id := newID()
		_ = shared.Put(bg, newRec(id, ""))
		ids = append(ids, id)
	}
	time.Sleep(time.Second)
	stop(c.nodes[1])
	time.Sleep(3 * time.Second) // well past the markers' lifetime
	for _, id := range ids {
		if !has(shared, id) {
			t.Fatal("the shared database was wiped after one of its nodes stopped")
		}
	}
}

func mustVersion(svc *service.Service, id string) hlc.Timestamp {
	o, err := svc.Orgs.Get(bg, id)
	if err != nil {
		return 0
	}
	return o.Version
}

// seedRestored puts records into a node's empty database as a restore would (versions kept) and leaves the marker.
func seedRestored(t *testing.T, dir string, recs ...*store.Record) {
	t.Helper()
	_ = os.RemoveAll(filepath.Join(dir, "badger"))
	_ = os.Remove(filepath.Join(dir, "cluster-state.json"))
	st := badgerBackend(t, dir)
	for _, r := range recs {
		if _, _, err := st.PutReplicated(bg, r); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	if err := os.WriteFile(filepath.Join(dir, RestoredMarker), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// MEDIUM: a restore into one node of a running cluster. The restored node meets peers that hold data: it refuses to
// serve, offers them nothing, and a record only the old backup has never reaches them.
func TestRestoreIntoRunningClusterRefused(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 30)
	waitFor(t, 10*time.Second, "replicated", func() bool { return holdsAll(c.nodes[1], ids) && holdsAll(c.nodes[2], ids) })
	dir := c.nodes[2].dir
	stop(c.nodes[2])
	zombie := newRec(newID(), "") // deleted from the cluster since the backup was taken
	seedRestored(t, dir, zombie)
	c.nodes[2] = c.build(2, dir, nil)
	c.start(c.nodes[2])
	waitFor(t, 10*time.Second, "restored node refuses", func() bool {
		ok, why := c.nodes[2].n.Ready()
		return !ok && strings.Contains(why, "restored from a backup")
	})
	time.Sleep(time.Second)
	for i, tn := range c.nodes[:2] {
		if has(tn.st(), zombie.ID) {
			t.Fatalf("node %d took a record from a backup restored into the running cluster", i)
		}
	}
}

// Restore into an empty cluster: one node restored, the others started with empty databases copy everything from it,
// and it becomes an ordinary member (the marker goes).
func TestRestoreIntoEmptyCluster(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	dirs := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	var recs []*store.Record
	for range 40 {
		recs = append(recs, newRec(newID(), ""))
	}
	seedRestored(t, dirs[0], recs...)
	for i := range 3 {
		c.nodes = append(c.nodes, c.build(i, dirs[i], nil))
	}
	c.start(c.nodes...)
	t.Cleanup(c.closeAll)
	c.waitReady()
	waitFor(t, 15*time.Second, "copied from the restored node", func() bool {
		return countAll(c.nodes[1].st()) == 40 && countAll(c.nodes[2].st()) == 40
	})
	if _, err := os.Stat(filepath.Join(dirs[0], RestoredMarker)); !os.IsNotExist(err) {
		t.Fatalf("restored marker still there: %v", err)
	}
}

// The peers list names this node by host name while it advertises an IP address (or the reverse): it is not counted
// twice, so three nodes keep a majority of two.
func TestSelfInPeersByAnotherName(t *testing.T) {
	ip := "203.0.113.7"
	for _, tc := range []struct {
		peer, adv string
		self      bool
	}{
		{"10.0.0.1:7946", "10.0.0.1:7946", true},
		{"LOCALHOST:7946", "localhost:7946", true},
		{"10.0.0.2:7946", "10.0.0.1:7946", false},
		{"10.0.0.1:7947", "10.0.0.1:7946", false},
		{"localhost:7946", "[::1]:7946", false}, // loopback says nothing about another machine
		{ip + ":7946", ip + ":7946", true},
	} {
		if got := isSelfAddr(tc.peer, tc.adv); got != tc.self {
			t.Errorf("isSelfAddr(%s, %s) = %v, want %v", tc.peer, tc.adv, got, tc.self)
		}
	}
	// this machine's own host name, with a wildcard bind
	if h, err := os.Hostname(); err == nil {
		if !isSelfAddr(h+":7946", "0.0.0.0:7946") {
			t.Errorf("own host name %s not recognised", h)
		}
	}
}

// deleteRec deletes a group record through the cluster store (a replicated tombstone).
func deleteRec(t *testing.T, tn *tnode, id string) {
	t.Helper()
	if err := tn.st().Put(bg, store.Tombstone(model.KindGroup, id)); err != nil {
		t.Fatal(err)
	}
}

// short retention for these tests: a node may go maxDowntime (3s less 0.75s) without a sync.
func shortRetention(o *Options) { o.TombstoneRetention = 3 * time.Second }

// A whole-cluster restart well within the retention: every node merges and keeps everything, including writes only
// it held (applied locally, never confirmed).
func TestWholeClusterRestartMerges(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 100)
	waitFor(t, 15*time.Second, "replicated", func() bool { return holdsAll(c.nodes[1], ids) && holdsAll(c.nodes[2], ids) })
	time.Sleep(time.Second)
	own := make([]string, 3)
	c.restartAll(t, func() {
		for i, tn := range c.nodes { // a write only this node holds
			st := badgerBackend(t, tn.dir)
			own[i] = newID()
			if _, _, err := st.PutReplicated(bg, newRec(own[i], "")); err != nil {
				t.Fatal(err)
			}
			st.Close()
		}
	})
	c.waitReady()
	all := append(slices.Clone(ids), own...)
	waitFor(t, 20*time.Second, "every record on every node", func() bool {
		for _, tn := range c.nodes {
			if !holdsAll(tn, all) {
				return false
			}
		}
		return true
	})
}

// A whole-cluster outage longer than the retention allows: every node refuses to start on its data (and keeps it).
// The operator starts the node with the newest data once with "quisora force-start" and the others with empty databases:
// they copy everything from it. Nothing is lost.
func TestWholeClusterLongOutageNeedsForceStart(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.opts = shortRetention
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 100)
	waitFor(t, 15*time.Second, "replicated", func() bool { return holdsAll(c.nodes[1], ids) && holdsAll(c.nodes[2], ids) })
	time.Sleep(time.Second)
	c.restartAll(t, func() { time.Sleep(3 * time.Second) })
	waitFor(t, 10*time.Second, "every node refuses", func() bool {
		for _, tn := range c.nodes {
			if _, why := tn.n.Ready(); !strings.Contains(why, "quisora force-start") {
				return false
			}
		}
		return true
	})
	for i, tn := range c.nodes {
		if !holdsAll(tn, ids) || tn.n.ServesTokens() || tn.n.Writable() {
			t.Fatalf("node %d: refused node lost data or serves", i)
		}
	}
	// node 0 forced, the others emptied
	dirs := []string{c.nodes[0].dir, c.nodes[1].dir, c.nodes[2].dir}
	for _, tn := range c.nodes {
		stop(tn)
	}
	for _, d := range dirs[1:] {
		_ = os.RemoveAll(d)
		_ = os.MkdirAll(d, 0o700)
	}
	// "quisora force-start" on node 0: a file the next start uses once
	if err := os.WriteFile(filepath.Join(dirs[0], ForceStartMarker), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.nodes[0] = c.build(0, dirs[0], nil)
	if _, err := os.Stat(filepath.Join(dirs[0], ForceStartMarker)); !os.IsNotExist(err) {
		t.Fatal("the force-start file was not consumed by the start")
	}
	c.nodes[1], c.nodes[2] = c.build(1, dirs[1], nil), c.build(2, dirs[2], nil)
	c.start(c.nodes...)
	c.waitReady()
	for i, tn := range c.nodes {
		if !holdsAll(tn, ids) {
			t.Fatalf("node %d after the forced start: %d of %d", i, countAll(tn.st()), len(ids))
		}
	}
	// it was one start: down too long again, node 0 refuses again
	time.Sleep(time.Second)
	for _, tn := range c.nodes {
		stop(tn)
	}
	time.Sleep(3 * time.Second)
	again := c.build(0, dirs[0], nil)
	c.nodes[0] = again
	if _, why := again.n.Ready(); !strings.Contains(why, "force-start") {
		t.Fatalf("a second long outage was forced through: %s", why)
	}
}

// HIGH (round 7): the only node with data is down; two empty nodes start. They do not copy from each other, do not
// serve, and once the node with data is back they copy everything from it — none of it is refused.
func TestEmptyNodesWaitForData(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.nodes = append(c.nodes, c.build(0, "", nil), c.build(1, "", nil), c.build(2, "", nil))
	t.Cleanup(c.closeAll)
	// node 0 holds the data (as after "quisora bootstrap --new-cluster"), with records older than any retention
	var ids []string
	for range 20 {
		r := newRec(newID(), "")
		r.Version = hlc.FromTime(time.Now().Add(-30 * 24 * time.Hour))
		if _, _, err := c.nodes[0].n.st.inner.PutReplicated(bg, r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	if err := MarkSynced(c.nodes[0].dir, c.nodes[0].n.st.inner.FeedID()); err != nil {
		t.Fatal(err)
	}
	dir0 := c.nodes[0].dir
	stop(c.nodes[0])
	c.start(c.nodes[1], c.nodes[2])
	time.Sleep(3 * time.Second)
	for i, tn := range c.nodes[1:] {
		if ok, _ := tn.n.Ready(); ok || !tn.n.bootstrap.Load() || tn.n.ServesTokens() {
			t.Fatalf("empty node %d formed a cluster without the data", i+1)
		}
	}
	c.nodes[0] = c.build(0, dir0, nil)
	c.start(c.nodes[0])
	c.waitReady()
	for i, tn := range c.nodes {
		if !holdsAll(tn, ids) {
			t.Fatalf("node %d: %d of %d records", i, countAll(tn.st()), len(ids))
		}
	}
}

// A node away for longer than the retention allows (the others ran and could purge deletions it missed) refuses to
// start on its data and keeps it. Started again with an empty database it copies everything, and a record deleted
// while it was away stays deleted.
func TestNodeAwayTooLongRefused(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.opts = shortRetention
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 5)
	waitFor(t, 15*time.Second, "replicated", func() bool { return holdsAll(c.nodes[2], ids) })
	time.Sleep(time.Second)
	dir := c.nodes[2].dir
	stop(c.nodes[2])
	deleteRec(t, c.nodes[0], ids[0])
	time.Sleep(3 * time.Second)
	for _, tn := range c.nodes[:2] {
		tn.n.purgeOnce(bg, time.Now()) // the tombstone is older than the retention: gone
	}
	back := c.build(2, dir, nil)
	c.nodes[2] = back
	c.start(back)
	if _, why := back.n.Ready(); !strings.Contains(why, "last synced") {
		t.Fatalf("a node away too long: %s", why)
	}
	time.Sleep(time.Second)
	if back.n.ServesTokens() || !holdsAll(back, ids) {
		t.Fatal("the node away too long serves, or lost its data")
	}
	for i, tn := range c.nodes[:2] {
		if has(tn.st(), ids[0]) {
			t.Fatalf("the deleted record came back on node %d", i)
		}
	}
	stop(back)
	_ = os.RemoveAll(dir)
	_ = os.MkdirAll(dir, 0o700)
	back = c.build(2, dir, nil)
	c.nodes[2] = back
	c.start(back)
	c.waitReady()
	if has(back.st(), ids[0]) || !holdsAll(back, ids[1:]) {
		t.Fatal("the emptied node did not copy the cluster's data")
	}
}

// A running node cut off from every peer for longer than the retention allows stops serving.
func TestIsolatedNodeStops(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.opts = shortRetention
	c.startAll()
	c.waitReady()
	stop(c.nodes[1])
	stop(c.nodes[2])
	waitFor(t, 10*time.Second, "isolated node stops", func() bool {
		_, why := c.nodes[0].n.Ready()
		return strings.Contains(why, "no sync with the other nodes")
	})
	if c.nodes[0].n.ServesTokens() {
		t.Fatal("an isolated node serves tokens")
	}
}

// MEDIUM (round 7): a node whose database holds data but whose cluster state is missing (a failed restore, a lost
// file) does not know how out of date it is: it refuses to start on that data.
func TestMissingStateFileRefused(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 5)
	waitFor(t, 15*time.Second, "replicated", func() bool { return holdsAll(c.nodes[2], ids) })
	dir := c.nodes[2].dir
	stop(c.nodes[2])
	_ = os.Remove(filepath.Join(dir, "cluster-state.json"))
	back := c.build(2, dir, nil)
	c.nodes[2] = back
	if _, why := back.n.Ready(); !strings.Contains(why, "cluster state") {
		t.Fatalf("missing state: %s", why)
	}
	if !holdsAll(back, ids) {
		t.Fatal("data lost")
	}
}

// A node on which "quisora bootstrap" was run by mistake joins a running cluster. Without cluster state it refuses to
// start at all; with it (bootstrap --new-cluster used by mistake) it joins, finds a separately set-up cluster and
// stops. Either way the cluster's records are unchanged on every node and the stray invitation opens nothing.
func TestMistakenBootstrapOverwritesNothing(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	c := newTCluster(t, 3, memBackend)
	for i := range 2 { // a two-node cluster running; the third joins later
		c.nodes = append(c.nodes, c.build(i, "", nil))
	}
	c.start(c.nodes...)
	t.Cleanup(c.closeAll)
	c.waitReady()
	svc := service.New(cfg, c.nodes[0].st(), sealer)
	if _, _, err := svc.Bootstrap(bg, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	org, _ := svc.PrimaryOrg(bg)
	org.Name = "headquarters"
	if err := svc.Orgs.Update(bg, org); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "replicated", func() bool {
		o, err := c.nodes[1].st().Get(bg, model.KindOrg, model.PrimaryOrgID)
		return err == nil && o.Version == mustVersion(svc, org.ID)
	})
	check := func(stray *tnode, link string) {
		t.Helper()
		time.Sleep(2 * time.Second)
		if ok, _ := stray.n.Ready(); ok || stray.n.ServesTokens() {
			t.Fatal("the separately bootstrapped node serves")
		}
		for i, tn := range c.nodes[:2] {
			s := service.New(cfg, tn.st(), sealer)
			o, err := s.Orgs.Get(bg, model.PrimaryOrgID)
			u, err2 := s.Users.Get(bg, model.BootstrapAdminID)
			if err != nil || err2 != nil || o.Name != "headquarters" || u.Email != "root@example.com" {
				t.Fatalf("node %d after a mistaken bootstrap: org %v %v, admin %v %v", i, o, err, u, err2)
			}
			token := link[strings.Index(link, "token=")+len("token="):]
			if _, _, err := s.PeekLink(bg, token, service.LinkInvite); !errors.Is(err, service.ErrLink) {
				t.Fatalf("node %d: the stray invitation opens an account: %v", i, err)
			}
			if ok, why := tn.n.Ready(); !ok {
				t.Fatalf("node %d: %s", i, why)
			}
		}
	}

	// bootstrap on the new node's store, no cluster state: it refuses to start on that data
	dir := t.TempDir()
	st := memstore.New()
	_, link, err := service.New(cfg, st, sealer).Bootstrap(bg, "someone-else@example.com")
	if err != nil || link == "" {
		t.Fatal(link, err)
	}
	stray := c.build(2, dir, nil)
	stray.n.Close()
	stray.n, _ = New(stray.cfg, st, fastOptions())
	c.nodes = append(c.nodes, stray)
	c.start(stray)
	if _, why := stray.n.Ready(); !strings.Contains(why, "cluster state") {
		t.Fatalf("stray without state: %s", why)
	}
	check(stray, link)

	// the same, with the state "bootstrap --new-cluster" writes: it joins, meets the other set-up and stops
	stop(stray)
	dir = t.TempDir()
	st = memstore.New()
	_, link, err = service.New(cfg, st, sealer).Bootstrap(bg, "someone-else@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkSynced(dir, st.FeedID()); err != nil {
		t.Fatal(err)
	}
	stray = c.build(2, dir, nil)
	stray.n.Close()
	stray.n, _ = New(stray.cfg, st, fastOptions())
	c.nodes[2] = stray
	c.start(stray)
	waitFor(t, 10*time.Second, "stray stops", func() bool {
		_, why := stray.n.Ready()
		return strings.Contains(why, "set up separately")
	})
	check(stray, link)
}

// MEDIUM (round 8): two nodes cut off from a five-node cluster keep pulling from each other, but without a majority in
// view that is no sync: their sync time ages and they stop like a lone node (deletions made on the majority side
// cannot reach them).
func TestMinorityPartitionStops(t *testing.T) {
	c := newTCluster(t, 5, memBackend)
	c.opts = shortRetention
	c.startAll()
	c.waitReady()
	for _, tn := range c.nodes[2:] {
		stop(tn)
	}
	waitFor(t, 15*time.Second, "both minority nodes stop", func() bool {
		for _, tn := range c.nodes[:2] {
			if _, why := tn.n.Ready(); !strings.Contains(why, "no sync with the other nodes") {
				return false
			}
		}
		return true
	})
}

// MEDIUM (round 8): the bootstrap records' creation times are compared from their own data, so a backend that keeps
// index times at microseconds (SQL) does not mistake the cluster's own records for another cluster's; a record from
// a real other bootstrap is refused, and a push of it is not acknowledged.
func TestBootstrapRecordsComparedByData(t *testing.T) {
	sq, err := sqlstore.Open(bg, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer sq.Close()
	for name, st := range map[string]store.Store{"memory": memstore.New(), "sqlite": sq} {
		t.Run(name, func(t *testing.T) { bootstrapComparedByData(t, st) })
	}
}

func bootstrapComparedByData(t *testing.T, st store.Store) {
	n, err := New(tempConfig(t), st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.joined.Store(true)
	created := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC) // nanoseconds
	org := &model.Org{Meta: model.Meta{ID: model.PrimaryOrgID, Created: created, Updated: created}, Name: "primary", Primary: true}
	local, err := store.EncodeAsIs(org)
	if err != nil {
		t.Fatal(err)
	}
	local.Version = model.BootstrapVersion
	local.Fields["created"] = created.Truncate(time.Microsecond) // as a SQL index column holds it
	if _, _, err := n.st.inner.PutReplicated(bg, local); err != nil {
		t.Fatal(err)
	}
	org.Name = "renamed"
	upd, _ := store.EncodeAsIs(org)
	upd.Version = store.Clock.Now()
	if _, err := n.st.applyReplica(bg, upd); err != nil {
		t.Fatalf("an update of the cluster's own primary organization was refused: %v", err)
	}
	other := &model.Org{Meta: model.Meta{ID: model.PrimaryOrgID, Created: created.Add(time.Hour)}, Name: "elsewhere", Primary: true}
	rec, _ := store.EncodeAsIs(other)
	rec.Version = store.Clock.Now()
	if _, err := n.st.applyReplica(bg, rec); !errors.Is(err, errRefused) {
		t.Fatalf("another cluster's primary organization: %v", err)
	}
	if n.applyPush(rec) == pushApplied {
		t.Fatal("a refused push was acknowledged")
	}
	if r, _ := n.st.Get(bg, model.KindOrg, model.PrimaryOrgID); r.Version != upd.Version {
		t.Fatal("the other cluster's record was applied")
	}
}

// A node that has joined a cluster restarts while the other nodes with data are down, next to a new, empty node. The
// empty node is no majority: the restarted node does not become ready, and the new node copies nothing from it
// (it could be out of date) until the cluster is back.
func TestRestartedNodeWithOnlyNewPeersWaits(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 10)
	waitFor(t, 15*time.Second, "replicated", func() bool { return holdsAll(c.nodes[1], ids) && holdsAll(c.nodes[2], ids) })
	time.Sleep(time.Second)
	dirs := []string{c.nodes[0].dir, c.nodes[1].dir, c.nodes[2].dir}
	for _, tn := range c.nodes {
		stop(tn)
	}
	_ = os.RemoveAll(dirs[1]) // node 1 is replaced by a new, empty node; node 2 stays down
	_ = os.MkdirAll(dirs[1], 0o700)
	c.nodes[0], c.nodes[1] = c.build(0, dirs[0], nil), c.build(1, dirs[1], nil)
	c.start(c.nodes[0], c.nodes[1])
	time.Sleep(3 * time.Second)
	if ok, _ := c.nodes[0].n.Ready(); ok {
		t.Fatal("a joined node counted a new, empty node as its majority")
	}
	if countAll(c.nodes[1].st()) != 0 || !c.nodes[1].n.bootstrap.Load() {
		t.Fatal("the new node copied from a node that had not caught up")
	}
	c.nodes[2] = c.build(2, dirs[2], nil)
	c.start(c.nodes[2])
	c.waitReady()
	if !holdsAll(c.nodes[1], ids) {
		t.Fatal("the new node did not copy once the cluster was back")
	}
}
