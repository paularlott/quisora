package cluster

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

// Data integrity under the failures a replicated cluster meets: partitions, long outages, empty replacements, restarts
// mid-copy, mixed storage backends and clock skew. See docs/REPLICATION.md for the rules these tests hold the code to.

// partitionRetention is the tombstone retention of the five-node partition tests: short, with more slack than
// shortRetention for a majority to keep its sync point fresh under a loaded test machine (maxDowntime 3.75s).
const partitionRetention = 5 * time.Second

func partitionOptions(o *Options) { o.TombstoneRetention = partitionRetention }

// afterRetention sleeps until a tombstone written at deleted is older than the retention.
func afterRetention(deleted time.Time) {
	time.Sleep(time.Until(deleted.Add(partitionRetention + 500*time.Millisecond)))
}

func sqliteBackend(t testing.TB, dir string) store.Store {
	s, err := sqlstore.Open(bg, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(dir, "quisora.db"), Feed: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wipeDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// replace stops node i and starts it again on an empty data directory (a replacement machine).
func (c *tcluster) replace(t *testing.T, i int) {
	t.Helper()
	dir := c.nodes[i].dir
	stop(c.nodes[i])
	wipeDir(t, dir)
	c.nodes[i] = c.build(i, dir, nil)
	c.start(c.nodes[i])
}

// waitReadyOrSay waits for tn to be ready and, failing that, says why it is not.
func waitReadyOrSay(t *testing.T, d time.Duration, tn *tnode) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok, _ := tn.n.Ready(); ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s := tn.n.Status()
	t.Fatalf("not ready after %v: %s (alive %d/%d, bootstrap %v, records %d)", d, readyWhy(tn), s.Alive, s.Members,
		tn.n.bootstrap.Load(), countAll(tn.st()))
}

func readyWhy(tn *tnode) string {
	_, why := tn.n.Ready()
	return why
}

func allHold(nodes []*tnode, ids []string) bool {
	for _, tn := range nodes {
		if !holdsAll(tn, ids) {
			return false
		}
	}
	return true
}

func noneHas(nodes []*tnode, id string) bool {
	for _, tn := range nodes {
		if has(tn.st(), id) {
			return false
		}
	}
	return true
}

// Five nodes split {0,1,2} | {3,4}. The minority cannot change anything; the majority deletes a record and, past the
// retention, purges its tombstone. The minority stops (it could not sync), and after the partition heals it hands
// nothing back: the deletion stays. Replaced by empty nodes, the minority copies the cluster's data.
func TestPartitionDeletePurgeHealAndEmptyReplacement(t *testing.T) {
	c := newTCluster(t, 5, memBackend)
	c.opts = partitionOptions
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 10)
	waitFor(t, 20*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })

	c.partition([]int{0, 1, 2}, []int{3, 4})
	majority, minority := c.nodes[:3], c.nodes[3:]
	waitFor(t, 30*time.Second, "minority not writable", func() bool {
		return !minority[0].n.Writable() && !minority[1].n.Writable()
	})
	c.waitReady(majority...)
	// The minority cannot change the record (nor anything else).
	edit := newRec(ids[0], "")
	edit.Data = []byte("edited on the minority side")
	for i, tn := range minority {
		if err := tn.st().Put(bg, edit); !errors.Is(err, store.ErrNotWritable) {
			t.Fatalf("minority node %d accepted a write: %v", i+3, err)
		}
	}
	deleted := time.Now()
	deleteRec(t, c.nodes[0], ids[0])
	waitFor(t, 15*time.Second, "deletion replicated on the majority side", func() bool { return noneHas(majority, ids[0]) })
	if !has(minority[0].st(), ids[0]) {
		t.Fatal("the deletion crossed the partition")
	}
	waitFor(t, 20*time.Second, "minority stops", func() bool {
		return strings.Contains(readyWhy(minority[0]), "no sync") && strings.Contains(readyWhy(minority[1]), "no sync")
	})
	afterRetention(deleted)
	for _, tn := range majority {
		tn.n.purgeOnce(bg, time.Now()) // the tombstone is older than the retention: gone
	}

	c.heal()
	time.Sleep(4 * time.Second) // gossip reconnects, many sync rounds
	if !noneHas(majority, ids[0]) {
		t.Fatal("the deleted record came back to the majority after the partition healed")
	}
	for i, tn := range minority {
		if tn.n.ServesTokens() || tn.n.Writable() || !holdsAll(tn, ids) {
			t.Fatalf("minority node %d after the heal: serves, writable, or lost its data (%s)", i+3, readyWhy(tn))
		}
	}
	// Empty replacements copy the cluster's data, without the deleted record.
	c.replace(t, 3)
	c.replace(t, 4)
	c.waitReady()
	waitFor(t, 20*time.Second, "replacements copied", func() bool { return allHold(c.nodes, ids[1:]) })
	if !noneHas(c.nodes, ids[0]) {
		t.Fatal("the deleted record is back")
	}
}

// D-1, the general form: a node that has not seen a deletion yet (replication lag) updates the record — with a newer
// version, and again with one from a clock an hour ahead. Under last-writer-wins the update would beat the tombstone
// and bring the record back everywhere; a tombstone beats every write of the generation it deleted, so it stays
// deleted on every node. The receivers report the skewed version.
func TestStaleUpdateNeverResurrects(t *testing.T) {
	saved := store.Clock
	t.Cleanup(func() { store.Clock = saved }) // after the cluster is closed (cleanups run last-in first-out)
	store.Clock = hlc.NewClock()
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 2)
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })

	c.dropData(2, true) // node 2 stays in view and writable, but receives and sends no data
	deleteRec(t, c.nodes[0], ids[0])
	waitFor(t, 15*time.Second, "deletion on node 1", func() bool { return !has(c.nodes[1].st(), ids[0]) })
	time.Sleep(500 * time.Millisecond)
	if !has(c.nodes[2].st(), ids[0]) || !c.nodes[2].n.Writable() {
		t.Fatal("test set-up: node 2 must still hold the record and be writable")
	}
	upd := newRec(ids[0], "")
	upd.Data = []byte("edited before the deletion arrived")
	if err := c.nodes[2].st().Put(bg, upd); err != nil {
		t.Fatalf("a writable node's update: %v", err)
	}
	skewed := newRec(ids[0], "")
	skewed.Data = []byte("edited by a node whose clock is an hour ahead")
	skewed.Version = hlc.FromTime(time.Now().Add(time.Hour))
	if err := c.nodes[2].st().Put(bg, skewed); err != nil {
		t.Fatalf("skewed update: %v", err)
	}
	// first the others pull node 2's feed (they receive its updates and must drop them), then everything heals
	for j := range 2 {
		ns := c.net(j)
		ns.mu.Lock()
		ns.dropTo[c.addrs[2]][msgFeed] = false
		ns.mu.Unlock()
	}
	waitFor(t, 15*time.Second, "the skewed update reached the others", func() bool {
		return c.nodes[0].n.Status().ClockSkewed > 0 && c.nodes[1].n.Status().ClockSkewed > 0
	})
	if has(c.nodes[0].st(), ids[0]) || has(c.nodes[1].st(), ids[0]) {
		t.Fatal("a stale update resurrected a deleted record")
	}
	c.dropData(2, false)
	waitFor(t, 15*time.Second, "node 2 receives the deletion", func() bool { return !has(c.nodes[2].st(), ids[0]) })
	time.Sleep(2 * time.Second) // more sync rounds: nothing may bring it back
	if !noneHas(c.nodes, ids[0]) {
		t.Fatal("a stale update resurrected a deleted record")
	}
	if !allHold(c.nodes, ids[1:]) {
		t.Fatal("an unrelated record was lost")
	}
}

// A node that cannot know its data is current, or cannot see a quorum, makes no replicated write at all: cut off from
// the majority (even within cluster.minority_grace), out of date, or catching up after a restart, it refuses data,
// sessions, grants, their deletions and audit entries alike; only node-local state is written. A refused write is
// not applied here either.
func TestNonWritableNodeWritesNothing(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.opts = shortRetention
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 2)
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
	sess := func(id string) *store.Record {
		return &store.Record{Kind: model.KindSession, ID: id, Version: store.Clock.Now(), Scope: "u1", Data: []byte("s")}
	}
	tomb := func(k model.Kind, id string) *store.Record { return store.Tombstone(k, id) }
	audit := func() *store.Record {
		return &store.Record{Kind: model.KindAudit, ID: newID(), Version: store.Clock.Now(), Scope: "org1", Data: []byte("{}")}
	}
	eph := func() *store.Record {
		return &store.Record{Kind: model.KindEphemeral, ID: "e-" + newID(), Version: store.Clock.Now(), Data: []byte("x")}
	}
	type try struct {
		what string
		rec  *store.Record
		ok   bool
	}
	check := func(state string, tn *tnode, tries []try) {
		t.Helper()
		for _, tr := range tries {
			_, before := tn.st().Get(bg, tr.rec.Kind, tr.rec.ID)
			err := tn.st().Put(bg, tr.rec)
			if tr.ok && err != nil || !tr.ok && !errors.Is(err, store.ErrNotWritable) {
				t.Fatalf("%s, %s: %v (want allowed: %v)", state, tr.what, err, tr.ok)
			}
			if !tr.ok {
				r, err := tn.st().Get(bg, tr.rec.Kind, tr.rec.ID)
				if tr.rec.Deleted && before == nil && err != nil || !tr.rec.Deleted && err == nil && r.Version == tr.rec.Version {
					t.Fatalf("%s, %s: a refused write was applied", state, tr.what)
				}
			}
		}
	}
	// node 2 cut off from the majority, within the grace
	c.partition([]int{0, 1}, []int{2})
	lone := c.nodes[2]
	waitFor(t, 30*time.Second, "minority", func() bool { return !lone.n.Writable() })
	edit := newRec(ids[0], "")
	check("minority, within the grace", lone, []try{
		{"data update", edit, false},
		{"new data", newRec(newID(), ""), false},
		{"data deletion", tomb(model.KindGroup, ids[1]), false},
		{"session", sess("s1"), false},
		{"session deletion", tomb(model.KindSession, "s1"), false},
		{"audit entry", audit(), true}, // node-local: each node keeps its own audit events
		{"node-local state", eph(), true},
	})
	// out of date: nothing replicated at all
	waitFor(t, 20*time.Second, "lone node stops", func() bool { return strings.Contains(readyWhy(lone), "no sync") })
	check("out of date", lone, []try{
		{"session", sess("s2"), false},
		{"session deletion", tomb(model.KindSession, "s2"), false},
		{"audit entry", audit(), true}, // node-local: never offered to anyone
		{"node-local state", eph(), true},
	})
	c.heal()
	time.Sleep(2 * time.Second)
	for i, tn := range c.nodes[:2] {
		if r, err := tn.st().Get(bg, model.KindGroup, ids[0]); err != nil || string(r.Data) != "data-"+ids[0] {
			t.Fatalf("node %d: the refused edit arrived (%v)", i, err)
		}
		if !has(tn.st(), ids[1]) {
			t.Fatalf("node %d: the refused deletion arrived", i)
		}
	}
	// catching up after a restart, with nobody to catch up with (a long retention: it must not go out of date)
	c.replace(t, 2)
	c.waitReady()
	dir := c.nodes[1].dir
	stop(c.nodes[1])
	c.partition([]int{0, 2}, []int{1})
	c.opts = nil
	c.nodes[1] = c.build(1, dir, nil)
	c.start(c.nodes[1])
	if !c.nodes[1].n.catchingUp.Load() {
		t.Fatal("test set-up: node 1 must be catching up")
	}
	check("catching up", c.nodes[1], []try{
		{"data update", newRec(ids[1], ""), false},
		{"session", sess("s3"), false},
		{"session deletion", tomb(model.KindSession, "s3"), false},
		{"audit entry", audit(), true}, // node-local
	})
	c.heal()
	c.waitReady()
}

// D-3 / R-4: the only node with data restarts (within the retention) next to two new, empty nodes (their disks were
// lost). It has joined a cluster, so empty nodes are no majority for it: nobody becomes ready, nothing is copied. The
// documented procedure — "quisora force-start" on it — lets it start as the cluster's data; the empty nodes copy from
// it. The forced start is consumed by that one start, and stays pending for the audit log (across restarts) until
// the application has written it.
func TestSurvivorWithEmptyPeersRecoversWithForceStart(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 20)
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
	time.Sleep(2500 * time.Millisecond) // the cluster state is saved
	dirs := []string{c.nodes[0].dir, c.nodes[1].dir, c.nodes[2].dir}
	for _, tn := range c.nodes {
		stop(tn)
	}
	wipeDir(t, dirs[1])
	wipeDir(t, dirs[2])
	for i := range c.nodes {
		c.nodes[i] = c.build(i, dirs[i], nil)
	}
	c.start(c.nodes...)
	time.Sleep(4 * time.Second)
	for i, tn := range c.nodes {
		if ok, _ := tn.n.Ready(); ok {
			t.Fatalf("node %d ready without the operator", i)
		}
	}
	if countAll(c.nodes[1].st()) != 0 || countAll(c.nodes[2].st()) != 0 || !c.nodes[0].n.catchingUp.Load() {
		t.Fatal("test set-up: the survivor must be waiting and the new nodes empty")
	}
	if c.nodes[0].n.ForcedStart() != "" {
		t.Fatal("forced without the operator")
	}

	// "quisora force-start" on the survivor
	stop(c.nodes[0])
	marker := filepath.Join(dirs[0], ForceStartMarker)
	if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.nodes[0] = c.build(0, dirs[0], nil)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the force-start file was not consumed")
	}
	if why := c.nodes[0].n.ForcedStart(); !strings.Contains(why, "in date") {
		t.Fatalf("forced start not recorded: %q", why)
	}
	if _, reason, ok := c.nodes[0].n.PendingForceStart(); !ok || reason == "" {
		t.Fatal("the forced start is not pending for the audit log")
	}
	c.start(c.nodes[0])
	c.waitReady()
	waitFor(t, 20*time.Second, "the new nodes copied everything", func() bool { return allHold(c.nodes, ids) })

	// one start only, and the audit stays pending across a restart until written
	stop(c.nodes[0])
	c.nodes[0] = c.build(0, dirs[0], nil)
	if c.nodes[0].n.ForcedStart() != "" {
		t.Fatal("the forced start applied to a second start")
	}
	if _, _, ok := c.nodes[0].n.PendingForceStart(); !ok {
		t.Fatal("the pending audit of the forced start was lost by a restart")
	}
	c.nodes[0].n.ForceStartAudited()
	c.start(c.nodes[0])
	c.waitReady()
	stop(c.nodes[0])
	c.nodes[0] = c.build(0, dirs[0], nil)
	c.start(c.nodes[0])
	if _, _, ok := c.nodes[0].n.PendingForceStart(); ok {
		t.Fatal("the forced start was audited twice")
	}
	c.waitReady()
}

// R-3: a node on the cut-off side of a partition seeds nobody. A new, empty node that starts next to it stays empty
// and not ready; once the partition heals it copies from the majority, without the record deleted (and purged)
// meanwhile.
func TestMinorityNodeSeedsNobody(t *testing.T) {
	c := newTCluster(t, 5, memBackend)
	c.opts = partitionOptions
	for i := range 4 {
		c.nodes = append(c.nodes, c.build(i, "", nil))
	}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	ids := writeN(t, c.nodes[0], 5)
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
	// Every node confirms one durable write, which proves the cluster has formed on that node: gossip readiness
	// can lag, and a node that never recorded a ready quorum before the partition would still be an origin.
	for i, tn := range c.nodes {
		if err := users(tn).Create(bg, newUser("org1", fmt.Sprintf("former%d", i))); err != nil {
			t.Fatalf("durable write on node %d: %v", i, err)
		}
		if !tn.n.formed.Load() {
			t.Fatalf("node %d confirmed a quorum write but its cluster has not formed", i)
		}
	}
	c.partition([]int{0, 1, 2}, []int{3, 4})
	waitFor(t, 30*time.Second, "minority", func() bool { return !c.nodes[3].n.Writable() })
	fresh := c.build(4, "", nil)
	c.nodes = append(c.nodes, fresh)
	c.start(fresh)
	deleted := time.Now()
	deleteRec(t, c.nodes[0], ids[0])
	afterRetention(deleted)
	if countAll(fresh.st()) != 0 || !fresh.n.bootstrap.Load() || fresh.n.ServesTokens() {
		t.Fatal("a node cut off from the majority seeded a new node")
	}
	for _, tn := range c.nodes[:3] {
		tn.n.purgeOnce(bg, time.Now())
	}
	c.heal()
	waitReadyOrSay(t, 45*time.Second, fresh)
	if has(fresh.st(), ids[0]) || !holdsAll(fresh, ids[1:]) {
		t.Fatal("the new node did not copy the cluster's data as it is")
	}
	time.Sleep(time.Second)
	if !noneHas(c.nodes[:3], ids[0]) {
		t.Fatal("the deleted record came back")
	}
}

// D-2 / R-3: a new node whose first copy completes without a majority to sync with (it reaches one node only) has no
// sync point. It ages from the copy and stops once that is too old, instead of never ageing; after the heal it hands
// back nothing that was deleted and purged meanwhile.
func TestFirstCopyWithoutMajorityAges(t *testing.T) {
	c := newTCluster(t, 5, memBackend)
	c.opts = partitionOptions
	for i := range 3 {
		c.nodes = append(c.nodes, c.build(i, "", nil))
	}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	ids := writeN(t, c.nodes[0], 5)
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
	c.cutBetween(3, 1, 2, 4) // node 3 reaches node 0 only
	newcomer := c.build(3, "", nil)
	c.nodes = append(c.nodes, newcomer)
	c.start(newcomer)
	waitFor(t, 20*time.Second, "first copy", func() bool { return holdsAll(newcomer, ids) && !newcomer.n.bootstrap.Load() })
	if newcomer.n.Status().LastSync.IsZero() && newcomer.n.Status().SyncPoint.IsZero() {
		t.Fatal("a completed copy left the node without any age")
	}
	waitFor(t, 20*time.Second, "newcomer stops", func() bool { return strings.Contains(readyWhy(newcomer), "no sync") })
	deleted := time.Now()
	deleteRec(t, c.nodes[0], ids[0])
	afterRetention(deleted)
	for _, tn := range c.nodes[:3] {
		tn.n.purgeOnce(bg, time.Now())
	}
	c.heal()
	time.Sleep(3 * time.Second)
	if !noneHas(c.nodes[:3], ids[0]) {
		t.Fatal("the deleted record came back from the node that never synced")
	}
	if newcomer.n.ServesTokens() {
		t.Fatal("the out-of-date node serves")
	}
}

// Nodes on different backends (badger, sqlite, memory) form one cluster from a real "quisora bootstrap" (creation
// times with nanoseconds, which SQL index columns keep only to the microsecond) and converge on every update and
// deletion, records byte for byte, generations included; nobody mistakes the cluster's own records for another
// cluster's.
func TestMixedBackendsConverge(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	c := newTCluster(t, 3, badgerBackend)
	c.noSeed = true
	c.mks = map[int]backend{1: sqliteBackend, 2: memBackend}
	dir0 := t.TempDir()
	st := badgerBackend(t, dir0) // "quisora bootstrap --new-cluster" on node 0
	if _, _, err := service.New(cfg, st, sealer).Bootstrap(bg, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := MarkSynced(dir0, st.FeedID()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	c.nodes = []*tnode{c.build(0, dir0, nil), c.build(1, "", nil), c.build(2, "", nil)}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	same := func(kind model.Kind, id string) func() bool {
		return func() bool {
			var first *store.Record
			for _, tn := range c.nodes {
				r, err := tn.st().Get(bg, kind, id)
				if err != nil {
					return false
				}
				if first == nil {
					first = r
				} else if r.Version != first.Version || r.Epoch != first.Epoch || r.Created != first.Created || string(r.Data) != string(first.Data) {
					return false
				}
			}
			return true
		}
	}
	waitFor(t, 20*time.Second, "bootstrap records everywhere", same(model.KindOrg, model.PrimaryOrgID))
	waitFor(t, 20*time.Second, "bootstrap admin everywhere", same(model.KindUser, model.BootstrapAdminID))
	// an update on the sqlite node, a new record on the memory node, then its deletion and re-creation on badger
	svc1 := service.New(cfg, c.nodes[1].st(), sealer)
	org, err := svc1.Orgs.Get(bg, model.PrimaryOrgID)
	if err != nil {
		t.Fatal(err)
	}
	org.DisplayName = "Renamed on sqlite"
	if err := svc1.Orgs.Update(bg, org); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "update converged", same(model.KindOrg, model.PrimaryOrgID))
	svc2 := service.New(cfg, c.nodes[2].st(), sealer)
	created := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC) // nanoseconds: SQL index columns keep microseconds
	g := &model.Group{Meta: model.Meta{ID: newID(), Created: created}, OrgID: model.PrimaryOrgID, DisplayName: "on memory"}
	if err := svc2.Groups.Create(bg, g); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "create converged", same(model.KindGroup, g.ID))
	svc0 := service.New(cfg, c.nodes[0].st(), sealer)
	if err := svc0.Groups.Delete(bg, g.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "deletion converged", func() bool { return noneHas(c.nodes, g.ID) })
	again := &model.Group{Meta: model.Meta{ID: g.ID}, OrgID: model.PrimaryOrgID, DisplayName: "created again"}
	if err := svc0.Groups.Create(bg, again); err != nil {
		t.Fatalf("re-creating a deleted id: %v", err)
	}
	waitFor(t, 15*time.Second, "re-creation converged", same(model.KindGroup, g.ID))
	for i, tn := range c.nodes {
		if s := tn.n.Status(); s.Refused != 0 || s.Behind {
			t.Fatalf("node %d refused the cluster's own records: %+v", i, s)
		}
		if ok, why := tn.n.Ready(); !ok {
			t.Fatalf("node %d: %s", i, why)
		}
	}
	g2 := &model.Group{Meta: model.Meta{ID: newID(), Created: created}, OrgID: model.PrimaryOrgID, DisplayName: "nanos"}
	if err := svc1.Groups.Create(bg, g2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "created on sqlite, converged", same(model.KindGroup, g2.ID))
	for i, tn := range c.nodes {
		got, err := service.New(cfg, tn.st(), sealer).Groups.Get(bg, g2.ID)
		if err != nil || !got.Created.Equal(created) {
			t.Fatalf("node %d: creation time not kept to the nanosecond: %v %v", i, got, err)
		}
	}
}

// A new node stopped in the middle of its first copy resumes it when it starts again soon after (it never served,
// and what it holds is young), and refuses once what it holds is too old.
func TestRestartMidCopy(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.opts = func(o *Options) {
		o.PageSize = 20
		o.TombstoneRetention = 8 * time.Second // maxDowntime 6s
	}
	c.startAll()
	c.waitReady()
	ids := writeN(t, c.nodes[0], 400)
	waitFor(t, 30*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
	dir := c.nodes[2].dir
	interrupt := func() {
		t.Helper()
		stop(c.nodes[2])
		wipeDir(t, dir)
		c.net(2).mu.Lock()
		c.net(2).feedDelay = 50 * time.Millisecond // 20 pages: a copy of about a second
		c.net(2).mu.Unlock()
		c.nodes[2] = c.build(2, dir, nil)
		c.start(c.nodes[2])
		waitFor(t, 20*time.Second, "copy under way", func() bool { return countAll(c.nodes[2].st()) >= 40 })
		stop(c.nodes[2])
		c.net(2).mu.Lock()
		c.net(2).feedDelay = 0
		c.net(2).mu.Unlock()
	}
	interrupted := func() {
		t.Helper()
		if n := countAll(c.nodes[2].st()); n == 0 || n >= len(ids) {
			t.Fatalf("test set-up: the copy was not interrupted (%d of %d)", n, len(ids))
		}
	}
	// soon after: it resumes
	interrupt()
	c.nodes[2] = c.build(2, dir, nil)
	interrupted()
	if !c.nodes[2].n.bootstrap.Load() || c.nodes[2].n.behind.Load() != nil {
		t.Fatalf("an interrupted first copy did not resume: %s", readyWhy(c.nodes[2]))
	}
	c.start(c.nodes[2])
	c.waitReady()
	waitFor(t, 20*time.Second, "copy complete", func() bool { return holdsAll(c.nodes[2], ids) })
	// long after: it refuses, keeping what it holds
	interrupt()
	time.Sleep(6500 * time.Millisecond)
	c.nodes[2] = c.build(2, dir, nil)
	interrupted()
	held := countAll(c.nodes[2].st())
	c.start(c.nodes[2])
	if why := readyWhy(c.nodes[2]); !strings.Contains(why, "interrupted too long ago") {
		t.Fatalf("an old interrupted copy: %s", why)
	}
	time.Sleep(time.Second)
	if countAll(c.nodes[2].st()) != held || c.nodes[2].n.ServesTokens() {
		t.Fatal("the refused node changed its data or serves")
	}
}

// With cluster.strict_durability a security change that a majority does not confirm fails: a create is deleted
// again, an update reverted, on this node and (through the undo's own replication) on the others.
func TestStrictDurability(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	for i := range c.addrs {
		c.nodes = append(c.nodes, c.build(i, "", func(cfg *config.Config) { cfg.Cluster.StrictDurability = true }))
	}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	durable := store.WithDurable(bg)
	kept := newRec(newID(), "")
	if err := c.nodes[0].st().Put(durable, kept); err != nil {
		t.Fatalf("a confirmed strict write: %v", err)
	}
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, []string{kept.ID}) })
	c.dropPushes(0)
	created := newRec(newID(), "")
	if err := c.nodes[0].st().Put(durable, created); !errors.Is(err, store.ErrUnconfirmed) || store.Applied(err) {
		t.Fatalf("an unconfirmed strict create: %v", err)
	}
	upd := newRec(kept.ID, "")
	upd.Data = []byte("unconfirmed change")
	if err := c.nodes[0].st().Put(durable, upd); !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("an unconfirmed strict update: %v", err)
	}
	if err := c.nodes[0].st().Put(bg, newRec(newID(), "")); err != nil {
		t.Fatalf("a non-durable write: %v", err)
	}
	time.Sleep(2 * time.Second)
	if !noneHas(c.nodes, created.ID) {
		t.Fatal("an unconfirmed strict create stands")
	}
	for i, tn := range c.nodes {
		if r, err := tn.st().Get(bg, model.KindGroup, kept.ID); err != nil || string(r.Data) != string(kept.Data) {
			t.Fatalf("node %d: an unconfirmed strict update stands (%v)", i, err)
		}
	}
	c.heal()
	// no majority in view: refused before anything is applied
	stop(c.nodes[1])
	stop(c.nodes[2])
	waitFor(t, 15*time.Second, "alone", func() bool { return len(c.nodes[0].n.otherPeers()) == 0 })
	if err := c.nodes[0].st().Put(durable, newRec(newID(), "")); err == nil || store.Applied(err) {
		t.Fatalf("a strict write with no peer: %v", err)
	}
}
