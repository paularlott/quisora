package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func genesisOf(tn *tnode) string {
	if g := tn.n.genesis.Load(); g != nil {
		return *g
	}
	return ""
}

func stateOfDir(t *testing.T, dir string) persisted {
	t.Helper()
	var ps persisted
	b, err := os.ReadFile(filepath.Join(dir, "cluster-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &ps); err != nil {
		t.Fatal(err)
	}
	return ps
}

// Nodes started with empty databases before anyone ran "quisora bootstrap --new-cluster" form no cluster: they hold no
// data set and wait, saying why. Once one node is bootstrapped and started, the others adopt its data set, copy
// everything from it and the cluster works (and keeps its data set through a restart of every node:
// TestWholeClusterRestart).
func TestEmptyNodesWaitForABootstrappedNode(t *testing.T) {
	b := sqliteBackend()
	c := newTCluster(t, 3, b)
	c.noSeed = true
	n1, n2 := c.build(1, "", nil), c.build(2, "", nil)
	c.start(n1, n2)
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			stop(n1)
			stop(n2)
		}
	})
	for _, tn := range []*tnode{n1, n2} {
		waitFor(t, 10*time.Second, "the reason it waits", func() bool {
			ok, why := tn.n.Ready()
			return !ok && strings.Contains(why, "no data set") && strings.Contains(why, "bootstrap --new-cluster")
		})
		if tn.n.manager() != nil || genesisOf(tn) != "" {
			t.Fatal("a node without a data set started the partition protocol")
		}
		if tn.n.IsLeader() {
			t.Fatal("a node without a data set runs housekeeping")
		}
		if err := tn.st().Put(bg, newRec(newID(), "")); !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("a write on a node without a data set: %v", err)
		}
	}
	// "quisora bootstrap --new-cluster" on node 0, which then starts
	dir0 := t.TempDir()
	st := b.open(t, dir0)
	seedNewCluster(t, st, dir0)
	st.Close()
	g := stateOfDir(t, dir0).Genesis
	if g == "" {
		t.Fatal("a bootstrapped node has no data set")
	}
	n0 := c.build(0, dir0, nil)
	c.nodes = []*tnode{n0, n1, n2}
	cleaned = true
	t.Cleanup(c.closeAll)
	c.start(n0)
	c.waitReady()
	waitFor(t, 30*time.Second, "the bootstrapped record on every node", func() bool {
		for _, tn := range c.nodes {
			if _, err := tn.st().Get(bg, model.KindLink, "seed"); err != nil {
				return false
			}
		}
		return true
	})
	for i, tn := range c.nodes {
		if genesisOf(tn) != g {
			t.Fatalf("node %d holds data set %q, the bootstrapped one is %q", i, genesisOf(tn), g)
		}
		waitFor(t, 10*time.Second, "the data set kept", func() bool {
			ps := stateOfDir(t, tn.dir)
			return ps.Genesis == g && ps.Intact && ps.Formed
		})
		if s := tn.n.Status(); s.DataSet != g {
			t.Fatalf("node %d reports data set %q", i, s.DataSet)
		}
	}
	waitFor(t, 15*time.Second, "a housekeeping leader", func() bool {
		return c.nodes[0].n.IsLeader() || c.nodes[1].n.IsLeader() || c.nodes[2].n.IsLeader()
	})
	ids := writeN(t, c.nodes[1], "adopt-org", 4)
	waitFor(t, 20*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
}

// The data set is created only by StartNewCluster, kept by a second run on the same database (with a forced start not
// audited yet), and trusted only for the database it was saved for: a data directory kept while the database was wiped
// keeps no identity, and is no obstacle to a new bootstrap, which makes another data set.
func TestDataSetIdentityBelongsToTheDatabase(t *testing.T) {
	b := badgerBackend()
	dir := t.TempDir()
	st := b.open(t, dir)
	seedPlain(t, st, 0, 3)
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatal(err)
	}
	first := stateOfDir(t, dir)
	if first.Genesis == "" || !first.Intact || first.Formed {
		t.Fatalf("a new data set: %+v", first)
	}
	// a second run before the node ran keeps the data set, and a forced start still to be audited
	pending := first
	pending.ForceAudit = &forceRecord{At: 7, Reason: "forced"}
	raw, _ := json.Marshal(pending)
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatal(err)
	}
	again := stateOfDir(t, dir)
	if again.Genesis != first.Genesis || again.ForceAudit == nil || again.ForceAudit.Reason != "forced" {
		t.Fatalf("a second run: %+v, first %+v", again, first)
	}
	// the node took part in its cluster: it holds the data set, and is refused as the first node of another
	held := again
	held.Formed = true
	raw, _ = json.Marshal(held)
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{CheckNewCluster(dir, st), StartNewCluster(bg, dir, st)} {
		if err == nil || !strings.Contains(err.Error(), "already holds") || !strings.Contains(err.Error(), "cluster-state.json") {
			t.Fatalf("a node that holds a data set: %v", err)
		}
	}
	// so is one that adopted a data set and is copying it (not intact)
	held.Formed, held.Intact = false, false
	raw, _ = json.Marshal(held)
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckNewCluster(dir, st); err == nil {
		t.Fatal("a node copying a data set was allowed a bootstrap")
	}
	held.Formed, held.Intact = true, true
	raw, _ = json.Marshal(held)
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// the database is wiped, the data directory kept
	if err := os.RemoveAll(filepath.Join(dir, "badger")); err != nil {
		t.Fatal(err)
	}
	st = b.open(t, dir)
	defer st.Close()
	c := newTCluster(t, 3, b)
	n, err := New(c.config(0, dir), st, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	if n.genesis.Load() != nil || n.formed.Load() || n.intact.Load() {
		t.Fatalf("a wiped database kept the identity: genesis %v formed %v intact %v", n.genesis.Load(),
			n.formed.Load(), n.intact.Load())
	}
	n.Close()
	if err := CheckNewCluster(dir, st); err != nil {
		t.Fatalf("a wiped database refused a bootstrap: %v", err)
	}
	seedPlain(t, st, 0, 1)
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatal(err)
	}
	if g := stateOfDir(t, dir).Genesis; g == "" || g == first.Genesis {
		t.Fatalf("a new bootstrap on a wiped database: data set %q, the old one %q", g, first.Genesis)
	}
}

// What the node does at start with the state it finds.
func TestLoadStateDecisions(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend())
	build := func(setup func(dir string, st store.Store), tweak ...func(*Options)) *Node {
		t.Helper()
		dir := t.TempDir()
		st := c.mk.open(t, dir)
		if setup != nil {
			setup(dir, st)
		}
		cfg := c.config(0, dir)
		opt := fastOptions()
		for _, f := range tweak {
			f(&opt)
		}
		n, err := New(cfg, st, opt)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close(); st.Close() })
		return n
	}
	put := func(st store.Store) {
		rec := &store.Record{Kind: model.KindLink, ID: "x", Version: store.Clock.Now(), Scope: "s", Partition: "s", Data: []byte("{}")}
		if _, err := st.PutReplicated(bg, rec); err != nil {
			t.Fatal(err)
		}
	}
	if n := build(nil); n.intact.Load() || n.unfit.Load() != nil || n.forceResync.Load() {
		t.Fatal("a new node is intact, unfit or forced")
	}
	n := build(func(dir string, st store.Store) {
		put(st)
		if err := StartNewCluster(bg, dir, st); err != nil {
			t.Fatal(err)
		}
	})
	if !n.intact.Load() || n.unfit.Load() != nil || n.genesis.Load() == nil || n.formed.Load() {
		t.Fatalf("the first node of a new cluster: intact %v unfit %v genesis %v", n.intact.Load(), n.unfit.Load(), n.genesis.Load())
	}
	// the state of another database is not trusted
	n = build(func(dir string, st store.Store) {
		put(st)
		if err := StartNewCluster(bg, dir, st); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), []byte(`{"self":"another","intact":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if n.intact.Load() {
		t.Fatal("the state of another database was trusted")
	}
	// a state that is not intact (a resync that did not finish) stays so
	n = build(func(dir string, st store.Store) {
		if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), []byte(`{"self":"`+st.FeedID()+`","intact":false}`), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if n.intact.Load() {
		t.Fatal("an unfinished resync was trusted")
	}
	// a state file that cannot be read is no state
	n = build(func(dir string, st store.Store) {
		if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), []byte(`not json`), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if n.intact.Load() {
		t.Fatal("garbage was trusted")
	}
	// records no partition write made: refused, forced or not
	for _, forced := range []bool{false, true} {
		n = build(func(dir string, st store.Store) { put(st) }, func(o *Options) { o.ForceStart = forced })
		if why := n.unfit.Load(); why == nil || !strings.Contains(*why, "no partition write made") {
			t.Fatalf("records outside the partitions (forced %v): %v", forced, why)
		}
	}
	// a forced start: not intact whatever the state says, audited, one shot
	var dir string
	n = build(func(d string, st store.Store) {
		dir = d
		put(st)
		if err := StartNewCluster(bg, d, st); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, ForceStartMarker), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if n.intact.Load() || !n.forceResync.Load() || n.ForcedStart() == "" {
		t.Fatalf("a forced start: intact %v forced %v", n.intact.Load(), n.forceResync.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, ForceStartMarker)); !os.IsNotExist(err) {
		t.Fatal("the marker was not consumed")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "cluster-state.json")); strings.Contains(string(b), `"intact":true`) {
		t.Fatalf("a forced start left the state saying intact: %s", b)
	}
	n.resynced()
	if !n.intact.Load() || n.forceResync.Load() {
		t.Fatal("not intact after its resync")
	}
}

// The state is written whole or not at all: a temporary file a crash left is not read, and the next start removes it.
func TestStartNewClusterStateIsAtomic(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "cluster-state.json.tmp")
	if err := os.WriteFile(tmp, []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := badgerBackend().open(t, dir)
	defer st.Close()
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "cluster-state.json"))
	if err != nil || !strings.Contains(string(b), `"intact":true`) || !strings.Contains(string(b), `"genesis":"`) {
		t.Fatalf("%s %v", b, err)
	}
	if err := os.WriteFile(tmp, []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newTCluster(t, 3, badgerBackend())
	n, err := New(c.config(0, dir), st, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("a torn temporary state file was kept")
	}
	if !n.intact.Load() {
		t.Fatal("the saved state was not read")
	}
	// a directory that cannot be written
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StartNewCluster(bg, filepath.Join(file, "dir"), st); err == nil {
		t.Fatal("a directory under a file was made")
	}
	// the backend must be able to hold a partitioned cluster
	if err := StartNewCluster(bg, dir, struct{ store.Store }{st}); err == nil || !strings.Contains(err.Error(), "partition support") {
		t.Fatalf("a backend without partition support: %v", err)
	}
}

// A node that has been part of a cluster is not made the first node of a new one: nothing is seeded, and the state is
// kept.
func TestStartNewClusterRefusesAFormedNode(t *testing.T) {
	dir := t.TempDir()
	st := memBackend().open(t, dir)
	seedPlain(t, st, 0, 5)
	state := []byte(`{"self":"` + st.FeedID() + `","intact":true,"genesis":"g","established":true}`) // (an older file's name for "formed")
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	err := StartNewCluster(bg, dir, st)
	if err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Fatalf("a node that was ready in a cluster: %v", err)
	}
	if n, _ := exportedCount(t, st); n != 0 {
		t.Fatalf("%d records seeded by a refused bootstrap", n)
	}
	if ps, trusted := readState(dir, st); !trusted || !ps.Formed {
		t.Fatalf("an older file's \"established\" is not read as formed: %+v", ps)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "cluster-state.json"))
	if string(b) != string(state) {
		t.Fatalf("the state of the node was rewritten: %s", b)
	}
	// a state that never formed (a bootstrap run twice) is fine
	var ps persisted
	_ = json.Unmarshal(state, &ps)
	ps.Formed, ps.LegacyEstablished = false, false
	b, _ = json.Marshal(ps)
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatalf("a node that never ran: %v", err)
	}
	if n, _ := exportedCount(t, st); n != 5 {
		t.Fatalf("%d records seeded", n)
	}
}

// "quisora bootstrap" and "quisora restore" on a gossip node seed its partitions: the others copy from it, unique values
// are found on every node, and seeding twice changes nothing.
func TestStartNewClusterSeedsThePartitions(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend())
	c.noSeed = true
	c.mks = map[int]backend{1: sqliteBackend()}
	dir := t.TempDir()
	st := c.mk.open(t, dir)
	org := &model.Org{Meta: model.Meta{ID: "org-seed"}, Name: "seeded"}
	user := newUser("org-seed", "admin")
	tenant := newTenant("org-seed", "default", "https://seeded.example.com")
	passkey := &model.Passkey{OrgID: "org-seed", UserID: "x", CredentialID: []byte("seed-cred"), Name: "k"}
	for _, e := range []model.Entity{org, user, tenant, passkey} {
		rec, err := store.Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.PutReplicated(bg, rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatal(err)
	}
	if err := StartNewCluster(bg, dir, st); err != nil { // again: nothing changes
		t.Fatal(err)
	}
	st.Close()
	c.nodes = []*tnode{c.build(0, dir, nil), c.build(1, "", nil), c.build(2, "", nil)}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	waitFor(t, 30*time.Second, "the seeded records on every node", func() bool {
		for _, tn := range c.nodes {
			for _, k := range []struct {
				kind model.Kind
				id   string
			}{{model.KindOrg, "org-seed"}, {model.KindUser, user.ID}, {model.KindTenant, tenant.ID}, {model.KindPasskey, passkey.ID}} {
				if _, err := tn.st().Get(bg, k.kind, k.id); err != nil {
					return false
				}
			}
		}
		return true
	})
	for i, tn := range c.nodes {
		// (a read of a partition whose owner is changing hands is refused for a moment: the staleness gate)
		waitFor(t, 10*time.Second, fmt.Sprintf("node %d: the seeded resource and credential", i), func() bool {
			h, err := tn.st().GetByUnique(bg, model.KindTenant, model.TenantResourceKey("org-seed", "https://seeded.example.com"))
			k, kerr := tn.st().GetByUnique(bg, model.KindPasskey, model.PasskeyCredentialKey("x", []byte("seed-cred")))
			return err == nil && h.ID == tenant.ID && kerr == nil && k.ID == passkey.ID
		})
	}
	// a resource is unique within its organization: the seeded one holds there, and another organization has its own
	if err := tenants(c.nodes[2]).Create(bg, newTenant("org-seed", "y", "https://seeded.example.com")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a seeded resource taken in its organization: %v", err)
	}
	if err := tenants(c.nodes[2]).Create(bg, newTenant("org-other", "x", "https://seeded.example.com")); err != nil {
		t.Fatalf("the same resource in another organization: %v", err)
	}
	// and the data can be written from any node
	u2 := newUser("org-seed", "second")
	if err := users(c.nodes[1]).Create(bg, u2); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u2.ID, func(*model.User) bool { return true })
}

// seedPlain writes n plain records (no partition write made them), spread over many organizations.
func seedPlain(t *testing.T, st store.Store, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		org := fmt.Sprintf("org-%03d", i%90)
		rec := &store.Record{Kind: dataKind, ID: fmt.Sprintf("seed-%05d", i), Version: store.Clock.Now(), Scope: org, Partition: org,
			Data: []byte("x")}
		if err := st.Put(bg, rec); err != nil {
			t.Fatal(err)
		}
	}
}

// exportedCount is how many records the partitions hold in all (the records a copying node would be sent).
func exportedCount(t *testing.T, st store.Store) (n int, seqs [partitions]uint64) {
	t.Helper()
	pst := st.(store.PartitionStore)
	for p := range partitions {
		if err := pst.ExportPartition(bg, p, 0, func(store.PartitionPos) error { return nil }, func(store.PartitionRecord) error { n++; return nil }); err != nil {
			t.Fatal(err)
		}
		ps, err := pst.PartitionState(bg, p)
		if err != nil {
			t.Fatal(err)
		}
		seqs[p] = ps.Committed.Seq
	}
	return n, seqs
}

// pageWatch is a store whose partition writes are counted and measured.
type pageWatch struct {
	store.Store
	store.PartitionStore
	mu    sync.Mutex
	calls int
	most  int
}

func (w *pageWatch) ApplyPartition(ctx context.Context, p int, recs []*store.Record, at store.PartitionPos) error {
	w.mu.Lock()
	w.calls++
	w.most = max(w.most, len(recs))
	w.mu.Unlock()
	return w.PartitionStore.ApplyPartition(ctx, p, recs, at)
}

// Seeding stamps every record, a page at a time (no write holds more than a page), with each partition's next sequence
// number, so that running it again, or after more records were written, stamps them as later writes: nothing is left
// that no partition write made, whenever the records were written before the node first runs.
func TestSeedingStreamsAndIsRerunnable(t *testing.T) {
	eachLocalBackend(t, func(t *testing.T, b backend) {
		dir := t.TempDir()
		st := b.open(t, dir)
		defer st.Close()
		const first, more = 2*seedPage + 300, 40
		seedPlain(t, st, 0, first)
		if n, _ := exportedCount(t, st); n != 0 {
			t.Fatalf("test set-up: %d records are exported before seeding", n)
		}
		w := &pageWatch{Store: st, PartitionStore: st.(store.PartitionStore)}
		if err := seedPartitions(bg, w, w); err != nil {
			t.Fatal(err)
		}
		if w.most > seedPage {
			t.Fatalf("a seeding write of %d records, more than a page (%d)", w.most, seedPage)
		}
		n, seqs := exportedCount(t, st)
		if n != first {
			t.Fatalf("%d of %d records are in a partition's history after seeding", n, first)
		}
		var written int
		for _, s := range seqs {
			written += int(s)
		}
		if written != w.calls || w.calls < 3 {
			t.Fatalf("%d partition writes recorded, %d made", written, w.calls)
		}
		// records written afterwards, then seeding again: they are stamped, as later writes
		seedPlain(t, st, first, more)
		if err := seedPartitions(bg, w, w); err != nil {
			t.Fatal(err)
		}
		n2, seqs2 := exportedCount(t, st)
		if n2 != first+more {
			t.Fatalf("%d of %d records are in a partition's history after seeding again", n2, first+more)
		}
		for p := range partitions {
			if seqs2[p] < seqs[p] || (seqs[p] > 0 && seqs2[p] == seqs[p]) {
				t.Fatalf("partition %d: sequence %d, then %d (every run is a later write)", p, seqs[p], seqs2[p])
			}
		}
		if c, _ := st.Count(bg, dataKind, ""); c != first+more {
			t.Fatalf("%d records", c)
		}
	})
}

// A database that holds records no partition write made (an older build's, or loaded by hand) is refused, not served
// and not copied from.
func TestUnpartitionedDatabaseIsRefused(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend())
	c.noSeed = true
	dir := t.TempDir()
	st := c.mk.open(t, dir)
	if _, err := st.PutReplicated(bg, newRec(newID(), "")); err != nil { // a record, written outside the partition protocol
		t.Fatal(err)
	}
	st.Close()
	tn := c.build(0, dir, nil)
	defer stop(tn)
	if ok, why := tn.n.Ready(); ok || !strings.Contains(why, "no partition write made") {
		t.Fatalf("ready %v: %q", ok, why)
	}
	if tn.n.Writable() {
		t.Fatal("a database the node cannot trust is served")
	}
	// an empty one, or one with records seeded as the first writes of their partitions, is fine
	empty := c.build(1, "", nil)
	defer stop(empty)
	if _, why := empty.n.Ready(); strings.Contains(why, "no partition write") {
		t.Fatalf("an empty database refused: %s", why)
	}
}

// A node bootstrapped (or restored) on its own that meets a cluster set up separately holds another data set: the
// partition protocol of either side ignores the other (the data set is its ClusterID), so nothing passes between them,
// in either direction, although the stranger runs the protocol. The stranger also says why it does not serve, the
// cluster carries on, and once the stranger is started with an empty database it adopts the cluster's data set and
// copies everything.
func TestSeparatelyBootstrappedNodeNeverExchangesData(t *testing.T) {
	c := started(t, badgerBackend())
	ids := writeN(t, c.nodes[0], "genesis-org", 4)
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
	g := genesisOf(c.nodes[0])
	stop(c.nodes[2])
	// node 2's database is replaced by one bootstrapped on its own, as "quisora bootstrap --new-cluster" does
	dir := t.TempDir()
	st := c.mk.open(t, dir)
	rec := &store.Record{Kind: model.KindLink, ID: "alien", Version: store.Clock.Now(), Scope: "alien", Partition: "alien", Data: []byte("{}")}
	if err := st.Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatal(err)
	}
	st.Close()
	tn := c.build(2, dir, nil)
	c.nodes[2] = tn
	c.start(tn)
	alienSet := genesisOf(tn)
	if alienSet == "" || alienSet == g {
		t.Fatalf("the stranger's data set %q, the cluster's %q", alienSet, g)
	}
	waitFor(t, 15*time.Second, "the stranger to say why it does not serve", func() bool {
		ok, why := tn.n.Ready()
		return !ok && strings.Contains(why, "another data set")
	})
	if tn.n.manager() == nil {
		t.Fatal("the stranger does not run the partition protocol: the test proves nothing")
	}
	// the cluster writes while the stranger is in view: none of it reaches the stranger
	more := writeN(t, c.nodes[1], "genesis-org", 4)
	waitFor(t, 15*time.Second, "replicated in the cluster", func() bool { return allHold(c.nodes[:2], more) })
	// the stranger is never the cluster's housekeeping leader, nor a leader of its own; the cluster keeps one
	waitFor(t, 15*time.Second, "a housekeeping leader in the cluster", func() bool {
		return c.nodes[0].n.IsLeader() || c.nodes[1].n.IsLeader()
	})
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if tn.n.IsLeader() {
			t.Fatal("the node of another data set leads")
		}
		for i, n := range c.nodes[:2] {
			for _, ms := range n.n.members(true) {
				if ms.Leader && ms.ID == tn.n.ID() {
					t.Fatalf("node %d of the cluster takes the stranger for its leader", i)
				}
			}
		}
	}
	if ok, why := tn.n.Ready(); ok || !strings.Contains(why, "another data set") {
		t.Fatalf("a node of another data set: ready %v (%s)", ok, why)
	}
	if tn.n.Writable() {
		t.Fatal("a node of another data set serves")
	}
	for _, id := range append(slices.Clone(ids), more...) {
		if _, err := tn.n.st.inner.Lookup(bg, dataKind, id); err == nil {
			t.Fatalf("the stranger holds the cluster's record %s", id)
		}
	}
	if _, err := tn.n.st.inner.Get(bg, model.KindLink, "alien"); err != nil {
		t.Fatalf("the stranger lost its own record: %v", err)
	}
	if genesisOf(tn) != alienSet {
		t.Fatalf("the stranger changed its data set to %q", genesisOf(tn))
	}
	for i, n := range c.nodes[:2] {
		if ok, why := n.n.Ready(); !ok {
			t.Fatalf("node %d of the cluster was stopped by the stranger: %s", i, why)
		}
		if _, err := n.n.st.inner.Lookup(bg, model.KindLink, "alien"); err == nil {
			t.Fatalf("node %d holds the stranger's record", i)
		}
		if genesisOf(n) != g {
			t.Fatalf("node %d changed its data set", i)
		}
	}
	if !allHold(c.nodes[:2], ids) {
		t.Fatal("the cluster lost records")
	}
	// started empty, it joins
	c.replace(2)
	c.waitReady()
	all := append(slices.Clone(ids), more...)
	waitFor(t, 30*time.Second, "the new node to hold everything", func() bool { return allHold(c.nodes, all) && committedEqual(c.nodes) })
	if genesisOf(c.nodes[2]) != g {
		t.Fatalf("the new node's data set %q, the cluster's %q", genesisOf(c.nodes[2]), g)
	}
}
