package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func holdsAll(tn *tnode, ids []string) bool { return allHold([]*tnode{tn}, ids) }

func countAll(s store.Store) int {
	n, _ := s.Count(bg, dataKind, "")
	return n
}

// Nodes whose ids change on restart (their data directories were not kept, their databases were), here every node of
// the cluster at once: each finds its database recorded as another node's, refuses to serve and wipes nothing.
func TestLostNodeIDNeverWipes(t *testing.T) {
	c := started(t, badgerBackend())
	ids := writeN(t, c.nodes[0], "org1", 100)
	waitFor(t, 15*time.Second, "replicated", func() bool { return holdsAll(c.nodes[1], ids) && holdsAll(c.nodes[2], ids) })
	c.restartAll(func() {
		for _, tn := range c.nodes {
			_ = os.Remove(filepath.Join(tn.dir, "node_id")) // every node comes back with a new id
			_ = os.Remove(filepath.Join(tn.dir, "cluster-state.json"))
		}
	})
	refuses := func(tn *tnode) bool { ok, why := tn.n.Ready(); return !ok && strings.Contains(why, "belongs to node") }
	waitFor(t, 15*time.Second, "every node with a new id to refuse", func() bool {
		return refuses(c.nodes[0]) && refuses(c.nodes[1]) && refuses(c.nodes[2])
	})
	consistently(t, 500*time.Millisecond, "every node refusing, its database whole", func() bool {
		for _, tn := range c.nodes {
			if !refuses(tn) || !holdsAll(tn, ids) {
				return false
			}
		}
		return true
	})
}

// A new node started on a copy of a peer's database (a cloned volume) refuses to serve and wipes nothing — it cannot
// tell a copy from its own database under a lost node id — and offers the copy to nobody; the peer keeps serving.
// Once the operator empties the copy, the node joins and copies everything.
func TestClonedDatabaseRefusedNotWiped(t *testing.T) {
	c := started(t, badgerBackend())
	for range 50 {
		if err := c.nodes[0].st().Put(bg, newRec(newID(), "")); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 10*time.Second, "replicated", func() bool { return countAll(c.nodes[1].st()) == 50 && countAll(c.nodes[2].st()) == 50 })
	src, dst := c.nodes[1], c.nodes[2]
	stop(src)
	stop(dst)
	if err := os.RemoveAll(filepath.Join(dst.dir, "badger")); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(filepath.Join(src.dir, "badger"), filepath.Join(dst.dir, "badger")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dst.dir, "cluster-state.json")); err != nil {
		t.Fatal(err)
	}
	c.nodes[1] = c.build(1, src.dir, nil)
	c.nodes[2] = c.build(2, dst.dir, nil)
	c.start(c.nodes[1], c.nodes[2])
	c.waitReady(c.nodes[0], c.nodes[1]) // the source and the others serve
	refuses := func() bool {
		ok, why := c.nodes[2].n.Ready()
		return !ok && (strings.Contains(why, "belongs to node") || strings.Contains(why, "same database"))
	}
	waitFor(t, 10*time.Second, "the node on a copied database to refuse", refuses)
	consistently(t, 500*time.Millisecond, "the node on a copied database refusing, the copy unchanged", func() bool {
		return refuses() && countAll(c.nodes[2].st()) == 50
	})
	// the operator empties the copy: the node joins as a new member
	stop(c.nodes[2])
	if err := os.RemoveAll(filepath.Join(dst.dir, "badger")); err != nil {
		t.Fatal(err)
	}
	c.nodes[2] = c.build(2, dst.dir, nil)
	c.start(c.nodes[2])
	c.waitReady()
	if countAll(c.nodes[2].st()) != 50 {
		t.Fatalf("after emptying, %d records copied", countAll(c.nodes[2].st()))
	}
}

// Two gossip nodes on one database: the one that finds the database recorded as the other's refuses to serve and
// offers nothing; nothing is wiped and the other keeps serving it.
func TestGossipNodesSharingADatabaseRefuse(t *testing.T) {
	shared := memstore.New()
	c := newTCluster(t, 2, backend{"shared", func(testing.TB, string) store.Store { return shared }})
	c.startAll() // (the first node seeds the shared database as the first node of a new cluster)
	waitFor(t, 15*time.Second, "one refuses", func() bool {
		refusing := 0
		for _, tn := range c.nodes {
			if ok, why := tn.n.Ready(); !ok && strings.Contains(why, "belongs to node") && !tn.n.Writable() {
				refusing++
			}
		}
		return refusing >= 1
	})
	if n, _ := shared.Count(bg, model.KindLink, ""); n != 1 {
		t.Fatalf("the shared database holds %d of its records", n)
	}
}

// A gossip node and a node without gossip on one database both refuse, and serve again once the other has gone.
func TestMixedDatabaseRefused(t *testing.T) {
	oldTTL, oldRenew, oldMargin := leaseTTL, leaseRenew, leaseMargin
	leaseTTL, leaseRenew, leaseMargin = time.Second, 100*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { leaseTTL, leaseRenew, leaseMargin = oldTTL, oldRenew, oldMargin })
	shared := memstore.New()
	// A gossip node (its configured peer never starts) and a node without gossip, on one database.
	c := newTCluster(t, 2, backend{"shared", func(testing.TB, string) store.Store { return shared }})
	c.nodes = append(c.nodes, c.build(0, "", nil))
	c.start(c.nodes[0])
	t.Cleanup(c.closeAll)
	cfg := tempConfig(t)
	cfg.Storage.Backend = "postgres"
	plain, err := New(cfg, shared, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Start(bg); err != nil {
		t.Fatal(err)
	}
	g := c.nodes[0].n
	waitFor(t, 5*time.Second, "both refuse", func() bool {
		ok1, why1 := g.Ready()
		ok2, why2 := plain.Ready()
		return !ok1 && !ok2 && strings.Contains(why1, "without gossip") && strings.Contains(why2, "with gossip") &&
			!g.Writable() && !plain.Writable()
	})
	plain.Close() // the node without gossip goes (its lease is released)
	waitFor(t, 5*time.Second, "gossip node serves again", func() bool { return g.mixed.Load() == nil })
}

func TestGossipNodeDatabaseOwnerAndMarkers(t *testing.T) {
	n, cs := gnode(t)
	owner := func() string {
		e, err := store.NewTable[model.Ephemeral](cs.Store).Get(bg, ownerID)
		if err != nil {
			return ""
		}
		return string(e.Value)
	}
	// A database without an owner becomes this node's.
	n.checkOwner(bg)
	if owner() != n.ID() || n.foreign.Load() != nil {
		t.Fatalf("owner %q", owner())
	}
	n.checkOwner(bg) // and stays so
	// One that names another node is refused, and not touched.
	e, _ := store.NewTable[model.Ephemeral](cs.Store).Get(bg, ownerID)
	e.Value = []byte("another-node")
	if err := store.NewTable[model.Ephemeral](cs.Store).Put(bg, e); err != nil {
		t.Fatal(err)
	}
	n.checkOwner(bg)
	if why := n.foreign.Load(); why == nil || !strings.Contains(*why, "another-node") {
		t.Fatalf("foreign database not refused: %v", why)
	}
	// Once it names this node again the refusal lifts.
	e, _ = store.NewTable[model.Ephemeral](cs.Store).Get(bg, ownerID)
	e.Value = []byte(n.ID())
	if err := store.NewTable[model.Ephemeral](cs.Store).Put(bg, e); err != nil {
		t.Fatal(err)
	}
	n.checkOwner(bg)
	if n.foreign.Load() != nil {
		t.Fatal("the refusal stayed")
	}
	// Failing reads and writes of the owner record are logged, not fatal.
	cs.get = errors.New("db down")
	n.checkOwner(bg)
	cs.get = nil
	if err := store.NewTable[model.Ephemeral](cs.Store).Delete(bg, ownerID); err != nil {
		t.Fatal(err)
	}
	cs.put = errors.New("disk full")
	n.checkOwner(bg)
	n.markGossip(bg) // its markers cannot be written either
	cs.put = nil

	// A node without gossip's lease in this database refuses; its lapse lifts the refusal.
	l := store.NewTable[model.Ephemeral](cs.Store)
	if err := l.Put(bg, &model.Ephemeral{Meta: model.Meta{ID: leaseID}, Value: []byte("plain-node"), Expires: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	n.markGossip(bg)
	if why := n.mixed.Load(); why == nil || !strings.Contains(*why, "plain-node") {
		t.Fatalf("mixed database not refused: %v", why)
	}
	if err := l.Delete(bg, leaseID); err != nil {
		t.Fatal(err)
	}
	n.markGossip(bg)
	if n.mixed.Load() != nil {
		t.Fatal("mixed refusal stayed")
	}

	// The other side: a node without gossip meeting a gossip node's marker.
	sh := snode(t, cs.Store)
	if err := l.Put(bg, &model.Ephemeral{Meta: model.Meta{ID: gossipMarkerID}, Value: []byte("gossip-node"), Expires: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	sh.checkNoGossip(bg)
	if why := sh.mixed.Load(); why == nil || !strings.Contains(*why, "gossip-node") {
		t.Fatalf("%v", why)
	}
	if err := l.Delete(bg, gossipMarkerID); err != nil {
		t.Fatal(err)
	}
	sh.checkNoGossip(bg)
	if sh.mixed.Load() != nil {
		t.Fatal("refusal stayed")
	}
}

func TestPrefix(t *testing.T) {
	a, b := PrefixOf(newID()), PrefixOf(newID())
	if len(a) != 8 || a == b {
		t.Fatalf("bad prefixes %q %q", a, b)
	}
	if ephemeral.Owner(a+".xyz") != a {
		t.Fatal("prefix must not contain a dot")
	}
}

func TestPrefixCollisionRefusesToStart(t *testing.T) {
	c := newTCluster(t, 2, memBackend())
	c.opts = func(o *Options) { o.prefix = func(string) string { return "samesame" } }
	c.nodes = []*tnode{c.build(0, "", nil), c.build(1, "", nil)}
	errs := make(chan error, 2)
	for _, tn := range c.nodes {
		go func() { errs <- tn.n.Start(bg) }()
	}
	failed := 0
	for range 2 {
		if err := <-errs; errors.Is(err, ErrPrefixCollision) {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("no node refused to start on a prefix collision")
	}
	t.Cleanup(c.closeAll)
}

// A node that cannot see a majority, or has not caught up, makes no replicated write at all: cut off from the majority
// (even within cluster.minority_grace) or resynchronising, it refuses data, sessions and their deletions alike; only
// node-local records are written (short-lived state, and its own audit events, which are never replicated). A refused
// write is not applied here either.
func TestNonWritableNodeWritesNothing(t *testing.T) {
	c := started(t, badgerBackend())
	ids := writeN(t, c.nodes[0], "org1", 2)
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
	sess := func(id string) *store.Record {
		return &store.Record{Kind: model.KindSession, ID: id, Version: store.Clock.Now(), Scope: "u1", Partition: "org1", Data: []byte("s")}
	}
	tomb := func(k model.Kind, id string) *store.Record { return store.Tombstone(k, id) }
	audit := func() *store.Record {
		return &store.Record{Kind: model.KindAudit, ID: newID(), Version: store.Clock.Now(), Scope: "org1", Partition: "org1",
			Data: []byte("{}")}
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
			err := tn.st().Put(bg, tr.rec)
			if tr.ok && err != nil || !tr.ok && !errors.Is(err, store.ErrNotWritable) {
				t.Fatalf("%s, %s: %v (want allowed: %v)", state, tr.what, err, tr.ok)
			}
			if !tr.ok && !tr.rec.Deleted {
				if r, err := tn.st().Get(bg, tr.rec.Kind, tr.rec.ID); err == nil && r.Version == tr.rec.Version {
					t.Fatalf("%s, %s: a refused write was applied", state, tr.what)
				}
			}
		}
	}
	// node 2 cut off from the majority, within the grace
	c.partition([]int{0, 1}, []int{2})
	lone := c.nodes[2]
	waitFor(t, 30*time.Second, "minority", func() bool { return !lone.n.Writable() })
	if ok, _ := lone.n.Ready(); ok {
		t.Fatal("a node that sees no majority reports itself ready")
	}
	edit := newRec(ids[0], "")
	edit.Data = []byte("edited on the minority side")
	check("minority", lone, []try{
		{"data update", edit, false},
		{"new data", newRec(newID(), ""), false},
		{"new data of another organization", newOrgRec("org-other"), false},
		{"global data", newOrgRec(""), false},
		{"data deletion", tomb(dataKind, ids[1]), false},
		{"session", sess("s1"), false},
		{"session deletion", tomb(model.KindSession, "s1"), false},
		{"audit entry", audit(), true}, // this node's own: never replicated
		{"node-local state", eph(), true},
	})
	c.heal()
	c.waitReady()
	consistently(t, 500*time.Millisecond, "the refused edit and deletion nowhere", func() bool { // (what each node holds)
		for _, tn := range c.nodes {
			if r, err := tn.st().Inner().Get(bg, dataKind, ids[0]); err != nil || string(r.Data) != "data-"+ids[0] || !has(tn.st(), ids[1]) {
				return false
			}
		}
		return true
	})
	// a node with a new disk, resynchronising while the others' partition protocol is out of its reach (it sees them in
	// gossip, so it adopts their data set, but no partition message passes either way)
	stop(c.nodes[1])
	for _, j := range []int{0, 2} {
		c.drop(j, 1, true, partitionMsgs...)
		c.drop(1, j, true, partitionMsgs...)
	}
	fresh := c.build(1, "", nil)
	c.nodes[1] = fresh
	c.start(fresh)
	waitFor(t, 10*time.Second, "the new node resynchronising", func() bool { return fresh.n.Status().Resyncing })
	check("resynchronising", fresh, []try{
		{"data update", newRec(ids[1], ""), false},
		{"session", sess("s3"), false},
		{"session deletion", tomb(model.KindSession, "s3"), false},
		{"audit entry", audit(), true},
		{"node-local state", eph(), true},
	})
	c.heal()
	c.waitReady()
}
