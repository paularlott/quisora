package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A node that lost its disk copies everything from the others before it promises or stores anything, then is a member
// like any other: its next restart needs no copy.
func TestLostDiskResync(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		c := started(t, b)
		var ids []string
		for i := range 6 {
			ids = append(ids, writeN(t, c.nodes[i%3], []string{"a-org", "b-org", "c-org"}[i%3], 4)...)
		}
		waitFor(t, 20*time.Second, "everything everywhere", func() bool { return allHold(c.nodes, ids) && committedEqual(c.nodes) })
		stop(c.nodes[2])
		tn := c.build(2, "", nil) // a new disk: a new database, a new node id
		c.nodes[2] = tn
		if tn.n.intact.Load() {
			t.Fatal("a node with a new database is intact")
		}
		c.start(tn)
		c.waitReady(tn)
		waitFor(t, 30*time.Second, "the new node to hold everything", func() bool {
			return allHold([]*tnode{tn}, ids) && committedEqual(c.nodes) && sameData(c.nodes)
		})
		if !tn.n.intact.Load() {
			t.Fatal("the node is not intact after its resync")
		}
		b2, err := os.ReadFile(filepath.Join(tn.dir, "cluster-state.json"))
		if err != nil || !strings.Contains(string(b2), `"intact":true`) {
			t.Fatalf("state file %s %v", b2, err)
		}
		putRetrying(t, tn, newOrgRec("a-org"))
		// the restart of a node with its data needs no copy: it is intact from the start
		tn2 := c.restart(2)
		if !tn2.n.intact.Load() || tn2.n.Status().Resyncing {
			t.Fatalf("a restarted node resynchronises: %+v", tn2.n.Status())
		}
		c.waitReady(tn2)
	})
}

// Two nodes impaired at once (one down, another with a new disk): the new node cannot get a majority of the other nodes
// and waits; "quisora force-start" has it copy from the one that answers.
func TestForceStart(t *testing.T) {
	c := started(t, badgerBackend())
	ids := writeN(t, c.nodes[0], "force-org", 5)
	waitFor(t, 20*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) })
	stop(c.nodes[1])
	stop(c.nodes[2])
	tn := c.build(2, "", nil)
	c.nodes[2] = tn
	c.start(tn)
	// (with the other node down it never gets the majority of the others it needs: gossip/partition's
	// TestDTForceResyncWithAnotherNodeDown)
	waitFor(t, 20*time.Second, "the node with a new disk to say it resynchronises", func() bool {
		ok, why := tn.n.Ready()
		return !ok && strings.Contains(why, "resynchronising") && tn.n.Status().Resyncing && !tn.n.Writable()
	})
	// the operator accepts it: the marker file makes the next start copy from whichever nodes answer
	stop(tn)
	marker := filepath.Join(tn.dir, ForceStartMarker)
	if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tn = c.build(2, tn.dir, nil)
	c.nodes[2] = tn
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the marker was not consumed: a forced start applies to one start only")
	}
	if why := tn.n.ForcedStart(); why == "" {
		t.Fatal("the forced start is not reported")
	}
	if at, reason, ok := tn.n.PendingForceStart(); !ok || reason == "" || time.Since(at) > time.Minute {
		t.Fatalf("pending audit %v %q %v", at, reason, ok)
	}
	c.start(tn)
	c.waitReady(c.nodes[0], tn)
	waitFor(t, 30*time.Second, "the forced node to hold everything", func() bool { return allHold([]*tnode{tn}, ids) })
	putRetrying(t, tn, newOrgRec("force-org"))
	// the audit stays pending (in the saved state, across a crash) until it is written
	if b, err := os.ReadFile(filepath.Join(tn.dir, "cluster-state.json")); err != nil || !strings.Contains(string(b), "force_audit") {
		t.Fatalf("the pending audit is not saved: %s %v", b, err)
	}
	tn.n.ForceStartAudited()
	if b, _ := os.ReadFile(filepath.Join(tn.dir, "cluster-state.json")); strings.Contains(string(b), "force_audit") {
		t.Fatalf("the audit stays saved after it was written: %s", b)
	}
	if _, _, ok := tn.n.PendingForceStart(); ok {
		t.Fatal("still pending after it was written")
	}
	// the next start is an ordinary one
	tn2 := c.restart(2)
	if tn2.n.ForcedStart() != "" || !tn2.n.intact.Load() {
		t.Fatalf("a start after a forced one: %q intact %v", tn2.n.ForcedStart(), tn2.n.intact.Load())
	}
}

// A node with its data that is told nothing else comes back after being away: a state file naming another database
// (the database was replaced by hand) is not trusted either.
func TestReplacedDatabaseResyncs(t *testing.T) {
	c := started(t, badgerBackend())
	stop(c.nodes[2])
	dir := c.nodes[2].dir
	// the state file of another database: this one's feed id does not match
	if err := os.WriteFile(filepath.Join(dir, "cluster-state.json"), []byte(`{"self":"another-database","intact":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tn := c.build(2, dir, nil)
	c.nodes[2] = tn
	if tn.n.intact.Load() {
		t.Fatal("a database that is not the one the state was saved for is trusted")
	}
	c.start(tn)
	c.waitReady(tn)
	if !tn.n.intact.Load() {
		t.Fatal("not intact after its resync")
	}
}

// A node restored in place from a snapshot of itself — its whole data directory (a VM or disk snapshot), or its database
// alone (a point-in-time restore, a copied-back file) — is not taken as intact: it resyncs, and then holds everything. A
// plain restart is intact.
func TestRestoredFromItsOwnSnapshotResyncs(t *testing.T) {
	eachLocalBackend(t, func(t *testing.T, b backend) {
		c := started(t, b)
		held := writeN(t, c.nodes[0], "org1", 3)
		c.waitHas(held[2])
		for _, whole := range []bool{true, false} {
			what := map[bool]string{true: "data directory", false: "database"}[whole]
			dir := c.nodes[2].dir
			stop(c.nodes[2])
			snap := t.TempDir()
			if err := copyTree(dir, snap); err != nil {
				t.Fatal(err)
			}
			c.nodes[2] = c.build(2, dir, nil) // a plain restart (after a resync, for the database): intact
			c.start(c.nodes[2])
			c.waitReady()
			if !c.nodes[2].n.startedIntact.Load() {
				t.Fatalf("%s: a plain restart was not intact", what)
			}
			after := writeN(t, c.nodes[2], "org1", 3) // (node 2 promises and stores these)
			c.waitHas(after[2])
			held = append(held, after...)

			stop(c.nodes[2])
			restore(t, b, snap, dir, whole)
			c.nodes[2] = c.build(2, dir, nil)
			c.start(c.nodes[2])
			if c.nodes[2].n.startedIntact.Load() {
				t.Fatalf("%s: a node restored from its own snapshot started as intact", what)
			}
			c.waitReady()
			waitFor(t, 20*time.Second, what+": everything on the restored node", func() bool {
				return allHold(c.nodes[2:], held)
			})
		}
		// the next restart is a plain one again
		c.restart(2)
		c.waitReady()
		if !c.nodes[2].n.startedIntact.Load() {
			t.Fatal("the restart after the resync was not intact")
		}
	})
}

// restore puts the snapshot snap of a node's data directory back into dir: all of it, or only the database.
func restore(t *testing.T, b backend, snap, dir string, whole bool) {
	t.Helper()
	if whole {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := copyTree(snap, dir); err != nil {
			t.Fatal(err)
		}
		return
	}
	isDB := func(name string) bool { return name == "badger" || strings.HasPrefix(name, "quisora.db") }
	for _, d := range []string{dir, snap} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			switch {
			case !isDB(e.Name()):
			case d == dir: // the newer database goes, its log included
				if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
					t.Fatal(err)
				}
			default:
				if err := copyTree(filepath.Join(snap, e.Name()), filepath.Join(dir, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

// Every node stops and starts again: they promise and catch up among themselves, with no operator involved, and keep
// their data set.
func TestWholeClusterRestart(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		c := started(t, b)
		var ids []string
		for i := range 3 {
			ids = append(ids, writeN(t, c.nodes[i], "restart-org", 3)...)
		}
		waitFor(t, 20*time.Second, "replicated", func() bool { return allHold(c.nodes, ids) && committedEqual(c.nodes) })
		g := genesisOf(c.nodes[0])
		c.restartAll(nil)
		c.waitReady()
		if !allHold(c.nodes, ids) || !sameData(c.nodes) {
			t.Fatal("data lost across a whole-cluster restart")
		}
		for i, tn := range c.nodes {
			if tn.n.Status().Resyncing || tn.n.ForcedStart() != "" {
				t.Fatalf("a node needed a resync or a force-start: %+v", tn.n.Status())
			}
			if genesisOf(tn) != g || !tn.n.intact.Load() {
				t.Fatalf("node %d after the restart: data set %q (was %q), intact %v", i, genesisOf(tn), g, tn.n.intact.Load())
			}
		}
		more := putRetrying(t, c.nodes[1], newOrgRec("restart-org"))
		c.waitHas(more)
	})
}
