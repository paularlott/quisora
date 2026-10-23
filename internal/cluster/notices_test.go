package cluster

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

// Two nodes on one database with the notice gossip (cluster.notify): a write on one runs the other's change hooks
// within moments; the writer's own hooks run once, for its own write. Without cluster.notify there is no gossip.
func TestSharedDatabaseNoticeGossip(t *testing.T) {
	shared, err := sqlstore.Open(bg, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "shared.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shared.Close() })
	key := testKey()
	addrs := []string{freeAddr(t), freeAddr(t)}
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
	want := []string{"group:" + rec.ID + ":org1:remote", "user:" + gone.ID + ":org1:deleted:remote"}
	if len(got[b]) != 2 || got[b][0] != want[0] || got[b][1] != want[1] {
		t.Errorf("b got %v, want %v", got[b], want)
	}
	if len(got[a]) != 2 || got[a][0] != "group:"+rec.ID+":org1:local" {
		t.Errorf("a (the writer) got %v", got[a])
	}

	// a real deletion (store.Tombstone: no scope) still tells both nodes' hooks the scope of what it removed
	mu.Unlock()
	if err := a.st.Put(bg, store.Tombstone(rec.Kind, rec.ID)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "b hears of the deletion", func() bool { mu.Lock(); defer mu.Unlock(); return len(got[b]) >= 3 })
	mu.Lock()
	if g := got[b][2]; g != "group:"+rec.ID+":org1:deleted:remote" {
		t.Errorf("b got %q for the deletion", g)
	}
	if g := got[a][2]; g != "group:"+rec.ID+":org1:deleted:local" {
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
	addrs := []string{freeAddr(t), freeAddr(t)}
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
