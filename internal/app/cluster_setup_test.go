package app

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// "quisora bootstrap --new-cluster" makes only an empty database a new cluster's first node: one that holds data (part
// of a copy from a cluster) is refused and its cluster state left alone; a second run on the first node changes
// nothing.
func TestGossipBootstrapNeedsAnEmptyDatabase(t *testing.T) {
	ctx := context.Background()
	key := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	cfgFor := func(dir string) *config.Config {
		c := config.Default()
		c.Server.DataDir = dir
		c.Server.MasterKey = key
		c.Storage.Backend = "sqlite"
		c.Storage.SQLite.Path = filepath.Join(dir, "quisora.db")
		c.Cluster.Bind, c.Cluster.Key = "127.0.0.1:7946", key
		c.Limits.PasswordWorkers = 2
		return c
	}
	log := logger.NewNullLogger()

	dir := t.TempDir()
	c := cfgFor(dir)
	st, err := OpenStore(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(ctx, &store.Record{Kind: model.KindGroup, ID: "copied", Version: store.Clock.Now(), Scope: "o",
		Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, _, err := Bootstrap(ctx, c, log); err == nil || !strings.Contains(err.Error(), "empty database") {
		t.Fatalf("bootstrap of a database holding data: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-state.json")); !os.IsNotExist(err) {
		t.Fatal("the refused bootstrap wrote cluster state")
	}

	dir = t.TempDir()
	c = cfgFor(dir)
	user, link, err := Bootstrap(ctx, c, log)
	if err != nil || user == "" || link == "" {
		t.Fatalf("bootstrap of an empty database: %q %q %v", user, link, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-state.json")); err != nil {
		t.Fatal("the first node's cluster state was not written")
	}
	if user, link, err = Bootstrap(ctx, c, log); err != nil || user != "" || link != "" {
		t.Fatalf("a second bootstrap: %q %q %v", user, link, err)
	}
}

// Nodes sharing a database must share the master key: a node with another key refuses.
func TestSharedDatabaseMasterKeyCheck(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	a, _ := secure.NewSealer(secure.RandomBytes(32))
	b, _ := secure.NewSealer(secure.RandomBytes(32))
	log := logger.NewNullLogger()
	if err := checkSharedKey(ctx, st, a, log); err != nil {
		t.Fatal(err)
	}
	if err := checkSharedKey(ctx, st, a, log); err != nil {
		t.Fatalf("the same key again: %v", err)
	}
	if err := checkSharedKey(ctx, st, b, log); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("another key: %v", err)
	}
}

// A master key rotation on a shared database: a node whose ring holds the database's key as a previous one starts
// and moves the database to its active key; from then on a node given only the old key refuses, and one given only the
// new key starts.
func TestSharedDatabaseMasterKeyRotation(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	k1, k2 := secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(k1)
	ring, _ := secure.NewKeyring(k2, k1)
	only2, _ := secure.NewSealer(k2)
	log := logger.NewNullLogger()
	if err := checkSharedKey(ctx, st, old, log); err != nil {
		t.Fatal(err)
	}
	if err := checkSharedKey(ctx, st, ring, log); err != nil {
		t.Fatalf("the rotating node: %v", err)
	}
	if err := checkSharedKey(ctx, st, old, log); err == nil {
		t.Fatal("a node with only the old key started after the rotation")
	}
	if err := checkSharedKey(ctx, st, only2, log); err != nil {
		t.Fatalf("a node with only the new key: %v", err)
	}
}
