package cluster

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// tempConfig is the default configuration with a temporary data directory (not ./data in the source tree).
func tempConfig(t *testing.T) *config.Config {
	c := config.Default()
	c.Server.DataDir = t.TempDir()
	return c
}

// gnode is a gossip node over a failing store that is built but never started: its state is what New makes it, and
// nothing in the background changes it while a test drives the methods.
func gnode(t *testing.T) (*Node, *failStore) {
	t.Helper()
	cs := &failStore{Store: memstore.New()}
	c := newTCluster(t, 3, backend{"failing", func(testing.TB, string) store.Store { return cs }})
	tn := c.build(0, "", nil)
	t.Cleanup(func() { tn.n.Close() })
	return tn.n, cs
}

// hnode is a standalone node over a failing store, so the handlers can be called directly.
func hnode(t *testing.T) (*Node, *failStore) {
	t.Helper()
	cs := &failStore{Store: memstore.New()}
	n, err := New(tempConfig(t), cs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n, cs
}

// snode is a node sharing a database server (not opened: the failing store is given), not started.
func snode(t *testing.T, st store.Store) *Node {
	t.Helper()
	cfg := tempConfig(t)
	cfg.Storage.Backend = "postgres"
	n, err := New(cfg, st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func newTestNode(t *testing.T) *Node { t.Helper(); n, _ := gnode(t); return n }

// failStore fails the calls its fields name.
type failStore struct {
	*memstore.Store
	lookup, put, list, purge, putRepl, get, cas error
	gets                                        atomic.Int64
	getHook                                     func(*store.Record, error) (*store.Record, error)
}

func (s *failStore) Get(ctx context.Context, k model.Kind, id string) (*store.Record, error) {
	s.gets.Add(1)
	if s.get != nil {
		return nil, s.get
	}
	r, err := s.Store.Get(ctx, k, id)
	if s.getHook != nil {
		return s.getHook(r, err)
	}
	return r, err
}

func (s *failStore) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if s.cas != nil {
		return s.cas
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func (s *failStore) Lookup(ctx context.Context, k model.Kind, id string) (*store.Record, error) {
	if s.lookup != nil {
		return nil, s.lookup
	}
	return s.Store.Lookup(ctx, k, id)
}

func (s *failStore) Put(ctx context.Context, r *store.Record) error {
	if s.put != nil {
		return s.put
	}
	return s.Store.Put(ctx, r)
}

func (s *failStore) List(ctx context.Context, k model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if s.list != nil {
		return nil, s.list
	}
	return s.Store.List(ctx, k, q)
}

func (s *failStore) Purge(ctx context.Context, a, b time.Time) (int, error) {
	if s.purge != nil {
		return 0, s.purge
	}
	return s.Store.Purge(ctx, a, b)
}

func (s *failStore) PutReplicated(ctx context.Context, r *store.Record) (bool, error) {
	if s.putRepl != nil {
		return false, s.putRepl
	}
	return s.Store.PutReplicated(ctx, r)
}

// packetOf is a packet carrying v, as a peer's request would arrive at a handler.
func packetOf(t testing.TB, v any) *gossip.Packet {
	t.Helper()
	c := shamaton.New()
	b, err := c.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := gossip.NewPacket()
	p.SetCodec(c)
	p.SetPayload(b)
	t.Cleanup(p.Release)
	return p
}

// badPacket is a packet whose payload cannot be read as the struct a handler expects.
func badPacket(t testing.TB) *gossip.Packet { return packetOf(t, "not a struct") }

func users(tn *tnode) *store.Table[model.User, *model.User] {
	return store.NewTable[model.User](tn.st())
}

func newUser(org, name string) *model.User {
	return &model.User{OrgID: org, Username: name, Email: name + "@example.com", Role: model.RoleUser, Active: true}
}

func sessions(tn *tnode) *store.Table[model.Session, *model.Session] {
	return store.NewTable[model.Session](tn.st())
}

func newSession(org string) *model.Session {
	return &model.Session{OrgID: org, UserID: "user-" + org, Expires: time.Now().Add(time.Hour)}
}

func tenants(tn *tnode) *store.Table[model.Tenant, *model.Tenant] {
	return store.NewTable[model.Tenant](tn.st())
}

func newTenant(org, name string, resources ...string) *model.Tenant {
	return &model.Tenant{OrgID: org, Name: name, Resources: resources}
}

func passkeys(tn *tnode) *store.Table[model.Passkey, *model.Passkey] {
	return store.NewTable[model.Passkey](tn.st())
}
