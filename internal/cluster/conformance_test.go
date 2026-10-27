package cluster

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

// The store's conformance suite (storetest) run against cluster.Store: the measure of the storage contract
// (docs/design/storage-contract.md, step 2). Every case that fails here and passes on a driver is a gap the contract
// closes. Each case starts a cluster of its own, so it runs only with QUISORA_CONFORMANCE=1 (or when named with -run).
//
//	QUISORA_CONFORMANCE=1 go test -run TestConformance ./internal/cluster/
//
// The variants (a gossip cluster has at least two nodes; a single node runs without gossip, and cluster.Store then
// passes everything to its driver):
//   - two nodes, three nodes: everything through node 0 (an owner of some partitions, a follower of the rest);
//   - three nodes, split: writes through node 0, reads through node 1, each read made once StaleAfter has passed since
//     the last write (the contract's bounded staleness: a read on another node may trail a write by StaleAfter at most);
//     node-local kinds (audit events, short-lived state) are read where they were written, as the application does;
//   - lost replies: three nodes through node 0, and every third partition write lands and then reports an unknown
//     outcome below the store's settling (the reply lost), which the store must settle: its caller never sees it.
//
// A node that is behind is checked by TestBehindNodeAnswersCurrentOrRefuses (it runs always).
func TestConformance(t *testing.T) {
	if os.Getenv("QUISORA_CONFORMANCE") == "" && !namedRun("TestConformance") {
		t.Skip("set QUISORA_CONFORMANCE=1 to run the store conformance suite against cluster.Store")
	}
	opt := storetest.Options{NoReplicated: true}
	for _, b := range localBackends() {
		t.Run(b.name, func(t *testing.T) {
			t.Run("two nodes", func(t *testing.T) {
				storetest.RunWith(t, func(tb testing.TB) store.Store { return noClose{conformCluster(tb, 2, b).nodes[0].st()} }, opt)
			})
			t.Run("three nodes", func(t *testing.T) {
				storetest.RunWith(t, func(tb testing.TB) store.Store { return noClose{conformCluster(tb, 3, b).nodes[0].st()} }, opt)
			})
			t.Run("three nodes split", func(t *testing.T) {
				storetest.RunWith(t, func(tb testing.TB) store.Store { return newSplit(conformCluster(tb, 3, b)) }, opt)
			})
			t.Run("lost replies", func(t *testing.T) {
				storetest.RunWith(t, func(tb testing.TB) store.Store {
					c := conformCluster(tb, 3, b)
					var n atomic.Int64
					c.nodes[0].n.loseReply = func() bool { return n.Add(1)%3 == 0 }
					return noClose{c.nodes[0].st()}
				}, opt)
			})
		})
	}
}

// A node behind its owner by more than StaleAfter (it misses the partition writes and catch-ups, and hears the
// owner's position) answers every read from current data or refuses it (store.ErrUnavailable), never from its old
// copy: a record by id or by unique value, one it has never received, a deleted one, a batch, and listings and
// counts by organization and by user.
func TestBehindNodeAnswersCurrentOrRefuses(t *testing.T) {
	eachLocalBackend(t, func(t *testing.T, b backend) {
		c := conformCluster(t, 3, b)
		org := c.orgOwnedBy(0)
		w, r := c.nodes[0].st(), c.nodes[1].st()
		users := func(s *Store) *store.Table[model.User, *model.User] { return store.NewTable[model.User](s) }
		sessions := func(s *Store) *store.Table[model.Session, *model.Session] { return store.NewTable[model.Session](s) }
		u := &model.User{OrgID: org, Username: "behind", Email: "behind@example.com", GivenName: "Before", Active: true}
		if err := users(w).Create(bg, u); err != nil {
			t.Fatal(err)
		}
		gone := &model.Session{UserID: u.ID, OrgID: org, Expires: time.Now().Add(time.Hour)}
		if err := sessions(w).Create(bg, gone); err != nil {
			t.Fatal(err)
		}
		c.waitVersion(t, model.KindSession, gone.ID, gone.Version)
		c.waitVersion(t, model.KindUser, u.ID, u.Version)

		c.lagBehind(1, true)
		u.GivenName = "After"
		if err := users(w).Update(bg, u); err != nil {
			t.Fatal(err)
		}
		v := &model.User{OrgID: org, Username: "newcomer", Email: "newcomer@example.com", GivenName: "New", Active: true}
		if err := users(w).Create(bg, v); err != nil {
			t.Fatal(err)
		}
		if err := sessions(w).Delete(bg, gone.ID); err != nil {
			t.Fatal(err)
		}
		kept := &model.Session{UserID: u.ID, OrgID: org, Expires: time.Now().Add(time.Hour)}
		if err := sessions(w).Create(bg, kept); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Duration(c.nodes[1].n.staleAfter.Load()) + 200*time.Millisecond)

		refused := func(what string, err error) bool {
			t.Helper()
			if errors.Is(err, store.ErrUnavailable) {
				return true
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s: %v", what, err)
				return true
			}
			return false
		}
		if got, err := users(r).Get(bg, u.ID); !refused("a changed user", err) && (err != nil || got.GivenName != "After") {
			t.Errorf("a changed user answered from the old copy: %+v %v", got, err)
		}
		if got, err := users(r).Get(bg, v.ID); !refused("a new user", err) && (err != nil || got.ID != v.ID) {
			t.Errorf("a user this node never received answered as %+v %v", got, err)
		}
		if got, err := users(r).GetByUnique(bg, model.UserEmailKey(org, v.Email)); !refused("a new user by address", err) && (err != nil || got.ID != v.ID) {
			t.Errorf("a new user by address answered as %+v %v", got, err)
		}
		if got, err := sessions(r).Get(bg, gone.ID); !refused("a deleted session", err) && err == nil {
			t.Errorf("a deleted session answered from the old copy: %+v", got)
		}
		if got, err := users(r).GetMany(bg, []string{u.ID, v.ID}); !refused("a batch", err) && len(got) != 2 {
			t.Errorf("a batch answered with %d users, want 2", len(got))
		}
		if list, _, err := sessions(r).List(bg, store.ListQuery{Scope: u.ID}); !refused("a user's sessions", err) &&
			(len(list) != 1 || list[0].ID != kept.ID) {
			t.Errorf("a user's sessions answered from the old copy: %d", len(list))
		}
		if n, err := r.Count(bg, model.KindUser, org); !refused("an organization's users", err) && n != 2 {
			t.Errorf("an organization's users counted %d, want 2", n)
		}
		if n, err := r.Count(bg, model.KindUser, ""); !refused("every user", err) && n < 2 {
			t.Errorf("every user counted %d", n)
		}
	})
}

// namedRun reports whether -test.run names test.
func namedRun(test string) bool {
	for i, a := range os.Args {
		if a == "-test.run="+test || a == "-test.run" && i+1 < len(os.Args) && os.Args[i+1] == test {
			return true
		}
	}
	return false
}

// conformCluster starts a ready cluster of size nodes for one conformance case.
func conformCluster(tb testing.TB, size int, b backend) *tcluster {
	c := newTCluster(tb, size, b)
	c.startAll()
	c.waitReady()
	// every node has heard every partition's owner (a read that cannot tell its partition needs them all)
	waitFor(tb, 30*time.Second, "every partition readable on every node", func() bool {
		for _, tn := range c.nodes {
			if tn.n.readableWithin(bg, -1, 0) != nil {
				return false
			}
		}
		return true
	})
	return c
}

// noClose is a node's store whose Close does nothing: the cluster harness stops the node.
type noClose struct{ *Store }

func (noClose) Close() error { return nil }

// split writes through node 0 and reads through node 1, each read once StaleAfter (and a margin for the test's
// timers) has passed since the last write ended.
type split struct {
	noClose
	r         *Store
	bound     time.Duration
	lastWrite atomic.Int64 // unix nanoseconds
}

func newSplit(c *tcluster) *split {
	return &split{noClose: noClose{c.nodes[0].st()}, r: c.nodes[1].st(),
		bound: time.Duration(c.nodes[1].n.staleAfter.Load()) + 100*time.Millisecond}
}

func (s *split) wrote(err error) error {
	s.lastWrite.Store(time.Now().UnixNano())
	return err
}

// settle waits until StaleAfter has passed since the last write.
func (s *split) settle() {
	if d := time.Until(time.Unix(0, s.lastWrite.Load()).Add(s.bound)); d > 0 {
		time.Sleep(d)
	}
}

func (s *split) Put(ctx context.Context, rec *store.Record) error {
	return s.wrote(s.noClose.Put(ctx, rec))
}

func (s *split) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	return s.wrote(s.noClose.CompareAndPut(ctx, rec, expect))
}

func (s *split) Tx(ctx context.Context, ops []store.Op) error { return s.wrote(s.noClose.Tx(ctx, ops)) }

// reader is the node a read of kind is made on: node 1, but the writer for a node-local kind.
func (s *split) reader(kind model.Kind) *Store {
	if localOnly(kind) {
		return s.Store
	}
	s.settle()
	return s.r
}

func (s *split) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	return s.reader(kind).Get(ctx, kind, id)
}

func (s *split) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	return s.reader(kind).GetByUnique(ctx, kind, value)
}

func (s *split) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	return s.reader(kind).Lookup(ctx, kind, id)
}

func (s *split) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	return s.reader(kind).GetMany(ctx, kind, ids)
}

func (s *split) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	return s.reader(kind).List(ctx, kind, q)
}

func (s *split) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	return s.reader(kind).Count(ctx, kind, scope)
}

func (s *split) Snapshot(ctx context.Context) (store.Reader, error) {
	s.settle()
	return s.r.Snapshot(ctx)
}
