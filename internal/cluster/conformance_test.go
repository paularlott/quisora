package cluster

import (
	"context"
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
// The variants:
//   - two nodes: everything through node 0 (a gossip cluster has at least two; a single node runs without gossip, and
//     cluster.Store then passes everything to its driver);
//   - three nodes: everything through node 0 (an owner of some partitions, a follower of the rest);
//   - three nodes, split: writes through node 0, reads through node 1, each read made once StaleAfter has passed since
//     the last write (the contract's bounded staleness: a read on another node may trail a write by StaleAfter at most);
//   - three nodes, split, node 1 behind: the same, with node 1 missing the partition writes and catch-ups (a node that
//     cannot keep up must refuse once it trails by more than StaleAfter, never answer from its old copy);
//   - lost replies: three nodes through node 0, and every third write lands and then reports store.ErrUnconfirmed, as a write whose
//     owner was lost before it answered does today (the contract settles these inside the store).
func TestConformance(t *testing.T) {
	if os.Getenv("QUISORA_CONFORMANCE") == "" && !namedRun("TestConformance") {
		t.Skip("set QUISORA_CONFORMANCE=1 to run the store conformance suite against cluster.Store")
	}
	for _, b := range localBackends() {
		t.Run(b.name, func(t *testing.T) {
			t.Run("two nodes", func(t *testing.T) {
				storetest.Run(t, func(tb testing.TB) store.Store { return noClose{conformCluster(tb, 2, b).nodes[0].st()} })
			})
			t.Run("three nodes", func(t *testing.T) {
				storetest.Run(t, func(tb testing.TB) store.Store { return noClose{conformCluster(tb, 3, b).nodes[0].st()} })
			})
			t.Run("three nodes split", func(t *testing.T) {
				storetest.Run(t, func(tb testing.TB) store.Store {
					c := conformCluster(tb, 3, b)
					return newSplit(c)
				})
			})
			t.Run("three nodes split behind", func(t *testing.T) {
				storetest.Run(t, func(tb testing.TB) store.Store {
					c := conformCluster(tb, 3, b)
					c.lagBehind(1, true)
					return newSplit(c)
				})
			})
			t.Run("lost replies", func(t *testing.T) {
				storetest.Run(t, func(tb testing.TB) store.Store {
					return &replyLost{noClose: noClose{conformCluster(tb, 3, b).nodes[0].st()}}
				})
			})
		})
	}
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

func (s *split) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	s.settle()
	return s.r.Get(ctx, kind, id)
}

func (s *split) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	s.settle()
	return s.r.GetByUnique(ctx, kind, value)
}

func (s *split) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	s.settle()
	return s.r.Lookup(ctx, kind, id)
}

func (s *split) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	s.settle()
	return s.r.GetMany(ctx, kind, ids)
}

func (s *split) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	s.settle()
	return s.r.List(ctx, kind, q)
}

func (s *split) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	s.settle()
	return s.r.Count(ctx, kind, scope)
}

func (s *split) Snapshot(ctx context.Context) (store.Reader, error) {
	s.settle()
	return s.r.Snapshot(ctx)
}

// replyLost makes every third write land and then report store.ErrUnconfirmed.
type replyLost struct {
	noClose
	n atomic.Int64
}

func (s *replyLost) lose(err error) error {
	if err == nil && s.n.Add(1)%3 == 0 {
		return store.ErrUnconfirmed
	}
	return err
}

func (s *replyLost) Put(ctx context.Context, rec *store.Record) error {
	return s.lose(s.noClose.Put(ctx, rec))
}

func (s *replyLost) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	return s.lose(s.noClose.CompareAndPut(ctx, rec, expect))
}
