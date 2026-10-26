package cluster

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/store"
)

// faultStore is a node's database with faults the tests switch on: a slow disk for the durable writes of the partition
// protocol (SetPartitionPending), and catch-ups of one partition that fail.
type faultStore struct {
	store.Store
	pst          store.PartitionStore
	pendingDelay atomic.Int64 // nanoseconds every SetPartitionPending sleeps first
	failImport   atomic.Int64 // partition+1 whose imports fail (0: none)
	// cutAfterReset is the partition+1 whose next full import is cut short after its reset: the backend does the First
	// step (the marker, the removal of every record) and the import then fails, as a crash or a failed call would.
	cutAfterReset atomic.Int64
	// what the faults did (the chaos soak reports them): full imports started, imports failed by failImport, full imports
	// cut after their reset
	fullImports, failedImports, cutImports atomic.Int64
}

func (f *faultStore) PartitionState(ctx context.Context, p int) (store.PartitionState, error) {
	return f.pst.PartitionState(ctx, p)
}

func (f *faultStore) SetPartitionPromised(ctx context.Context, p int, e store.PartitionEpoch) error {
	return f.pst.SetPartitionPromised(ctx, p, e)
}

func (f *faultStore) SetPartitionPending(ctx context.Context, p int, seq uint64, pending []byte) error {
	if d := time.Duration(f.pendingDelay.Load()); d > 0 && pending != nil {
		time.Sleep(d)
	}
	return f.pst.SetPartitionPending(ctx, p, seq, pending)
}

func (f *faultStore) ApplyPartition(ctx context.Context, p int, recs []*store.Record, committed store.PartitionPos) error {
	return f.pst.ApplyPartition(ctx, p, recs, committed)
}

func (f *faultStore) ExportPartition(ctx context.Context, p int, afterSeq uint64, start func(store.PartitionPos) error,
	fn func(store.PartitionRecord) error) error {
	return f.pst.ExportPartition(ctx, p, afterSeq, start, fn)
}

func (f *faultStore) ImportPartition(ctx context.Context, p int, recs []store.PartitionRecord, upTo store.PartitionPos,
	step store.ImportStep) error {
	if step.Full && step.First {
		f.fullImports.Add(1)
	}
	if step.Full && step.First && f.cutAfterReset.Load() == int64(p)+1 {
		f.cutImports.Add(1)
		cut := step
		cut.Final = false
		if err := f.pst.ImportPartition(ctx, p, nil, upTo, cut); err != nil {
			return err
		}
		return errTestImport
	}
	if f.failImport.Load() == int64(p)+1 {
		f.failedImports.Add(1)
		return errTestImport
	}
	return f.pst.ImportPartition(ctx, p, recs, upTo, step)
}

func (f *faultStore) PurgePartition(ctx context.Context, p int, beforeSeq uint64) (int, error) {
	return f.pst.PurgePartition(ctx, p, beforeSeq)
}

func (f *faultStore) PartitionTombstones(ctx context.Context, p int, afterSeq, upTo uint64,
	fn func(seq uint64, version hlc.Timestamp) error) error {
	return f.pst.PartitionTombstones(ctx, p, afterSeq, upTo, fn)
}

var errTestImport = &testError{"test: the import fails"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

// faults hands out the faultStore of each node directory.
type faults struct {
	mu    sync.Mutex
	byDir map[string]*faultStore
}

// over wraps b: every database it opens is a faultStore.
func (fs *faults) over(b backend) backend {
	return backend{b.name, func(t testing.TB, dir string) store.Store {
		st := b.open(t, dir)
		f := &faultStore{Store: st, pst: st.(store.PartitionStore)}
		fs.mu.Lock()
		defer fs.mu.Unlock()
		if fs.byDir == nil {
			fs.byDir = map[string]*faultStore{}
		}
		fs.byDir[dir] = f
		return f
	}}
}

// of returns the faultStore of node tn.
func (fs *faults) of(tn *tnode) *faultStore {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.byDir[tn.dir]
}
