package kvstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/paularlott/quisora/internal/store"
)

// Group commit (Badger).
//
// With SyncWrites every Badger commit pays for an fsync of the value log and of the memtable WAL (Badger groups
// concurrent commits for the value log but still syncs the WAL once per transaction), so one transaction per record
// caps a node at roughly one write per fsync whatever the concurrency. The committer coalesces concurrent record
// writes (Put, CompareAndPut, PutReplicated) into one Badger transaction and one commit:
//
//   - Writes go to a queue chosen by record key (one queue by default; with several, two writes of one record always
//     meet in the same queue, in arrival order). Its worker takes the first queued write, then whatever else is
//     already queued, up to MaxOps; with a Delay it also waits up to that long after the first write for more. An
//     idle store commits a lone write at once: it pays one channel hand-off, not a delay. Under load, batches form
//     from the writes that arrive while the previous batch is committing.
//   - The writes of a batch run one after the other against one Badger transaction through badgerBatch: each sees the
//     writes before it (same-key ordering and unique-value checks as if run serially), and a write that fails (stale
//     version, unique conflict, deleted record) is dropped without affecting the others. Results are per caller.
//   - The batch commits once (sequence numbers assigned in batch order under the engine mutex, as for any commit) and
//     every caller returns only after that commit is durable. Nothing is visible to readers before it.
//   - A commit conflict (another worker or a non-grouped writer such as Purge changed a key the batch read) re-runs
//     the whole batch against a fresh snapshot, as Update re-runs a single write. A batch too big for one Badger
//     transaction is split in two, in order.
//   - Queues are bounded (callers block, honouring their context, while their queue is full). A caller whose context
//     ends while its write is still queued gets the context error and its write is skipped; once a worker has taken
//     it, the caller waits for the real outcome. Close drains every queue before the database closes.

// GroupOptions tunes Badger group commit; the zero value is the default.
type GroupOptions struct {
	// Disabled commits every write in its own transaction (one fsync per write).
	Disabled bool
	// Workers is the number of commit queues and workers. Default 1: Badger syncs its WAL once per transaction even
	// when it writes several together, and a new transaction waits for the commits in flight, so concurrent workers
	// mostly add fsyncs (measured on an M5 Max: 1 worker 28 us/Put with 18 writers, 2 workers 31 us, 4 workers 38 us;
	// with 72 writers 1 and 2 workers are within 5%).
	Workers int
	// MaxOps is the most writes committed together, and each queue's capacity. Default 1000.
	MaxOps int
	// Delay is how long a worker waits, after taking the first write of a batch, for more writes before committing
	// (it commits earlier when MaxOps are queued). Default 0: commit whatever is queued at once; batches then form
	// from the writes that arrive while the previous commit of the queue is in progress.
	Delay time.Duration
}

const (
	defaultGroupWorkers = 1
	defaultGroupMaxOps  = 1000
)

// errStoreClosed is returned by a write submitted after Close began.
var errStoreClosed = fmt.Errorf("kvstore: store is closed: %w", badger.ErrDBClosed)

type groupOp struct {
	fn    func(tx txn) error
	state atomic.Int32 // opQueued, opTaken or opAbandoned
	err   error
	panic any
	done  chan struct{}
}

const (
	opQueued int32 = iota
	opTaken
	opAbandoned
)

type committer struct {
	e      *badgerEngine
	queues []chan *groupOp
	maxOps int
	delay  time.Duration
	mu     sync.RWMutex // held shared while enqueuing; Close takes it exclusively to close the queues
	closed bool
	wg     sync.WaitGroup
	// commits counts the batches committed (tests and diagnostics).
	commits atomic.Uint64
}

func newCommitter(e *badgerEngine, o GroupOptions) *committer {
	n := o.Workers
	if n <= 0 {
		n = defaultGroupWorkers
	}
	c := &committer{e: e, maxOps: o.MaxOps, delay: max(o.Delay, 0), queues: make([]chan *groupOp, n)}
	if c.maxOps <= 0 {
		c.maxOps = defaultGroupMaxOps
	}
	for i := range c.queues {
		c.queues[i] = make(chan *groupOp, c.maxOps)
		c.wg.Add(1)
		go c.worker(c.queues[i])
	}
	return c
}

// route hashes a record key (kind and id) to a queue: FNV-1a, without building the key.
func route(kind, id string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(kind); i++ {
		h = (h ^ uint32(kind[i])) * 16777619
	}
	h = (h ^ '/') * 16777619
	for i := 0; i < len(id); i++ {
		h = (h ^ uint32(id[i])) * 16777619
	}
	return h
}

// submit queues fn and waits for its outcome (the semantics of Update: fn may run more than once and must be free
// of side effects; its error is returned as is).
func (c *committer) submit(ctx context.Context, r uint32, fn func(tx txn) error) error {
	op := &groupOp{fn: fn, done: make(chan struct{})}
	q := c.queues[r%uint32(len(c.queues))]
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return errStoreClosed
	}
	select {
	case q <- op:
	default: // full: wait for room, or give up with the caller's context
		select {
		case q <- op:
		case <-ctx.Done():
			c.mu.RUnlock()
			return ctx.Err()
		}
	}
	c.mu.RUnlock()
	select {
	case <-op.done:
	case <-ctx.Done():
		if op.state.CompareAndSwap(opQueued, opAbandoned) {
			return ctx.Err() // never ran, never will
		}
		<-op.done
	}
	if op.panic != nil {
		panic(op.panic)
	}
	return op.err
}

// close stops accepting writes, commits everything queued and waits for the workers.
func (c *committer) close() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		for _, q := range c.queues {
			close(q)
		}
	}
	c.mu.Unlock()
	c.wg.Wait()
}

func (c *committer) worker(q chan *groupOp) {
	defer c.wg.Done()
	batch := make([]*groupOp, 0, 64)
	var timer *time.Timer
	if c.delay > 0 {
		timer = time.NewTimer(time.Hour)
		timer.Stop()
	}
	take := func(op *groupOp) {
		if op.state.CompareAndSwap(opQueued, opTaken) {
			batch = append(batch, op)
		}
	}
	for {
		op, ok := <-q
		if !ok {
			return
		}
		take(op)
		var deadline <-chan time.Time
		if timer != nil {
			timer.Reset(c.delay)
			deadline = timer.C
		}
	collect:
		for len(batch) < c.maxOps {
			select {
			case op, ok := <-q:
				if !ok {
					break collect // closed: commit what was taken; the next receive ends the worker
				}
				take(op)
				continue
			default:
			}
			if deadline == nil {
				break
			}
			select {
			case op, ok := <-q:
				if !ok {
					break collect
				}
				take(op)
			case <-deadline:
				deadline = nil
				break collect
			}
		}
		if timer != nil && deadline != nil {
			timer.Stop()
		}
		if len(batch) > 0 {
			c.run(batch)
		}
		clear(batch)
		batch = batch[:0]
	}
}

// run commits ops (in order) as one transaction, retrying conflicts and splitting a batch too big for Badger, and
// hands every op its outcome.
func (c *committer) run(ops []*groupOp) {
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if err = c.runOnce(ops); !errors.Is(err, errConflict) {
			break
		}
		time.Sleep(conflictBackoff(attempt))
	}
	if errors.Is(err, errConflict) {
		err = fmt.Errorf("kvstore: too many conflicting retries: %w", store.ErrStale)
	}
	if isTxnTooBig(err) && len(ops) > 1 {
		h := len(ops) / 2
		c.run(ops[:h])
		c.run(ops[h:])
		return
	}
	for _, op := range ops {
		if op.err == nil && op.panic == nil {
			op.err = err // the commit's outcome; an op refused by its own checks keeps its error
		}
		close(op.done)
	}
}

// runOnce runs every op against one batch and commits it. Each op's own error is left in op.err.
func (c *committer) runOnce(ops []*groupOp) error {
	b := c.e.newBatch()
	for _, op := range ops {
		b.begin()
		if op.err, op.panic = call(op.fn, b); op.err != nil || op.panic != nil {
			b.rollback()
		}
	}
	if b.empty() {
		b.t.Discard()
		return nil
	}
	err := b.commit()
	if err == nil {
		c.commits.Add(1)
	}
	return err
}

// call runs fn, turning a panic into a value re-raised in the caller's goroutine (as if it had run there).
func call(fn func(tx txn) error, t txn) (err error, p any) {
	defer func() {
		p = recover() // never nil for a panic (panic(nil) is a *runtime.PanicNilError)
	}()
	return fn(t), nil
}
