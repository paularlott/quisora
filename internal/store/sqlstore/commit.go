package sqlstore

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/paularlott/quisora/internal/store"
)

// Group commit (SQLite).
//
// SQLite has one writer connection and every commit waits for the disk (synchronous=FULL), so a write costs the disk's
// sync time however many callers there are: with a sync of a few milliseconds that is a few hundred writes a second
// in all. The committer runs the writes that arrive while a commit is syncing in one transaction and one sync:
//
//   - Writes (Put, CompareAndPut, PutReplicated, Tx) are queued; the worker takes the first and whatever else is already
//     queued (up to maxBatch) and runs them one after the other in one transaction, each through applyIn, so each
//     sees the writes before it (same-record ordering and unique values as if run serially). An idle store commits a
//     lone write at once, with no delay: a batch is the writes that came while the previous one was syncing.
//   - When several writes share a transaction each runs in a savepoint, so one that fails (stale version, unique
//     conflict) leaves nothing behind and does not touch the others; every caller gets its own result.
//   - A caller returns only after the commit that holds its write is on disk. Nothing is visible to readers before.
//   - The statements run under the committer's own context, not the callers': one caller's cancellation must not
//     interrupt a transaction that holds the others' writes. A caller whose context ends while its write is still queued
//     gets the context error and the write is skipped; once the worker has taken it the caller waits for the outcome.
//
// Servers do not need it: they group the commits of their connections themselves.

// maxBatch is the most writes committed together (and the queue's capacity).
const maxBatch = 512

// The savepoint each write runs in.
const (
	savepointSQL = "SAVEPOINT qsr_write"
	releaseSQL   = "RELEASE qsr_write"
	rollbackSQL  = "ROLLBACK TO qsr_write"
)

var errStoreClosed = fmt.Errorf("%w: %w", store.ErrUnavailable, store.ErrClosed)

type write struct {
	ctx   context.Context
	ops   []op
	state atomic.Int32 // writeQueued, writeTaken or writeAbandoned
	done  chan result  // the outcome (capacity 1)
}

type result struct {
	written bool
	err     error
}

const (
	writeQueued int32 = iota
	writeTaken
	writeAbandoned
)

type committer struct {
	s      *Store
	queue  chan *write
	closed chan struct{} // closed by stop
	ended  chan struct{} // closed when the worker has returned
	once   sync.Once
}

func (s *Store) startCommitter() {
	for _, q := range []string{savepointSQL, releaseSQL, rollbackSQL} {
		s.wc.get(context.Background(), q)
	}
	g := &committer{s: s, queue: make(chan *write, maxBatch), closed: make(chan struct{}), ended: make(chan struct{})}
	s.gc = g
	go g.run()
}

// stop ends the worker after it has committed what is queued; later writes fail.
func (g *committer) stop() {
	g.once.Do(func() { close(g.closed) })
	<-g.ended
}

// submit queues ops and waits for the commit that holds them.
func (g *committer) submit(ctx context.Context, ops []op) (bool, error) {
	w := &write{ctx: ctx, ops: ops, done: make(chan result, 1)}
	select {
	case g.queue <- w:
	case <-ctx.Done():
		return false, ctx.Err()
	case <-g.closed:
		return false, errStoreClosed
	}
	select {
	case r := <-w.done:
		return r.written, r.err
	case <-ctx.Done():
		if w.state.CompareAndSwap(writeQueued, writeAbandoned) {
			return false, ctx.Err()
		}
		r := <-w.done // the worker has it: the outcome is what the caller must report
		return r.written, r.err
	case <-g.ended: // closed with the write still queued, or just delivered
		select {
		case r := <-w.done:
			return r.written, r.err
		default:
			return false, errStoreClosed
		}
	}
}

func (g *committer) run() {
	defer close(g.ended)
	batch := make([]*write, 0, maxBatch)
	for {
		select {
		case w := <-g.queue:
			batch = append(batch[:0], w)
		case <-g.closed:
			for { // what is queued still gets its commit
				select {
				case w := <-g.queue:
					batch = append(batch[:0], w)
					g.commit(batch)
				default:
					return
				}
			}
		}
	fill:
		for len(batch) < maxBatch {
			select {
			case w := <-g.queue:
				batch = append(batch, w)
			default:
				break fill
			}
		}
		g.commit(batch)
	}
}

// commit runs the batch's writes in one transaction and delivers each its result.
func (g *committer) commit(batch []*write) {
	s := g.s
	ctx := context.Background()
	results := make([]result, len(batch))
	tx, err := s.wdb.BeginTx(ctx, nil)
	if err != nil {
		for _, w := range batch {
			w.done <- result{err: err}
		}
		return
	}
	defer tx.Rollback()
	r := runner{c: s.wc, tx: tx}
	kept := 0
	for i, w := range batch {
		if !w.state.CompareAndSwap(writeQueued, writeTaken) {
			continue // abandoned: its caller has gone
		}
		if err := w.ctx.Err(); err != nil {
			results[i].err = err
			continue
		}
		results[i].written, results[i].err = g.runWrite(ctx, r, w, len(batch) > 1)
		if results[i].err == nil {
			kept++
		}
	}
	if kept > 0 {
		if err := tx.Commit(); err != nil { // the batch may or may not have landed: each write is settled as a lone one is
			for i, w := range batch {
				if results[i].err == nil {
					results[i].written, results[i].err = s.settle(w.ctx, w.ops, err)
				}
			}
		}
	}
	for i, w := range batch {
		w.done <- results[i]
	}
}

// runWrite runs one write of the batch's transaction. With others in it, it runs in a savepoint: kept when it succeeds,
// undone when it fails. A write alone in its transaction needs none: the transaction is rolled back when it fails.
func (g *committer) runWrite(ctx context.Context, r runner, w *write, shared bool) (written bool, err error) {
	defer func() {
		if p := recover(); p != nil { // a bug in one write must not strand the callers of the others
			written, err = false, fmt.Errorf("sqlstore: write panicked: %v", p)
		}
		if err != nil && shared {
			g.undo(ctx, r)
		}
	}()
	if shared {
		if _, err = r.exec(ctx, savepointSQL); err != nil {
			return false, err
		}
	}
	if written, err = g.s.applyIn(ctx, r, w.ops); err != nil {
		return false, err
	}
	if shared {
		_, err = r.exec(ctx, releaseSQL)
	}
	return written, err
}

func (g *committer) undo(ctx context.Context, r runner) {
	_, _ = r.exec(ctx, rollbackSQL)
	_, _ = r.exec(ctx, releaseSQL)
}
