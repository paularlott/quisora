package cluster

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// The storage contract's cluster side (package store): a write's outcome is settled inside the store, and handed to its
// caller as unknown only when it cannot be (errUnsettled); every wait is bounded, and so is the number of requests
// waiting at once.

// settleWait bounds how long a write whose outcome is unknown is settled for (its context's deadline, if sooner): a
// takeover after an owner is lost takes a few seconds. A variable for tests.
var settleWait = 10 * time.Second

// maxWaiting caps the requests of a node waiting at once in its store (a copy catching up, an outcome being settled):
// past it a request is refused at once (store.ErrUnavailable), so a failover at full load costs 503s, not the node's
// memory. A variable for tests.
var maxWaiting = 2048

// maxPartitionWrites caps the writes of one partition under way from a node at once (submit, settling included); past
// it a write is refused at once (store.ErrUnavailable, nothing sent: a clean retry). A write waits for an owner that
// cannot take it up to the write timeout (5 s), and a lost owner cannot be told from a slow one for the owner timeout
// (5 s), after which its partitions are between owners until the takeover (a second or two more): a lost node's
// partitions are a third of a three-node cluster's, and their writes, uncapped, would pile up on every node at the
// request rate until they filled the HTTP layer's in-flight limit (limits.max_in_flight, 4096 by default), which then
// sheds every organization's requests. Capped, the lost owner's partitions hold at most about 22 × 64 ≈ 1,400 of a
// node's requests, and the other partitions' writes go on. A partition that is merely busy is capped too, which is
// the price: its writes are committed one at a time (its owner takes 32 at once, partition.Tuning.MaxChangesPerPartition,
// and answers more "busy"), so 64 waiting on one node already queue behind a saturated owner, and the cap turns a
// further pile-up of waits into prompt 503s. Writes are not refused by a guess at the owner's state instead: during the
// owner timeout there is nothing to tell a lost owner by, and a write that arrives while the partition is between
// owners succeeds once the takeover completes, within its timeout.
const maxPartitionWrites = 64

// errUnsettled marks a write whose outcome could not be settled before its deadline: it may have been applied (its
// claims of global values are kept: the sweep releases those of a record that never was). It is store.ErrUnavailable
// to the caller and also matches store.ErrUnconfirmed, the one mark that a write may have been applied (the service
// audits such a change with outcome unknown).
var errUnsettled = fmt.Errorf("%w: the outcome of the write could not be settled in time", store.ErrUnconfirmed)

// waitSlot takes one of the node's waiting places, and reports false when none is free (the caller refuses).
func (n *Node) waitSlot() bool {
	select {
	case n.waiting <- struct{}{}:
		return true
	default:
		return false
	}
}

func (n *Node) waitDone() { <-n.waiting }

// errBusy is the refusal of a request that would wait while every waiting place is taken.
var errBusy = fmt.Errorf("%w: too many requests are waiting on this node", store.ErrUnavailable)

// submit writes change c to partition p and settles its outcome: a write whose outcome is unknown (its owner was lost
// or a reply timed out after replication may have begun) is submitted again, unchanged, until it is answered, while no
// owner or majority can be reached it is tried again too, and past the deadline (settleWait, or the context's) it is
// store.ErrUnavailable marked errUnsettled. Submitting again is safe for every change: a record write carries its
// request id, and its owner answers one that landed with whyDone (the caller reads its stamp: settleDone); a claim,
// a release and a purge are refused as nothing to do (whyHeld, whyNotHeld, whyNothing) once applied.
//
// The request id is known only while the record still carries it: a write that landed and was then overwritten (or
// deleted) by another is not recognised, and its resubmission is refused as the first attempt itself may have caused
// (stale, conflict, deleted, not found). Such a refusal of a resubmission is not an answer about this write: it is
// unsettled too (ambiguous), as a SQL store's write whose connection was lost and whose record no longer shows it.
//
// At most maxPartitionWrites changes of p are under way from this node at once: one past them is refused before it is
// sent (store.ErrUnavailable, not marked errUnsettled).
func (s *Store) submit(ctx context.Context, p int, c *change) (partition.Result, error) {
	n := s.n
	if n.writing[p].Add(1) > maxPartitionWrites {
		n.writing[p].Add(-1)
		n.stats.unavailable.Add(1)
		return partition.Result{}, fmt.Errorf("%w: too many writes of partition %d are under way on this node (its owner "+
			"may be lost)", store.ErrUnavailable, p)
	}
	defer n.writing[p].Add(-1)
	res, err := s.submitOnce(ctx, p, c)
	if err == nil || !unsettled(err) {
		return res, err
	}
	if !n.waitSlot() {
		return res, fmt.Errorf("%w: %w: %v", errBusy, errUnsettled, err)
	}
	replay := *c
	replay.Replay = true // (applied only while its records are where the first attempt found them: change.Base)
	c = &replay
	defer n.waitDone()
	deadline := time.Now().Add(settleWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for wait := 50 * time.Millisecond; ; wait = min(2*wait, time.Second) {
		if time.Now().Add(wait).After(deadline) {
			return res, fmt.Errorf("%w: %w: %v", store.ErrUnavailable, errUnsettled, err)
		}
		select {
		case <-ctx.Done():
			return res, fmt.Errorf("%w: %w: %v", store.ErrUnavailable, errUnsettled, ctx.Err())
		case <-n.ctx.Done():
			return res, fmt.Errorf("%w: %w: the node is stopping", store.ErrUnavailable, errUnsettled)
		case <-time.After(wait):
		}
		if res, err = s.submitOnce(ctx, p, c); err == nil || !unsettled(err) {
			if ambiguous(err) {
				return res, fmt.Errorf("%w: %w: an earlier attempt may have been applied and then changed: %v",
					store.ErrUnavailable, errUnsettled, err)
			}
			return res, err
		}
	}
}

// ambiguous reports whether err, the refusal of a resubmitted write, may have been caused by its own earlier attempt
// having landed (and been changed since): it then says nothing about whether the write was applied.
func ambiguous(err error) bool {
	var re *partition.RefusedError
	if !errors.As(err, &re) {
		return false
	}
	switch re.Code {
	case whyStale, whyConflict, whyDeleted, whyNotFound:
		return true
	}
	return false
}

// unsettled reports whether a write that ended with err may still be applied by trying again: its outcome is unknown,
// or no owner or majority could take it (a refusal is an answer).
func unsettled(err error) bool {
	var re *partition.RefusedError
	return !errors.As(err, &re)
}

// isDone reports whether err is the owner's answer that the write's request is stored already (whyDone).
func isDone(err error) bool {
	var re *partition.RefusedError
	return errors.As(err, &re) && re.Code == whyDone
}

// settleDone gives the records of a write its owner answered as done (whyDone) their stored stamps: read from the
// partition's owner, as the write's request left them.
//
// The write landed: a read that fails is the unavailable answer of a write that may have been applied (errUnsettled),
// never a refusal, and its retry is answered as done again.
func (s *Store) settleDone(ctx context.Context, recs []*store.Record) error {
	for _, rec := range recs {
		fresh, err := s.FreshIn(ctx, rec.Kind, rec.Partition, []string{rec.ID})
		if err != nil {
			return fmt.Errorf("%w: %w: the write landed, and its stamp could not be read: %v", store.ErrUnavailable, errUnsettled, err)
		}
		if cur := fresh[rec.ID]; cur != nil && cur.Req == rec.Req {
			store.Settle(rec, cur.Head())
		}
	}
	return nil
}

// Tx applies ops all or nothing (store.Store). In a gossip cluster every op must be of one partition (an
// organization's) and of a kind that is replicated: the transaction is one partition write, settled like any other, and
// its assertions are checked by the partition's owner as it prepares it (prepareTx), so in the partition's order.
// Otherwise (no gossip) it is the wrapped store's.
func (s *Store) Tx(ctx context.Context, ops []store.Op) (err error) {
	if err := s.open(); err != nil {
		return err
	}
	n := s.n
	if len(ops) == 0 {
		return store.ErrBadTx
	}
	if err := store.Ended(ctx); err != nil {
		return err
	}
	if err := store.CheckTx(ops); err != nil {
		return err
	}
	defer store.TxReq(ops, &err)() // (a failed transaction leaves the callers' records as they were passed)
	for _, op := range ops {
		if err := n.allowWrite(ctx, op.Rec); err != nil {
			return err
		}
		op.Rec.Origin = n.id
	}
	if n.gc == nil {
		for _, op := range ops {
			n.noteScope(ctx, op.Rec)
		}
		if err := s.inner.Tx(ctx, ops); err != nil {
			for _, op := range ops {
				n.forgetScope(op.Rec)
			}
			return err
		}
		for _, op := range ops {
			if !op.Assert {
				n.notice(n.fire(op.Rec, true))
			}
		}
		return nil
	}
	p := -1
	c := &change{Op: opTx}
	var recs, written []*store.Record // (recs: one per op of c; written: those of its writes)
	for _, op := range ops {
		rec := op.Rec
		if localOnly(rec.Kind) {
			return fmt.Errorf("%w: %s records stay on the node that writes them", store.ErrBadTx, rec.Kind)
		}
		mode, expect := modeUpsert, uint64(0)
		switch {
		case op.Assert:
			mode, expect = modeAssert, uint64(op.Expect)
		case op.Match:
			mode, expect = modeMatch, uint64(op.Expect)
		}
		var base uint64 // the version the write is based on (change.Base)
		switch {
		case op.Assert: // of the partition it names, and sent as it is: the owner checks it
		case rec.Deleted:
			// a tombstone carries the partition key of the record it deletes
			fresh, err := s.lookupOrFresh(ctx, rec.Kind, rec.ID)
			if err != nil {
				return err
			}
			if fresh == nil {
				if op.Match && op.Expect != 0 {
					return store.ErrNotFound
				}
				continue // nothing to delete, as for a deletion of its own (writePartitioned)
			}
			rec.Partition, rec.Scope, base = fresh.Partition, fresh.Scope, versionOf(fresh)
			if !op.Match {
				mode = modeBlind
			}
		default:
			old, err := s.lookup(ctx, rec.Kind, rec.ID)
			if err != nil {
				return err
			}
			if err := store.CheckMove(rec, old != nil, partitionOf(old)); err != nil {
				return err // (as for a write of its own: writePartitioned)
			}
			base = versionOf(old)
		}
		switch q := recPartition(rec); {
		case p < 0:
			p = q
		case q != p:
			return fmt.Errorf("%w: its ops are in partitions %d and %d", store.ErrBadTx, p, q)
		}
		provisional(rec) // (an assertion's record too: it must decode as well formed)
		if !op.Assert {
			written = append(written, rec)
		}
		b, err := encodeRecord(rec)
		if err != nil {
			return err
		}
		c.Ops = append(c.Ops, txOp{Mode: mode, Expect: expect, Rec: b, Base: base})
		recs = append(recs, rec)
	}
	if len(recs) == 0 {
		return nil // deletions of what is not there, only (store.Store.Put); with assertions, the owner checks them
	}
	res, err := s.submit(ctx, p, c)
	switch {
	case isDone(err):
		return s.settleDone(ctx, written)
	case err != nil:
		var re *partition.RefusedError
		switch {
		case errors.As(err, &re) && re.Code == whyBad:
			return fmt.Errorf("%w: %v", store.ErrBadTx, err)
		case errors.As(err, &re) && re.Code == whyNothing:
			return nil // deletions of what is no longer there, only
		}
		if behind := s.awaitRefused(ctx, p, err); behind != nil {
			return behind
		}
		return storeErr(err)
	}
	var rep writeReply
	if err := decodeMsg(res.Reply, &rep); err != nil {
		return err
	}
	if len(rep.Stamps) != len(recs) {
		return fmt.Errorf("cluster: a transaction of %d writes was answered with %d stamps", len(recs), len(rep.Stamps))
	}
	for i, st := range rep.Stamps {
		if st.Version == 0 {
			continue // an assertion, or a deletion of a record that was not live: nothing was written (store.Store.Put)
		}
		recs[i].Version, recs[i].Epoch, recs[i].Created = hlc.Timestamp(st.Version), hlc.Timestamp(st.Epoch), hlc.Timestamp(st.Created)
	}
	s.waitWritten(ctx, p, res.Pos)
	return nil
}

// provisional gives rec, about to be sent to its partition's owner, a version of this node's clock and no generation:
// the owner stamps all three (prepareWrite), so what its writer set means nothing, and a record must decode as well
// formed on the way.
func provisional(rec *store.Record) {
	rec.Version, rec.Epoch, rec.Created = store.Clock.Now(), 0, 0
}

// lookupOrFresh returns the stored record kind/id, tombstones included, from this node's copy or, when it has none,
// from the owners' (nil: none anywhere).
func (s *Store) lookupOrFresh(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	old, err := s.lookup(ctx, kind, id)
	if err != nil || old != nil {
		return old, err
	}
	fresh, err := s.Fresh(ctx, kind, []string{id})
	if err != nil {
		return nil, err
	}
	return fresh[id], nil
}
