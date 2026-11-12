package cluster

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/shamaton/msgpack/v3"
)

// partitions is the number of partitions the data is split into: a constant of the format (docs/REPLICATION.md).
// Partition 0 is the global data; every other partition is a hash of a record's partition key.
const partitions = 64

// globalPartition is the partition of the global data; its owner runs housekeeping (Node.IsLeader).
const globalPartition = 0

// partitionNum is the partition of a partition key (store.Record.Partition): 0 for the global key "".
func partitionNum(key string) int {
	if key == "" {
		return globalPartition
	}
	return partition.PartitionOf(key, partitions)
}

func recPartition(r *store.Record) int { return partitionNum(r.Partition) }

// ---- the change a write carries, and the write it becomes ----

// What a change does (change.Op).
const (
	opWrite uint8 = iota + 1 // put or compare-and-swap one record, a tombstone included
	opPurge                  // purge the tombstones below a sequence number
	opTx                     // write several records of the partition, all or nothing (store.Store.Tx)
)

// How a record write is checked (change.Mode).
const (
	modeUpsert uint8 = iota // whole-record put: refused over a tombstone
	modeMatch               // compare-and-swap on the live version (0: the record must not exist)
	modeBlind               // a deletion that needs no particular version
	modeAssert              // opTx only: no write, the record must be live at the version expected (store.Op.Assert)
)

// The codes a change is refused with (partition.Refuse); the cluster store turns them back into the store's errors.
const (
	whyStale    = "stale"    // the record is not at the version the writer expected
	whyConflict = "conflict" // a unique value is held by another record
	whyDeleted  = "deleted"  // a live write over a tombstone
	whyNotFound = "not-found"
	whyNothing  = "nothing" // nothing to do (a deletion of what is not there, a purge with nothing to purge)
	whyDone     = "done"    // the write's request is stored already: a retry of a write that landed (store.Retried)
	whyBad      = "bad"     // malformed or in the wrong partition: a bug, never expected
	whyMoved    = "moved"   // a write that would change a record's partition key (store.ErrBadRecord)
	whyLarge    = "large"   // read: the reply would not fit one message; ask for fewer records
)

// change is the argument of partition.Manager.Write: what the landing node wants. The owner's Prepare checks it against
// the committed data and turns it into a writeData.
type change struct {
	Op     uint8
	Mode   uint8
	Expect uint64 // opWrite, modeMatch: the live version the record must have (0: it must not exist)
	Rec    []byte // opWrite: the encoded record (encodeRecord), not yet stamped
	Before uint64 // opPurge: tombstones with a sequence below this go
	// Ops are opTx's writes, in order.
	Ops []txOp
	// Base (opWrite) is the version of the record, in any state, the writer based the write on (0: none); Replay marks
	// the change submitted again after an attempt whose outcome was not known. A replay is applied only while the record
	// is still at its Base (else whyStale, which the writer reports as unknown): an unconditional write replayed over a
	// successor another writer committed meanwhile would overwrite it, or delete its new generation, and its own
	// landing is recognised by its request id only while the record still carries it (retried).
	Base   uint64
	Replay bool
}

// txOp is one op of an opTx change: as an opWrite's Mode, Expect, Rec and Base, or an assertion (modeAssert: Rec
// names the record, Expect its version, and Base is not used).
type txOp struct {
	Mode   uint8
	Expect uint64
	Rec    []byte
	Base   uint64
}

// writeData is the data of a write (partition.Write.Data): the records every node applies, stamped by the owner, and
// the purge point to apply first. Commit does exactly this, deterministically.
type writeData struct {
	Recs  [][]byte
	Purge uint64
}

// writeReply is what the owner's Prepare tells the caller: the stamp of the record it wrote, and for an opTx those of
// each of its records, in order.
type writeReply struct {
	Version uint64
	Epoch   uint64
	Created uint64
	Stamps  []writeReply
}

func encodeMsg(v any) ([]byte, error) { return msgpack.MarshalAsArray(v) }
func decodeMsg(b []byte, v any) error { return msgpack.UnmarshalAsArray(b, v) }

// readReq is the argument of partition.Manager.Read: the records of one kind by id, tombstones included.
type readReq struct {
	Kind string
	IDs  []string
}

// maxReadReply bounds a read's reply (one message, the cluster's packet limit being 4 MB); a reply over it is refused
// with whyLarge and the caller asks for half the ids (a variable for tests).
var maxReadReply = 3 << 20

// ---- the Store of the partition protocol ----

// pstore is the partition.Store of a node: the protocol's durable state and committed data over the node's own backend
// (store.PartitionStore), and the owner's checks of every change (Prepare). It keeps each partition's state in memory
// (the library asks for it on every message): the backend is read once, at start, and written by the methods below.
type pstore struct {
	n      *Node
	inner  store.Store
	pst    store.PartitionStore
	states [partitions]atomic.Pointer[partition.State]
	// importing[p] is set from the start of a full import of p until its Final batch is stored (and from start-up, if the
	// backend's durable marker says one was cut short): the partition then holds only part of what the import brings
	// into the emptied partition, whatever position states[p] still carries. State reports it Incomplete, with the
	// position and pending write it had (they are what this node stored: a promise it gives must still report them, or a
	// takeover that hears only from it would miss writes it acknowledged; the library then catches it up with a full copy,
	// and neither takes it over nor acknowledges a write on top of what it lacks), reads of it are refused (readable),
	// and the next import of it, whatever the library asks, is a full one.
	importing [partitions]atomic.Bool
	// exports bounds the exports running at once (exportSlots): each holds a snapshot, and on SQLite a reader
	// connection, for as long as its stream lasts.
	exports chan struct{}
}

// readerPool is implemented by a backend whose reads are served from a pool of connections (sqlstore): Readers is its
// size.
type readerPool interface{ Readers() int }

// exportSlots is how many exports run at once over a backend with a pool of readers of the given size: never more than
// half of them (the rest serve the node's own reads), at most 4, at least 1. A backend without a pool counts as 8.
func exportSlots(pool int) int {
	return max(1, min(4, pool/2))
}

// Retryable refusals of an export (the asker's catch-up fails and is tried again, from this node or another).
var (
	errExportsBusy      = errors.New("cluster: too many catch-up exports at once on this node: try again")
	errImportUnfinished = errors.New("cluster: this node is importing the partition: try again once it has finished")
)

var _ partition.Store = (*pstore)(nil)

func newPStore(n *Node, inner store.Store) (*pstore, error) {
	pst, ok := inner.(store.PartitionStore)
	if !ok {
		return nil, fmt.Errorf("cluster: the %T storage backend cannot hold a gossip cluster's data (no partition support)", inner)
	}
	pool := 8
	if rp, ok := inner.(readerPool); ok {
		pool = rp.Readers()
	}
	s := &pstore{n: n, inner: inner, pst: pst, exports: make(chan struct{}, exportSlots(pool))}
	for p := range partitions {
		ps, err := pst.PartitionState(n.ctx, p)
		if err != nil {
			return nil, fmt.Errorf("cluster: partition %d state: %w", p, err)
		}
		st, err := stateOf(ps)
		if err != nil {
			return nil, fmt.Errorf("cluster: partition %d state: %w", p, err)
		}
		s.states[p].Store(&st)
		s.importing[p].Store(ps.Importing)
		// A purge records its point before it removes the tombstones below it, in batches (a crash part-way must
		// never leave tombstones missing below a lower point): one that a crash cut short is finished here, or
		// the tombstones it left would stay for good on this node alone.
		if ps.Purged > 0 {
			if _, err := pst.PurgePartition(n.ctx, p, ps.Purged+1); err != nil {
				return nil, fmt.Errorf("cluster: partition %d: finishing its purge: %w", p, err)
			}
		}
		if ps.Importing {
			n.log.Warn("a copy of a partition as a whole was cut short on this node: it serves none of the partition until "+
				"it is copied again from the others", "partition", p)
		}
	}
	return s, nil
}

func toEpoch(e store.PartitionEpoch) partition.Epoch {
	return partition.Epoch{Counter: e.Counter, Node: gossip.NodeID(e.Node)}
}

func fromEpoch(e partition.Epoch) store.PartitionEpoch {
	return store.PartitionEpoch{Counter: e.Counter, Node: [16]byte(e.Node)}
}

func toPos(p store.PartitionPos) partition.Pos {
	return partition.Pos{Epoch: toEpoch(p.Epoch), Seq: p.Seq}
}

func fromPos(p partition.Pos) store.PartitionPos {
	return store.PartitionPos{Epoch: fromEpoch(p.Epoch), Seq: p.Seq}
}

// stateOf converts the backend's state of a partition (its pending write is an opaque blob).
func stateOf(ps store.PartitionState) (partition.State, error) {
	st := partition.State{Promised: toEpoch(ps.Promised), Committed: toPos(ps.Committed)}
	if ps.Pending != nil {
		var w partition.Write
		if err := msgpack.Unmarshal(ps.Pending, &w); err != nil {
			return st, fmt.Errorf("the stored pending write: %w", err)
		}
		st.Pending = &w
	}
	return st, nil
}

// unpartitioned reports whether no partition has ever committed a write here: with records in the store, they were
// written by something other than the partition protocol (a restore outside "quisora restore").
func (s *pstore) unpartitioned() bool {
	for p := range partitions {
		if s.states[p].Load().Committed.Seq > 0 {
			return false
		}
	}
	return true
}

// update replaces the cached state of p with what f makes of a copy of it (the protocol serialises changes of one
// partition; readers see the old or the new state, never a torn one).
func (s *pstore) update(p int, f func(*partition.State)) {
	st := *s.states[p].Load()
	f(&st)
	s.states[p].Store(&st)
}

func (s *pstore) State(p int) (partition.State, error) {
	if p < 0 || p >= partitions {
		return partition.State{}, fmt.Errorf("cluster: partition %d out of range", p)
	}
	st := *s.states[p].Load()
	st.Incomplete = s.importing[p].Load() // (see importing)
	return st, nil
}

// isImporting reports whether a full import of p has begun here and not finished.
func (s *pstore) isImporting(p int) bool { return s.importing[p].Load() }

// anyImporting returns a partition a full import has begun here and not finished, if there is one.
func (s *pstore) anyImporting() (int, bool) {
	for p := range partitions {
		if s.importing[p].Load() {
			return p, true
		}
	}
	return 0, false
}

func (s *pstore) SetPromised(p int, e partition.Epoch) error {
	if err := s.pst.SetPartitionPromised(s.n.ctx, p, fromEpoch(e)); err != nil {
		return err
	}
	s.update(p, func(st *partition.State) { st.Promised = e })
	return nil
}

func (s *pstore) SetPending(p int, w *partition.Write) error {
	if w != nil && s.importing[p].Load() {
		return fmt.Errorf("cluster: partition %d: %w", p, errImportUnfinished) // nothing is stored on top of the hole
	}
	if w == nil {
		if err := s.pst.SetPartitionPending(s.n.ctx, p, 0, nil); err != nil {
			return err
		}
		s.update(p, func(st *partition.State) { st.Pending = nil })
		return nil
	}
	b, err := msgpack.Marshal(w)
	if err != nil {
		return err
	}
	if err := s.pst.SetPartitionPending(s.n.ctx, p, w.Pos.Seq, b); err != nil {
		return err
	}
	cp := *w
	s.update(p, func(st *partition.State) { st.Pending = &cp })
	return nil
}

// committed moves the cached committed position of p to pos (a pending write the commit passed is dropped).
func (s *pstore) committed(p int, pos partition.Pos) {
	s.update(p, func(st *partition.State) {
		st.Committed = pos
		if st.Pending != nil && st.Pending.Pos.Seq <= pos.Seq {
			st.Pending = nil
		}
	})
}

// Commit applies a committed write: the purge it carries, then its records and the new committed position in one
// transaction (the purge goes first: a crash between the two leaves the write pending, and applying it again purges
// again, which changes nothing). Every node does exactly the same.
func (s *pstore) Commit(w *partition.Write) error {
	if s.importing[w.Partition].Load() {
		return fmt.Errorf("cluster: partition %d: %w", w.Partition, errImportUnfinished) // nothing is applied on top of the hole
	}
	var d writeData
	if err := decodeMsg(w.Data, &d); err != nil {
		return fmt.Errorf("cluster: commit of partition %d at %s: %w", w.Partition, w.Pos, err)
	}
	recs := make([]*store.Record, len(d.Recs))
	for i, b := range d.Recs {
		r, err := decodeRecord(b)
		if err != nil {
			return err
		}
		recs[i] = r
	}
	if d.Purge > 0 {
		if _, err := s.pst.PurgePartition(s.n.ctx, w.Partition, d.Purge); err != nil {
			return err
		}
	}
	if err := s.pst.ApplyPartition(s.n.ctx, w.Partition, recs, fromPos(w.Pos)); err != nil {
		return err
	}
	s.n.applies.Add(1)
	s.committed(w.Partition, w.Pos)
	s.n.applied(recs)
	return nil
}

// ---- the owner's checks ----

func refuse(code, format string, a ...any) error {
	return partition.Refuse(code, fmt.Sprintf(format, a...))
}

func (s *pstore) lookup(kind model.Kind, id string) (*store.Record, error) {
	r, err := s.inner.Lookup(s.n.ctx, kind, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return r, err
}

// nextVersion is the version of a new write of a record that has the version cur (nil: none): this node's clock, and
// always above the one it replaces, whatever the clocks say.
func nextVersion(cur *store.Record) hlc.Timestamp {
	v := store.Clock.Now()
	if cur != nil && v <= cur.Version {
		v = cur.Version + 1
	}
	return v
}

func (s *pstore) Prepare(p int, b []byte) (data, reply []byte, err error) {
	var c change
	if err := decodeMsg(b, &c); err != nil {
		return nil, nil, refuse(whyBad, "malformed change: %v", err)
	}
	var recs []*store.Record
	var rep writeReply
	var purge uint64
	switch c.Op {
	case opWrite:
		rec, err := decodeRecord(c.Rec)
		if err != nil {
			return nil, nil, refuse(whyBad, "%v", err)
		}
		if err := s.retried(rec); err != nil {
			return nil, nil, err
		}
		if err := s.replayed(c.Replay, rec, c.Base); err != nil {
			return nil, nil, err
		}
		if err := s.prepareWrite(p, c.Mode, c.Expect, rec, nil); err != nil {
			return nil, nil, err
		}
		recs, rep = []*store.Record{rec}, stampOf(rec)
	case opTx:
		if recs, rep.Stamps, err = s.prepareTx(p, &c); err != nil {
			return nil, nil, err
		}
	case opPurge:
		if err := s.preparePurge(p, &c); err != nil {
			return nil, nil, err
		}
		purge = c.Before
	default:
		return nil, nil, refuse(whyBad, "unknown change %d", c.Op)
	}
	d := writeData{Purge: purge}
	for _, r := range recs {
		eb, err := encodeRecord(r)
		if err != nil {
			return nil, nil, err
		}
		d.Recs = append(d.Recs, eb)
	}
	if data, err = encodeMsg(&d); err != nil {
		return nil, nil, err
	}
	if reply, err = encodeMsg(&rep); err != nil {
		return nil, nil, err
	}
	return data, reply, nil
}

func stampOf(r *store.Record) writeReply {
	return writeReply{Version: uint64(r.Version), Epoch: uint64(r.Epoch), Created: uint64(r.Created)}
}

// retried refuses the write of rec with whyDone when the committed copy is rec's request's: a retry of a write that
// landed (store.Retried), which the writer answers as done rather than applying it twice.
func (s *pstore) retried(rec *store.Record) error {
	cur, err := s.lookup(rec.Kind, rec.ID)
	if err != nil {
		return err
	}
	if cur != nil && store.Retried(rec, cur.Head()) {
		return refuse(whyDone, "%s %s was written by this request", rec.Kind, rec.ID)
	}
	return nil
}

// replayed refuses a replay (change.Replay) of the write of rec when the record is no longer at base, the version the
// writer based it on: whyStale, an answer the writer reports as unknown (ambiguous).
func (s *pstore) replayed(replay bool, rec *store.Record, base uint64) error {
	if !replay {
		return nil
	}
	cur, err := s.lookup(rec.Kind, rec.ID)
	if err != nil {
		return err
	}
	if v := versionOf(cur); v != base {
		return refuse(whyStale, "%s %s changed since the write was first submitted", rec.Kind, rec.ID)
	}
	return nil
}

// versionOf is r's version in any state (0 for nil).
func versionOf(r *store.Record) uint64 {
	if r == nil {
		return 0
	}
	return uint64(r.Version)
}

// txUniques is what the earlier writes of a transaction did to unique values: the values they claimed (by record id)
// and those they released, each of its kind (a value is unique among the records of one kind: uniqueKey). A later
// write is checked against the committed copy as they leave it.
type txUniques struct {
	claimed  map[string]string // uniqueKey -> id of the record of the transaction claiming it
	released map[string]bool   // uniqueKey
}

// uniqueKey names unique value u of kind k in a transaction's bookkeeping (txUniques).
func uniqueKey(k model.Kind, u string) string { return string(k) + "\x00" + u }

// prepareTx checks and stamps an opTx: every write of partition p, in order, each as prepareWrite would, with unique
// values checked as the earlier writes leave them, and every assertion against the committed copy (whyStale when it
// does not hold). The owner prepares the partition's changes one at a time, each against what the ones before it
// committed, so an assertion is decided in the partition's order: no write of its record comes between it and the
// transaction's writes, and assertions of one record never conflict with each other. A transaction one of whose records
// is its request's already was applied (whyDone): every record of a transaction carries its one request id, and an
// assertion has none of its own to find (it writes nothing), so a transaction's outcome is that of its writes, and a
// replay (change.Replay) checks its assertions again as they now stand. A deletion of what is no longer live writes
// nothing (as a deletion of its own: writePartitioned), and the rest goes ahead. It returns the records to write and
// the stamp of every op, in order (an assertion or a deletion skipped: zero).
func (s *pstore) prepareTx(p int, c *change) ([]*store.Record, []writeReply, error) {
	if len(c.Ops) == 0 {
		return nil, nil, refuse(whyBad, "an empty transaction")
	}
	recs := make([]*store.Record, len(c.Ops))
	seen := map[string]bool{}
	for i, op := range c.Ops {
		rec, err := decodeRecord(op.Rec)
		if err != nil {
			return nil, nil, refuse(whyBad, "%v", err)
		}
		k := string(rec.Kind) + "/" + rec.ID
		if seen[k] {
			return nil, nil, refuse(whyBad, "%s written twice in one transaction", k)
		}
		seen[k] = true
		recs[i] = rec
		if op.Mode == modeAssert {
			continue
		}
		if err := s.retried(rec); err != nil {
			return nil, nil, err
		}
		if err := s.replayed(c.Replay, rec, op.Base); err != nil {
			return nil, nil, err
		}
	}
	tu := &txUniques{claimed: map[string]string{}, released: map[string]bool{}}
	var write []*store.Record
	stamps := make([]writeReply, len(c.Ops))
	for i, op := range c.Ops {
		if op.Mode == modeAssert {
			if err := s.prepareAssert(p, op.Expect, recs[i]); err != nil {
				return nil, nil, err
			}
			continue
		}
		if recs[i].Deleted && (op.Mode == modeBlind || op.Mode == modeMatch && op.Expect == 0) {
			cur, err := s.lookup(recs[i].Kind, recs[i].ID)
			if err != nil {
				return nil, nil, err
			}
			if cur == nil || !cur.Live(time.Now()) {
				continue
			}
		}
		if err := s.prepareWrite(p, op.Mode, op.Expect, recs[i], tu); err != nil {
			return nil, nil, err
		}
		write, stamps[i] = append(write, recs[i]), stampOf(recs[i])
	}
	if len(write) == 0 {
		return nil, nil, refuse(whyNothing, "nothing to write")
	}
	return write, stamps, nil
}

// prepareAssert checks an assertion of a transaction of partition p against the committed copy: the record rec names
// must be live, in p, at version expect (whyStale otherwise).
func (s *pstore) prepareAssert(p int, expect uint64, rec *store.Record) error {
	if localOnly(rec.Kind) || recPartition(rec) != p {
		return refuse(whyBad, "%s %s cannot be asserted in partition %d", rec.Kind, rec.ID, p)
	}
	cur, err := s.lookup(rec.Kind, rec.ID)
	if err != nil {
		return err
	}
	if !(store.Op{Rec: rec, Expect: hlc.Timestamp(expect)}).Asserted(cur, time.Now()) {
		return refuse(whyStale, "%s %s is not as the transaction expects", rec.Kind, rec.ID)
	}
	return nil
}

// prepareWrite checks and stamps rec, one record write in mode against the committed copy: the version compare of a
// compare-and-swap, a live write over a tombstone, the unique values within the partition (as the earlier writes of
// a transaction tu leave them; nil: a write of its own).
func (s *pstore) prepareWrite(p int, mode uint8, expect uint64, rec *store.Record, tu *txUniques) error {
	if localOnly(rec.Kind) {
		return refuse(whyBad, "%s records stay on the node that writes them", rec.Kind)
	}
	if recPartition(rec) != p {
		return refuse(whyBad, "%s %s belongs to partition %d, not %d", rec.Kind, rec.ID, recPartition(rec), p)
	}
	cur, err := s.lookup(rec.Kind, rec.ID)
	if err != nil {
		return err
	}
	if cur != nil && cur.Partition != rec.Partition {
		return refuse(whyMoved, "%s %s is in another partition (a record never moves)", rec.Kind, rec.ID)
	}
	live := cur != nil && cur.Live(time.Now())
	switch mode {
	case modeMatch:
		switch {
		case expect == 0 && live:
			return refuse(whyStale, "%s %s exists", rec.Kind, rec.ID)
		case expect != 0 && !live:
			return refuse(whyNotFound, "%s %s does not exist", rec.Kind, rec.ID)
		case expect != 0 && cur.Version != hlc.Timestamp(expect):
			return refuse(whyStale, "%s %s changed", rec.Kind, rec.ID)
		}
	case modeUpsert:
		if cur != nil && cur.Deleted {
			return refuse(whyDeleted, "%s %s was deleted", rec.Kind, rec.ID)
		}
	case modeBlind:
		if !live {
			return refuse(whyNothing, "%s %s is not there", rec.Kind, rec.ID)
		}
	}
	if rec.Deleted && !live {
		return refuse(whyNothing, "%s %s is not there", rec.Kind, rec.ID) // (store.Store.Put: nothing is written)
	}
	rec.Version = nextVersion(cur)
	var head *store.Head
	if cur != nil {
		head = cur.Head()
		if rec.Deleted {
			rec.Scope = cur.Scope // a tombstone carries it for the change hooks on every node
		}
	}
	// (a create is CompareAndPut's with no live record: a Put over an expired record continues its generation)
	if err := store.StampLocal(rec, head, mode == modeMatch && expect == 0); err != nil {
		return refuse(whyDeleted, "%v", err)
	}
	if !rec.Deleted {
		for _, u := range rec.Unique {
			if tu != nil {
				if id, ok := tu.claimed[uniqueKey(rec.Kind, u)]; ok && id != rec.ID {
					return refuse(whyConflict, "%q is in use", u)
				}
			}
			h, err := s.inner.GetByUnique(s.n.ctx, rec.Kind, u)
			switch {
			case err == nil && h.ID != rec.ID && (tu == nil || !tu.released[uniqueKey(rec.Kind, u)]):
				return refuse(whyConflict, "%q is in use", u)
			case err != nil && !errors.Is(err, store.ErrNotFound):
				return err
			}
		}
	}
	if tu != nil {
		if live {
			for _, u := range cur.Unique {
				if rec.Deleted || !slices.Contains(rec.Unique, u) {
					tu.released[uniqueKey(rec.Kind, u)] = true
				}
			}
		}
		if !rec.Deleted {
			for _, u := range rec.Unique {
				tu.claimed[uniqueKey(rec.Kind, u)] = rec.ID
				delete(tu.released, uniqueKey(rec.Kind, u))
			}
		}
	}
	return nil
}

// preparePurge checks a purge point the owner's housekeeping chose (purgeScan): never beyond what is committed, and
// not a purge that is already done.
func (s *pstore) preparePurge(p int, c *change) error {
	st := s.states[p].Load()
	switch {
	case c.Before > st.Committed.Seq+1:
		return refuse(whyBad, "purge point %d is beyond the committed position %d", c.Before, st.Committed.Seq)
	case c.Before < 2:
		return refuse(whyNothing, "nothing below sequence %d", c.Before)
	}
	ps, err := s.pst.PartitionState(s.n.ctx, p)
	if err != nil {
		return err
	}
	if store.PurgePoint(c.Before) <= ps.Purged {
		return refuse(whyNothing, "purged below %d already", ps.Purged+1)
	}
	return nil
}

// ---- reads, catch-up ----

// Read answers a fresh read on the owner: the records of one kind by id, tombstones included, from the committed data,
// those of this partition only (the asker may not know which partition holds an id and ask them all).
func (s *pstore) Read(p int, b []byte) ([]byte, error) {
	var q readReq
	if err := decodeMsg(b, &q); err != nil {
		return nil, refuse(whyBad, "malformed read: %v", err)
	}
	var out [][]byte
	size := 0
	for _, id := range q.IDs {
		r, err := s.lookup(model.Kind(q.Kind), id)
		if err != nil {
			return nil, err
		}
		if r == nil || recPartition(r) != p {
			continue
		}
		eb, err := encodeRecord(r)
		if err != nil {
			return nil, err
		}
		if size += len(eb); size > maxReadReply {
			return nil, refuse(whyLarge, "the records do not fit one message")
		}
		out = append(out, eb)
	}
	return encodeMsg(&out)
}

// exportRec is one record of a catch-up stream with the sequence of the write that last changed it.
type exportRec struct {
	Seq uint64
	Rec []byte
}

// exportEnd follows the end marker of a catch-up stream: the purge point of the source's copy, read after the records
// (so never below the snapshot's: nothing lowers a purge point). A purge is a write, but a catch-up carries records, not
// writes: a node that missed the purge write would keep the tombstones the others removed, and one that copies the
// partition whole would not know which of them its source had purged, so it purges to this point itself (Import). A
// stream without it is cut short.
type exportEnd struct {
	Purged uint64
}

// exportBuffer is how much of a catch-up stream is gathered before it is handed to the reader (and so the most an
// export holds in memory, besides one page of the backend's).
const exportBuffer = 64 << 10

// Export streams the committed data of p changed after a sequence: a frame per record, then an empty frame as the end
// marker, so that a stream cut short is told from a complete one. The backend reads the records from one snapshot and
// reports the position it reflects before the first of them (store.PartitionStore.ExportPartition), so the position is
// returned at once and the records follow as the reader takes them, through a pipe: nothing is gathered in memory beyond
// a buffer, and nothing is written to disk. The snapshot is held until the stream ends or the reader is closed (a
// reader that is closed early stops the export at its next record, and its context is cancelled at once).
//
// It refuses, with an error the asker's catch-up retries, when exportSlots exports run already, and when an import of p
// has begun here and not finished (the snapshot would hold the records it replaced at sequences above the committed
// position, which an export leaves out).
func (s *pstore) Export(p int, after uint64) (partition.Pos, io.ReadCloser, error) {
	if p < 0 || p >= partitions {
		return partition.Pos{}, nil, fmt.Errorf("cluster: partition %d out of range", p)
	}
	select {
	case s.exports <- struct{}{}:
	default:
		return partition.Pos{}, nil, errExportsBusy
	}
	type begun struct {
		pos store.PartitionPos
		err error
	}
	first := make(chan begun, 1)
	ctx, cancel := context.WithCancel(s.n.ctx)
	pr, pw := io.Pipe()
	go func() {
		defer func() { <-s.exports }()
		defer cancel()
		bw := bufio.NewWriterSize(pw, exportBuffer)
		started := false
		err := s.pst.ExportPartition(ctx, p, after, func(pos store.PartitionPos) error {
			started = true
			first <- begun{pos: pos}
			return nil
		}, func(r store.PartitionRecord) error {
			if localOnly(r.Kind) {
				return nil // (never in a partition: a node's own)
			}
			eb, err := encodeRecord(r.Record)
			if err != nil {
				return err
			}
			fb, err := encodeMsg(&exportRec{Seq: r.Seq, Rec: eb})
			if err != nil {
				return err
			}
			return writeFrame(bw, fb)
		})
		if !started {
			// Nobody reads the pipe (Export returns the error): nothing may be written to it.
			if err == nil {
				err = errors.New("cluster: the backend exported without a position")
			}
			first <- begun{err: err}
			_ = pw.CloseWithError(err)
			return
		}
		if err == nil {
			err = writeFrame(bw, nil) // the end marker
		}
		if err == nil {
			var st store.PartitionState
			if st, err = s.pst.PartitionState(ctx, p); err == nil {
				var tb []byte
				if tb, err = encodeMsg(&exportEnd{Purged: st.Purged}); err == nil {
					err = writeFrame(bw, tb)
				}
			}
		}
		if err == nil {
			err = bw.Flush()
		}
		_ = pw.CloseWithError(err) // nil: the reader sees the end of the stream
	}()
	b := <-first
	if b.err != nil {
		cancel()
		if errors.Is(b.err, store.ErrPartitionPurged) {
			return partition.Pos{}, nil, partition.ErrPurged
		}
		if errors.Is(b.err, store.ErrImportUnfinished) { // (a mark the data itself carries, across restarts)
			return partition.Pos{}, nil, errImportUnfinished
		}
		return partition.Pos{}, nil, b.err
	}
	return toPos(b.pos), &exportReader{PipeReader: pr, cancel: cancel}, nil
}

// exportReader is the reader of an export: closing it releases the snapshot.
type exportReader struct {
	*io.PipeReader
	cancel context.CancelFunc
}

func (r *exportReader) Close() error {
	r.cancel()
	return r.PipeReader.Close()
}

// importBatch is how many records Import applies in one call to the backend.
const importBatch = 1000

// Import applies a stream Export made, importBatch records at a time as they arrive (memory is bounded by a batch, not
// by the partition). The committed position moves only when the stream ends with its marker: a stream that ends early
// leaves the position where it was, with the batches before it already applied (committed data of the source, never
// uncommitted data, which the next catch-up, repeating the import, completes). A full copy first removes every record of p
// (the backend resets the partition), and the hooks hear of each removal (a cached session or grant that is gone must not be
// served); what the stream brings is applied, and heard of, after that.
func (s *pstore) Import(p int, r io.Reader, upTo partition.Pos, full bool) error {
	if p < 0 || p >= partitions {
		return fmt.Errorf("cluster: partition %d out of range", p)
	}
	// An import that began and did not finish left the partition holding some of a source's records and none of the rest
	// (a full one reset it first): whatever is asked now, it is replaced whole, by reset, then the stream (State reported
	// the partition Incomplete, so the library asked for all of it: the result is exact).
	full = full || s.importing[p].Load()
	br := bufio.NewReaderSize(r, exportBuffer)
	batch := make([]store.PartitionRecord, 0, importBatch)
	first := true
	removed := func(kind model.Kind, id string) {
		s.n.applied([]*store.Record{{Kind: kind, ID: id, Deleted: true}}) // removed by the copy
	}
	apply := func(final bool) error {
		step := store.ImportStep{Full: full, First: first, Final: final, Removed: removed}
		was := s.importing[p].Load()
		if full && first {
			if !was {
				s.n.log.Info("copying a partition whole to this node: it serves none of it until the copy finishes", "partition", p)
			}
			s.importing[p].Store(true) // before the backend resets anything: see importing
		}
		// Until an import completes, the partition's exports are refused by the backend (store.ErrImportUnfinished): its
		// records above the committed position, or its full-import marker, say so.
		if err := s.pst.ImportPartition(s.n.ctx, p, batch, fromPos(upTo), step); err != nil {
			if full && first && errors.Is(err, store.ErrPartitionBehind) {
				s.importing[p].Store(was) // refused before it reset anything
			}
			return err
		}
		s.n.applies.Add(1)
		first = false
		if final {
			s.committed(p, upTo)
			s.importing[p].Store(false)
		}
		recs := make([]*store.Record, len(batch))
		for i, b := range batch {
			recs[i] = b.Record
		}
		batch = batch[:0]
		s.n.applied(recs)
		return nil
	}
	// finish ends the import, full or not, by purging to the source's purge point or this node's, whichever is higher,
	// first: the source's purge writes are not in the stream, so a node that missed one would keep the tombstones the
	// others removed, and the records may bring tombstones at or below this node's own point (a point it took from an
	// earlier stream, ahead of its position). A purge point is only ever one a purge write set, never a position (a full
	// copy does not raise it to its own: the nodes that applied the purges keep the tombstones above them, and a node
	// that catches up from this one would purge to that position too), so every node at the same position holds the
	// same tombstones. The batches go first (a full copy's reset too), so that the purge reaches the tombstones they
	// bring, and the purge comes before the final step: a crash between the two repeats the catch-up, which finds the
	// purge done; after it, nothing would remind the node.
	finish := func() error {
		tb, err := readFrame(br)
		if err != nil {
			return fmt.Errorf("cluster: catch-up stream of partition %d ended early: %w", p, err)
		}
		var end exportEnd
		if err := decodeMsg(tb, &end); err != nil {
			return err
		}
		ps, err := s.pst.PartitionState(s.n.ctx, p)
		if err != nil {
			return err
		}
		if pt := max(end.Purged, ps.Purged); pt > 0 {
			if len(batch) > 0 || first {
				if err := apply(false); err != nil {
					return err
				}
			}
			if _, err := s.pst.PurgePartition(s.n.ctx, p, pt+1); err != nil {
				return err
			}
		}
		return apply(true)
	}
	for {
		fb, err := readFrame(br)
		if err != nil {
			return fmt.Errorf("cluster: catch-up stream of partition %d ended early: %w", p, err)
		}
		if len(fb) == 0 {
			return finish() // the end marker
		}
		var e exportRec
		if err := decodeMsg(fb, &e); err != nil {
			return err
		}
		rec, err := decodeRecord(e.Rec)
		if err != nil {
			return err
		}
		if localOnly(rec.Kind) {
			continue // another node's own records are never this node's
		}
		if batch = append(batch, store.PartitionRecord{Record: rec, Seq: e.Seq}); len(batch) == importBatch {
			if err := apply(false); err != nil {
				return err
			}
		}
	}
}

// Intact: the node's state can be trusted (loadState decides; the resync handler raises it once a resync completed).
func (s *pstore) Intact() bool { return s.n.intact.Load() }

// ---- the node's side of applying ----

// applied tells the node that records were applied by a commit or an import (on every node, the one that wrote them
// included): the change hooks run for each, so caches are evicted everywhere.
func (n *Node) applied(recs []*store.Record) {
	for _, r := range recs {
		n.checkSkew(r)
		n.fire(r, r.Origin == n.id)
	}
}
