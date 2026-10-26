package cluster

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	opWrite   uint8 = iota + 1 // put or compare-and-swap one record, a tombstone included
	opClaim                    // reserve a global unique value for a record (reservations)
	opRelease                  // free a reserved value its holder no longer holds
	opPurge                    // purge the tombstones below a sequence number
)

// How a record write is checked (change.Mode).
const (
	modeUpsert uint8 = iota // whole-record put: refused over a tombstone
	modeMatch               // compare-and-swap on the live version (0: the record must not exist)
	modeBlind               // a deletion that needs no particular version
)

// The codes a change is refused with (partition.Refuse); the cluster store turns them back into the store's errors.
const (
	whyStale    = "stale"    // the record is not at the version the writer expected
	whyConflict = "conflict" // a unique value is held by another record
	whyDeleted  = "deleted"  // a live write over a tombstone
	whyNotFound = "not-found"
	whyHeld     = "held"     // claim: this record already holds the reservation (nothing to write)
	whyNotHeld  = "not-held" // release: the reservation is not this record's (nothing to write)
	whyNothing  = "nothing"  // nothing to do (a deletion of what is not there, a purge with nothing to purge)
	whyBad      = "bad"      // malformed or in the wrong partition: a bug, never expected
	whyLarge    = "large"    // read: the reply would not fit one message; ask for fewer records
)

// change is the argument of partition.Manager.Write: what the landing node wants. The owner's Prepare checks it against
// the committed data and turns it into a writeData.
type change struct {
	Op     uint8
	Mode   uint8
	Expect uint64 // opWrite, modeMatch: the live version the record must have (0: it must not exist); opRelease: that of the reservation (0: any)
	Rec    []byte // opWrite: the encoded record (encodeRecord), not yet stamped
	Kind   string // opClaim, opRelease: the kind of the holder, and of the value's namespace
	ID     string // opClaim, opRelease: the holder's id
	Key    string // opClaim, opRelease: the reserved unique value
	Before uint64 // opPurge: tombstones with a sequence below this go
	// opRelease by the sweep (SweepReservations), which knows the reservation and not the value: the reservation's id
	// instead of Key, and the version it read (Expect), which the reservation must still have.
	Resv string
}

// writeData is the data of a write (partition.Write.Data): the records every node applies, stamped by the owner, and
// the purge point to apply first. Commit does exactly this, deterministically.
type writeData struct {
	Recs  [][]byte
	Purge uint64
}

// writeReply is what the owner's Prepare tells the caller: the stamp of the record it wrote.
type writeReply struct {
	Version uint64
	Epoch   uint64
	Created uint64
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

// ---- reservations of global unique values ----

// reservationGrace is how long a reservation is left alone after it was made or last taken over, whatever its holder
// looks like: the holder is written after the claim (so a crash between the two leaves the value reserved with no
// record to hold it), and a claimant that finds a young reservation whose holder does not hold the value yet must not
// take it over under a record that is about to. After it a claim takes the reservation over only when the holder is
// known not to hold the value (prepareClaim); one whose holder this node does not hold at all is left to the sweep
// (SweepReservations). A variable for tests.
var reservationGrace = time.Minute

// maxResvKey is the longest reservation id stored as it is: the SQL backends' id column is 191 characters.
const maxResvKey = 150

// reservationID is the id of the reservation of a unique value of a kind: the kind and the value, or, when that is too
// long for an id, the kind and a hash of the value (the same value always gives the same id).
func reservationID(kind model.Kind, key string) string {
	id := string(kind) + "/" + key
	if len(id) <= maxResvKey {
		return id
	}
	h := sha256.Sum256([]byte(key))
	return string(kind) + "/#" + base64.RawURLEncoding.EncodeToString(h[:])
}

// globalKind reports whether k has unique values that must hold across organizations (model.GlobalUnique): the kinds
// whose records are checked for them when written (TestGlobalKindsMatchTheModel keeps it in step with the model).
func globalKind(k model.Kind) bool { return k == model.KindTenant || k == model.KindPasskey }

// holdsUnique reports whether the entity in r still lists key among its unique values.
func holdsUnique(r *store.Record, key string) bool {
	e := model.NewEntity(r.Kind)
	if e == nil || store.Decode(r, e) != nil {
		return false
	}
	for _, u := range e.Index().Unique {
		if u == key {
			return true
		}
	}
	return false
}

// globalsOf returns the global unique values the entity in r lists (r.Unique has them stripped: they are reserved).
func globalsOf(r *store.Record) []string {
	if r == nil || !globalKind(r.Kind) || r.Deleted {
		return nil
	}
	e := model.NewEntity(r.Kind)
	if e == nil || store.Decode(r, e) != nil {
		return nil
	}
	var out []string
	for _, u := range e.Index().Unique {
		if model.GlobalUnique(r.Kind, u) {
			out = append(out, u)
		}
	}
	return out
}

// ---- the Store of the partition protocol ----

// pstore is the partition.Store of a node: the protocol's durable state and committed data over the node's own backend
// (store.PartitionStore), and the owner's checks of every change (Prepare). It keeps each partition's state in memory
// (the library asks for it on every message): the backend is read once, at start, and written by the methods below.
type pstore struct {
	n      *Node
	inner  store.Store
	pst    store.PartitionStore
	states [partitions]atomic.Pointer[partition.State]
	// exports bounds the exports running at once (exportSlots): each holds a snapshot, and on SQLite a reader
	// connection, for as long as its stream lasts.
	exports chan struct{}
	// importing marks a partition whose import has begun here and not finished (Import): its records may be above the
	// committed position, so an export would miss the ones the import replaced (Export refuses until it finishes).
	importing [partitions]atomic.Bool
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
// written by something other than the partition protocol (an older build, a restore outside "quisora restore").
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
	return *s.states[p].Load(), nil
}

func (s *pstore) SetPromised(p int, e partition.Epoch) error {
	if err := s.pst.SetPartitionPromised(s.n.ctx, p, fromEpoch(e)); err != nil {
		return err
	}
	s.update(p, func(st *partition.State) { st.Promised = e })
	return nil
}

func (s *pstore) SetPending(p int, w *partition.Write) error {
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
		rec, err := s.prepareWrite(p, &c)
		if err != nil {
			return nil, nil, err
		}
		recs, rep = []*store.Record{rec}, writeReply{uint64(rec.Version), uint64(rec.Epoch), uint64(rec.Created)}
	case opClaim:
		rec, err := s.prepareClaim(p, &c)
		if err != nil {
			return nil, nil, err
		}
		recs, rep = []*store.Record{rec}, writeReply{Version: uint64(rec.Version)}
	case opRelease:
		rec, err := s.prepareRelease(p, &c)
		if err != nil {
			return nil, nil, err
		}
		recs, rep = []*store.Record{rec}, writeReply{Version: uint64(rec.Version)}
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

// prepareWrite checks and stamps one record write against the committed copy: the version compare of a
// compare-and-swap, a live write over a tombstone, the unique values within the partition.
func (s *pstore) prepareWrite(p int, c *change) (*store.Record, error) {
	rec, err := decodeRecord(c.Rec)
	if err != nil {
		return nil, refuse(whyBad, "%v", err)
	}
	if localOnly(rec.Kind) {
		return nil, refuse(whyBad, "%s records stay on the node that writes them", rec.Kind)
	}
	if recPartition(rec) != p {
		return nil, refuse(whyBad, "%s %s belongs to partition %d, not %d", rec.Kind, rec.ID, recPartition(rec), p)
	}
	cur, err := s.lookup(rec.Kind, rec.ID)
	if err != nil {
		return nil, err
	}
	if cur != nil && cur.Partition != rec.Partition {
		return nil, refuse(whyBad, "%s %s is in another partition (a record never moves)", rec.Kind, rec.ID)
	}
	live := cur != nil && cur.Live(time.Now())
	switch c.Mode {
	case modeMatch:
		switch {
		case c.Expect == 0 && live:
			return nil, refuse(whyStale, "%s %s exists", rec.Kind, rec.ID)
		case c.Expect != 0 && !live:
			return nil, refuse(whyNotFound, "%s %s does not exist", rec.Kind, rec.ID)
		case c.Expect != 0 && cur.Version != hlc.Timestamp(c.Expect):
			return nil, refuse(whyStale, "%s %s changed", rec.Kind, rec.ID)
		}
	case modeUpsert:
		if cur != nil && cur.Deleted {
			return nil, refuse(whyDeleted, "%s %s was deleted", rec.Kind, rec.ID)
		}
	case modeBlind:
		if !live {
			return nil, refuse(whyNothing, "%s %s is not there", rec.Kind, rec.ID)
		}
	}
	rec.Version = nextVersion(cur)
	var head *store.Head
	if cur != nil {
		head = cur.Head()
		if rec.Deleted {
			rec.Scope = cur.Scope // a tombstone carries it for the change hooks on every node
		}
	}
	if err := store.StampLocal(rec, head, !live); err != nil {
		return nil, refuse(whyDeleted, "%v", err)
	}
	if !rec.Deleted {
		for _, u := range rec.Unique {
			if model.GlobalUnique(rec.Kind, u) {
				return nil, refuse(whyBad, "%s %s lists the global value %q (it is reserved, not indexed)", rec.Kind, rec.ID, u)
			}
			if h, err := s.inner.GetByUnique(s.n.ctx, rec.Kind, u); err == nil && h.ID != rec.ID {
				return nil, refuse(whyConflict, "%q is in use", u)
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
	}
	return rec, nil
}

// reservation returns the stored reservation record id (live) and its holder.
func (s *pstore) reservation(id string) (*store.Record, *model.Reservation, error) {
	cur, err := s.lookup(model.KindReservation, id)
	if err != nil || cur == nil || !cur.Live(time.Now()) {
		return cur, nil, err
	}
	r := &model.Reservation{}
	if err := store.Decode(cur, r); err != nil {
		return cur, nil, err
	}
	return cur, r, nil
}

// prepareClaim reserves a global unique value for a record. A value held by a record that holds it is refused. One whose
// reservation is older than reservationGrace is taken over only on positive evidence: the holder, as this node (the
// reservation's owner) has it, is a tombstone or a live record that does not list the value, and that copy was written
// after the reservation (its version is later). This node's copy of the holder's partition may lag: a copy from before
// the reservation (a holder this node does not have at all, or one that predates the update that added the value) is
// not evidence of anything, so the reservation stays, and the sweep of the housekeeping leader, which reads the holder
// through its own partition's owner, releases the reservations of holders that really are gone.
func (s *pstore) prepareClaim(p int, c *change) (*store.Record, error) {
	kind := model.Kind(c.Kind)
	id := reservationID(kind, c.Key)
	if partitionNum(id) != p || !model.GlobalUnique(kind, c.Key) {
		return nil, refuse(whyBad, "%q is not a global value of %s, or belongs to another partition", c.Key, kind)
	}
	cur, r, err := s.reservation(id)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if r != nil {
		if r.HolderKind == kind && r.HolderID == c.ID {
			return nil, refuse(whyHeld, "%q is already reserved for %s %s", c.Key, kind, c.ID)
		}
		if now.Sub(r.Updated) < reservationGrace {
			return nil, refuse(whyConflict, "%q is in use", c.Key)
		}
		h, err := s.lookup(r.HolderKind, r.HolderID)
		if err != nil {
			return nil, err
		}
		if h == nil || h.Version <= cur.Version || (h.Live(now) && holdsUnique(h, c.Key)) {
			return nil, refuse(whyConflict, "%q is in use", c.Key)
		}
	}
	e := &model.Reservation{Meta: model.Meta{ID: id, Created: now.UTC(), Updated: now.UTC(), Version: nextVersion(cur)},
		HolderKind: kind, HolderID: c.ID}
	rec, err := store.EncodeAsIs(e)
	if err != nil {
		return nil, err
	}
	rec.Origin = s.n.id
	var head *store.Head
	if cur != nil {
		head = cur.Head()
	}
	if err := store.StampLocal(rec, head, r == nil); err != nil {
		return nil, refuse(whyDeleted, "%v", err)
	}
	return rec, nil
}

// prepareRelease frees a reservation its holder no longer holds the value of (after the record changed or was deleted,
// or the sweep found the holder gone). The sweep names the reservation and the version it read: a reservation that has
// changed since (taken over, made again) is not released.
func (s *pstore) prepareRelease(p int, c *change) (*store.Record, error) {
	kind := model.Kind(c.Kind)
	id := c.Resv
	if id == "" {
		id = reservationID(kind, c.Key)
	}
	if partitionNum(id) != p {
		return nil, refuse(whyBad, "%q belongs to another partition", id)
	}
	cur, r, err := s.reservation(id)
	if err != nil {
		return nil, err
	}
	if r == nil || r.HolderKind != kind || r.HolderID != c.ID {
		return nil, refuse(whyNotHeld, "%q is not reserved for %s %s", id, kind, c.ID)
	}
	if c.Expect != 0 && cur.Version != hlc.Timestamp(c.Expect) {
		return nil, refuse(whyStale, "%q changed", id)
	}
	t := store.Tombstone(model.KindReservation, id)
	t.Version, t.Origin, t.Partition = nextVersion(cur), s.n.id, id
	return t, nil
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
			// The snapshot is taken: an import that began before it may be in it, half done.
			if s.importing[p].Load() {
				return errImportUnfinished
			}
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
// uncommitted data, which the next catch-up, repeating the import, completes). A full copy removes every record of p it
// does not bring, and the hooks hear of each removal (a cached session or grant that is gone must not be served).
func (s *pstore) Import(p int, r io.Reader, upTo partition.Pos, full bool) error {
	if p < 0 || p >= partitions {
		return fmt.Errorf("cluster: partition %d out of range", p)
	}
	br := bufio.NewReaderSize(r, exportBuffer)
	batch := make([]store.PartitionRecord, 0, importBatch)
	first := true
	removed := func(kind model.Kind, id string) {
		s.n.applied([]*store.Record{{Kind: kind, ID: id, Deleted: true}}) // removed by the copy
	}
	apply := func(final bool) error {
		step := store.ImportStep{Full: full, First: first, Final: final, Removed: removed}
		// Until an import completes, the partition's exports are refused (Export): marked before its first batch is
		// applied, cleared by its final one only, so an import that fails part way leaves the mark until another
		// completes (the partition is behind, so one does).
		s.importing[p].Store(true)
		if err := s.pst.ImportPartition(s.n.ctx, p, batch, fromPos(upTo), step); err != nil {
			return err
		}
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
	for {
		fb, err := readFrame(br)
		if err != nil {
			return fmt.Errorf("cluster: catch-up stream of partition %d ended early: %w", p, err)
		}
		if len(fb) == 0 {
			return apply(true) // the end marker
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
		if r.Kind == model.KindReservation {
			continue
		}
		n.checkSkew(r)
		n.fire(r, r.Origin == n.id)
	}
}
