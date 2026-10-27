package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
)

// Partition support: what a node-local backend must add for the gossip mode that replicates by partition
// (docs/design/partitioned-replication.md; the protocol is github.com/paularlott/gossip/partition). A backend that can
// run it implements PartitionStore. The cluster layer sits between the two: it owns the protocol, the partition numbers
// (a record's partition key, Record.Partition, hashed to 0..63) and the wire format; the backend keeps, in the same
// database as the data, each partition's protocol state and enough about every record to answer "what changed in
// partition p after sequence s".
//
// Records written by ApplyPartition and ImportPartition carry two stamps besides their Partition key: the partition
// number they were applied to and the sequence number (Seq) of the write that last changed them. A record written any
// other way (Put, CompareAndPut, PutReplicated) carries no stamp: it belongs to no partition write and is never
// exported. Sequence numbers start at 1 and are compared as numbers, so a stamp is 0 only when there is none.
//
// Durability, as the protocol needs it (partition/store.go, "Durability"): SetPartitionPromised and SetPartitionPending
// are durable when they return, and make everything applied or imported before them durable too (a database's log is
// ordered; each backend says how). ApplyPartition, ImportPartition and PurgePartition are atomic, and need not be
// durable when they return.
type PartitionStore interface {
	// PartitionState returns the stored state of partition p (the zero state for a partition never written).
	PartitionState(ctx context.Context, p int) (PartitionState, error)

	// SetPartitionPromised durably records the promised epoch of p. It never lowers it: an epoch below the stored one is
	// refused with ErrPartitionRegress. It also makes durable every earlier ApplyPartition, ImportPartition and
	// PurgePartition of every partition.
	SetPartitionPromised(ctx context.Context, p int, e PartitionEpoch) error

	// SetPartitionPending durably records the pending write of p: an opaque blob, and the sequence number of the write it
	// holds (so that applying that write, or a later one, clears it in the same transaction). A nil blob clears it. Like
	// SetPartitionPromised it makes every earlier apply and import durable.
	SetPartitionPending(ctx context.Context, p int, seq uint64, pending []byte) error

	// ApplyPartition applies one committed write of partition p, in one transaction: every record is stored exactly as
	// given (no version comparison, no conflict resolution: the owner decided it; a tombstone is stored as a tombstone),
	// stamped with p and committed.Seq, its unique values updated as for a put (a value it lists is indexed under it
	// whoever held it before; a value it no longer lists is released), and p's committed position set to committed. The
	// pending write is cleared if its sequence is at most committed.Seq. It fails, changing nothing, with
	// ErrPartitionBehind unless committed.Seq is above the stored committed sequence. Records listed twice apply in order.
	ApplyPartition(ctx context.Context, p int, recs []*Record, committed PartitionPos) error

	// ExportPartition streams the committed data of partition p changed after afterSeq (0: every record), tombstones
	// included, from one consistent snapshot, which it holds until it returns. It calls start first, once, with the
	// committed position the snapshot reflects (the caller needs it before the records: a stream begins with it), then fn
	// for every record whose sequence is above afterSeq and at most that position (a record a crashed import left above
	// it is not committed data yet), in no particular order across kinds. It never holds more than a page of records in
	// memory. It returns ErrPartitionPurged, without calling start, if afterSeq is not 0 and is below the partition's
	// purge point (PartitionState.Purged): tombstones the caller needs may be gone, so it must ask again for everything.
	// It returns ErrImportUnfinished, without calling start, if the snapshot holds a record of p above the committed
	// position (commits write records and position together, so only an import that has not finished leaves one, and the
	// snapshot may lack records the committed position promises: one the import overwrote), or if a full import of p is in
	// progress (it began by removing records, which leaves nothing above the position). An error from start or fn stops
	// the export and is returned.
	ExportPartition(ctx context.Context, p int, afterSeq uint64, start func(PartitionPos) error, fn func(PartitionRecord) error) error

	// ImportPartition applies what ExportPartition returned, one batch of it per call, so that a partition of any size
	// is copied with bounded memory. Every record is stored as given with its own sequence (Seq, 1 to upTo.Seq), as
	// ApplyPartition does, and the committed position is set to upTo only by the Final batch (step: the caller makes
	// every call of one import with the same upTo, First on the first, Final on the last, one batch being both). Every
	// call fails, changing nothing, with ErrPartitionBehind unless upTo.Seq is above the stored committed sequence. No
	// call changes the purge point: the source's is not in the records, and the caller applies it with PurgePartition
	// before the Final call (a purge point is only ever one that a purge of the partition set, never a position: every
	// node at the same position must hold the same tombstones).
	//
	// With step.Full the copy replaces the partition, by reset then import: the First call, in one transaction, durably
	// marks the import as in progress (ExportPartition refuses, ErrImportUnfinished, until it ends), and then removes (not
	// tombstones) every record of p, in as many transactions as it takes, calling step.Removed for each after its removal
	// is committed; the batches then store the source's records into the emptied partition; the Final call sets the
	// committed position and clears the marker, in one transaction. A record the reset removed and a batch brings back is
	// reported removed all the same. The partition is not a copy of anything while the import runs (it holds only what
	// the batches brought), and a full import that did not finish (a crash, a failed call) is repeated from its First
	// call, which resets again.
	//
	// Atomicity: one batch is atomic, an import is not: a crash between its calls leaves the committed position where it
	// was with the batches already applied stored (committed data of the source, never uncommitted data: every record
	// carries the sequence of the write that made it), and the same import repeated, as the next catch-up does, completes
	// it. A record above the committed position is not exported. The Badger backend also splits one batch too big for a
	// transaction.
	ImportPartition(ctx context.Context, p int, recs []PartitionRecord, upTo PartitionPos, step ImportStep) error

	// PurgePartition removes the tombstones of partition p with a sequence below beforeSeq and records the purge point
	// (PartitionState.Purged = beforeSeq-1, never lowered); it returns how many it removed. Purging is a write of the
	// partition (every node purges the same ones at the same position), so nothing depends on a clock.
	PurgePartition(ctx context.Context, p int, beforeSeq uint64) (int, error)

	// PartitionTombstones calls fn with the sequence and version of every tombstone of partition p whose sequence is
	// above afterSeq and at most upTo (the committed position: a tombstone above it is a crashed import's), in no
	// particular order. It reads the tombstones only, from an index of them (the housekeeping scan for what to purge,
	// once an hour per partition, costs the number of tombstones, not of records). An error from fn stops it and is
	// returned.
	PartitionTombstones(ctx context.Context, p int, afterSeq, upTo uint64, fn func(seq uint64, version hlc.Timestamp) error) error
}

// ErrPartitionPurged is returned by ExportPartition when the tombstones the caller would need have been purged
// (PurgePartition): it must copy the partition whole (ExportPartition with afterSeq 0).
var ErrPartitionPurged = errors.New("store: partition history purged")

// ErrImportUnfinished is returned by ExportPartition while an import into the partition has not finished (here or before
// a restart): what the partition holds is not yet a copy of any committed position. The caller asks another node, or later.
var ErrImportUnfinished = errors.New("store: partition import not finished")

// ErrPartitionBehind is returned by ApplyPartition and ImportPartition when the position they would set is not above the
// partition's committed one: committed positions only move forward.
var ErrPartitionBehind = errors.New("store: partition position not above the committed one")

// ErrPartitionRegress is returned by SetPartitionPromised for an epoch below the stored promise.
var ErrPartitionRegress = errors.New("store: promised epoch below the stored one")

// MaxPartitionSeq is the highest sequence number a backend stores (the SQL backends keep it in a signed 64-bit column).
// The protocol refuses a write at the limit of 64 bits long before; this is a bound the stores can check.
const MaxPartitionSeq = math.MaxInt64

// PartitionEpoch identifies one tenure of ownership of a partition: ordered by Counter, then by Node. The zero epoch is
// the lowest.
type PartitionEpoch struct {
	Counter uint64
	Node    [16]byte // the proposing node's id (a UUID)
}

// Compare returns -1, 0 or 1 as e is lower than, equal to or higher than o.
func (e PartitionEpoch) Compare(o PartitionEpoch) int {
	switch {
	case e.Counter < o.Counter:
		return -1
	case e.Counter > o.Counter:
		return 1
	}
	return bytes.Compare(e.Node[:], o.Node[:])
}

// PartitionPos is the position of a committed write: the epoch of the owner that made it and its sequence number in the
// partition. Backends compare and index by Seq alone: the same write can carry different epochs on different nodes.
type PartitionPos struct {
	Epoch PartitionEpoch
	Seq   uint64
}

// PartitionState is the protocol state a backend keeps for one partition.
type PartitionState struct {
	// Promised is the highest epoch promised.
	Promised PartitionEpoch
	// Committed is the position of the last write applied; the partition's visible records are exactly the writes up to it.
	Committed PartitionPos
	// Pending is the stored but not yet committed write (opaque), and PendingSeq the sequence number it holds; nil, 0 if
	// none. A pending write whose sequence is at most Committed.Seq is cleared with the commit that passes it, so
	// the state never shows one.
	Pending    []byte
	PendingSeq uint64
	// Purged is the purge point: tombstones of the partition with a sequence at most Purged may have been removed
	// (PurgePartition), so changes can be exported only after a sequence of at least Purged. 0: none purged.
	Purged uint64
	// Importing is set while a full import of the partition has begun and not finished (the durable marker its First call
	// sets and its Final call clears; it survives a restart). The partition then holds only what the import's batches
	// brought into the emptied partition, whatever Committed says: the caller must not read it, take part in the
	// partition's protocol on the strength of it, or export it, and must repeat the import from its First call (a Full
	// one) however the next copy of the partition comes.
	Importing bool
}

// ImportStep says where one ImportPartition call lies in an import (see ImportPartition).
type ImportStep struct {
	// Full replaces the partition's data: the First call removes every record of it before the batches bring theirs.
	Full bool
	// First is the first call of the import (a Full import resets the partition, whatever an earlier import that did not
	// finish left); Final is the last one, which sets the committed position (and, Full, ends the import).
	First, Final bool
	// Removed, with Full and First, is called for every record the reset removed, after the removal is committed.
	Removed func(kind model.Kind, id string)
}

// PartitionRecord is a record of a partition with the sequence number of the write that last changed it.
type PartitionRecord struct {
	*Record
	Seq uint64
}

// CheckApply validates the arguments every backend's ApplyPartition shares.
func CheckApply(p int, committed PartitionPos) error {
	if p < 0 {
		return fmt.Errorf("store: partition %d out of range", p)
	}
	if committed.Seq == 0 || committed.Seq > MaxPartitionSeq {
		return fmt.Errorf("store: partition %d: write sequence %d out of range", p, committed.Seq)
	}
	return nil
}

// CheckImport validates the arguments every backend's ImportPartition shares.
func CheckImport(p int, recs []PartitionRecord, upTo PartitionPos) error {
	if err := CheckApply(p, upTo); err != nil {
		return err
	}
	for _, r := range recs {
		if r.Record == nil || r.Seq == 0 || r.Seq > upTo.Seq {
			return fmt.Errorf("store: partition %d import: a record has sequence %d outside 1 to %d", p, r.Seq, upTo.Seq)
		}
	}
	return nil
}

// PurgePoint is the PartitionState.Purged that purging below beforeSeq sets.
func PurgePoint(beforeSeq uint64) uint64 {
	if beforeSeq == 0 {
		return 0
	}
	return beforeSeq - 1
}

// ExportAllowed reports whether a partition with purge point purged can export the changes after afterSeq.
func ExportAllowed(purged, afterSeq uint64) bool { return afterSeq == 0 || afterSeq >= purged }
