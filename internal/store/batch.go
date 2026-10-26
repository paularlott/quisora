package store

import (
	"context"
	"errors"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// BatchReplicator is optionally implemented by backends that can apply many records in one write transaction (one
// fsync instead of one per record), with the semantics of PutReplicated for each in order: applied[i] describes
// recs[i]. A record refused with an error (a unique value another record holds: ErrConflict) stops the batch, and what
// the same transaction had applied may be undone: the caller gives up on an error. A restore uses it when available.
type BatchReplicator interface {
	PutReplicatedBatch(ctx context.Context, recs []*Record) (applied []bool, err error)
}

// Reader is a read-only view of a store.
type Reader interface {
	List(ctx context.Context, kind model.Kind, q ListQuery) (*ListResult, error)
	Count(ctx context.Context, kind model.Kind, scope string) (int, error)
	Close() error
}

// ErrNoSnapshot is returned by Snapshot when the backend (or its configuration) has no point-in-time view.
var ErrNoSnapshot = errors.New("store: no snapshot available")

// Snapshotter is optionally implemented by backends that can read a consistent point-in-time view of the whole
// store: Badger (one read transaction) and the SQL backends (one repeatable-read, read-only transaction). Backups
// read through it when available.
type Snapshotter interface {
	Snapshot(ctx context.Context) (Reader, error)
}

// ErrNoDueIndex is returned by ListDue when the backend keeps no due index.
var ErrNoDueIndex = errors.New("store: no due index")

// DueLister is implemented by backends that index records by when a housekeeping job must look at them (model.Due):
// the key-value stores, whose filtered queries read a whole kind. A job then reads only the records due, not every
// record (every user, every minute). The SQL backends answer the job's own query from their indexes and need none.
type DueLister interface {
	// ListDue returns up to limit live records of kind due at or before before, earliest first (ErrNoDueIndex: none
	// kept; use a query).
	ListDue(ctx context.Context, kind model.Kind, before time.Time, limit int) ([]*Record, error)
}

// QuorumReader is implemented by the cluster layer's store: Fresh returns the committed state of records as the owners
// of their partitions have it (tombstones included), so a decision made on them reflects every write committed before
// the call, wherever it was made. Without a cluster it reads the local store.
type QuorumReader interface {
	Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*Record, error)
}

// PartitionReader is a QuorumReader that can also be told which partition the records are in: FreshIn is Fresh for records
// that all have the partition key partitionKey (Record.Partition: for organization data, the organization's id), asked
// of that partition's owner directly, whether or not this store holds the records. An id this store holds is found
// by Fresh from its own copy; one it does not hold (a record another node made a moment ago) would otherwise be asked
// of every owner. The caller must know the key: a record of another partition is not found.
type PartitionReader interface {
	QuorumReader
	FreshIn(ctx context.Context, kind model.Kind, partitionKey string, ids []string) (map[string]*Record, error)
}
