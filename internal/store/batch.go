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
// read through it when available. A view that holds a partition part-way through an import is refused with
// ErrUnavailable, by the rule exports follow (ErrImportUnfinished): a full import's marker (PartitionState.Importing:
// its reset removed records the view would then lack), or records above a partition's committed position (an import
// cut short: some of a write's records changed and the others not yet). A backup of either would verify and restore,
// and hold data the cluster never committed together. The backend refuses it whoever asks, a running node or an
// offline command.
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
