package store

import (
	"context"
	"errors"

	"github.com/paularlott/quisora/internal/model"
)

// BatchReplicator is optionally implemented by backends that can apply many replicated records in one write
// transaction (one fsync instead of one per record). It has the semantics of calling PutReplicated for each record
// in order: applied[i] and losers[i] describe recs[i]. Bulk anti-entropy uses it when available.
type BatchReplicator interface {
	PutReplicatedBatch(ctx context.Context, recs []*Record) (applied []bool, losers [][]string, err error)
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

// QuorumReader is implemented by the cluster layer's store: Fresh returns the newest copies of records held by a
// quorum of the cluster (tombstones included), so a decision made on them reflects every write a majority confirmed
// before the call, wherever it was made. Without a cluster it reads the local store.
type QuorumReader interface {
	Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*Record, error)
}
