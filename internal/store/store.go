// Package store defines the storage contract shared by every backend, plus a typed wrapper (Table) used by the
// rest of the code base.
package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
)

var (
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned by Put when a unique value is held by another live record of the same kind.
	ErrConflict = errors.New("store: unique value already in use")
	// ErrStale is returned by Put when the stored record is at the same or a newer version, and by CompareAndPut
	// when the stored version is not the expected one.
	ErrStale = errors.New("store: stale version")
	// ErrBadQuery is returned for an unknown sort or filter field.
	ErrBadQuery = errors.New("store: invalid query")
	// ErrDeleted is returned by Put when a live record would replace a tombstone: the record was deleted, and an
	// update (made from a copy read before the deletion arrived) must not bring it back. A record is created again
	// only with CompareAndPut(expect 0), which starts a new generation (see Record.Epoch). It matches ErrNotFound.
	ErrDeleted = fmt.Errorf("%w (deleted)", ErrNotFound)
	// ErrUnavailable is the one "try again" answer of every store: it cannot complete the request now (a database or
	// connection that failed, a database that refuses service, a lock or busy timeout; in a cluster, a node that cannot
	// vouch for its copy, or a write whose outcome could not be settled within its deadline). A write may have been
	// applied by an earlier attempt; retrying it is safe (Record.Req).
	ErrUnavailable = errors.New("store: unavailable now, try again shortly")
	// ErrBadTx is returned by Tx for a transaction it cannot take: no writes, one record written twice, or (in a
	// gossip cluster) writes in more than one partition or of node-local kinds. Nothing was written.
	ErrBadTx = errors.New("store: invalid transaction")
	// ErrUnconfirmed marks an ErrUnavailable whose write may have been applied: the store could not settle its outcome
	// before its deadline (a commit whose connection was lost and could not be read back; in a cluster, a write whose
	// owner did not answer for longer than the settling). It is the one thing a caller may tell from a plain
	// ErrUnavailable, and only to record the change as of unknown outcome (the audit log); retrying is safe either way.
	ErrUnconfirmed = errors.New("store: write not confirmed by a majority of the cluster")
)

// Record is the backend-neutral form of a stored entity.
type Record struct {
	Kind    model.Kind
	ID      string
	Version hlc.Timestamp
	// Epoch is the generation of a live record: 0 for a record created once, or — for a record created again after
	// a deletion — the version of the tombstone its writer had seen and superseded. Updates keep it. Tombstones carry
	// 0 here. See StampLocal.
	Epoch hlc.Timestamp
	// Created is the version of the write that created this generation of a live record; updates keep it. 0 on
	// tombstones.
	Created hlc.Timestamp
	Origin  string // id of the node that minted Version
	// Req is the id of the request that wrote this version (NewReq; set by the store when the writer sets none): a
	// retry of that request finds it stored and is answered as done (Retried). Kept by every write path, partition
	// writes, exports and imports included.
	Req     string
	Deleted bool // tombstone: invisible to Get/GetByUnique/List/Count, kept until purged
	Scope   string
	// Partition is the record's partition key (model.Index.Partition): "" for global data. Stored and returned by every
	// backend with the record; a tombstone keeps it (the writer of a tombstone sets it from the record it deletes).
	Partition string
	Unique    []string       // unique values, unique within Kind
	Fields    map[string]any // queryable values for the kind's schema (string, int64, bool, time.Time)
	Data      []byte         // msgpack of the entity; nil for tombstones
	Expires   time.Time      // zero = never; an expired record behaves as if it does not exist
}

// Live reports whether the record is visible at now.
func (r *Record) Live(now time.Time) bool {
	return !r.Deleted && (r.Expires.IsZero() || now.Before(r.Expires))
}

// Head is the version metadata of a stored record (backends keep it in their own form).
type Head struct {
	Kind                    model.Kind
	Version, Epoch, Created hlc.Timestamp
	Deleted                 bool
	Origin                  string
	Req                     string
}

// Head returns the record's version metadata.
func (r *Record) Head() *Head {
	return &Head{Kind: r.Kind, Version: r.Version, Epoch: r.Epoch, Created: r.Created, Deleted: r.Deleted, Origin: r.Origin,
		Req: r.Req}
}

// Filter is a condition on a schema field: equality (Op ""), or one of the operators below.
type Filter struct {
	Field string
	Value any
	Op    string
}

// Filter operators besides equality.
const (
	OpPrefix = "prefix" // a string field starts with Value (case-insensitively)
	OpGTE    = "gte"    // a time or integer field is at or after Value
	OpLT     = "lt"     // a time or integer field is before Value
)

// MultiGetter is optionally implemented by backends that read several records in one round trip. GetMany uses it
// where available and falls back to one Get per id.
type MultiGetter interface {
	// GetMany returns the live records of kind among ids, in the order of ids; ids with no live record are left out.
	GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*Record, error)
}

// GetMany returns the live records of kind among ids, in the order of ids, leaving out those with none: one read on a
// backend that reads many at once (MultiGetter), else one Get per id.
func GetMany(ctx context.Context, s Store, kind model.Kind, ids []string) ([]*Record, error) {
	if mg, ok := s.(MultiGetter); ok {
		return mg.GetMany(ctx, kind, ids)
	}
	out := make([]*Record, 0, len(ids))
	for _, id := range ids {
		r, err := s.Get(ctx, kind, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ListQuery selects records of one kind.
//
// Scope restricts the listing to one scope ("" lists every record of the kind). Search is a case-insensitive prefix
// match over the schema's Search fields (any field starting with it selects the record). Filters must all match.
// Sort names a Sort field (strings compare case-insensitively); "" sorts by ID. Ties always break by ID ascending.
// Limit <= 0 means no limit.
//
// When Sort is "" and Search and Filters are empty, backends page through the scope in ID order without loading
// the whole scope (IDs are UUIDv7, so this is creation order). That is the path used for very large scopes such
// as audit logs.
type ListQuery struct {
	Scope   string
	Search  string
	Filters []Filter
	Sort    string
	Desc    bool
	Offset  int
	Limit   int
	// After pages by key instead of offset: only records with an ID greater than After, in ID order. It needs an
	// ID-ordered ascending query (no Sort, not Desc) and ignores Offset; Total is then the page length. Records
	// created or deleted between pages cannot shift later pages, so a scan of a live store sees every record that
	// existed throughout it.
	After string
	// IDsOnly says only the records' ids are wanted: a backend that can answer from an index without loading the
	// records (the key-value stores, for one indexed filter) returns records holding only Kind and ID. Use Table.IDs.
	IDsOnly bool
}

// ListResult holds one page of a listing; Total counts every match ignoring Offset and Limit.
type ListResult struct {
	Records []*Record
	Total   int
}

// Op is one write of a transaction (Store.Tx): rec (a tombstone when rec.Deleted), as Put, or with Match as
// CompareAndPut(rec, Expect).
type Op struct {
	Rec    *Record
	Match  bool
	Expect hlc.Timestamp
}

// NewReq returns a new request id (Record.Req): a random prefix of this process and a count, unique without a random
// draw per write (a write's ids are made on its hot path).
func NewReq() string { return reqPrefix + strconv.FormatUint(reqCount.Add(1), 36) }

var (
	reqPrefix = model.NewID() + "/"
	reqCount  atomic.Uint64
)

// EnsureReq gives rec a request id for the write being made when its writer set none, and returns what takes that id
// off again, to be called when the write returns (deferred): an id the store made is this write's own, so a record its
// writer changes and writes again is another request, not a retry of this one (Retried would answer it as done and
// write nothing). An id the writer set is kept: writing it again is a retry. Every write path calls it first.
func EnsureReq(rec *Record) (done func()) {
	if rec.Req != "" {
		return func() {}
	}
	rec.Req = NewReq()
	return func() { rec.Req = "" }
}

// TxReq is EnsureReq for the records of a transaction (Store.Tx): the first op's id, its writer's or one the store
// makes, on every op that has none; the returned function takes off those the store set.
func TxReq(ops []Op) (done func()) {
	first := ops[0].Rec.Req
	if first == "" {
		first = NewReq()
	}
	var set []*Record
	for _, op := range ops {
		if op.Rec.Req == "" {
			op.Rec.Req = first
			set = append(set, op.Rec)
		}
	}
	return func() {
		for _, r := range set {
			r.Req = ""
		}
	}
}

// Retried reports whether old, the record stored, was written by rec's request: a retry of a write that was applied.
// The store then writes nothing and answers success, with rec taking the stored version (Settle).
func Retried(rec *Record, old *Head) bool { return old != nil && rec.Req != "" && old.Req == rec.Req }

// Settle gives rec the version, epoch and creation of old, the stored record its request wrote (Retried).
func Settle(rec *Record, old *Head) {
	rec.Version, rec.Epoch, rec.Created = old.Version, old.Epoch, old.Created
}

// StampWrite gives rec the version of a write made now over the stored record old (nil: nothing stored): from Clock,
// and newer than old's whatever the clocks (the store orders writes; a caller's version is not used).
func StampWrite(rec *Record, old *Head) {
	if old != nil {
		Witness(old.Version)
	}
	rec.Version = Clock.Now()
	if old != nil && rec.Version <= old.Version {
		rec.Version = old.Version + 1
	}
}

// StampLocal sets rec.Epoch and rec.Created for a local write of rec over the stored record old (nil: nothing
// stored, not even a tombstone) and refuses a live write that would replace a tombstone (ErrDeleted), unless create
// (CompareAndPut with expect 0) or the kind is node-local (KindEphemeral). A live write over a live record continues
// its generation; a create over nothing starts generation 0; a create over a tombstone starts a generation whose
// epoch is that tombstone's version (the deletion this writer has seen). A deletion has none. Backends call it inside
// the write transaction, after StampWrite.
func StampLocal(rec *Record, old *Head, create bool) error {
	switch {
	case rec.Deleted:
		rec.Epoch, rec.Created = 0, 0
	case old == nil:
		rec.Epoch, rec.Created = 0, rec.Version
	case old.Deleted:
		if !create && rec.Kind != model.KindEphemeral {
			return ErrDeleted
		}
		rec.Epoch, rec.Created = old.Version, rec.Version
	case create: // over a stored record that has expired: a new record, same generation
		rec.Epoch, rec.Created = old.Epoch, rec.Version
	default:
		rec.Epoch, rec.Created = old.Epoch, old.Created
	}
	return nil
}

// Store is implemented by every backend. All methods are safe for concurrent use.
type Store interface {
	// Get returns a live record.
	Get(ctx context.Context, kind model.Kind, id string) (*Record, error)
	// GetByUnique returns the live record of kind holding the unique value.
	GetByUnique(ctx context.Context, kind model.Kind, value string) (*Record, error)
	// Put writes rec (or a tombstone when rec.Deleted), whatever version is stored. The store stamps rec.Version
	// (StampWrite: newer than the stored one; the caller's is not used), and a request id for the write when the caller
	// set none (EnsureReq; taken off rec again when it returns). It fails with
	// ErrDeleted when a live rec would replace a tombstone (except KindEphemeral), and with ErrConflict if another live
	// record of the kind holds one of rec.Unique. Unique values the record no longer lists are released. It sets
	// rec.Epoch and rec.Created (StampLocal). A retry (Retried) is answered as done.
	Put(ctx context.Context, rec *Record) error
	// PutReplicated applies a record as it is (its Version, Epoch and Created are kept, nothing is stamped) unless one
	// of the same kind and id is stored, a tombstone included, with the same or a higher version (applied is false).
	// It is for loading records made elsewhere (a restore: into a store that holds none of them, or, with force, over
	// older ones); a gossip cluster's records arrive through partition writes (PartitionStore) and never through
	// here. A unique value another live record holds is refused with ErrConflict: nothing is resolved or stored
	// without its value.
	PutReplicated(ctx context.Context, rec *Record) (applied bool, err error)
	// Lookup returns the stored record of kind and id whatever its state: live, expired or a tombstone (which
	// carries only its metadata). ErrNotFound when nothing is stored.
	Lookup(ctx context.Context, kind model.Kind, id string) (*Record, error)
	// CompareAndPut writes rec only if the stored live record's version equals expect (ErrStale otherwise). With
	// expect == 0 it succeeds only when there is no live record (create; over a tombstone this starts a new
	// generation). ErrNotFound if expect != 0 and there is no live record. Also fails with ErrConflict like Put. It
	// stamps rec.Version and rec.Req and sets rec.Epoch and rec.Created as Put does. A retry (Retried) is answered as
	// done, whatever expect.
	CompareAndPut(ctx context.Context, rec *Record, expect hlc.Timestamp) error
	// Tx applies ops all or nothing, in one transaction: each as Put (or CompareAndPut, with Op.Match) would, with the
	// same refusals and stamps; the first refusal is returned and nothing is written. Unique values are checked across
	// the ops too, against the state the earlier ops leave (two claiming one value conflict; a value one op releases a
	// later op may claim). Records must be distinct, and there must be some (ErrBadTx otherwise). The records share one
	// request id: the first op's, or one the store makes, on every op without one (TxReq). A transaction
	// whose request is found stored (Retried, on any of its records) was applied: it is answered as done, each record
	// taking its stored version (Settle).
	Tx(ctx context.Context, ops []Op) error
	// List returns a page of live records.
	List(ctx context.Context, kind model.Kind, q ListQuery) (*ListResult, error)
	// Count returns the number of live records of kind in scope ("" = all).
	Count(ctx context.Context, kind model.Kind, scope string) (int, error)
	// FeedID identifies this database: random, created with it and persisted, so a wiped, replaced or restored database
	// has another. (The name is historical: no store keeps a change feed any more.)
	FeedID() string
	// Purge permanently removes tombstones last written before `tombstonesBefore` and records that expired before
	// `expiredBefore`. Returns how many records were removed.
	Purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error)
	// Close releases resources.
	Close() error
}
