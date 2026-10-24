// Package store defines the storage contract shared by every backend, plus a typed wrapper (Table) used by the
// rest of the code base.
package store

import (
	"context"
	"errors"
	"fmt"
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
	// ErrNotReplicated means a durable write was applied locally but a majority did not acknowledge it in time; it
	// still reaches the peers later, so whatever must follow it (ending sessions, auditing) should. The cluster layer
	// counts and logs it and reports success to the caller (Applied treats it as success either way); with
	// cluster.strict_durability the caller gets ErrUnconfirmed instead.
	ErrNotReplicated = errors.New("store: write not acknowledged by a majority")
	// ErrDeleted is returned by Put when a live record would replace a tombstone: the record was deleted, and an
	// update (made from a copy read before the deletion arrived) must not bring it back. A record is created again
	// only with CompareAndPut(expect 0), which starts a new generation (see Record.Epoch). It matches ErrNotFound.
	ErrDeleted = fmt.Errorf("%w (deleted)", ErrNotFound)
	// ErrNotWritable is returned by a write refused because this node cannot know that its data is current (it is
	// catching up, out of date, or cut off from the majority of its cluster). Nothing was written.
	ErrNotWritable = errors.New("store: this node does not accept writes now")
	// ErrUnconfirmed is returned by a quorum compare-and-swap (model.QuorumCAS kinds) that a majority of the cluster
	// did not confirm, and, with cluster.strict_durability, by a durable write of another kind a majority did not
	// confirm. A quorum write refused before its commit has no effect anywhere; one whose commit reached fewer than a
	// majority may be in effect on some nodes (it then replicates like any write, and every later conflicting write
	// ranks above it). Unlike ErrNotReplicated it is a failure (Applied false).
	ErrUnconfirmed = errors.New("store: write not confirmed by a majority of the cluster")
)

// Applied reports whether a write took effect locally: it succeeded, or only its replication is unconfirmed.
func Applied(err error) bool { return err == nil || errors.Is(err, ErrNotReplicated) }

// Record is the backend-neutral form of a stored entity.
type Record struct {
	Kind    model.Kind
	ID      string
	Version hlc.Timestamp
	// Epoch is the generation of a live record: 0 for a record created once, or — for a record created again after
	// a deletion — the version of the tombstone its writer had seen and superseded. Updates keep it. A tombstone's
	// epoch is its own Version (Rank), so a deletion the re-creating writer had not seen still wins. Tombstones carry
	// 0 here. See Newer.
	Epoch hlc.Timestamp
	// Created is the version of the write that created this generation of a live record; updates keep it. Of two
	// records claiming one unique value the one created first keeps it (KeepsUnique). 0 on tombstones.
	Created hlc.Timestamp
	Origin  string // id of the node that minted Version; breaks ties between equal versions
	Deleted bool   // tombstone: invisible to Get/GetByUnique/List/Count, kept for replication until purged
	Scope   string
	Unique  []string       // unique values, unique within Kind
	Fields  map[string]any // queryable values for the kind's schema (string, int64, bool, time.Time)
	Data    []byte         // msgpack of the entity; nil for tombstones
	Expires time.Time      // zero = never; an expired record behaves as if it does not exist
}

// Live reports whether the record is visible at now.
func (r *Record) Live(now time.Time) bool {
	return !r.Deleted && (r.Expires.IsZero() || now.Before(r.Expires))
}

// Head is the replication metadata of a stored record (backends keep it in their own form).
type Head struct {
	Kind                    model.Kind
	Version, Epoch, Created hlc.Timestamp
	Deleted                 bool
	Origin                  string
}

// Head returns the record's replication metadata.
func (r *Record) Head() *Head {
	return &Head{Kind: r.Kind, Version: r.Version, Epoch: r.Epoch, Created: r.Created, Deleted: r.Deleted, Origin: r.Origin}
}

// Rank orders the stored states of one record: by epoch (generation), then version. The higher rank wins
// everywhere — on every replication path and in every backend.
type Rank struct {
	Epoch, Version hlc.Timestamp
}

// Less reports whether r ranks below o.
func (r Rank) Less(o Rank) bool {
	if r.Epoch != o.Epoch {
		return r.Epoch < o.Epoch
	}
	return r.Version < o.Version
}

// Rank returns the record's rank. For a kind written by plain replication it is (epoch, version), a tombstone's epoch
// being its own version: a deletion outranks every write of the generation it deleted, whatever the clocks, so a
// write that had not seen it never brings the record back. For a quorum kind (model.QuorumCAS) it is the version
// alone: the voters already order the versions of a record as its writes are granted (any two grants share a voter,
// whose high-water mark forces the later one higher; no voter grants a version far ahead of its clock; a restarted
// voter starts above everything it granted), and the quorum, not the rank, keeps a confirmed deletion from being
// undone (a later write must win a quorum that holds the tombstone, which refuses a write that had not seen it). So
// the later write always wins: a confirmed write over a partly applied one (a commit that reached fewer than a
// quorum), deletion or not, whatever generations they belong to. Generations still order what the voters check
// (cluster prepare), only not the merge.
func (h *Head) Rank() Rank {
	switch {
	case model.QuorumCAS(h.Kind):
		return Rank{Version: h.Version}
	case h.Deleted:
		return Rank{Epoch: h.Version, Version: h.Version}
	}
	return Rank{Epoch: h.Epoch, Version: h.Version}
}

// Rank returns the record's rank (Head.Rank).
func (r *Record) Rank() Rank { return r.Head().Rank() }

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

// FieldRefresher is implemented by backends that can recompute a kind's stored index fields in place. A field
// added to a kind's schema is empty on records written before (see sqlstore.reconcile) until they are rewritten,
// and some kinds (audit events) never are.
type FieldRefresher interface {
	// RefreshFields recomputes, from their data, the index fields of the live records of kind that q selects (q.Limit
	// of them at most), without changing their version or replicating anything, and returns how many it rewrote.
	RefreshFields(ctx context.Context, kind model.Kind, q ListQuery) (int, error)
}

// MultiGetter is optionally implemented by backends that read several records in one round trip. Table.GetMany uses
// it where available and falls back to one Get per id.
type MultiGetter interface {
	// GetMany returns the live records of kind among ids, in the order of ids; ids with no live record are left out.
	GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*Record, error)
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

// Change is one entry of a node-local change feed.
type Change struct {
	Seq    uint64
	Record *Record
}

// Newer reports whether a supersedes b under the replication ordering: a total order on (rank, deleted, Origin), so
// every node that applies the same records in any order ends with the same one. Rank is (epoch, Version):
//
//   - A tombstone's epoch is its own version (when the deletion happened); a live record's is its generation (0, or
//     the version of the tombstone its re-creation superseded). A tombstone therefore beats every live write of a
//     generation started before it, however new that write's version: an update made on a copy that had not seen
//     the deletion (replication lag, a partition, a node catching up, a fast clock) can never bring the record back.
//   - A re-creation (CompareAndPut with expect 0 over a tombstone) takes the version of the tombstone its writer saw
//     as its epoch: it beats that tombstone (same epoch, newer version) but not a deletion its writer had not seen
//     (a newer tombstone has a higher epoch), however far ahead the re-creating node's clock is. This is the causal
//     rule: wall-clock order never decides between a deletion and a re-creation.
//   - At equal rank (only possible between a tombstone and a live record of the same version) the tombstone wins;
//     then the higher Origin.
func Newer(a, b *Record) bool { return a.Head().Newer(b.Head()) }

// Newer is the record ordering on replication metadata (store.Newer).
func (h *Head) Newer(o *Head) bool {
	if ra, rb := h.Rank(), o.Rank(); ra != rb {
		return rb.Less(ra)
	}
	if h.Deleted != o.Deleted {
		return h.Deleted
	}
	return h.Origin > o.Origin
}

// StampLocal sets rec.Epoch and rec.Created for a local write of rec over the stored record old (nil: nothing
// stored, not even a tombstone) and refuses a live write that would replace a tombstone (ErrDeleted), unless create
// (CompareAndPut with expect 0) or the kind is node-local (KindEphemeral). A live write over a live record continues
// its generation; a create over nothing starts generation 0; a create over a tombstone starts a generation whose
// epoch is that tombstone's version (the deletion this writer has seen). A deletion has none. Backends call it inside
// the write transaction, after their version checks.
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

// KeepsUnique reports whether a (rather than b, a different record of the same kind) keeps a unique value both
// claim: the record created first (lower Created) keeps it — the first claim wins, so a long-standing record never
// loses its value to one created concurrently elsewhere. Ties (equal Created) break by id. The other record is kept,
// without that value (see PutReplicated).
func KeepsUnique(a, b *Head, aID, bID string) bool {
	if a.Created != b.Created {
		return a.Created < b.Created
	}
	return aID < bID
}

// Store is implemented by every backend. All methods are safe for concurrent use.
type Store interface {
	// Get returns a live record.
	Get(ctx context.Context, kind model.Kind, id string) (*Record, error)
	// GetByUnique returns the live record of kind holding the unique value.
	GetByUnique(ctx context.Context, kind model.Kind, value string) (*Record, error)
	// Put writes rec (or a tombstone when rec.Deleted). It fails with ErrStale unless rec.Version is newer than the
	// stored version, with ErrDeleted when a live rec would replace a tombstone (except KindEphemeral), and with
	// ErrConflict if another live record of the kind holds one of rec.Unique. Unique values the record no longer
	// lists are released. It sets rec.Epoch and rec.Created (StampLocal).
	Put(ctx context.Context, rec *Record) error
	// PutReplicated applies a record received from another node, as is (Epoch and Created included), when it is
	// Newer than the stored one: a tombstone beats every write of a generation started before it. Applying is
	// idempotent.
	//
	// Unique clashes with a different live record are resolved deterministically: the record created first (lower
	// Created, KeepsUnique) keeps the unique value. The other record is still stored — never deleted — but is not
	// indexed under that value, and its id is returned in losers; the caller (cluster layer) reports it so the
	// application can strip the value from it and flag it for an administrator.
	PutReplicated(ctx context.Context, rec *Record) (applied bool, losers []string, err error)
	// Lookup returns the stored record of kind and id whatever its state: live, expired or a tombstone (which
	// carries only its metadata). ErrNotFound when nothing is stored. Replication uses it to compare ranks.
	Lookup(ctx context.Context, kind model.Kind, id string) (*Record, error)
	// CompareAndPut writes rec only if the stored live record's version equals expect (ErrStale otherwise). With
	// expect == 0 it succeeds only when there is no live record (create; over a tombstone this starts a new
	// generation, which needs rec.Version newer than the tombstone). ErrNotFound if expect != 0 and there is no
	// live record. Also fails with ErrConflict like Put. It sets rec.Epoch and rec.Created (StampLocal).
	CompareAndPut(ctx context.Context, rec *Record, expect hlc.Timestamp) error
	// List returns a page of live records.
	List(ctx context.Context, kind model.Kind, q ListQuery) (*ListResult, error)
	// Count returns the number of live records of kind in scope ("" = all).
	Count(ctx context.Context, kind model.Kind, scope string) (int, error)
	// FeedID identifies this store's change feed. It is random, created with the store, and persisted; a wiped or
	// restored store gets a new one, which tells peers to restart their cursor from 0.
	FeedID() string
	// Changes returns up to limit changes (including tombstones and replicated applies) with Seq > since, in Seq
	// order, and the Seq to pass next time. Seq is local to this store, only ever increases, and is assigned in
	// commit order (a reader must never observe seq N+1 before seq N is visible). Only the latest change of each
	// record is kept.
	Changes(ctx context.Context, since uint64, limit int) ([]Change, uint64, error)
	// Purge permanently removes tombstones last written before `tombstonesBefore` and records that expired before
	// `expiredBefore`. Returns how many records were removed.
	Purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error)
	// Close releases resources.
	Close() error
}
