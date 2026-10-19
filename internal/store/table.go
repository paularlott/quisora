package store

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/shamaton/msgpack/v3"
)

// Clock mints record versions (the gossip library's hybrid logical clock: every version it mints is strictly
// greater than every version it minted or witnessed before). Versions read or received are witnessed into it with
// Witness, bounded by MaxSkew.
var Clock = hlc.NewClock()

// MaxSkew is how far ahead of this machine's clock a version read or received may be and still move the clock
// (Witness). A version further ahead comes from a node whose clock is badly wrong (or is corrupt): following it
// would make every version minted here inherit the error, and age-based cut-offs (tombstone purging) with it.
const MaxSkew = 30 * time.Second

var skewRefused atomic.Int64

// Witness moves Clock past ts (so this node's next version of the record is newer), unless ts is more than MaxSkew
// ahead of this machine's clock: that is counted (SkewRefused) and the clock is left alone. A later local write of
// such a record then fails as stale until the clocks are back in step, rather than every node inheriting the skew.
func Witness(ts hlc.Timestamp) {
	if !Clock.WitnessBounded(ts, MaxSkew) {
		skewRefused.Add(1)
	}
}

// SkewRefused is how many versions Witness refused to follow (too far ahead of this machine's clock).
func SkewRefused() int64 { return skewRefused.Load() }

// Ahead reports how far ts is ahead of this machine's clock (0 when it is not).
func Ahead(ts hlc.Timestamp) time.Duration { return ts.Ahead(time.Now()) }

// Origin is this node's id, stamped on every record written here. Set once at start-up.
var Origin = "local"

// Encode turns an entity into a Record, stamping a fresh version and the Created/Updated times.
func Encode(e model.Entity) (*Record, error) {
	m := e.GetMeta()
	now := time.Now().UTC()
	if m.ID == "" {
		m.ID = model.NewID()
	}
	if m.Created.IsZero() {
		m.Created = now
	}
	m.Updated = now
	m.Version = Clock.Now()
	return EncodeAsIs(e)
}

// EncodeAsIs turns an entity into a Record without touching its metadata.
func EncodeAsIs(e model.Entity) (*Record, error) {
	data, err := msgpack.Marshal(e)
	if err != nil {
		return nil, err
	}
	m := e.GetMeta()
	ix := e.Index()
	return &Record{
		Kind: e.Kind(), ID: m.ID, Version: m.Version, Origin: Origin, Scope: ix.Scope, Unique: ix.Unique, Fields: ix.Fields,
		Data: data, Expires: ix.Expires,
	}, nil
}

// Decode fills e from a record.
func Decode(r *Record, e model.Entity) error {
	if err := msgpack.Unmarshal(r.Data, e); err != nil {
		return err
	}
	e.GetMeta().Version = r.Version
	return nil
}

// Tombstone returns a deletion record for kind/id at a fresh version.
func Tombstone(kind model.Kind, id string) *Record {
	return &Record{Kind: kind, ID: id, Version: Clock.Now(), Origin: Origin, Deleted: true}
}

// Table gives typed access to one kind. T is the entity struct type, PT its pointer type.
type Table[T any, PT interface {
	*T
	model.Entity
}] struct {
	S    Store
	Kind model.Kind
}

// NewTable returns a typed table over s for the entity type.
func NewTable[T any, PT interface {
	*T
	model.Entity
}](s Store) *Table[T, PT] {
	var zero T
	return &Table[T, PT]{S: s, Kind: PT(&zero).Kind()}
}

func (t *Table[T, PT]) decode(r *Record) (PT, error) {
	v := PT(new(T))
	if err := Decode(r, v); err != nil {
		return nil, err
	}
	return v, nil
}

// Get loads a live entity by id.
func (t *Table[T, PT]) Get(ctx context.Context, id string) (PT, error) {
	r, err := t.S.Get(ctx, t.Kind, id)
	if err != nil {
		return nil, err
	}
	return t.decode(r)
}

// GetByUnique loads a live entity by one of its unique values.
func (t *Table[T, PT]) GetByUnique(ctx context.Context, value string) (PT, error) {
	r, err := t.S.GetByUnique(ctx, t.Kind, value)
	if err != nil {
		return nil, err
	}
	return t.decode(r)
}

// Put creates or replaces the entity, stamping a new version (and ID/Created when unset). The entity's version is
// the stored one afterwards (a quorum write stamps its own).
func (t *Table[T, PT]) Put(ctx context.Context, e PT) error {
	r, err := Encode(e)
	if err != nil {
		return err
	}
	err = t.S.Put(ctx, r)
	if Applied(err) {
		e.GetMeta().Version = r.Version
	}
	return err
}

// Create writes a new entity; it fails with ErrStale if a live record with the same id exists and ErrConflict on
// a unique clash.
func (t *Table[T, PT]) Create(ctx context.Context, e PT) error {
	r, err := Encode(e)
	if err != nil {
		return err
	}
	err = t.S.CompareAndPut(ctx, r, 0)
	if Applied(err) {
		e.GetMeta().Version = r.Version
	}
	return err
}

// Update writes e only if nobody changed it since it was read (optimistic concurrency).
func (t *Table[T, PT]) Update(ctx context.Context, e PT) error {
	expect := e.GetMeta().Version
	r, err := Encode(e)
	if err != nil {
		e.GetMeta().Version = expect
		return err
	}
	err = t.S.CompareAndPut(ctx, r, expect)
	if !Applied(err) {
		e.GetMeta().Version = expect
		return err
	}
	e.GetMeta().Version = r.Version
	return err
}

// Delete tombstones the entity.
func (t *Table[T, PT]) Delete(ctx context.Context, id string) error {
	return t.S.Put(ctx, Tombstone(t.Kind, id))
}

// DeleteIf tombstones the entity only if nobody changed it since it was read at version expect (optimistic
// concurrency, as Update): a decision made on that copy cannot be applied to a newer one.
func (t *Table[T, PT]) DeleteIf(ctx context.Context, id string, expect hlc.Timestamp) error {
	return t.S.CompareAndPut(ctx, Tombstone(t.Kind, id), expect)
}

// List returns a page of entities and the total number of matches.
func (t *Table[T, PT]) List(ctx context.Context, q ListQuery) ([]PT, int, error) {
	res, err := t.S.List(ctx, t.Kind, q)
	if err != nil {
		return nil, 0, err
	}
	out := make([]PT, 0, len(res.Records))
	for _, r := range res.Records {
		v, err := t.decode(r)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, res.Total, nil
}

// All returns every entity in scope (use only for scopes known to be small).
func (t *Table[T, PT]) All(ctx context.Context, scope string) ([]PT, error) {
	v, _, err := t.List(ctx, ListQuery{Scope: scope})
	return v, err
}

// Count returns the number of live entities in scope.
func (t *Table[T, PT]) Count(ctx context.Context, scope string) (int, error) {
	return t.S.Count(ctx, t.Kind, scope)
}
