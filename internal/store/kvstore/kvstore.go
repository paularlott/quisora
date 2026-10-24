// Package kvstore implements store.Store once, over a small ordered key-value engine interface, with two engines:
// BadgerDB (embedded, node-local) and Valkey (shared server).
//
// Key layout (Valkey keys additionally carry the configured prefix):
//
//	rec/<kind>/<id>                    -> [8-byte feed seq][msgpack wireRecord]
//	uq/<kind>/<value>                  -> id
//	sc/<kind>/<scope>/<id>             -> ordered scope index (scope escaped so it never contains '/')
//	al/<kind>/<id>                     -> ordered "all" index of a kind (unscoped listing)
//	seq/<20-digit seq>/<kind>/<id>     -> change feed (the record stores its current seq; the old entry is removed)
//	exp/<unix-ms 15 digits>/<kind>/<id> -> expiry index, range-deleted by Purge
//	tomb/<version 20 digits>/<kind>/<id> -> tombstone index, range-deleted by Purge
//	fx/<kind>/<field>/<value>/<scope>/<id> -> field index (model.Field.Index): the records with that value, by scope
//	due/<unix-ms 15 digits>/<kind>/<id>  -> due index (model.Due), range-scanned by ListDue
//	meta/feed_id, meta/seq
//
// Ordered indexes are engine "ordered sets" (bucket + member): plain keys under a prefix in Badger, sorted sets
// with lexicographic ordering in Valkey. Housekeeping (Purge, Changes) only ever range-scans the exp, tomb and
// seq indexes, never the records.
//
// Listing: plain ID-ordered scans page through the scope index without loading the scope; the total is a count of
// the index (key-only iteration in Badger, ZLEXCOUNT arithmetic in Valkey) that excludes expired records, because
// the index carries each member's expiry. An equality filter on an indexed field reads that field's index: the
// records with the value (in the scope: a contiguous range of the bucket, in id order, so one such filter alone is
// paged like a plain scan), or, for an indexed bool filtered on false, the scope paged with the records with true
// skipped (the way an administrator's user listing leaves out the super admins). Other searched, filtered or sorted
// listings load every record of the scope (O(scope size)); doing that without a scope is O(kind size) and should be
// avoided for large kinds.
package kvstore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Store is a store.Store over a kv engine.
type Store struct {
	eng    engine
	mu     sync.RWMutex
	feedID string
}

var (
	_ store.Store           = (*Store)(nil)
	_ store.BatchReplicator = (*Store)(nil)
	_ store.MultiGetter     = (*Store)(nil)
)

func newStore(ctx context.Context, eng engine, feedID string) *Store {
	return &Store{eng: eng, feedID: feedID}
}

func (s *Store) FeedID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.feedID
}

// Store format: this backend's layout of records and indexes. It is formatBase plus the number of format
// migrations; a store at an older format is brought up to this build's at open, one migration after the other, each
// recorded as it completes (an interrupted upgrade resumes where it stopped), under a lock so that the processes
// sharing a Valkey store do it once. A store written by a newer build, or by a pre-release build older than
// formatBase, is refused. Never edit or remove a released migration: append one. There are none yet: nothing has
// been released, and a layout change raises formatBase instead (3: the due and field indexes; 4: field index
// members carry their scope).
const (
	metaFormat  = "meta/format"
	metaMigrate = "meta/migrating" // the lock held while migrating: "<holder> <expiry unix ms>"
	formatBase  = 4
)

// formatMigration brings a store from one format to the next. It may run again after an interruption: make it
// idempotent.
type formatMigration struct {
	name string
	run  func(ctx context.Context, s *Store) error
}

// formatMigrations[i] brings a store from format formatBase+i to formatBase+i+1.
var formatMigrations []formatMigration

func currentFormat() int { return formatBase + len(formatMigrations) }

// checkFormat marks a new store, migrates an older one, and refuses one it cannot read.
func (s *Store) checkFormat(ctx context.Context) error {
	b, err := s.eng.Get(ctx, metaFormat)
	if err != nil {
		return err
	}
	if b == nil {
		seq, err := s.eng.Get(ctx, metaSeq)
		if err != nil {
			return err
		}
		if seqOf(seq) == 0 { // nothing written yet: a new store
			return s.markFormat(ctx, currentFormat())
		}
	}
	have, err := strconv.Atoi(string(b))
	switch {
	case err != nil || have < formatBase:
		return fmt.Errorf("kvstore: the store holds data written by an earlier, incompatible pre-release build of "+
			"Quisora (format %q, this build reads %d and later): there is no conversion; wipe the store and start "+
			"clean (restore from a backup made by this build if needed)", string(b), formatBase)
	case have > currentFormat():
		return fmt.Errorf("kvstore: the store was written by a newer build of Quisora (format %d, this build writes %d): "+
			"downgrading is not supported; run the newer build, or restore a backup made by this one", have, currentFormat())
	case have == currentFormat():
		return nil
	}
	return s.migrateFormat(ctx)
}

// migrateFormat runs the format migrations a store needs, holding the migration lock.
func (s *Store) migrateFormat(ctx context.Context) error {
	release, err := s.lockMigration(ctx)
	if err != nil {
		return err
	}
	defer release()
	for {
		b, err := s.eng.Get(ctx, metaFormat) // again: another process may have migrated meanwhile
		if err != nil {
			return err
		}
		have, err := strconv.Atoi(string(b))
		if err != nil {
			return fmt.Errorf("kvstore: unreadable store format %q", string(b))
		}
		if have >= currentFormat() {
			return nil
		}
		m := formatMigrations[have-formatBase]
		if err := m.run(ctx, s); err != nil {
			return fmt.Errorf("kvstore: migrating the store from format %d (%s): %w", have, m.name, err)
		}
		if err := s.markFormat(ctx, have+1); err != nil {
			return err
		}
	}
}

// migrationLockTTL bounds how long a lock of a process that died while migrating stops the others.
const migrationLockTTL = 10 * time.Minute

// lockMigration takes the migration lock, waiting while another process holds it; release gives it back.
func (s *Store) lockMigration(ctx context.Context) (release func(), err error) {
	holder := model.NewID()
	for {
		took := false
		err := s.eng.Update(ctx, func(tx txn) error {
			cur, err := tx.Get(metaMigrate)
			if err != nil {
				return err
			}
			if cur != nil {
				_, exp, _ := strings.Cut(string(cur), " ")
				if ms, err := strconv.ParseInt(exp, 10, 64); err == nil && time.Now().UnixMilli() < ms {
					return nil // held by another process
				}
			}
			tx.Set(metaMigrate, []byte(holder+" "+strconv.FormatInt(time.Now().Add(migrationLockTTL).UnixMilli(), 10)))
			took = true
			return nil
		})
		if err != nil {
			return nil, err
		}
		if took {
			return func() {
				_ = s.eng.Update(context.WithoutCancel(ctx), func(tx txn) error {
					if cur, err := tx.Get(metaMigrate); err == nil && strings.HasPrefix(string(cur), holder+" ") {
						tx.Delete(metaMigrate)
					}
					return nil
				})
			}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// seqOf reads the stored feed counter: 8 bytes big endian (Badger) or a decimal integer (Valkey's INCR).
func seqOf(b []byte) uint64 {
	if len(b) == 8 {
		return binary.BigEndian.Uint64(b)
	}
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func (s *Store) markFormat(ctx context.Context, v int) error {
	return s.eng.Update(ctx, func(tx txn) error { tx.Set(metaFormat, []byte(strconv.Itoa(v))); return nil })
}

// Wipe deletes every record and index of this store (only keys under its own prefix for Valkey), restarts the
// sequence and assigns a new FeedID so peers restart their cursors. Callers must not write concurrently.
func (s *Store) Wipe(ctx context.Context) error {
	id := model.NewID()
	if err := s.eng.wipe(ctx, id); err != nil {
		return err
	}
	if err := s.markFormat(ctx, currentFormat()); err != nil {
		return err
	}
	s.mu.Lock()
	s.feedID = id
	s.mu.Unlock()
	return nil
}

func (s *Store) Close() error { return s.eng.Close() }

// Snapshot returns a read-only, point-in-time view of the whole store (store.Snapshotter): on Badger one read
// transaction, so a backup taken through it is consistent. Valkey has no such view: ErrNoSnapshot. Close the view
// when done.
func (s *Store) Snapshot(context.Context) (store.Reader, error) {
	e, ok := s.eng.(*badgerEngine)
	if !ok {
		return nil, store.ErrNoSnapshot
	}
	return &Store{eng: &badgerSnapshot{t: e.db.NewTransaction(false)}, feedID: s.FeedID()}, nil
}

// ---- keys ----

func recKey(kind model.Kind, id string) string { return "rec/" + string(kind) + "/" + id }
func uqKey(kind model.Kind, v string) string   { return "uq/" + string(kind) + "/" + v }
func allBucket(kind model.Kind) string         { return "al/" + string(kind) }

var scopeEscaper = strings.NewReplacer("%", "%25", "/", "%2F")

func scopeBucket(kind model.Kind, scope string) string {
	return "sc/" + string(kind) + "/" + scopeEscaper.Replace(scope)
}

func listBucket(kind model.Kind, scope string) string {
	if scope == "" {
		return allBucket(kind)
	}
	return scopeBucket(kind, scope)
}

func seqMember(seq uint64, entry string) string {
	b := make([]byte, 0, 21+len(entry))
	return string(append(append(appendPadded(b, seq, 20), '/'), entry...))
}

// appendPadded appends v in decimal, zero-padded to width digits (fmt's %0*d without the allocations).
func appendPadded(b []byte, v uint64, width int) []byte {
	var d [20]byte
	n := strconv.AppendUint(d[:0], v, 10)
	for i := len(n); i < width; i++ {
		b = append(b, '0')
	}
	return append(b, n...)
}

// indexMember is "<padded n>/<kind>/<id>", the member of the tomb and exp indexes.
func indexMember(n uint64, width int, kind model.Kind, id string) string {
	b := make([]byte, 0, width+2+len(kind)+len(id))
	b = appendPadded(b, n, width)
	b = append(append(append(append(b, '/'), kind...), '/'), id...)
	return string(b)
}

func entryOf(kind model.Kind, id string) string { return string(kind) + "/" + id }

// expMs rounds an expiry up to whole milliseconds so an index entry never reads as expired early.
func expMs(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return (t.UnixNano() + int64(time.Millisecond) - 1) / int64(time.Millisecond)
}

// indexEntry is one ordered-set membership of a record.
type indexEntry struct {
	bucket, member string
	exp            int64
}

// indexEntries lists every ordered-set membership of rec other than the change feed.
func indexEntries(r *store.Record) []indexEntry {
	if r.Deleted {
		return []indexEntry{{"tomb", indexMember(uint64(r.Version), 20, r.Kind, r.ID), 0}}
	}
	exp := expMs(r.Expires)
	out := make([]indexEntry, 1, 3)
	out[0] = indexEntry{allBucket(r.Kind), r.ID, exp}
	if r.Scope != "" {
		out = append(out, indexEntry{scopeBucket(r.Kind, r.Scope), r.ID, exp})
	}
	if exp > 0 {
		out = append(out, indexEntry{"exp", indexMember(uint64(exp), 15, r.Kind, r.ID), 0})
	}
	if due, ok := model.Due(r.Kind, r.Fields); ok {
		out = append(out, indexEntry{dueBucket, indexMember(dueMs(due), 15, r.Kind, r.ID), 0})
	}
	for _, f := range model.Schemas[r.Kind].Fields {
		if f.Index {
			if v, ok := fieldKey(r.Fields[f.Name]); ok {
				out = append(out, indexEntry{fieldBucket(r.Kind, f.Name, v), fieldMember(r.Scope, r.ID), exp})
			}
		}
	}
	return out
}

// fieldBucket holds the records of kind whose field (a model.Field marked Index) has value v (fieldKey), as
// fieldMember members.
func fieldBucket(kind model.Kind, field, v string) string {
	return "fx/" + string(kind) + "/" + field + "/" + scopeEscaper.Replace(v)
}

// fieldMember is a record's member of a field index bucket: its scope (escaped, so it holds no '/') then its id. One
// bucket so serves both the records of one scope with the value, a contiguous range of it in id order (scopeBounds),
// and all of them.
func fieldMember(scope, id string) string { return scopeEscaper.Replace(scope) + "/" + id }

// fieldMemberID is the id of a field index member.
func fieldMemberID(m string) string {
	_, id, _ := strings.Cut(m, "/")
	return id
}

// scopeBounds is the range [from, to) of a scope's members in a field index bucket.
func scopeBounds(scope string) (from, to string) {
	s := scopeEscaper.Replace(scope)
	return s + "/", s + "0" // '0' follows '/'
}

// fieldKey is a field or filter value as an index bucket names it; false for values that are not indexed.
func fieldKey(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case int:
		return strconv.Itoa(x), true
	}
	return "", false
}

// indexBuckets returns the field index buckets that serve the filters of q: in is the bucket of the first equality
// filter on an indexed field (the records it can match are only those, whatever else the query asks), and out the
// buckets of the records each filter on false of an indexed bool field leaves out (the records with true: the small
// set such a field is indexed for; a filter on false is never served from the large "false" bucket). The two
// classes are exclusive: when out covers every filter and in is "", the query is a plain page of the scope with
// those records skipped.
func indexBuckets(kind model.Kind, q store.ListQuery) (in string, out []string) {
	for _, flt := range q.Filters {
		if flt.Op != "" {
			continue
		}
		for _, f := range model.Schemas[kind].Fields {
			if f.Name != flt.Field || !f.Index {
				continue
			}
			if f.Type == model.FieldBool && flt.Value == false {
				out = append(out, fieldBucket(kind, f.Name, "true"))
			} else if v, ok := fieldKey(flt.Value); ok && in == "" {
				in = fieldBucket(kind, f.Name, v)
			}
		}
	}
	return in, out
}

// dueBucket orders the records a housekeeping job must look at by when (model.Due, ListDue).
const dueBucket = "due"

// dueMs is a due time as an index position (milliseconds; before the epoch: 0).
func dueMs(t time.Time) uint64 { return uint64(max(t.UnixMilli(), 0)) }

// ListDue returns up to limit live records of kind due at or before before, earliest first (store.DueLister): a range
// of the due index, not a read of the whole kind.
func (s *Store) ListDue(ctx context.Context, kind model.Kind, before time.Time, limit int) ([]*store.Record, error) {
	to := string(appendPadded(nil, dueMs(before), 15)) + "/\xff"
	var out []*store.Record
	from := ""
	for limit <= 0 || len(out) < limit {
		members, err := s.eng.Range(ctx, dueBucket, from, to, 512)
		if err != nil {
			return nil, err
		}
		if len(members) == 0 {
			return out, nil
		}
		from = members[len(members)-1] + "\x00"
		var ids []string
		for _, m := range members {
			if parts := strings.SplitN(m, "/", 3); len(parts) == 3 && parts[1] == string(kind) {
				ids = append(ids, parts[2])
			}
		}
		recs, err := s.loadMembers(ctx, kind, ids)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if due, ok := model.Due(kind, r.Fields); ok && !due.After(before) {
				out = append(out, r)
				if limit > 0 && len(out) == limit {
					break
				}
			}
		}
	}
	return out, nil
}

// ---- transactional helpers ----

func loadRec(tx txn, kind model.Kind, id string) (*stored, error) {
	b, err := tx.Get(recKey(kind, id))
	if err != nil || b == nil {
		return nil, err
	}
	return decodeRecord(b)
}

func live(s *stored) bool { return s != nil && s.rec.Live(time.Now()) }

// stamp applies store.StampLocal for a local write of rec over old.
func stamp(rec *store.Record, old *stored, create bool) error {
	if old == nil {
		return store.StampLocal(rec, nil, create)
	}
	return store.StampLocal(rec, old.rec.Head(), create)
}

// holder returns the live record other than id holding the unique value indexed under key (uqKey).
func holder(tx txn, kind model.Kind, key, id string) (*stored, error) {
	b, err := tx.Get(key)
	if err != nil || b == nil || string(b) == id {
		return nil, err
	}
	other, err := loadRec(tx, kind, string(b))
	if err != nil || !live(other) {
		return nil, err
	}
	return other, nil
}

// conflicts reports whether another live record holds one of rec's unique values. It returns the index keys of those
// values (for apply).
func conflicts(tx txn, rec *store.Record) (bool, []string, error) {
	if rec.Deleted || len(rec.Unique) == 0 {
		return false, nil, nil
	}
	keys := make([]string, len(rec.Unique))
	for i, u := range rec.Unique {
		keys[i] = uqKey(rec.Kind, u)
		o, err := holder(tx, rec.Kind, keys[i], rec.ID)
		if err != nil || o != nil {
			return o != nil, nil, err
		}
	}
	return false, keys, nil
}

// apply writes rec over old (which may be nil), indexing it under the unique values in index, whose index keys are
// keys (built here when nil).
func apply(tx txn, old *stored, rec *store.Record, index, keys []string) error {
	r := *rec
	if r.Deleted {
		r.Data, r.Fields, r.Unique, r.Scope, r.Expires, r.Created = nil, nil, nil, "", time.Time{}, 0 // Epoch kept: a quorum tombstone's generation (store.Head.Rank)
		index = nil
	}
	var oldSeq uint64
	var oldEntries []indexEntry
	if old != nil {
		oldSeq = old.seq
		oldEntries = indexEntries(old.rec)
		for _, u := range old.rec.Unique {
			if slices.Contains(index, u) {
				continue
			}
			k := uqKey(r.Kind, u)
			if b, err := tx.Get(k); err != nil {
				return err
			} else if string(b) == r.ID {
				tx.Delete(k)
			}
		}
	}
	for i, u := range index {
		var k string
		if keys != nil {
			k = keys[i]
		} else {
			k = uqKey(r.Kind, u)
		}
		if b, err := tx.Get(k); err != nil {
			return err
		} else if string(b) != r.ID {
			tx.Set(k, []byte(r.ID))
		}
	}
	newEntries := indexEntries(&r)
	for _, o := range oldEntries {
		if !hasEntry(newEntries, o) {
			tx.SetDel(o.bucket, o.member)
		}
	}
	for _, n := range newEntries {
		if !hasEntry(oldEntries, n) {
			tx.SetAdd(n.bucket, n.member, n.exp)
		}
	}
	body, err := encodeRecord(&r)
	if err != nil {
		return err
	}
	tx.Feed(recKey(r.Kind, r.ID), body, entryOf(r.Kind, r.ID), oldSeq)
	return nil
}

func hasEntry(list []indexEntry, e indexEntry) bool {
	for _, x := range list {
		if x == e {
			return true
		}
	}
	return false
}

// remove deletes a record and everything that indexes it.
func remove(tx txn, old *stored) error {
	r := old.rec
	for _, u := range r.Unique {
		k := uqKey(r.Kind, u)
		if b, err := tx.Get(k); err != nil {
			return err
		} else if string(b) == r.ID {
			tx.Delete(k)
		}
	}
	for _, e := range indexEntries(r) {
		tx.SetDel(e.bucket, e.member)
	}
	tx.Feed(recKey(r.Kind, r.ID), nil, entryOf(r.Kind, r.ID), old.seq)
	return nil
}

// ---- reads ----

func (s *Store) get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	b, err := s.eng.Get(ctx, recKey(kind, id))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, store.ErrNotFound
	}
	st, err := decodeRecord(b)
	if err != nil {
		return nil, err
	}
	if !st.rec.Live(time.Now()) {
		return nil, store.ErrNotFound
	}
	return st.rec, nil
}

func (s *Store) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	return s.get(ctx, kind, id)
}

// Lookup returns the stored record whatever its state (store.Store).
func (s *Store) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	b, err := s.eng.Get(ctx, recKey(kind, id))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, store.ErrNotFound
	}
	st, err := decodeRecord(b)
	if err != nil {
		return nil, err
	}
	return st.rec, nil
}

func (s *Store) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	b, err := s.eng.Get(ctx, uqKey(kind, value))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, store.ErrNotFound
	}
	return s.get(ctx, kind, string(b))
}

// ---- writes ----

// write runs fn as a write of the record kind/id: through the engine's group commit when it has one.
func (s *Store) write(ctx context.Context, kind model.Kind, id string, fn func(tx txn) error) error {
	if g, ok := s.eng.(grouper); ok {
		return g.Group(ctx, string(kind), id, fn)
	}
	return s.eng.Update(ctx, fn)
}

func (s *Store) Put(ctx context.Context, rec *store.Record) error {
	return s.write(ctx, rec.Kind, rec.ID, func(tx txn) error {
		old, err := loadRec(tx, rec.Kind, rec.ID)
		if err != nil {
			return err
		}
		if old != nil && old.rec.Version >= rec.Version {
			return store.ErrStale
		}
		if err := stamp(rec, old, false); err != nil {
			return err
		}
		c, keys, err := conflicts(tx, rec)
		if err != nil {
			return err
		} else if c {
			return store.ErrConflict
		}
		return apply(tx, old, rec, rec.Unique, keys)
	})
}

func (s *Store) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	return s.write(ctx, rec.Kind, rec.ID, func(tx txn) error {
		old, err := loadRec(tx, rec.Kind, rec.ID)
		if err != nil {
			return err
		}
		if expect == 0 {
			if live(old) || (old != nil && old.rec.Version >= rec.Version) {
				return store.ErrStale
			}
		} else {
			if !live(old) {
				return store.ErrNotFound
			}
			if old.rec.Version != expect || rec.Version <= expect {
				return store.ErrStale
			}
		}
		if err := stamp(rec, old, expect == 0); err != nil {
			return err
		}
		c, keys, err := conflicts(tx, rec)
		if err != nil {
			return err
		} else if c {
			return store.ErrConflict
		}
		return apply(tx, old, rec, rec.Unique, keys)
	})
}

func (s *Store) PutReplicated(ctx context.Context, rec *store.Record) (bool, []string, error) {
	var applied bool
	var losers []string
	store.Witness(rec.Version)
	err := s.write(ctx, rec.Kind, rec.ID, func(tx txn) (err error) {
		applied, losers, err = replicateOne(tx, rec)
		return err
	})
	if err != nil {
		return false, nil, err
	}
	return applied, losers, nil
}

// replicateOne applies rec inside tx with the PutReplicated semantics.
func replicateOne(tx txn, rec *store.Record) (bool, []string, error) {
	old, err := loadRec(tx, rec.Kind, rec.ID)
	if err != nil {
		return false, nil, err
	}
	if old != nil && !store.Newer(rec, old.rec) {
		return false, nil, nil
	}
	var losers []string
	index := make([]string, 0, len(rec.Unique))
	keys := make([]string, 0, len(rec.Unique))
	if !rec.Deleted {
		for _, u := range rec.Unique {
			k := uqKey(rec.Kind, u)
			other, err := holder(tx, rec.Kind, k, rec.ID)
			if err != nil {
				return false, nil, err
			}
			switch {
			case other == nil:
				index, keys = append(index, u), append(keys, k)
			case store.KeepsUnique(other.rec.Head(), rec.Head(), other.rec.ID, rec.ID):
				losers = appendOnce(losers, rec.ID)
			default:
				// The value moves to rec; apply overwrites the index, the other record keeps its data.
				losers = appendOnce(losers, other.rec.ID)
				index, keys = append(index, u), append(keys, k)
			}
		}
	}
	if err := apply(tx, old, rec, index, keys); err != nil {
		return false, nil, err
	}
	return true, losers, nil
}

// batchGroup is the most records applied in one transaction.
const batchGroup = 256

// PutReplicatedBatch applies recs with the PutReplicated semantics, many per write transaction on Badger (one
// fsync per group instead of one per record). It implements store.BatchReplicator. Engines without cheap
// multi-record transactions (Valkey) fall back to one transaction per record.
func (s *Store) PutReplicatedBatch(ctx context.Context, recs []*store.Record) ([]bool, [][]string, error) {
	applied := make([]bool, len(recs))
	losers := make([][]string, len(recs))
	if _, ok := s.eng.(*badgerEngine); !ok {
		for i, r := range recs {
			var err error
			if applied[i], losers[i], err = s.PutReplicated(ctx, r); err != nil {
				return nil, nil, err
			}
		}
		return applied, losers, nil
	}
	for _, r := range recs {
		store.Witness(r.Version)
	}
	// Records of one group run in order in one transaction; each sees the ones before it (the same record twice, or
	// two records claiming one unique value, resolve as if applied one by one).
	for i := 0; i < len(recs); {
		size := batchGroup
		for {
			j := min(i+size, len(recs))
			err := s.eng.Update(ctx, func(tx txn) error {
				for k := i; k < j; k++ {
					a, l, err := replicateOne(tx, recs[k])
					if err != nil {
						return err
					}
					applied[k], losers[k] = a, l
				}
				return nil
			})
			if err == nil {
				i = j
				break
			}
			if isTxnTooBig(err) && size > 1 {
				size /= 2
				continue
			}
			return nil, nil, err
		}
	}
	return applied, losers, nil
}

func appendOnce(list []string, id string) []string {
	for _, v := range list {
		if v == id {
			return list
		}
	}
	return append(list, id)
}

// ---- listing ----

func nowMs() int64 { return time.Now().UnixMilli() }

func (s *Store) loadMembers(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	if len(ids) == 0 {
		return []*store.Record{}, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = recKey(kind, id)
	}
	vals, err := s.eng.MGet(ctx, keys)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]*store.Record, 0, len(ids))
	for _, v := range vals {
		if v == nil {
			continue
		}
		st, err := decodeRecord(v)
		if err != nil {
			return nil, err
		}
		if st.rec.Live(now) {
			out = append(out, st.rec)
		}
	}
	return out, nil
}

// GetMany returns the live records of kind among ids, in their order (store.MultiGetter): one engine read.
func (s *Store) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	return s.loadMembers(ctx, kind, ids)
}

func (s *Store) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if err := store.ValidateQuery(kind, q); err != nil {
		return nil, err
	}
	bucket := listBucket(kind, q.Scope)
	if store.IsPlainScan(q) {
		if q.After != "" {
			return s.listAfter(ctx, kind, bucket, q.After, q.Limit)
		}
		return s.listPage(ctx, kind, bucket, pageQuery{Reverse: q.Desc, Offset: max(q.Offset, 0), Limit: q.Limit}, false, false)
	}
	in, out := indexBuckets(kind, q)
	unsorted := q.Sort == "" && q.Search == ""
	switch {
	case in != "" && unsorted && len(q.Filters) == 1 && q.Scope != "":
		// One indexed filter: the scope's range of the bucket is the result, in id order; page it like a plain scan.
		from, to := scopeBounds(q.Scope)
		p := pageQuery{From: from, To: to, Reverse: q.Desc, Offset: max(q.Offset, 0), Limit: q.Limit}
		if q.After != "" {
			p.From, p.Offset = from+q.After+"\x00", 0
		}
		return s.listPage(ctx, kind, in, p, true, q.After != "")
	case unsorted && in == "" && len(out) == len(q.Filters):
		return s.listExcluding(ctx, kind, bucket, q, out)
	}
	var ids []string
	var err error
	if in != "" {
		ids, err = s.indexedIDs(ctx, kind, in, q.Scope, nowMs()) // only the records the filter can match
	} else {
		ids, _, err = s.eng.Page(ctx, bucket, pageQuery{}, nowMs()) // the whole scope, or kind
	}
	if err != nil {
		return nil, err
	}
	recs, err := s.loadMembers(ctx, kind, ids)
	if err != nil {
		return nil, err
	}
	return store.ApplyQuery(kind, recs, q)
}

// listPage loads the page p selects from bucket; field says the bucket is a field index, whose members carry their
// scope (fieldMember), and after that the query pages by key, so its total is the page length.
func (s *Store) listPage(ctx context.Context, kind model.Kind, bucket string, p pageQuery, field, after bool) (*store.ListResult, error) {
	members, total, err := s.eng.Page(ctx, bucket, p, nowMs())
	if err != nil {
		return nil, err
	}
	if field {
		for i, m := range members {
			members[i] = fieldMemberID(m)
		}
	}
	recs, err := s.loadMembers(ctx, kind, members)
	if err != nil {
		return nil, err
	}
	if after {
		total = len(recs)
	}
	return &store.ListResult{Records: recs, Total: total}, nil
}

// listExcluding serves a query whose every filter leaves out the records of an indexed set (buckets out: the super
// admins of an organization, to the administrators who may not see them, on each of their user listings) by paging
// the scope's index (bucket) with those records skipped. The page costs a plain page plus the excluded sets' ids,
// however large the scope; loading the scope to filter it costs the scope.
func (s *Store) listExcluding(ctx context.Context, kind model.Kind, bucket string, q store.ListQuery, out []string) (*store.ListResult, error) {
	now := nowMs()
	skip := map[string]struct{}{}
	for _, b := range out {
		ids, err := s.indexedIDs(ctx, kind, b, q.Scope, now)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			skip[id] = struct{}{}
		}
	}
	p := pageQuery{Skip: skip, Reverse: q.Desc, Offset: max(q.Offset, 0), Limit: q.Limit}
	if q.After != "" {
		p.From, p.Offset = q.After+"\x00", 0
	}
	return s.listPage(ctx, kind, bucket, p, false, q.After != "")
}

// indexedIDs returns the ids of the live records of scope ("" = every scope) in field index bucket b, in id order
// within each scope.
func (s *Store) indexedIDs(ctx context.Context, kind model.Kind, b, scope string, now int64) ([]string, error) {
	var p pageQuery
	if scope != "" {
		p.From, p.To = scopeBounds(scope)
	}
	members, _, err := s.eng.Page(ctx, b, p, now)
	if err != nil {
		return nil, err
	}
	for i, m := range members {
		members[i] = fieldMemberID(m)
	}
	return members, nil
}

// listAfter returns up to limit live records with an ID greater than after, in ID order. Index members are the
// record ids; expired members still in the index are skipped (and do not end the page early).
func (s *Store) listAfter(ctx context.Context, kind model.Kind, bucket, after string, limit int) (*store.ListResult, error) {
	out := []*store.Record{}
	from := after + "\x00" // the smallest member greater than after
	batch := 512
	if limit > 0 && limit < batch {
		batch = limit
	}
	for limit <= 0 || len(out) < limit {
		ids, err := s.eng.Range(ctx, bucket, from, "", batch)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			break
		}
		recs, err := s.loadMembers(ctx, kind, ids)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if limit > 0 && len(out) >= limit {
				break
			}
			out = append(out, r)
		}
		from = ids[len(ids)-1] + "\x00"
	}
	return &store.ListResult{Records: out, Total: len(out)}, nil
}

func (s *Store) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	return s.eng.Count(ctx, listBucket(kind, scope), nowMs())
}

// ---- change feed ----

func (s *Store) Changes(ctx context.Context, since uint64, limit int) ([]store.Change, uint64, error) {
	out := []store.Change{}
	next := since
	from := fmt.Sprintf("%020d", since+1)
	batch := 512
	if limit > 0 && limit < batch {
		batch = limit
	}
	for {
		members, err := s.eng.Range(ctx, feedBkt, from, "", batch)
		if err != nil {
			return nil, since, err
		}
		if len(members) == 0 {
			return out, next, nil
		}
		keys := make([]string, len(members))
		seqs := make([]uint64, len(members))
		for i, m := range members {
			seqStr, entry, ok := strings.Cut(m, "/")
			n, err := strconv.ParseUint(seqStr, 10, 64)
			if !ok || err != nil {
				return nil, since, fmt.Errorf("kvstore: corrupt feed entry %q", m)
			}
			seqs[i], keys[i] = n, "rec/"+entry
		}
		vals, err := s.eng.MGet(ctx, keys)
		if err != nil {
			return nil, since, err
		}
		for i, v := range vals {
			next = seqs[i]
			if v == nil {
				continue
			}
			st, err := decodeRecord(v)
			if err != nil {
				return nil, since, err
			}
			if st.seq != seqs[i] { // rewritten since: its newer entry comes later
				continue
			}
			out = append(out, store.Change{Seq: seqs[i], Record: st.rec})
			if limit > 0 && len(out) >= limit {
				return out, next, nil
			}
		}
		from = fmt.Sprintf("%020d", seqs[len(seqs)-1]+1)
	}
}

// ---- purge ----

const purgeBatch = 100

func (s *Store) Purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
	total := 0
	tombTo := fmt.Sprintf("%020d/\xff", hlc.FromTime(tombstonesBefore).Uint64()+(1<<hlc.CounterBits))
	n, err := s.purgeIndex(ctx, "tomb", tombTo, func(r *store.Record) bool {
		return r.Deleted && r.Version.Time().Before(tombstonesBefore)
	})
	total += n
	if err != nil {
		return total, err
	}
	expTo := fmt.Sprintf("%015d/\xff", max(expMs(expiredBefore), 0))
	n, err = s.purgeIndex(ctx, "exp", expTo, func(r *store.Record) bool {
		return !r.Deleted && !r.Expires.IsZero() && r.Expires.Before(expiredBefore)
	})
	return total + n, err
}

// purgeIndex removes the records listed in an index bucket up to member `to` whose current state still satisfies
// due. Each entry is re-verified against the record inside the transaction.
func (s *Store) purgeIndex(ctx context.Context, bucket, to string, due func(*store.Record) bool) (int, error) {
	removed := 0
	from := ""
	for {
		members, err := s.eng.Range(ctx, bucket, from, to, purgeBatch)
		if err != nil {
			return removed, err
		}
		if len(members) == 0 {
			return removed, nil
		}
		from = members[len(members)-1] + "\x00"
		var n int
		err = s.eng.Update(ctx, func(tx txn) error {
			n = 0
			for _, m := range members {
				parts := strings.SplitN(m, "/", 3)
				if len(parts) != 3 {
					return fmt.Errorf("kvstore: corrupt %s index entry %q", bucket, m)
				}
				st, err := loadRec(tx, model.Kind(parts[1]), parts[2])
				if err != nil {
					return err
				}
				if st == nil || !due(st.rec) {
					continue
				}
				if err := remove(tx, st); err != nil {
					return err
				}
				n++
			}
			return nil
		})
		if err != nil {
			return removed, err
		}
		removed += n
	}
}

// retry runs fn until it stops reporting a conflict; used by engines.
func retry(ctx context.Context, attempt func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		if err = attempt(); !errors.Is(err, errConflict) {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		time.Sleep(time.Duration(i%8+1) * 100 * time.Microsecond)
	}
	return fmt.Errorf("kvstore: too many conflicting retries: %w", store.ErrStale)
}

// RefreshFields recomputes the index fields stored with the records q selects, from their data
// (store.FieldRefresher). The record keeps its version and its place in the change feed; one rewritten meanwhile is
// left alone.
func (s *Store) RefreshFields(ctx context.Context, kind model.Kind, q store.ListQuery) (int, error) {
	res, err := s.List(ctx, kind, q)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range res.Records {
		fields, err := store.IndexFields(r)
		if err != nil {
			return n, err
		}
		changed := false
		err = s.write(ctx, kind, r.ID, func(tx txn) error {
			k := recKey(kind, r.ID)
			b, err := tx.Get(k)
			if err != nil || b == nil {
				return err
			}
			old, err := decodeRecord(b)
			if err != nil || !live(old) || old.rec.Version != r.Version {
				return err
			}
			rec := *old.rec
			rec.Fields = fields
			body, err := encodeRecord(&rec)
			if err != nil {
				return err
			}
			copy(body[:seqHeader], b[:seqHeader]) // the same feed position
			tx.Set(k, body)
			// Index entries that follow the fields (the due index, field indexes) follow them here too.
			oldEntries, newEntries := indexEntries(old.rec), indexEntries(&rec)
			for _, e := range oldEntries {
				if !hasEntry(newEntries, e) {
					tx.SetDel(e.bucket, e.member)
				}
			}
			for _, e := range newEntries {
				if !hasEntry(oldEntries, e) {
					tx.SetAdd(e.bucket, e.member, e.exp)
				}
			}
			changed = true
			return nil
		})
		if err != nil {
			return n, err
		}
		if changed {
			n++
		}
	}
	return n, nil
}
