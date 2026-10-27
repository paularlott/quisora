// Package kvstore implements store.Store over a small ordered key-value engine interface, with BadgerDB (embedded,
// node-local) as its engine.
//
// Key layout:
//
//	rec/<kind>/<id>                    -> msgpack wireRecord
//	uq/<kind>/<value>                  -> id
//	sc/<kind>/<scope>/<id>             -> ordered scope index (scope escaped so it never contains '/')
//	al/<kind>/<id>                     -> ordered "all" index of a kind (unscoped listing)
//	exp/<unix-ms 15 digits>/<kind>/<id> -> expiry index, range-deleted by Purge
//	tomb/<version 20 digits>/<kind>/<id> -> tombstone index, range-deleted by Purge
//	fx/<kind>/<field>/<value>/<scope>/<id> -> field index (model.Field.Index): the records with that value, by scope
//	                                      (an indexed bool field indexes only the records with true)
//	sx/<kind>/<field>/<scope>/<sort key>\x00<id> -> sort index (model.Field.SortIndex): the scope's records in the
//	                                      order a listing sorted on the field returns them (sortKey)
//	n/<range>, nx/<range>                -> counters: the members of an index range (al/<kind>, sc/<kind>/<scope>,
//	                                      fx/<kind>/<field>/<value>/<scope>), and those of them carrying an expiry
//	due/<unix-ms 15 digits>/<kind>/<id>  -> due index (model.Due), range-scanned by ListDue
//	ps/<partition>/<20-digit pseq>/<kind>/<id> -> partition sequence index: the records ApplyPartition and
//	                                      ImportPartition wrote, by the sequence of the write that last changed them,
//	                                      range-scanned by ExportPartition (tombstones included)
//	pt/<partition>/<20-digit pseq>/<kind>/<id> -> the tombstones among the ps members, scanned by PartitionTombstones
//	                                      and PurgePartition
//	pstate/<partition>                   -> the partition's protocol state (promised, committed, pending, purge point)
//	meta/feed_id, meta/format            -> the store's identity, and its format
//
// Ordered indexes are engine "ordered sets" (bucket + member): plain keys under a prefix. Housekeeping (Purge) only
// ever range-scans the exp, tomb and pt indexes, never the records.
//
// Listing: plain ID-ordered scans page through the scope index without loading the scope. An equality filter on an
// indexed field reads that field's index: the records with the value (in the scope: a contiguous range of the
// bucket, in id order, so one such filter alone is paged like a plain scan), or, for an indexed bool filtered on
// false, the scope paged with the records with true skipped (the way an administrator's user listing leaves out
// the super admins). A listing sorted on a SortIndex field pages the sort index the same way, ascending or
// descending, with the same exclusions: a page costs its offset plus its length in index keys and loads only its
// own records, whatever the size of the scope. Totals come from the counters when no member of the range carries
// an expiry (the counters count members, which stay in the indexes until Purge removes the expired ones), and
// otherwise from a count of the index that excludes the expired members (key-only iteration), as the index carries
// each member's expiry.
//
// A search (a prefix of the Search fields) of a kind whose Search fields all have sort indexes reads, keys only, the
// range of each index that starts with it: only the matching records are read. A word-list field (tags) is indexed
// once per word, so a filter on a tag reads only the records carrying it.
//
// Other listings (a filter on an unindexed field, a sort on an unindexed field, a sorted listing without a scope of a
// scoped kind) stream the scope in batches through the index that gives the result's order when there is one (the
// sort index, or the id index), matching records as they go and keeping only the page: O(scope size) in time and in
// record decoding, O(page) in memory. Wherever records are read for matching (these, a search, an indexed filter),
// they are read a batch at a time and only the page's worth is kept (store.Collector), so memory stays O(page).
// Doing any of that without a scope is O(kind size) and should be avoided for large kinds.
package kvstore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// plocks holds one *sync.RWMutex per partition: its protocol writes (group committed, so they never conflict with each
	// other) share it, and an import or purge of the partition holds it exclusively.
	plocks sync.Map
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
// recorded as it completes (an interrupted upgrade resumes where it stopped), under a lock. A store written by a newer build, or by a pre-release build older than
// formatBase, is refused. Never edit or remove a released migration: append one. Format 1 is the first release's;
// until that release the layout changes in place, and stores from earlier development builds are wiped, not
// migrated (format 2: the partition key and stamp in every record, the ps index and the partition state; format 3: no
// change-feed header in the records and no feed index, the tombstone index of each partition). A migration that
// rewrites records uses rewriteRecords (TestMigrationScale runs one over five million users).
const (
	metaFormat  = "meta/format"
	metaMigrate = "meta/migrating" // the lock held while migrating: "<holder> <expiry unix ms>"
	formatBase  = 3
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

// checkFormat migrates an older store and refuses one it cannot read. (A new store was marked when the engine made it:
// badgerEngine.init.)
func (s *Store) checkFormat(ctx context.Context) error {
	b, err := s.eng.Get(ctx, metaFormat)
	if err != nil {
		return err
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

// rewriteBatch is how many records rewriteRecords changes in one write transaction.
const rewriteBatch = 1000

// rewriteRecords is for format migrations: it passes every live or expired record of kind to fn, a batch at a time
// in id order, and stores those fn changed in place, in one write transaction per batch: the same version and change
// partition stamp (nothing is replicated: every node migrates its own store), with the stored index fields and the
// index entries rebuilt from the new data. fn may change the data, not the id or the unique values, and must be
// idempotent (an interrupted migration runs again from the start). Tombstones hold no data and are left alone. It
// returns how many records it changed.
func (s *Store) rewriteRecords(ctx context.Context, kind model.Kind, fn func(r *store.Record) (bool, error)) (int, error) {
	bucket, from, n := allBucket(kind), "", 0
	for {
		ids, err := s.eng.Range(ctx, bucket, from, "", rewriteBatch)
		if err != nil || len(ids) == 0 {
			return n, err
		}
		err = s.eng.Update(ctx, func(tx txn) error {
			for _, id := range ids {
				k := recKey(kind, id)
				b, err := tx.Get(k)
				if err != nil || b == nil {
					return err
				}
				old, err := decodeRecord(b)
				if err != nil {
					return err
				}
				if old.rec.Deleted {
					continue
				}
				rec := *old.rec
				changed, err := fn(&rec)
				if err != nil || !changed {
					return err
				}
				if rec.Fields, err = store.IndexFields(&rec); err != nil {
					return err
				}
				body, err := encodeRecord(&rec, old.ps) // the same partition stamp too
				if err != nil {
					return err
				}
				tx.Set(k, body)
				reindex(tx, indexEntries(old.rec, old.ps), indexEntries(&rec, old.ps))
				n++
			}
			return nil
		})
		if err != nil {
			return n, err
		}
		if err := ctx.Err(); err != nil {
			return n, err
		}
		from = ids[len(ids)-1] + "\x00"
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

func (s *Store) markFormat(ctx context.Context, v int) error {
	return s.eng.Update(ctx, func(tx txn) error { tx.Set(metaFormat, []byte(strconv.Itoa(v))); return nil })
}

// Wipe deletes every record and index of this store and gives it a new identity (FeedID). Callers must not write
// concurrently.
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
// transaction, so a backup taken through it is consistent. Close the view when done.
func (s *Store) Snapshot(context.Context) (store.Reader, error) {
	e, ok := s.eng.(*badgerEngine)
	if !ok {
		return nil, store.ErrNoSnapshot
	}
	t := e.db.NewTransaction(false)
	if importing(t) {
		t.Discard()
		return nil, errSnapshotImporting
	}
	return &Store{eng: &badgerSnapshot{t: t}, feedID: s.FeedID()}, nil
}

// errSnapshotImporting refuses a snapshot whose view holds a partition part-way through a full import (Snapshotter).
var errSnapshotImporting = fmt.Errorf("%w: a partition is part-way through a full import; try again once it has finished", store.ErrUnavailable)

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

// expMs rounds an expiry up to whole milliseconds so an index entry never reads as expired early.
func expMs(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return (t.UnixNano() + int64(time.Millisecond) - 1) / int64(time.Millisecond)
}

// indexEntry is one ordered-set membership of a record. count names the counted range the member belongs to
// (counterKey), "" for the members of the uncounted housekeeping indexes and of the sort indexes (whose scope
// ranges hold the same members as the scope index, and are counted by it).
type indexEntry struct {
	bucket, member string
	exp            int64
	count          string
}

// psBucket is the partition sequence index of partition p.
func psBucket(p uint32) string { return "ps/" + strconv.FormatUint(uint64(p), 10) }

// ptBucket is the tombstone index of partition p: the members of its sequence index that are tombstones, so the
// housekeeping scan for what to purge and the purge itself read tombstones only.
func ptBucket(p uint32) string { return "pt/" + strconv.FormatUint(uint64(p), 10) }

// indexEntries lists every ordered-set membership of rec. ps is the record's partition
// stamp (zero: none), which puts it in the partition sequence index, a tombstone too.
func indexEntries(r *store.Record, ps pstamp) []indexEntry {
	var out []indexEntry
	if r.Deleted {
		out = append(out, indexEntry{"tomb", indexMember(uint64(r.Version), 20, r.Kind, r.ID), 0, ""})
		if ps.seq > 0 {
			m := indexMember(ps.seq, 20, r.Kind, r.ID)
			out = append(out, indexEntry{psBucket(ps.num), m, 0, ""}, indexEntry{ptBucket(ps.num), m, 0, ""})
		}
		return out
	}
	exp := expMs(r.Expires)
	out = make([]indexEntry, 1, 5)
	out[0] = indexEntry{allBucket(r.Kind), r.ID, exp, allBucket(r.Kind)}
	if ps.seq > 0 {
		out = append(out, indexEntry{psBucket(ps.num), indexMember(ps.seq, 20, r.Kind, r.ID), 0, ""})
	}
	if r.Scope != "" {
		out = append(out, indexEntry{scopeBucket(r.Kind, r.Scope), r.ID, exp, scopeBucket(r.Kind, r.Scope)})
	}
	if exp > 0 {
		out = append(out, indexEntry{"exp", indexMember(uint64(exp), 15, r.Kind, r.ID), 0, ""})
	}
	if due, ok := model.Due(r.Kind, r.Fields); ok {
		out = append(out, indexEntry{dueBucket, indexMember(dueMs(due), 15, r.Kind, r.ID), 0, ""})
	}
	for _, f := range model.Schemas[r.Kind].Fields {
		if f.Index && f.Words { // one entry per word
			s, _ := r.Fields[f.Name].(string)
			words := strings.Fields(strings.ToLower(s)) // a filter on a word ignores case (indexBuckets)
			slices.Sort(words)
			for _, w := range slices.Compact(words) {
				if v, ok := fieldKey(w); ok { // as a filter on the word names its bucket (indexBuckets)
					b := fieldBucket(r.Kind, f.Name, v)
					out = append(out, indexEntry{b, fieldMember(r.Scope, r.ID), exp, fieldRange(b, r.Scope)})
				}
			}
		} else if f.Index && (f.Type != model.FieldBool || r.Fields[f.Name] == true) { // a bool's false records: never read
			if v, ok := fieldKey(r.Fields[f.Name]); ok && v != "" { // nor an empty string's (sparse: most users have no manager)
				b := fieldBucket(r.Kind, f.Name, v)
				out = append(out, indexEntry{b, fieldMember(r.Scope, r.ID), exp, fieldRange(b, r.Scope)})
			}
		}
		if f.SortIndex {
			out = append(out, indexEntry{sortBucket(r.Kind, f.Name), sortMember(r.Scope, f, r.Fields[f.Name], r.ID), exp, ""})
		}
	}
	return out
}

// ---- sort indexes ----

// sortBucket holds the records of kind in the order of their field (a model.Field marked SortIndex), as sortMember
// members: the records of one scope are a contiguous range of it (scopeBounds) that iterates in the order a listing
// sorted ascending on the field returns them.
func sortBucket(kind model.Kind, field string) string { return "sx/" + string(kind) + "/" + field }

// sortMember is a record's member of a sort index bucket: its scope (escaped, so it holds no '/'), then the sort key
// of its value, a NUL (which no sort key contains, so a shorter key sorts first as a shorter string does) and its id.
func sortMember(scope string, f model.Field, v any, id string) string {
	b := make([]byte, 0, len(scope)+len(id)+24)
	b = append(append(b, scopeEscaper.Replace(scope)...), '/')
	b = appendSortKey(b, f, v)
	return string(append(append(b, 0), id...))
}

// sortMemberID is the id of a sort index member.
func sortMemberID(m string) string { return m[sortKeyEnd(m)+1:] }

// sortKeyEnd is the position of the NUL that ends the sort key of member m.
func sortKeyEnd(m string) int {
	i := strings.IndexByte(m, '/') + 1
	return i + strings.IndexByte(m[i:], 0)
}

// appendSortKey appends the sort key of v, a value of field f: bytes whose order, under byte-wise comparison, is the
// order store.CompareValues gives the values. Strings fold case (lowered as there: the key is the lowered string);
// times are seconds then nanoseconds, fixed width, offset so the zero time is the smallest; integers fixed width
// and offset; false precedes true. A missing value (nil, or one of another type) keys as the type's zero value, which
// CompareValues puts first too. NUL and 0x01 bytes are escaped (0x01 0x01 and 0x01 0x02: order preserved) so the
// key holds no NUL.
func appendSortKey(b []byte, f model.Field, v any) []byte {
	var raw []byte
	var tmp [12]byte
	switch f.Type {
	case model.FieldString:
		s, _ := v.(string)
		raw = []byte(strings.ToLower(s))
	case model.FieldBool:
		if t, _ := v.(bool); t {
			tmp[0] = 1
		}
		raw = tmp[:1]
	case model.FieldTime:
		t, _ := v.(time.Time)
		binary.BigEndian.PutUint64(tmp[:8], uint64(t.Unix())+1<<63)
		binary.BigEndian.PutUint32(tmp[8:12], uint32(t.Nanosecond()))
		raw = tmp[:12]
	default:
		var n int64
		switch x := v.(type) {
		case int:
			n = int64(x)
		case int32:
			n = int64(x)
		case int64:
			n = x
		case uint32:
			n = int64(x)
		case uint64:
			n = int64(x)
		}
		binary.BigEndian.PutUint64(tmp[:8], uint64(n)+1<<63)
		raw = tmp[:8]
	}
	for _, c := range raw {
		switch c {
		case 0:
			b = append(b, 1, 1)
		case 1:
			b = append(b, 1, 2)
		default:
			b = append(b, c)
		}
	}
	return b
}

// sortIndexed returns the field a sort index serves q.Sort with, if there is one.
// sortBounds returns the part of scope's range of f's sort index that flts select, when every one of them is a range
// filter on f (gte: from; lt: to; prefix: the keys starting with it). The bounds are sort index positions:
// "<scope>/<sort key>", from inclusive and to exclusive (a member is "<scope>/<sort key>\x00<id>").
func sortBounds(scope string, f model.Field, flts []store.Filter) (from, to string, ok bool) {
	from, to = scopeBounds(scope)
	if len(flts) == 0 {
		return from, to, false
	}
	at := func(v any) string {
		return string(appendSortKey(append([]byte(scopeEscaper.Replace(scope)), '/'), f, v))
	}
	for _, flt := range flts {
		if flt.Field != f.Name {
			return from, to, false
		}
		switch flt.Op {
		case store.OpGTE:
			from = max(from, at(flt.Value))
		case store.OpLT:
			to = min(to, at(flt.Value))
		case store.OpPrefix:
			b := at(flt.Value)                         // a string's key is the lowered string, as the filter (case-insensitive)
			from, to = max(from, b), min(to, b+"\xff") // no key holds 0xff (UTF-8 never does; NUL and 0x01 are escaped)
		default:
			return from, to, false
		}
	}
	return from, to, true
}

func sortIndexed(kind model.Kind, sort string) (model.Field, bool) {
	f, ok := model.Schemas[kind].Field(sort)
	return f, ok && f.SortIndex
}

// ---- counters ----

// counterKey is the key of the counter of an index range (indexEntry.count): "n/" counts its members, "nx/" those
// of them that carry an expiry. Both are maintained in the transaction that adds or removes a member, so a total
// that needs no expiry check (nx is 0) is one read instead of a count of the range. Members stay in the indexes
// until Purge removes the expired ones, so while nx is not 0 the range's live total comes from the engine's count,
// which excludes them. An expiring kind (sessions, grants) therefore counts the way it did; the kinds that page
// large scopes (users, groups, organizations, audit events) never expire.
func counterKey(rng string, expiring bool) string {
	if expiring {
		return "nx/" + rng
	}
	return "n/" + rng
}

// counterOf decodes a counter: 8 bytes big endian; absent is 0.
func counterOf(b []byte) int64 {
	if len(b) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b))
}

// fieldRange is the counted range of a field index bucket's members of one scope (fieldMember: the scope's
// members are contiguous).
func fieldRange(bucket, scope string) string { return bucket + "/" + scopeEscaper.Replace(scope) }

// counts returns the two counters of range rng: its members, and those of them with an expiry.
func (s *Store) counts(ctx context.Context, rng string) (n, expiring int, err error) {
	vals, err := s.eng.MGet(ctx, []string{counterKey(rng, false), counterKey(rng, true)})
	if err != nil {
		return 0, 0, err
	}
	return int(counterOf(vals[0])), int(counterOf(vals[1])), nil
}

// reindex replaces a record's memberships old with new, keeping the counters of the ranges that changed.
func reindex(tx txn, old, new []indexEntry) {
	for _, o := range old {
		if !hasEntry(new, o) {
			tx.SetDel(o.bucket, o.member)
			if o.count != "" {
				tx.Add(counterKey(o.count, false), -1)
				if o.exp > 0 {
					tx.Add(counterKey(o.count, true), -1)
				}
			}
		}
	}
	for _, n := range new {
		if !hasEntry(old, n) {
			tx.SetAdd(n.bucket, n.member, n.exp)
			if n.count != "" {
				tx.Add(counterKey(n.count, false), 1)
				if n.exp > 0 {
					tx.Add(counterKey(n.count, true), 1)
				}
			}
		}
	}
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
// set such a field is indexed for; a filter on false is never served from the large "false" bucket; nor is an empty
// string indexed: a filter on "" scans). The two
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
			v, ok := fieldKey(flt.Value)
			if f.Words {
				v = strings.ToLower(v)
			}
			if f.Type == model.FieldBool && flt.Value == false {
				out = append(out, fieldBucket(kind, f.Name, "true"))
			} else if ok && v != "" && in == "" { // a filter on "" scans: empty strings are not indexed
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
// keys (built here when nil). ps is the record's partition stamp (zero for every write but a partition's).
func apply(tx txn, old *stored, rec *store.Record, index, keys []string, ps pstamp) error {
	r := *rec
	if r.Deleted {
		r.Data, r.Fields, r.Unique, r.Scope, r.Expires, r.Created = nil, nil, nil, "", time.Time{}, 0 // Epoch and Partition kept
		index = nil
	}
	var oldEntries []indexEntry
	if old != nil {
		oldEntries = indexEntries(old.rec, old.ps)
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
	reindex(tx, oldEntries, indexEntries(&r, ps))
	body, err := encodeRecord(&r, ps)
	if err != nil {
		return err
	}
	tx.Set(recKey(r.Kind, r.ID), body)
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
	reindex(tx, indexEntries(r, old.ps), nil)
	tx.Delete(recKey(r.Kind, r.ID))
	return nil
}

// ---- reads ----

// liveRecord decodes the stored body b of a record, which is nil when it was not found, and returns it when it is live.
func liveRecord(b []byte) (*store.Record, error) {
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
	b, err := s.eng.Get(ctx, recKey(kind, id))
	if err != nil {
		return nil, err
	}
	return liveRecord(b)
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

// GetByUnique reads the unique index and the record it names in one snapshot (two reads, one transaction).
func (s *Store) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	var b []byte
	err := s.eng.View(ctx, func(get func(string) ([]byte, error)) error {
		id, err := get(uqKey(kind, value))
		if err != nil || id == nil {
			return err
		}
		b, err = get(recKey(kind, string(id)))
		return err
	})
	if err != nil {
		return nil, err
	}
	return liveRecord(b)
}

// ---- writes ----

// write runs fn as a write of the record kind/id: through the engine's group commit when it has one.
func (s *Store) write(ctx context.Context, kind model.Kind, id string, fn func(tx txn) error) error {
	if g, ok := s.eng.(grouper); ok {
		return g.Group(ctx, string(kind), id, fn)
	}
	return s.eng.Update(ctx, fn)
}

// putTx is one write inside tx: Put (match false) or CompareAndPut(rec, expect) (match true). A retry (the stored
// record carries rec's request id) is answered as done whatever the expectation, writing nothing; the store stamps
// the version, so the caller's is neither compared nor used. It may run more than once (Update, group commit): the
// stamps it sets are recomputed.
func putTx(tx txn, rec *store.Record, match bool, expect hlc.Timestamp) error {
	old, err := loadRec(tx, rec.Kind, rec.ID)
	if err != nil {
		return err
	}
	if old != nil && store.Retried(rec, old.rec.Head()) {
		store.Settle(rec, old.rec.Head())
		return nil
	}
	if match {
		if expect == 0 && live(old) {
			return store.ErrStale
		}
		if expect != 0 {
			if !live(old) {
				return store.ErrNotFound
			}
			if old.rec.Version != expect {
				return store.ErrStale
			}
		}
	}
	if old == nil {
		store.StampWrite(rec, nil)
	} else {
		store.StampWrite(rec, old.rec.Head())
	}
	if err := stamp(rec, old, match && expect == 0); err != nil {
		return err
	}
	c, keys, err := conflicts(tx, rec)
	if err != nil {
		return err
	} else if c {
		return store.ErrConflict
	}
	return apply(tx, old, rec, rec.Unique, keys, pstamp{})
}

func (s *Store) Put(ctx context.Context, rec *store.Record) (err error) {
	defer store.EnsureReq(rec, &err)()
	return s.write(ctx, rec.Kind, rec.ID, func(tx txn) error { return putTx(tx, rec, false, 0) })
}

func (s *Store) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) (err error) {
	defer store.EnsureReq(rec, &err)()
	return s.write(ctx, rec.Kind, rec.ID, func(tx txn) error { return putTx(tx, rec, true, expect) })
}

// Tx applies ops all or nothing as one write (one Badger transaction, or one operation of a group commit batch, which
// is rolled back whole when it fails), routed by its first record. Each op runs as putTx does, in order, so a later
// op sees what the earlier ones wrote: a unique value one releases another may claim, and two claiming one conflict.
func (s *Store) Tx(ctx context.Context, ops []store.Op) (err error) {
	if len(ops) == 0 {
		return store.ErrBadTx
	}
	seen := make(map[[2]string]bool, len(ops))
	for _, op := range ops {
		k := [2]string{string(op.Rec.Kind), op.Rec.ID}
		if seen[k] {
			return store.ErrBadTx
		}
		seen[k] = true
	}
	defer store.TxReq(ops, &err)()
	return s.write(ctx, ops[0].Rec.Kind, ops[0].Rec.ID, func(tx txn) error {
		stored := make([]*stored, len(ops))
		retried := false
		for i, op := range ops {
			var err error
			if stored[i], err = loadRec(tx, op.Rec.Kind, op.Rec.ID); err != nil {
				return err
			}
			retried = retried || (stored[i] != nil && store.Retried(op.Rec, stored[i].rec.Head()))
		}
		if retried { // the whole transaction was applied: every record it wrote takes its stored version
			for i, op := range ops {
				if stored[i] != nil && stored[i].rec.Req == op.Rec.Req {
					store.Settle(op.Rec, stored[i].rec.Head())
				}
			}
			return nil
		}
		for _, op := range ops {
			if err := putTx(tx, op.Rec, op.Match, op.Expect); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PutReplicated(ctx context.Context, rec *store.Record) (bool, error) {
	var applied bool
	store.Witness(rec.Version)
	err := s.write(ctx, rec.Kind, rec.ID, func(tx txn) (err error) {
		applied, err = replicateOne(tx, rec)
		return err
	})
	if err != nil {
		return false, err
	}
	return applied, nil
}

// replicateOne applies rec inside tx with the PutReplicated semantics: not when a record of that id is stored at the
// same or a higher version, and not over a unique value another live record holds (ErrConflict).
func replicateOne(tx txn, rec *store.Record) (bool, error) {
	old, err := loadRec(tx, rec.Kind, rec.ID)
	if err != nil {
		return false, err
	}
	if old != nil && old.rec.Version >= rec.Version {
		return false, nil
	}
	clash, keys, err := conflicts(tx, rec)
	if err != nil {
		return false, err
	}
	if clash {
		return false, store.ErrConflict
	}
	if err := apply(tx, old, rec, rec.Unique, keys, pstamp{}); err != nil {
		return false, err
	}
	return true, nil
}

// batchGroup is the most records applied in one transaction.
const batchGroup = 256

// PutReplicatedBatch applies recs with the PutReplicated semantics, many per write transaction on Badger (one
// fsync per group instead of one per record). It implements store.BatchReplicator. Engines without cheap
// multi-record transactions fall back to one transaction per record.
func (s *Store) PutReplicatedBatch(ctx context.Context, recs []*store.Record) ([]bool, error) {
	applied := make([]bool, len(recs))
	if _, ok := s.eng.(*badgerEngine); !ok {
		for i, r := range recs {
			var err error
			if applied[i], err = s.PutReplicated(ctx, r); err != nil {
				return nil, err
			}
		}
		return applied, nil
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
					a, err := replicateOne(tx, recs[k])
					if err != nil {
						return err
					}
					applied[k] = a
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
			return nil, err
		}
	}
	return applied, nil
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
		p := pageQuery{Reverse: q.Desc, Offset: max(q.Offset, 0), Limit: q.Limit}
		return s.listPage(ctx, kind, bucket, p, nil, bucket, false, q.IDsOnly)
	}
	if q.Search != "" {
		ids, ok, err := s.searchIDs(ctx, kind, q)
		if err != nil {
			return nil, err
		}
		if ok { // only the matches are read; the rest of the query applies to them
			return s.collect(ctx, kind, ids, q)
		}
	}
	in, out := indexBuckets(kind, q)
	unsorted := q.Sort == "" && q.Search == ""
	excluding := in == "" && len(out) == len(q.Filters) // every filter leaves out an indexed set (or there is none)
	switch {
	case in != "" && unsorted && len(q.Filters) == 1 && q.Scope != "":
		// One indexed filter: the scope's range of the bucket is the result, in id order; page it like a plain scan.
		from, to := scopeBounds(q.Scope)
		p := pageQuery{From: from, To: to, Reverse: q.Desc, Offset: max(q.Offset, 0), Limit: q.Limit}
		if q.After != "" {
			p.From, p.Offset = from+q.After+"\x00", 0
		}
		return s.listPage(ctx, kind, in, p, fieldMemberID, fieldRange(in, q.Scope), q.After != "", q.IDsOnly)
	case unsorted && excluding:
		return s.listExcluding(ctx, kind, bucket, q, out)
	case q.Search == "" && excluding && (q.Scope != "" || model.Unscoped(kind)):
		if f, ok := sortIndexed(kind, q.Sort); ok {
			from, to := scopeBounds(q.Scope)
			return s.listSorted(ctx, kind, q, f, out, from, to)
		}
	}
	if in == "" && q.Search == "" && (q.Scope != "" || model.Unscoped(kind)) {
		// Range filters a sort index serves: on the sort field itself (an audit page from/to, by time), the page is
		// that range of the index; on another sort-indexed field (an action prefix), the range's ids are the only
		// candidates.
		if f, ok := sortIndexed(kind, q.Sort); ok {
			if from, to, ok := sortBounds(q.Scope, f, q.Filters); ok {
				return s.listSorted(ctx, kind, q, f, nil, from, to)
			}
		}
		for _, flt := range q.Filters {
			if f, ok := sortIndexed(kind, flt.Field); ok && flt.Op != "" {
				from, to, _ := sortBounds(q.Scope, f, []store.Filter{flt})
				members, _, err := s.eng.Page(ctx, sortBucket(kind, f.Name), pageQuery{From: from, To: to, NoTotal: true}, nowMs())
				if err != nil {
					return nil, err
				}
				for i, m := range members {
					members[i] = sortMemberID(m)
				}
				return s.collect(ctx, kind, members, q)
			}
		}
	}
	if in != "" {
		// An indexed equality filter: only the records with the value can match; they are read (as many as the
		// filter selects, not as the scope holds) and searched, filtered further, sorted and paged.
		ids, err := s.indexedIDs(ctx, kind, in, q.Scope, nowMs())
		if err != nil {
			return nil, err
		}
		return s.collect(ctx, kind, ids, q)
	}
	return s.listStreaming(ctx, kind, q)
}

// collect reads the records ids names a batch at a time, through a store.Collector for q: what is held at once is a
// batch and the page, however many there are.
func (s *Store) collect(ctx context.Context, kind model.Kind, ids []string, q store.ListQuery) (*store.ListResult, error) {
	c, err := store.NewCollector(kind, q)
	if err != nil {
		return nil, err
	}
	for len(ids) > 0 {
		n := min(len(ids), streamBatch)
		recs, err := s.loadMembers(ctx, kind, ids[:n])
		if err != nil {
			return nil, err
		}
		c.Add(recs)
		ids = ids[n:]
	}
	return c.Result(), nil
}

// searchIDs returns the ids of the records whose Search fields start with q.Search, read from the fields' sort
// indexes (a range of each per field, keys only); false when the kind cannot be searched that way (a Search field
// without a sort index, or a scoped kind searched across every scope), and the caller reads the scope.
func (s *Store) searchIDs(ctx context.Context, kind model.Kind, q store.ListQuery) ([]string, bool, error) {
	if q.Scope == "" && !model.Unscoped(kind) {
		return nil, false, nil
	}
	var fields []model.Field
	for _, f := range model.Schemas[kind].Fields {
		if f.Search {
			if !f.SortIndex || f.Type != model.FieldString {
				return nil, false, nil
			}
			fields = append(fields, f)
		}
	}
	if len(fields) == 0 {
		return nil, false, nil
	}
	from := scopeEscaper.Replace(q.Scope) + "/" + string(appendSortKey(nil, fields[0], q.Search))
	seen := map[string]bool{}
	var ids []string
	for _, f := range fields {
		members, _, err := s.eng.Page(ctx, sortBucket(kind, f.Name), pageQuery{From: from, To: from + "\xff", NoTotal: true}, nowMs())
		if err != nil {
			return nil, false, err
		}
		for _, m := range members {
			if id := sortMemberID(m); !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, true, nil
}

// counted returns the total of the page p selects from the counted range rng (counterKey), or -1 when only a count of
// the page's members gives it. When no member of the range carries an expiry its counter, less the members p skips
// (every one a live member of the range), is the total, and p is set to stop at the end of the page. A page without
// a limit reads the whole range anyway, and counts it as it goes.
func (s *Store) counted(ctx context.Context, rng string, p *pageQuery) (int, error) {
	if rng == "" || p.Limit <= 0 {
		return -1, nil
	}
	n, expiring, err := s.counts(ctx, rng)
	if err != nil || expiring > 0 {
		return -1, err
	}
	p.NoTotal = true
	return n - len(p.Skip), nil
}

// listPage loads the page p selects from bucket. idOf maps a member to its record id (nil: members are ids). rng is
// the counted range (counterKey) the page selects from, "" when there is none (see counted). A query paged by key
// (after: by After) has the page length as its total.
func (s *Store) listPage(ctx context.Context, kind model.Kind, bucket string, p pageQuery, idOf func(string) string, rng string, after, idsOnly bool) (*store.ListResult, error) {
	total := -1
	if after {
		p.NoTotal = true
	} else if t, err := s.counted(ctx, rng, &p); err != nil {
		return nil, err
	} else {
		total = t
	}
	members, scanned, err := s.eng.Page(ctx, bucket, p, nowMs())
	if err != nil {
		return nil, err
	}
	if total < 0 {
		total = scanned
	}
	if idOf != nil {
		for i, m := range members {
			members[i] = idOf(m)
		}
	}
	if idsOnly { // the index holds only live members (Page leaves the expired out): no record need be read
		recs := make([]*store.Record, len(members))
		for i, id := range members {
			recs[i] = &store.Record{Kind: kind, ID: id}
		}
		if after {
			total = len(recs)
		}
		return &store.ListResult{Records: recs, Total: max(total, 0)}, nil
	}
	recs, err := s.loadMembers(ctx, kind, members)
	if err != nil {
		return nil, err
	}
	if after {
		total = len(recs)
	}
	return &store.ListResult{Records: recs, Total: max(total, 0)}, nil
}

// listExcluding serves a query whose every filter leaves out the records of an indexed set (buckets out: the super
// admins of an organization, to the administrators who may not see them, on each of their user listings) by paging
// the scope's index (bucket) with those records skipped. The page costs a plain page plus the excluded sets' ids,
// however large the scope; loading the scope to filter it costs the scope.
func (s *Store) listExcluding(ctx context.Context, kind model.Kind, bucket string, q store.ListQuery, out []string) (*store.ListResult, error) {
	ids, err := s.excluded(ctx, kind, q.Scope, out)
	if err != nil {
		return nil, err
	}
	skip := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		skip[id] = struct{}{}
	}
	p := pageQuery{Skip: skip, Reverse: q.Desc, Offset: max(q.Offset, 0), Limit: q.Limit}
	if q.After != "" {
		p.From, p.Offset = q.After+"\x00", 0
	}
	return s.listPage(ctx, kind, bucket, p, nil, bucket, q.After != "", false)
}

// excluded returns the ids of the live records of scope ("" = every scope) in the field index buckets out: the
// records a listing with those exclusions leaves out. They are few (an organization's super admins, or its
// administrators), whatever the size of the scope.
func (s *Store) excluded(ctx context.Context, kind model.Kind, scope string, out []string) ([]string, error) {
	now := nowMs()
	var ids []string
	for _, b := range out {
		more, err := s.indexedIDs(ctx, kind, b, scope, now)
		if err != nil {
			return nil, err
		}
		ids = append(ids, more...)
	}
	if len(out) > 1 {
		slices.Sort(ids)
		ids = slices.Compact(ids)
	}
	return ids, nil
}

// listSorted serves a listing sorted on f (a SortIndex field) from the sort index: the scope's range of the
// field's bucket, with the records of the excluded sets (buckets out) skipped; their members are computed from the
// records, which are loaded (an excluded set is small). Ascending, the page is a plain page of the range.
// Descending, the range is read backwards, which orders the records of equal values by id descending where the
// store's order (store.ListQuery: ties break by id ascending, whatever the direction) wants them ascending: the
// runs of equal values the page holds are put right by fixDescTies.
func (s *Store) listSorted(ctx context.Context, kind model.Kind, q store.ListQuery, f model.Field, out []string, from, to string) (*store.ListResult, error) {
	bucket, rng := sortBucket(kind, q.Sort), listBucket(kind, q.Scope)
	if sf, st := scopeBounds(q.Scope); from != sf || to != st {
		rng = "" // a range of the scope: its total is counted as it is read, not taken from the scope's counter
	}
	var skip map[string]struct{}
	if len(out) > 0 {
		ids, err := s.excluded(ctx, kind, q.Scope, out)
		if err != nil {
			return nil, err
		}
		recs, err := s.loadMembers(ctx, kind, ids)
		if err != nil {
			return nil, err
		}
		skip = make(map[string]struct{}, len(recs))
		for _, r := range recs {
			skip[sortMember(r.Scope, f, r.Fields[f.Name], r.ID)] = struct{}{}
		}
	}
	p := pageQuery{From: from, To: to, Skip: skip, Reverse: q.Desc, Offset: max(q.Offset, 0), Limit: q.Limit}
	if !q.Desc {
		return s.listPage(ctx, kind, bucket, p, sortMemberID, rng, false, false)
	}
	total, err := s.counted(ctx, rng, &p)
	if err != nil {
		return nil, err
	}
	members, scanned, err := s.eng.Page(ctx, bucket, p, nowMs())
	if err != nil {
		return nil, err
	}
	if total < 0 {
		total = scanned
	}
	if err := s.fixDescTies(ctx, bucket, members, skip); err != nil {
		return nil, err
	}
	for i, m := range members {
		members[i] = sortMemberID(m)
	}
	recs, err := s.loadMembers(ctx, kind, members)
	if err != nil {
		return nil, err
	}
	return &store.ListResult{Records: recs, Total: max(total, 0)}, nil
}

// fixDescTies puts the runs of equal sort keys in members, a page of a sort index read backwards (so each run holds
// ids descending), into the store's descending order (ids ascending within a run). A run wholly inside the page is
// reversed in place. The run at the top of the page may continue above it: its members above the page (those with
// greater ids, skipped by the offset) are counted, then its part of the page is read forwards from that position.
// The run at the bottom may continue below: its part of the page is the first as many of it read forwards. Each
// read is bounded by the page and its offset, like the page itself.
func (s *Store) fixDescTies(ctx context.Context, bucket string, members []string, skip map[string]struct{}) error {
	now := nowMs()
	for i := 0; i < len(members); {
		prefix := members[i][:sortKeyEnd(members[i])+1] // "<scope>/<sort key>\x00": the run's members start with it
		j := i + 1
		for j < len(members) && strings.HasPrefix(members[j], prefix) {
			j++
		}
		run := members[i:j]
		var p pageQuery
		switch {
		case i == 0:
			_, above, err := s.eng.Page(ctx, bucket, pageQuery{From: members[0] + "\x00", To: prefix + "\xff", Skip: skip, Limit: 1}, now)
			if err != nil {
				return err
			}
			p = pageQuery{From: prefix, To: prefix + "\xff", Skip: skip, Offset: above, Limit: len(run), NoTotal: true}
		case j == len(members):
			p = pageQuery{From: prefix, To: prefix + "\xff", Skip: skip, Limit: len(run), NoTotal: true}
		default:
			slices.Reverse(run)
			i = j
			continue
		}
		asc, _, err := s.eng.Page(ctx, bucket, p, now)
		if err != nil {
			return err
		}
		if len(asc) != len(run) { // the index changed under the page: keep what was read, in the order it came
			slices.Reverse(run)
		} else {
			copy(run, asc)
		}
		i = j
	}
	return nil
}

// streamBatch is how many index members a streamed listing (listStreaming) reads, and records it loads, at a time.
const streamBatch = 512

// listStreaming serves the listings no index answers outright: a search, a filter on an unindexed field, a sort on
// an unindexed field, a sorted listing of a scoped kind without a scope. It reads the scope a batch at a time
// through the index that iterates in the result's order when there is one (the sort index of a SortIndex sort
// field within a scope, the id index of an unsorted listing), matches the records as they come (store.Match) and
// keeps only those of the page: it holds a batch and the page, not the scope, and the total is exact. Without such
// an index the matches are collected and ordered in memory (store.ApplyQuery): O(matches) in memory. Either way
// every record of the scope is read once: O(scope) in time.
func (s *Store) listStreaming(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	bucket, from, to := listBucket(kind, q.Scope), "", ""
	idOf := func(m string) string { return m }
	ordered, ties := true, false // ordered: the stream comes in the result's order; ties: except within equal values
	var f model.Field
	if q.Sort != "" {
		var ok bool
		if f, ok = sortIndexed(kind, q.Sort); ok && (q.Scope != "" || model.Unscoped(kind)) {
			bucket, idOf = sortBucket(kind, q.Sort), sortMemberID
			from, to = scopeBounds(q.Scope)
			ties = q.Desc // read backwards, equal values come by id descending; the order wants ascending
		} else {
			ordered = false
		}
	}
	if q.After != "" {
		from = q.After + "\x00"
	}
	offset := max(q.Offset, 0)
	if q.After != "" {
		offset = 0
	}
	matched := 0
	page := []*store.Record{}
	take := func(r *store.Record) {
		if matched >= offset && (q.Limit <= 0 || len(page) < q.Limit) {
			page = append(page, r)
		}
		matched++
	}
	// A run of equal values read backwards comes by id descending and is taken ascending, so only its last matches
	// (the lowest ids) can be on the page: the run keeps as many as the page still needs and counts the rest.
	var run []*store.Record // the kept matches of the current run of equal values (ties)
	skipped := 0            // matches of the run left out (higher ids than those kept: after them, past the page)
	keepRun := func() int { // how many of a run the page can need (-1: every one)
		if q.Limit <= 0 {
			return -1
		}
		return max(offset+q.Limit-matched, 0)
	}
	var unordered *store.Collector // without an index in the result's order: every match goes through it
	if !ordered {
		var err error
		if unordered, err = store.NewCollector(kind, q); err != nil {
			return nil, err
		}
	}
	var runKey string
	trim := func(keep int) {
		if keep >= 0 && len(run) > keep {
			n := len(run) - keep
			skipped += n
			copy(run, run[n:])
			clear(run[keep:])
			run = run[:keep]
		}
	}
	flush := func() {
		trim(keepRun())
		for i := len(run) - 1; i >= 0; i-- {
			take(run[i])
		}
		matched += skipped
		run, skipped = run[:0], 0
	}
	now := nowMs()
	for {
		members, _, err := s.eng.Page(ctx, bucket, pageQuery{From: from, To: to, Reverse: q.Desc, Limit: streamBatch, NoTotal: true}, now)
		if err != nil {
			return nil, err
		}
		if len(members) == 0 {
			break
		}
		last := members[len(members)-1]
		if q.Desc {
			to = last
		} else {
			from = last + "\x00"
		}
		for i, m := range members {
			members[i] = idOf(m)
		}
		recs, err := s.loadMembers(ctx, kind, members)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if !store.Match(kind, r, q) {
				continue
			}
			switch {
			case !ordered:
				unordered.Add([]*store.Record{r})
			case ties:
				k := string(appendSortKey(nil, f, r.Fields[f.Name]))
				if k != runKey && len(run) > 0 {
					flush()
				}
				runKey = k
				run = append(run, r)
				if keep := keepRun(); keep >= 0 && len(run) > 2*keep {
					trim(keep) // now and then: at most twice what the page needs is held
				}
			default:
				take(r)
			}
		}
		if len(members) < streamBatch { // (expired members do not fill a page: fewer means the range is read)
			break
		}
	}
	flush()
	if !ordered {
		return unordered.Result(), nil
	}
	if q.After != "" {
		matched = len(page)
	}
	return &store.ListResult{Records: page, Total: matched}, nil
}

// indexedIDs returns the ids of the live records of scope ("" = every scope) in field index bucket b, in id order
// within each scope.
func (s *Store) indexedIDs(ctx context.Context, kind model.Kind, b, scope string, now int64) ([]string, error) {
	p := pageQuery{NoTotal: true}
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

// Count is the scope's counter when no member of the scope carries an expiry, and otherwise a count of its index
// that leaves the expired members out.
func (s *Store) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	rng := listBucket(kind, scope)
	n, expiring, err := s.counts(ctx, rng)
	if err != nil {
		return 0, err
	}
	if expiring > 0 {
		return s.eng.Count(ctx, rng, nowMs())
	}
	return n, nil
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

// retryConflicts counts the transactions retried after a conflict (tests).
var retryConflicts atomic.Int64

// retry runs fn until it stops reporting a conflict; used by engines.
func retry(ctx context.Context, attempt func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		if err = attempt(); !errors.Is(err, errConflict) {
			return err
		}
		retryConflicts.Add(1)
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		time.Sleep(conflictBackoff(i))
	}
	return fmt.Errorf("kvstore: too many conflicting retries: %w", store.ErrUnavailable)
}

// conflictBackoff is the wait before retry i of a conflicting transaction: exponential, up to about 6 ms, and random
// within that, so transactions that conflicted (on a counter every new record of a kind moves, say) do not retry in
// step and conflict again.
func conflictBackoff(i int) time.Duration {
	return time.Duration(rand.Int64N(int64(100*time.Microsecond)<<min(i, 6)) + 1)
}
