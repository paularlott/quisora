package kvstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// BadgerOptions tunes the Badger engine; the zero value is a sensible production default.
type BadgerOptions struct {
	// NoSync disables fsync on commit (faster, may lose the last writes on a crash). Default: fsync every commit
	// (concurrent record writes share commits, see Group).
	NoSync bool
	// SyncInterval, with NoSync, syncs the write-ahead log to disk this often (0: never; the operating system flushes
	// it when it sees fit). A write is acknowledged once it is in the page cache, so it survives the process dying
	// but not the machine: a power cut or kernel panic loses what was written in the last SyncInterval (and the time
	// a sync takes). It is not for a store whose acknowledged writes others rely on (a cluster node).
	SyncInterval time.Duration
	// InMemory keeps everything in RAM (tests); path is ignored.
	InMemory bool
	// EncryptionKey (32 bytes) encrypts the files at rest; nil: not encrypted. A store keeps the choice it was
	// created with: opening it with another key, or without its key, fails.
	EncryptionKey []byte
	// Compression is "none" (default: records are small and the LSM is read from the page cache), "snappy" or "zstd".
	Compression string
	// BlockCacheMB and IndexCacheMB size the caches (only used with compression). Default 128 and 64.
	BlockCacheMB int64
	IndexCacheMB int64
	// ValueLogFileSizeMB is the size of one value log file. Default 256.
	ValueLogFileSizeMB int64
	// GCInterval is how often value log garbage collection runs. Default 5 minutes.
	GCInterval time.Duration
	// Logger receives Badger's log output; nil discards everything except errors via the standard quiet logger.
	Logger badger.Logger
	// Group tunes group commit of record writes (see group.go); on by default.
	Group GroupOptions
}

type quietLogger struct{}

func (quietLogger) Errorf(string, ...any)   {}
func (quietLogger) Warningf(string, ...any) {}
func (quietLogger) Infof(string, ...any)    {}
func (quietLogger) Debugf(string, ...any)   {}

type badgerEngine struct {
	db   *badger.DB
	stop chan struct{}
	wg   sync.WaitGroup
	once sync.Once
	gc   *committer // nil when group commit is disabled
}

// OpenBadger opens (creating if needed) a Badger-backed store in the directory path.
func OpenBadger(ctx context.Context, path string, o BadgerOptions) (*Store, error) {
	opts := badger.DefaultOptions(path).
		WithNumVersionsToKeep(1).
		WithSyncWrites(!o.NoSync).
		WithLogger(o.Logger).
		WithInMemory(o.InMemory).
		WithDetectConflicts(true)
	if o.Logger == nil {
		opts = opts.WithLogger(quietLogger{})
	}
	if o.InMemory {
		opts = opts.WithDir("").WithValueDir("").WithSyncWrites(false)
	}
	switch o.Compression {
	case "", "none":
		opts = opts.WithCompression(options.None)
	case "snappy":
		opts = opts.WithCompression(options.Snappy)
	case "zstd":
		opts = opts.WithCompression(options.ZSTD)
	default:
		return nil, fmt.Errorf("kvstore: unknown compression %q", o.Compression)
	}
	opts = opts.WithBlockCacheSize(dflt(o.BlockCacheMB, 128) << 20).
		WithIndexCacheSize(dflt(o.IndexCacheMB, 64) << 20).
		WithValueLogFileSize(dflt(o.ValueLogFileSizeMB, 256) << 20)
	if len(o.EncryptionKey) > 0 {
		opts = opts.WithEncryptionKey(o.EncryptionKey) // the index cache, which encryption needs, is set above
	}
	db, err := badger.Open(opts)
	if err != nil {
		if errors.Is(err, badger.ErrEncryptionKeyMismatch) || strings.Contains(err.Error(), "ncryption") {
			return nil, fmt.Errorf("kvstore: open badger: %w (storage.badgerdb.encryption_key must be the key the "+
				"store was created with, and set only for a store created encrypted)", err)
		}
		return nil, fmt.Errorf("kvstore: open badger: %w", err)
	}
	e := &badgerEngine{db: db, stop: make(chan struct{})}
	feedID, err := e.init()
	if err != nil {
		db.Close()
		return nil, err
	}
	gc := o.GCInterval
	if gc <= 0 {
		gc = 5 * time.Minute
	}
	if !o.InMemory {
		e.wg.Add(1)
		go e.every(gc, func() {
			for e.db.RunValueLogGC(0.5) == nil {
			}
		})
		if o.NoSync && o.SyncInterval > 0 {
			e.wg.Add(1)
			go e.every(o.SyncInterval, func() {
				if err := e.db.Sync(); err != nil {
					opts.Errorf("kvstore: periodic sync: %v", err)
				}
			})
		}
	}
	if !o.Group.Disabled {
		e.gc = newCommitter(e, o.Group)
	}
	st := newStore(ctx, e, feedID)
	if err := st.checkFormat(ctx); err != nil {
		e.Close()
		return nil, err
	}
	return st, nil
}

func dflt(v, d int64) int64 {
	if v <= 0 {
		return d
	}
	return v
}

func (e *badgerEngine) init() (string, error) {
	var feedID string
	err := e.db.Update(func(t *badger.Txn) error {
		it, err := t.Get([]byte(metaFeed))
		switch {
		case err == nil:
			b, err := it.ValueCopy(nil)
			if err != nil {
				return err
			}
			feedID = string(b)
		case errors.Is(err, badger.ErrKeyNotFound):
			// A new store: it has an identity and the current format (a store without them was made by an earlier build).
			feedID = model.NewID()
			if err := t.Set([]byte(metaFeed), []byte(feedID)); err != nil {
				return err
			}
			if err := t.Set([]byte(metaFormat), []byte(strconv.Itoa(currentFormat()))); err != nil {
				return err
			}
		default:
			return err
		}
		return nil
	})
	return feedID, err
}

// every runs fn every d until the engine is closed.
func (e *badgerEngine) every(d time.Duration, fn func()) {
	defer e.wg.Done()
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			fn()
		}
	}
}

func (e *badgerEngine) Close() error {
	var err error
	e.once.Do(func() {
		if e.gc != nil {
			e.gc.close() // commits every queued write first
		}
		close(e.stop)
		e.wg.Wait()
		err = e.db.Close()
	})
	return err
}

// engineErr answers what the engine cannot do now as the store's one "try again" (store.Store: a closed database, a
// context that ended, are store.ErrUnavailable); anything else is returned as it is.
func engineErr(err error) error {
	switch {
	case err == nil || errors.Is(err, store.ErrUnavailable):
		return err
	case errors.Is(err, badger.ErrDBClosed):
		return fmt.Errorf("%w: %w: %w", store.ErrUnavailable, store.ErrClosed, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	return err
}

func (e *badgerEngine) Get(_ context.Context, key string) ([]byte, error) {
	var out []byte
	err := e.view(func(t *badger.Txn) error {
		var err error
		out, err = getVal(t, key)
		return err
	})
	return out, err
}

func (e *badgerEngine) View(_ context.Context, fn func(get func(key string) ([]byte, error)) error) error {
	return e.view(func(t *badger.Txn) error { return fn(func(key string) ([]byte, error) { return getVal(t, key) }) })
}

// view runs fn in a read transaction.
func (e *badgerEngine) view(fn func(t *badger.Txn) error) error { return engineErr(e.db.View(fn)) }

func getVal(t *badger.Txn, key string) ([]byte, error) {
	it, err := t.Get([]byte(key))
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return it.ValueCopy(nil)
}

func (e *badgerEngine) MGet(_ context.Context, keys []string) ([][]byte, error) {
	var out [][]byte
	err := e.view(func(t *badger.Txn) (err error) { out, err = mget(t, keys); return })
	return out, err
}

func mget(t *badger.Txn, keys []string) ([][]byte, error) {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		v, err := getVal(t, k)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// memberKey is the Badger key of an ordered-set member (one allocation).
func memberKey(bucket, member string) []byte {
	k := make([]byte, 0, len(bucket)+1+len(member))
	return append(append(append(k, bucket...), '/'), member...)
}

func memberStr(bucket, member string) string { return bucket + "/" + member }

func expOf(it *badger.Item) (int64, error) {
	if it.ValueSize() == 0 {
		return 0, nil
	}
	var exp int64
	err := it.Value(func(v []byte) error {
		if len(v) == 8 {
			exp = int64(binary.BigEndian.Uint64(v))
		}
		return nil
	})
	return exp, err
}

func (e *badgerEngine) Page(_ context.Context, bucket string, p pageQuery, nowMs int64) ([]string, int, error) {
	var out []string
	var total int
	err := e.view(func(t *badger.Txn) (err error) {
		out, total, err = page(t, bucket, p, nowMs)
		return
	})
	return out, total, err
}

// page selects p from bucket in one key-only iteration (a value is read only to check a member's expiry): it starts
// at the bound it iterates from, stops at the other, and counts every live member it passes that p does not skip.
func page(t *badger.Txn, bucket string, p pageQuery, nowMs int64) ([]string, int, error) {
	prefix := []byte(bucket + "/")
	var lo, hi []byte // the bounds as keys; nil when unbounded
	if p.From != "" {
		lo = memberKey(bucket, p.From)
	}
	if p.To != "" {
		hi = memberKey(bucket, p.To)
	}
	out := []string{}
	total := 0
	err := func() error {
		o := badger.DefaultIteratorOptions
		o.Prefix, o.Reverse, o.PrefetchValues = prefix, p.Reverse, false
		it := t.NewIterator(o)
		defer it.Close()
		switch {
		case p.Reverse && hi != nil:
			it.Seek(hi) // at hi or the largest key below it; hi itself is outside the range
			if it.ValidForPrefix(prefix) && bytes.Equal(it.Item().Key(), hi) {
				it.Next()
			}
		case p.Reverse:
			it.Seek(append(append([]byte{}, prefix...), 0xFF))
		case lo != nil:
			it.Seek(lo)
		default:
			it.Rewind()
		}
		for ; it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()
			if p.Reverse {
				if lo != nil && bytes.Compare(key, lo) < 0 {
					break
				}
			} else if hi != nil && bytes.Compare(key, hi) >= 0 {
				break
			}
			exp, err := expOf(item)
			if err != nil {
				return err
			}
			if exp > 0 && nowMs >= exp {
				continue
			}
			m := key[len(prefix):]
			if p.Skip != nil {
				if _, skip := p.Skip[string(m)]; skip { // (the lookup's conversion does not allocate)
					continue
				}
			}
			if total >= p.Offset && (p.Limit <= 0 || len(out) < p.Limit) {
				out = append(out, string(m))
			}
			total++
			if p.NoTotal && p.Limit > 0 && len(out) >= p.Limit {
				break // the page is full and nobody wants the rest counted
			}
		}
		return nil
	}()
	return out, total, err
}

func (e *badgerEngine) Count(ctx context.Context, bucket string, nowMs int64) (int, error) {
	_, n, err := e.Page(ctx, bucket, pageQuery{Limit: 1}, nowMs)
	return n, err
}

func (e *badgerEngine) Range(_ context.Context, bucket, from, to string, limit int) ([]string, error) {
	var out []string
	err := e.view(func(t *badger.Txn) (err error) { out, err = rangeOf(t, bucket, from, to, limit); return })
	return out, err
}

func rangeOf(t *badger.Txn, bucket, from, to string, limit int) ([]string, error) {
	prefix := []byte(bucket + "/")
	hi := []byte(to)
	out := []string{}
	err := func() error {
		o := badger.DefaultIteratorOptions
		o.Prefix, o.PrefetchValues = prefix, false
		it := t.NewIterator(o)
		defer it.Close()
		for it.Seek(memberKey(bucket, from)); it.ValidForPrefix(prefix); it.Next() {
			m := it.Item().Key()[len(prefix):]
			if to != "" && bytes.Compare(m, hi) > 0 {
				break
			}
			out = append(out, string(m))
			if limit > 0 && len(out) >= limit {
				break
			}
		}
		return nil
	}()
	return out, err
}

// badgerSnapshot is a read-only engine over one Badger read transaction: a consistent point-in-time view of the
// whole store (Store.Snapshot).
// importing reports whether t's view holds the marker of a full import in progress (importActiveKey).
func importing(t *badger.Txn) bool {
	o := badger.DefaultIteratorOptions
	o.Prefix, o.PrefetchValues = []byte(importActivePrefix), false
	it := t.NewIterator(o)
	defer it.Close()
	it.Rewind()
	return it.Valid()
}

// unfinishedImport reports whether t's view holds an import that has not finished in any partition (importUnfinished):
// a full import's marker, or a partition whose sequence index has a record above its committed position. It looks at
// every partition with a sequence index, one seek each.
func unfinishedImport(ctx context.Context, t *badger.Txn) (bool, error) {
	if importing(t) {
		return true, nil
	}
	eng := &badgerSnapshot{t: t}
	const prefix = "ps/"
	o := badger.DefaultIteratorOptions
	o.Prefix, o.PrefetchValues = []byte(prefix), false
	it := t.NewIterator(o)
	defer it.Close()
	for it.Rewind(); it.Valid(); {
		rest := it.Item().Key()[len(prefix):]
		i := bytes.IndexByte(rest, '/')
		if i < 0 {
			return false, fmt.Errorf("kvstore: corrupt partition index key %q", it.Item().Key())
		}
		p, err := strconv.Atoi(string(rest[:i]))
		if err != nil {
			return false, fmt.Errorf("kvstore: corrupt partition index key %q", it.Item().Key())
		}
		b, err := eng.Get(ctx, pstateKey(p))
		if err != nil {
			return false, err
		}
		st, err := decodeState(b)
		if err != nil {
			return false, err
		}
		if unfinished, err := importUnfinished(ctx, eng, p, st.Committed.Seq); err != nil || unfinished {
			return unfinished, err
		}
		it.Seek(append([]byte(memberStr(psBucket(uint32(p)), "")), 0xff)) // the next partition's index
	}
	return false, nil
}

type badgerSnapshot struct {
	t *badger.Txn
}

var errReadOnly = errors.New("kvstore: snapshot is read-only")

func (b *badgerSnapshot) Get(_ context.Context, key string) ([]byte, error) { return getVal(b.t, key) }
func (b *badgerSnapshot) View(_ context.Context, fn func(get func(key string) ([]byte, error)) error) error {
	return fn(func(key string) ([]byte, error) { return getVal(b.t, key) })
}
func (b *badgerSnapshot) MGet(_ context.Context, keys []string) ([][]byte, error) {
	return mget(b.t, keys)
}
func (b *badgerSnapshot) Page(_ context.Context, bucket string, p pageQuery, nowMs int64) ([]string, int, error) {
	return page(b.t, bucket, p, nowMs)
}
func (b *badgerSnapshot) Count(ctx context.Context, bucket string, nowMs int64) (int, error) {
	_, n, err := b.Page(ctx, bucket, pageQuery{Limit: 1}, nowMs)
	return n, err
}
func (b *badgerSnapshot) Range(_ context.Context, bucket, from, to string, limit int) ([]string, error) {
	return rangeOf(b.t, bucket, from, to, limit)
}
func (b *badgerSnapshot) Update(context.Context, func(tx txn) error) error { return errReadOnly }
func (b *badgerSnapshot) wipe(context.Context, string) error               { return errReadOnly }
func (b *badgerSnapshot) Close() error                                     { b.t.Discard(); return nil }

// Group runs fn like Update, committed together with other concurrent writes when group commit is on (grouper).
func (e *badgerEngine) Group(ctx context.Context, kind, id string, fn func(tx txn) error) error {
	if e.gc == nil {
		return e.Update(ctx, fn)
	}
	return engineErr(e.gc.submit(ctx, route(kind, id), fn))
}

func (e *badgerEngine) Update(ctx context.Context, fn func(tx txn) error) error {
	if e.db.IsClosed() {
		return engineErr(badger.ErrDBClosed)
	}
	return engineErr(retry(ctx, func() error {
		b := e.newBatch()
		b.begin()
		if err := fn(b); err != nil {
			b.t.Discard()
			return err
		}
		return b.commit()
	}))
}

// bwrite is a buffered write: a value (nil for an ordered-set member without expiry) or a deletion.
type bwrite struct {
	val []byte
	del bool
}

// undoEntry restores one buffered write when the operation that made it fails.
type undoEntry struct {
	key  string
	prev bwrite
	had  bool
}

// badgerBatch is one Badger write transaction carrying the writes of one or more operations (group commit); it is
// the txn every operation runs against. Writes are buffered here rather than in the Badger transaction until
// commit, so each operation reads what the operations before it wrote, and an operation that fails is rolled back
// (rollback) without touching the others.
type badgerBatch struct {
	t      *badger.Txn
	reads  map[string][]byte // values read from the transaction's snapshot (nil = absent)
	writes map[string]bwrite // buffered writes
	undo   []undoEntry       // writes of the running operation, newest last
	rerr   error             // a read error met by an operation that could not return it (Add); fails the commit
}

func (e *badgerEngine) newBatch() *badgerBatch {
	return &badgerBatch{t: e.db.NewTransaction(true)}
}

// begin starts an operation: its writes can be rolled back until the next begin.
func (b *badgerBatch) begin() { b.undo = b.undo[:0] }

// rollback drops every write of the running operation.
func (b *badgerBatch) rollback() {
	for i := len(b.undo) - 1; i >= 0; i-- {
		if u := b.undo[i]; u.had {
			b.writes[u.key] = u.prev
		} else {
			delete(b.writes, u.key)
		}
	}
	b.undo = b.undo[:0]
}

// Get reads key as the batch sees it: buffered writes first, then the snapshot. Snapshot reads are cached (the
// snapshot does not change), which spares repeated reads of one key their Badger lookup; the first read of every
// key still goes through the Badger transaction, so commit-time conflict detection sees it.
func (b *badgerBatch) Get(key string) ([]byte, error) {
	if w, ok := b.writes[key]; ok {
		if w.del {
			return nil, nil
		}
		return w.val, nil
	}
	if v, ok := b.reads[key]; ok {
		return v, nil
	}
	v, err := getVal(b.t, key)
	if err != nil {
		return nil, err
	}
	if b.reads == nil {
		b.reads = make(map[string][]byte, 8)
	}
	b.reads[key] = v
	return v, nil
}

func (b *badgerBatch) put(key string, w bwrite) {
	if b.writes == nil {
		b.writes = make(map[string]bwrite, 16)
		b.undo = make([]undoEntry, 0, 16)
	}
	prev, had := b.writes[key]
	b.undo = append(b.undo, undoEntry{key, prev, had})
	b.writes[key] = w
}

func (b *badgerBatch) Set(key string, val []byte) { b.put(key, bwrite{val: val}) }
func (b *badgerBatch) Delete(key string)          { b.put(key, bwrite{del: true}) }

func (b *badgerBatch) SetAdd(bucket, member string, expMs int64) {
	var v []byte
	if expMs > 0 {
		v = binary.BigEndian.AppendUint64(make([]byte, 0, 8), uint64(expMs))
	}
	b.put(memberStr(bucket, member), bwrite{val: v})
}

func (b *badgerBatch) SetDel(bucket, member string) {
	b.put(memberStr(bucket, member), bwrite{del: true})
}

// Add reads the counter (through Get: a buffered write of this batch, or the snapshot, which registers the key for
// conflict detection) and buffers its new value, 8 bytes big endian; a counter back at 0 is deleted.
func (b *badgerBatch) Add(key string, delta int64) {
	cur, err := b.Get(key)
	if err != nil && b.rerr == nil {
		b.rerr = err // fails the commit
	}
	n := counterOf(cur) + delta
	if n <= 0 {
		b.put(key, bwrite{del: true})
		return
	}
	b.put(key, bwrite{val: binary.BigEndian.AppendUint64(make([]byte, 0, 8), uint64(n))})
}

func (b *badgerBatch) empty() bool { return len(b.writes) == 0 }

// commit moves the buffered writes into the Badger transaction and commits it, then waits until the commit is durable
// (fsync with SyncWrites). The Badger transaction is always finished.
func (b *badgerBatch) commit() error {
	t := b.t
	if b.rerr != nil {
		t.Discard()
		return b.rerr
	}
	if b.empty() {
		t.Discard()
		return nil
	}
	for k, w := range b.writes {
		var err error
		if w.del {
			err = t.Delete([]byte(k))
		} else {
			err = t.Set([]byte(k), w.val)
		}
		if err != nil {
			t.Discard()
			return err
		}
	}
	done := make(chan error, 1)
	t.CommitWith(func(err error) { done <- err })
	err := <-done
	if errors.Is(err, badger.ErrConflict) {
		return errConflict
	}
	return err
}

func (e *badgerEngine) wipe(_ context.Context, newFeedID string) error {
	if err := e.db.DropAll(); err != nil {
		return fmt.Errorf("kvstore: wipe badger: %w", err)
	}
	return e.db.Update(func(t *badger.Txn) error { return t.Set([]byte(metaFeed), []byte(newFeedID)) })
}

func isTxnTooBig(err error) bool { return errors.Is(err, badger.ErrTxnTooBig) }
