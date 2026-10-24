package kvstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
	"github.com/paularlott/quisora/internal/model"
)

// BadgerOptions tunes the Badger engine; the zero value is a sensible production default.
type BadgerOptions struct {
	// NoSync disables fsync on commit (faster, may lose the last writes on a crash). Default: fsync every commit
	// (concurrent record writes share commits, see Group).
	NoSync bool
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
	mu   sync.Mutex // held from seq assignment until the commit is enqueued, so seq order == commit order
	seq  uint64
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
		go e.gcLoop(gc)
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
			feedID = model.NewID()
			if err := t.Set([]byte(metaFeed), []byte(feedID)); err != nil {
				return err
			}
		default:
			return err
		}
		if it, err := t.Get([]byte(metaSeq)); err == nil {
			b, err := it.ValueCopy(nil)
			if err != nil || len(b) != 8 {
				return fmt.Errorf("kvstore: corrupt %s", metaSeq)
			}
			e.seq = binary.BigEndian.Uint64(b)
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
	})
	return feedID, err
}

func (e *badgerEngine) gcLoop(every time.Duration) {
	defer e.wg.Done()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			for e.db.RunValueLogGC(0.5) == nil {
			}
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

func (e *badgerEngine) Get(_ context.Context, key string) ([]byte, error) {
	var out []byte
	err := e.db.View(func(t *badger.Txn) error {
		var err error
		out, err = getVal(t, key)
		return err
	})
	return out, err
}

// view runs fn in a read transaction.
func (e *badgerEngine) view(fn func(t *badger.Txn) error) error { return e.db.View(fn) }

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
type badgerSnapshot struct {
	t *badger.Txn
}

var errReadOnly = errors.New("kvstore: snapshot is read-only")

func (b *badgerSnapshot) Get(_ context.Context, key string) ([]byte, error) { return getVal(b.t, key) }
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
	return e.gc.submit(ctx, route(kind, id), fn)
}

func (e *badgerEngine) Update(ctx context.Context, fn func(tx txn) error) error {
	return retry(ctx, func() error {
		b := e.newBatch()
		b.begin()
		if err := fn(b); err != nil {
			b.t.Discard()
			return err
		}
		return b.commit()
	})
}

type feedOp struct {
	recKey string
	body   []byte
	entry  string
	oldSeq uint64
}

// pendingSeq marks the sequence number in the header of a record written earlier in the same, not yet committed,
// transaction: the low bits are the index of that write's feed operation, resolved to the real number at commit.
// A later operation of the transaction that rewrites the record passes it on as oldSeq.
const pendingSeq = uint64(1) << 63

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
// commit, so each operation reads what the operations before it wrote (including records written through Feed,
// whose sequence numbers are only assigned at commit), and an operation that fails is rolled back (rollback)
// without touching the others.
type badgerBatch struct {
	e      *badgerEngine
	t      *badger.Txn
	reads  map[string][]byte // values read from the transaction's snapshot (nil = absent)
	writes map[string]bwrite // buffered writes
	feeds  []feedOp
	undo   []undoEntry // writes of the running operation, newest last
	mark   int         // len(feeds) when the running operation began
	rerr   error       // a read error met by an operation that could not return it (Add); fails the commit
}

func (e *badgerEngine) newBatch() *badgerBatch {
	return &badgerBatch{e: e, t: e.db.NewTransaction(true)}
}

// begin starts an operation: its writes can be rolled back until the next begin.
func (b *badgerBatch) begin() {
	b.undo = b.undo[:0]
	b.mark = len(b.feeds)
}

// rollback drops every write of the running operation.
func (b *badgerBatch) rollback() {
	for i := len(b.undo) - 1; i >= 0; i-- {
		if u := b.undo[i]; u.had {
			b.writes[u.key] = u.prev
		} else {
			delete(b.writes, u.key)
		}
	}
	clear(b.feeds[b.mark:])
	b.feeds = b.feeds[:b.mark]
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

// Feed buffers the record (readable by later operations, with a pending sequence number) and its feed entry. A key
// written through Feed must not also be written with Set or Delete.
func (b *badgerBatch) Feed(recKey string, body []byte, entry string, oldSeq uint64) {
	if body == nil {
		b.put(recKey, bwrite{del: true})
	} else {
		binary.BigEndian.PutUint64(body, pendingSeq|uint64(len(b.feeds)))
		b.put(recKey, bwrite{val: body})
	}
	b.feeds = append(b.feeds, feedOp{recKey, body, entry, oldSeq})
}

func (b *badgerBatch) empty() bool { return len(b.writes) == 0 && len(b.feeds) == 0 }

// fedSet returns a test for the keys this batch writes through Feed.
func (b *badgerBatch) fedSet() func(string) bool {
	if len(b.feeds) <= 8 {
		return func(k string) bool {
			for i := range b.feeds {
				if b.feeds[i].recKey == k {
					return true
				}
			}
			return false
		}
	}
	m := make(map[string]struct{}, len(b.feeds))
	for i := range b.feeds {
		m[b.feeds[i].recKey] = struct{}{}
	}
	return func(k string) bool { _, ok := m[k]; return ok }
}

// commit moves the buffered writes into the Badger transaction and commits it. Feed operations are applied under
// the engine mutex, in order, assigning sequence numbers in enqueue order (which Badger preserves as commit order);
// then it waits until the commit is durable (fsync with SyncWrites). The Badger transaction is always finished.
func (b *badgerBatch) commit() error {
	t, e := b.t, b.e
	if b.rerr != nil {
		t.Discard()
		return b.rerr
	}
	if b.empty() {
		t.Discard()
		return nil
	}
	fed := b.fedSet()
	for k, w := range b.writes {
		if fed(k) {
			continue
		}
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
	if len(b.feeds) > 0 {
		e.mu.Lock()
		seq := atomic.LoadUint64(&e.seq)
		var buf [16]uint64
		assigned := buf[:0]
		if len(b.feeds) > len(buf) {
			assigned = make([]uint64, 0, len(b.feeds))
		}
		assigned = assigned[:len(b.feeds)]
		var err error
		note := func(e error) {
			if err == nil {
				err = e
			}
		}
		for i, f := range b.feeds {
			old := f.oldSeq
			if old&pendingSeq != 0 { // written earlier in this batch: the number it was just given (0 if deleted)
				old = assigned[old&^pendingSeq]
			}
			if old > 0 {
				note(t.Delete(memberKey(feedBkt, seqMember(old, f.entry))))
			}
			if f.body == nil {
				note(t.Delete([]byte(f.recKey)))
				continue
			}
			seq++
			assigned[i] = seq
			binary.BigEndian.PutUint64(f.body, seq)
			note(t.Set([]byte(f.recKey), f.body))
			note(t.Set(memberKey(feedBkt, seqMember(seq, f.entry)), nil))
		}
		note(t.Set([]byte(metaSeq), binary.BigEndian.AppendUint64(nil, seq)))
		if err != nil {
			e.mu.Unlock()
			t.Discard()
			return err
		}
		atomic.StoreUint64(&e.seq, seq)
		t.CommitWith(func(err error) { done <- err })
		e.mu.Unlock()
	} else {
		t.CommitWith(func(err error) { done <- err })
	}
	err := <-done
	if errors.Is(err, badger.ErrConflict) {
		return errConflict
	}
	return err
}

func (e *badgerEngine) wipe(_ context.Context, newFeedID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.db.DropAll(); err != nil {
		return fmt.Errorf("kvstore: wipe badger: %w", err)
	}
	err := e.db.Update(func(t *badger.Txn) error {
		if err := t.Set([]byte(metaFeed), []byte(newFeedID)); err != nil {
			return err
		}
		return t.Set([]byte(metaSeq), binary.BigEndian.AppendUint64(nil, 0))
	})
	if err != nil {
		return err
	}
	atomic.StoreUint64(&e.seq, 0)
	return nil
}

func isTxnTooBig(err error) bool { return errors.Is(err, badger.ErrTxnTooBig) }
