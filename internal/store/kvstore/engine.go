package kvstore

import (
	"context"
	"errors"
)

// engine is the small ordered-KV interface the store logic is written against.
//
// Besides plain keys it offers ordered sets: a bucket holds members that iterate in byte order. Members may carry
// an expiry (unix ms) so a bucket can be counted and paged without loading the records it indexes.
//
// Reads outside a transaction are individually consistent only. Update runs fn as an optimistic transaction: every
// key fn reads is validated at commit and fn is re-run (so it must be free of side effects) when one changed.
type engine interface {
	// Get returns the value of key, or nil when absent. Stored values are never empty.
	Get(ctx context.Context, key string) ([]byte, error)
	// MGet returns the values of keys in order (nil for absent keys).
	MGet(ctx context.Context, keys []string) ([][]byte, error)
	// Page returns the members of bucket that p selects and that are live at nowMs, plus how many there are in all.
	Page(ctx context.Context, bucket string, p pageQuery, nowMs int64) (members []string, total int, err error)
	// Count returns the number of members of bucket that are live at nowMs.
	Count(ctx context.Context, bucket string, nowMs int64) (int, error)
	// Range returns up to limit members (all when limit <= 0) with from <= member <= to in ascending order,
	// regardless of expiry. An empty to means unbounded.
	Range(ctx context.Context, bucket, from, to string, limit int) ([]string, error)
	// Update runs fn in a transaction. Errors returned by fn abort the transaction and are returned as is.
	Update(ctx context.Context, fn func(tx txn) error) error
	// wipe removes every key of the store, restarts the sequence and stores newFeedID.
	wipe(ctx context.Context, newFeedID string) error
	Close() error
}

// pageQuery selects a page of an ordered set: the live members within [From, To) ("" = no bound on that side) that
// are not in Skip, in byte order (Reverse: descending), leaving out the first Offset of them and returning at most
// Limit (Limit <= 0: all). The total a page comes with counts every member selected, ignoring Offset and Limit,
// unless NoTotal says the caller has no use for it (the store keeps counters: see counterKey): the engine then
// stops at the end of the page instead of visiting the rest of the range, and the total it returns means nothing.
// Skip is an exclusion set (nil: none): a listing that leaves out the records of a small indexed set pages the
// scope's index with them skipped, instead of loading the scope.
type pageQuery struct {
	From, To string
	Skip     map[string]struct{}
	Reverse  bool
	Offset   int
	Limit    int
	NoTotal  bool
}

// grouper is implemented by engines that commit concurrent record writes together (group commit). Group has the
// semantics of Update for one write of the record kind/id (fn may run more than once, its error is returned as is,
// it returns once the write is durable); writes of one record are applied in the order they were submitted.
type grouper interface {
	Group(ctx context.Context, kind, id string, fn func(tx txn) error) error
}

// txn buffers writes until commit; reads see the transaction's own writes.
type txn interface {
	Get(key string) ([]byte, error)
	Set(key string, val []byte)
	Delete(key string)
	SetAdd(bucket, member string, expMs int64)
	SetDel(bucket, member string)
	// Add adds delta to the integer counter at key (absent: 0), deleting it when it reaches 0. Badger reads the key
	// (so concurrent transactions adding to one counter conflict and one retries); Valkey increments it in place
	// without a read. A counter is not read in the transaction that adds to it. counterOf decodes one.
	Add(key string, delta int64)
	// Feed writes the record at recKey and registers it in the change feed under a fresh sequence number assigned
	// in commit order: body must start with seqHeader reserved bytes, which are overwritten with the sequence
	// number (big endian). The feed entry of the record's previous sequence (oldSeq, 0 if none) is removed. A nil
	// body deletes the record and its feed entry instead and consumes no sequence number.
	// A key written with Feed is not also written with Set or Delete in the same transaction. Badger: a later read of
	// recKey in the transaction returns body with a placeholder sequence, resolved at commit when passed as oldSeq.
	Feed(recKey string, body []byte, entry string, oldSeq uint64)
}

const (
	seqHeader = 8
	feedBkt   = "seq"
	metaSeq   = "meta/seq"
	metaFeed  = "meta/feed_id"
	// maxRetries bounds optimistic transaction retries.
	maxRetries = 100
)

// errConflict is returned by an engine commit when a read key changed; Update retries.
var errConflict = errors.New("kvstore: transaction conflict")
