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
	// Page returns members of bucket that are live at nowMs, skipping offset and returning at most limit
	// (limit <= 0: all), plus the number of live members.
	Page(ctx context.Context, bucket string, reverse bool, offset, limit int, nowMs int64) (members []string, total int, err error)
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
