package kvstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

var bg = context.Background()

func badgerFactory(t testing.TB) store.Store {
	s, err := OpenBadger(context.Background(), t.TempDir(), BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// openBadger opens a store with options o in a new directory, closed when the test ends.
func openBadger(t testing.TB, o BadgerOptions) *Store {
	t.Helper()
	s, err := OpenBadger(context.Background(), t.TempDir(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// record returns a record of kind in scope "sc" with a fresh version, expiring at expires (zero: never).
func record(kind model.Kind, id string, expires time.Time, uniq ...string) *store.Record {
	return &store.Record{Kind: kind, ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "sc", Unique: uniq,
		Data: []byte("d"), Expires: expires}
}

// countingReads counts the records an engine loads (the record keys of its MGet calls; the two counter keys a total
// reads are not records) and the scope-wide ranges it is asked to count (Page calls without NoTotal over a whole
// bucket or scope range, whose From is empty or a scope prefix: a count of a run of equal sort values, bounded by
// the offset, is not one): what a listing costs beyond its index reads.
type countingReads struct {
	engine
	records int
	counted int
}

func (e *countingReads) MGet(ctx context.Context, keys []string) ([][]byte, error) {
	for _, k := range keys {
		if strings.HasPrefix(k, "rec/") {
			e.records++
		}
	}
	return e.engine.MGet(ctx, keys)
}

func (e *countingReads) Page(ctx context.Context, bucket string, p pageQuery, nowMs int64) ([]string, int, error) {
	if !p.NoTotal && (p.From == "" || strings.HasSuffix(p.From, "/")) {
		e.counted++
	}
	return e.engine.Page(ctx, bucket, p, nowMs)
}
