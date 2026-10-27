//go:build faults

package sqlstore

// The tests that use the hook the faults build tag adds (faults.go): run with -tags faults.

import (
	"context"
	"database/sql"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// How the partition writes commit, per database: unsynced for applies, imports and purges, synced for the state writes,
// and the SQLite connection always back at FULL afterwards.
func TestPartitionSyncMode(t *testing.T) {
	ctx := context.Background()
	// SQLite and PostgreSQL have a per-transaction setting; the MySQL family is always durable
	forEachDialect(t, dialects[:2], func(t *testing.T, d testDialect) {
		s, _ := openTest(t, d.name, d.env, 4)
		defer s.Close()
		var mu sync.Mutex
		var seen []string
		partitionTxHook = func(ctx context.Context, tx *sql.Tx, unsynced bool) {
			var v string
			var err error
			if d.name == "sqlite" {
				var n int
				err = tx.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&n)
				v = map[int]string{0: "off", 1: "normal", 2: "full"}[n]
			} else {
				err = tx.QueryRowContext(ctx, "SHOW synchronous_commit").Scan(&v)
			}
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if unsynced {
				seen = append(seen, "unsynced:"+v)
			} else {
				seen = append(seen, "synced:"+v)
			}
		}
		defer func() { partitionTxHook = nil }()
		u, _ := store.Encode(&model.User{OrgID: "o", Username: "sm", Role: model.RoleUser})
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(s.ApplyPartition(ctx, 1, []*store.Record{u}, store.PartitionPos{Seq: 1}))
		must(s.SetPartitionPending(ctx, 1, 2, []byte("x")))
		must(s.ImportPartition(ctx, 1, nil, store.PartitionPos{Seq: 3}, store.ImportStep{First: true, Final: true}))
		_, err := s.PurgePartition(ctx, 1, 2)
		must(err)
		must(s.SetPartitionPromised(ctx, 1, store.PartitionEpoch{Counter: 1}))
		mu.Lock()
		got := append([]string(nil), seen...)
		mu.Unlock()
		off, on := "unsynced:normal", "synced:full"
		if d.name == "postgres" {
			off, on = "unsynced:off", "synced:"+got[1][len("synced:"):] // the server's own setting
		}
		want := []string{off, on, off, off, on}
		for i := range want {
			if i >= len(got) || got[i] != want[i] {
				t.Fatalf("commit modes: %v, want %v", got, want)
			}
		}
		if d.name == "sqlite" { // the writer connection is back at FULL
			var n int
			if err := s.wdb.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&n); err != nil || n != 2 {
				t.Fatalf("writer synchronous after a partition write: %d %v", n, err)
			}
			// ... and an ordinary write is not unsynced either
			partitionTxHook = nil
			must(s.Put(ctx, mustRec(t, "o", "after")))
			if err := s.wdb.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&n); err != nil || n != 2 {
				t.Fatalf("writer synchronous after a put: %d %v", n, err)
			}
		}
	})
}
