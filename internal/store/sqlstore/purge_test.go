package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"modernc.org/sqlite"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// commitLog records what each commit of a SQLite store's writer connection changed: per commit, the rows deleted from
// and inserted into each table ("delete qsr_link"). It reads the connection's own hooks, so it sees every transaction
// the store commits, the group committer's and the partition writes' alike.
type commitLog struct {
	mu       sync.Mutex
	cur      map[string]int
	commits  []map[string]int
	onCommit func(map[string]int) // called in the committing goroutine, inside its commit
}

func watchCommits(t *testing.T, s *Store) *commitLog {
	t.Helper()
	l := &commitLog{cur: map[string]int{}}
	conn, err := s.wdb.Conn(context.Background()) // the one writer connection
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = conn.Raw(func(dc any) error {
		h := dc.(sqlite.HookRegisterer)
		h.RegisterPreUpdateHook(func(d sqlite.SQLitePreUpdateData) {
			op := map[int32]string{9: "delete ", 18: "insert ", 23: "update "}[d.Op]
			l.mu.Lock()
			l.cur[op+d.TableName]++
			l.mu.Unlock()
		})
		h.RegisterCommitHook(func() int32 {
			l.mu.Lock()
			c, f := l.cur, l.onCommit
			l.cur = map[string]int{}
			l.commits = append(l.commits, c)
			l.mu.Unlock()
			if f != nil {
				f(c)
			}
			return 0
		})
		h.RegisterRollbackHook(func() {
			l.mu.Lock()
			l.cur = map[string]int{}
			l.mu.Unlock()
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// reset forgets the commits so far and sets the commit callback.
func (l *commitLog) reset(onCommit func(map[string]int)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.commits, l.onCommit = nil, onCommit
}

func (l *commitLog) all() []map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]map[string]int(nil), l.commits...)
}

// besideFirstBatch returns a commit callback that, at the first commit deleting rows of table, starts a Put of record
// id (of the table's kind) and waits until that Put is queued for the writer connection, which the purge holds until
// its commit ends. done receives the Put's outcome.
func besideFirstBatch(t *testing.T, s *Store, table, id string, done chan<- error) func(map[string]int) {
	var once sync.Once
	return func(c map[string]int) {
		if c["delete "+table] == 0 {
			return
		}
		once.Do(func() {
			waits := s.wdb.Stats().WaitCount
			go func() { done <- s.Put(context.Background(), record(model.KindLink, id, time.Time{})) }()
			for deadline := time.Now().Add(10 * time.Second); s.wdb.Stats().WaitCount == waits; {
				if time.Now().After(deadline) {
					t.Error("the concurrent Put never waited for the writer")
					return
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

// checkBatched checks that the commits deleted want rows of table in batches of at most batchRows, more than one, and
// that the Put started beside the first batch (besideFirstBatch) was committed before the last one: it waited for a
// batch, not for the whole purge.
func checkBatched(t *testing.T, commits []map[string]int, table string, want int) {
	t.Helper()
	deleted, batches, lastBatch, put := 0, 0, -1, -1
	for i, c := range commits {
		if n := c["delete "+table]; n > 0 {
			if n > batchRows {
				t.Errorf("one commit deleted %d rows of %s (batches of %d)", n, table, batchRows)
			}
			deleted += n
			batches++
			lastBatch = i
		}
		if c["insert "+table] > 0 {
			put = i
		}
	}
	if deleted != want || batches < 2 {
		t.Errorf("%d rows of %s deleted in %d commits, want %d in more than one", deleted, table, batches, want)
	}
	if put < 0 || put > lastBatch {
		t.Errorf("the concurrent Put was committed at commit %d, after the purge's last batch (%d): it waited for the whole purge", put, lastBatch)
	}
}

// A purge of more rows than one batch removes them all (releasing the unique values of expired records), a batch to a
// transaction, on every dialect; on SQLite each batch is its own commit, so a write made meanwhile waits for one batch,
// not the whole purge, and a cancelled context stops it between batches.
func TestPurgeInBatches(t *testing.T) {
	ctx := context.Background()
	const many = 2*batchRows + 7
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	recs := func(prefix string, n int, expires time.Time, unique bool) []store.Op {
		ops := make([]store.Op, n)
		for i := range ops {
			id := fmt.Sprintf("%s%04d", prefix, i)
			r := record(model.KindLink, id, expires)
			if unique {
				r.Unique = []string{"u/" + id}
			}
			ops[i] = store.Op{Rec: r}
		}
		return ops
	}
	// fill stores many tombstones, many expired records without unique values, batchRows+3 expired ones with, and a
	// live one with a unique value.
	fill := func(t *testing.T, s *Store) {
		t.Helper()
		live := recs("t", many, time.Time{}, false)
		for _, step := range [][]store.Op{live, recs("e", many, past, false), recs("x", batchRows+3, past, true),
			{{Rec: record(model.KindLink, "keep", future, "u/keep")}}} {
			if err := s.Tx(ctx, step); err != nil {
				t.Fatal(err)
			}
		}
		for i := range live { // deleted: tombstones
			live[i].Rec = &store.Record{Kind: model.KindLink, ID: live[i].Rec.ID, Origin: "n", Deleted: true}
		}
		if err := s.Tx(ctx, live); err != nil {
			t.Fatal(err)
		}
	}
	// tombstones applies many tombstones to partition 3, at sequence 1.
	tombstones := func(t *testing.T, s *Store) {
		t.Helper()
		tombs := make([]*store.Record, many)
		for i := range tombs {
			tombs[i] = &store.Record{Kind: model.KindLink, ID: fmt.Sprintf("p%04d", i), Version: store.Clock.Now(), Origin: "n",
				Deleted: true, Partition: "o"}
		}
		if err := s.ApplyPartition(ctx, 3, tombs, store.PartitionPos{Seq: 1}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(t *testing.T, s *Store, q string) int {
		t.Helper()
		var n int
		if err := s.wdb.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	linkTable := "qsr_" + string(model.KindLink)

	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		s, _ := openTest(t, d.name, d.env, 0)
		defer s.Close()
		fill(t, s)
		tombstones(t, s)
		sqlite := d.name == "sqlite"
		var log *commitLog
		putDone := make(chan error, 1)
		if sqlite {
			log = watchCommits(t, s)
			log.reset(besideFirstBatch(t, s, linkTable, "beside1", putDone))
		}
		n, err := s.Purge(ctx, time.Now().Add(time.Hour), time.Now())
		if want := 2*many + batchRows + 3; err != nil || n != want {
			t.Fatalf("purge: %d %v, want %d", n, err, want)
		}
		live := 1 // "keep"
		if sqlite {
			if err := <-putDone; err != nil {
				t.Fatal(err)
			}
			checkBatched(t, log.all(), linkTable, n)
			live++ // and the one put beside the purge
		}
		if left := count(t, s, "SELECT COUNT(*) FROM "+linkTable+" WHERE pseq = 0"); left != live {
			t.Errorf("%d unpartitioned rows left, want the %d live ones", left, live)
		}
		if left := count(t, s, "SELECT COUNT(*) FROM "+uniqueTable); left != 1 {
			t.Errorf("%d unique values left, want the live record's", left)
		}
		if got, err := s.GetByUnique(ctx, model.KindLink, "u/keep"); err != nil || got.ID != "keep" {
			t.Errorf("the live record: %v", err)
		}

		if sqlite {
			log.reset(besideFirstBatch(t, s, linkTable, "beside2", putDone))
		}
		n, err = s.PurgePartition(ctx, 3, 2)
		if err != nil || n != many {
			t.Fatalf("partition purge: %d %v, want %d", n, err, many)
		}
		if st, err := s.PartitionState(ctx, 3); err != nil || st.Purged != 1 {
			t.Fatalf("purge point: %d %v", st.Purged, err)
		}
		if left := count(t, s, "SELECT COUNT(*) FROM "+linkTable+" WHERE pseq > 0"); left != 0 {
			t.Errorf("%d partition tombstones left", left)
		}
		if sqlite {
			if err := <-putDone; err != nil {
				t.Fatal(err)
			}
			checkBatched(t, log.all(), linkTable, many)
		}
	})

	t.Run("CancelledBetweenBatches", func(t *testing.T) {
		s, _ := openSQLite(t)
		fill(t, s)
		log := watchCommits(t, s)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		log.reset(func(c map[string]int) {
			if c["delete "+linkTable] > 0 {
				cancel() // inside the first batch's commit: it commits, and no batch follows
			}
		})
		n, err := s.Purge(ctx, time.Now().Add(time.Hour), time.Now())
		if !errors.Is(err, context.Canceled) || !errors.Is(err, store.ErrUnavailable) || n != batchRows {
			t.Fatalf("purge cancelled in its first batch: %d %v, want %d and the cancellation", n, err, batchRows)
		}
		if left := count(t, s, "SELECT COUNT(*) FROM "+linkTable); left != 2*many+batchRows+3+1-batchRows {
			t.Fatalf("%d rows left after one batch", left)
		}
	})
}
