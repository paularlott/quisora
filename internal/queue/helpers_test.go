package queue

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

// backend is a store the queue is tested on. open returns a store on a database of its own, and again (nil where a
// database takes one process only) opens another store on the same database: a second node sharing it.
type backend struct {
	name string
	open func(t *testing.T) (st store.Store, again func() store.Store)
}

// backends are every store: memory, BadgerDB and SQLite always, the database servers when their test DSNs are set
// (scripts/test-dbs.sh). The servers' tests share one database per server, each test's queues apart by their node
// ids (every listing and count of a queue is of one node's items).
func backends() []backend {
	out := []backend{
		{"memory", func(t *testing.T) (store.Store, func() store.Store) {
			st := memstore.New()
			return st, func() store.Store { return st }
		}},
		{"badgerdb", func(t *testing.T) (store.Store, func() store.Store) {
			st, err := kvstore.OpenBadger(context.Background(), filepath.Join(t.TempDir(), "badger"), kvstore.BadgerOptions{NoSync: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			return st, nil
		}},
		{"sqlite", func(t *testing.T) (store.Store, func() store.Store) {
			dsn := filepath.Join(t.TempDir(), "quisora.db")
			return openSQL(t, "sqlite", dsn), func() store.Store { return openSQL(t, "sqlite", dsn) }
		}},
	}
	for _, s := range []struct{ driver, env string }{{"postgres", "QUISORA_TEST_POSTGRES_DSN"},
		{"mysql", "QUISORA_TEST_MYSQL_DSN"}, {"mariadb", "QUISORA_TEST_MARIADB_DSN"}} {
		if admin := os.Getenv(s.env); admin != "" {
			out = append(out, backend{s.driver, func(t *testing.T) (store.Store, func() store.Store) {
				dsn := serverDatabase(t, s.driver, admin)
				return openSQL(t, s.driver, dsn), func() store.Store { return openSQL(t, s.driver, dsn) }
			}})
		}
	}
	return out
}

// eachBackend runs fn once per backend.
func eachBackend(t *testing.T, fn func(t *testing.T, b backend)) {
	for _, b := range backends() {
		t.Run(b.name, func(t *testing.T) { fn(t, b) })
	}
}

func openSQL(t *testing.T, driver, dsn string) store.Store {
	t.Helper()
	st, err := sqlstore.Open(context.Background(), sqlstore.Config{Driver: driver, DSN: dsn, MaxOpenConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// servers holds the database of each server (driver -> DSN), made by the first test that needs it and dropped by
// TestMain.
var servers = struct {
	sync.Mutex
	dsn   map[string]string
	drops []func()
}{dsn: map[string]string{}}

func TestMain(m *testing.M) {
	code := m.Run()
	for _, drop := range servers.drops {
		drop()
	}
	os.Exit(code)
}

// serverDatabase returns the DSN of this run's database on the server of driver (admin: its admin DSN).
func serverDatabase(t *testing.T, driver, admin string) string {
	t.Helper()
	servers.Lock()
	defer servers.Unlock()
	if dsn, ok := servers.dsn[driver]; ok {
		return dsn
	}
	db := "qsr_q_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	var sdb *sql.DB
	var err error
	var dsn string
	if driver == "postgres" {
		sdb, err = sql.Open("pgx", admin)
		u, _ := url.Parse(admin)
		u.Path = "/" + db
		dsn = u.String()
	} else {
		cfg, perr := mysql.ParseDSN(admin)
		if perr != nil {
			t.Fatal(perr)
		}
		sdb, err = sql.Open("mysql", cfg.FormatDSN())
		cfg.DBName = db
		dsn = cfg.FormatDSN()
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdb.Exec("CREATE DATABASE " + db); err != nil {
		t.Fatal(err)
	}
	servers.drops = append(servers.drops, func() {
		q := "DROP DATABASE " + db
		if driver == "postgres" {
			q += " WITH (FORCE)"
		}
		_, _ = sdb.Exec(q)
		_ = sdb.Close()
	})
	servers.dsn[driver] = dsn
	return dsn
}

func sealer(t *testing.T, keys ...[]byte) *secure.Sealer {
	t.Helper()
	s, err := secure.NewKeyring(keys[0], keys[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// options are a test queue's: a node of its own on st, a new master key, room for 1000 items.
func options(t *testing.T, st store.Store, deliver func(context.Context, string) error) Options[string] {
	return Options[string]{Name: "test", Log: logger.NewNullLogger(), Store: st, Node: model.NewID(),
		Sealer: sealer(t, secure.RandomBytes(32)), Binding: "test/queue", Max: 1000, Deliver: deliver}
}

// start opens a queue of o, closed when the test ends.
func start(t *testing.T, o Options[string]) *Queue[string] {
	t.Helper()
	q := Open(o)
	t.Cleanup(q.Close)
	return q
}

// pass starts what is due on a queue whose scheduler is not running, waits for those deliveries to end, and returns
// when the next item waiting is due (zero: none), as the scheduler would learn it from the wake-up each delivery ends
// with.
func pass[T any](q *Queue[T], ctx context.Context) time.Time {
	q.dispatch(ctx)
	q.deliveries.Wait()
	return q.dispatch(ctx)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func addAll(t *testing.T, q *Queue[string], items ...string) {
	t.Helper()
	for _, it := range items {
		if err := q.Add(it, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
}

// stored returns q's items as the store holds them, oldest first.
func stored[T any](t *testing.T, q *Queue[T]) []*model.QueueItem {
	t.Helper()
	items, _, err := q.items.List(context.Background(), store.ListQuery{Scope: q.scope})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// only returns q's one stored item.
func only[T any](t *testing.T, q *Queue[T]) *model.QueueItem {
	t.Helper()
	items := stored(t, q)
	if len(items) != 1 {
		t.Fatalf("%d items stored, want 1", len(items))
	}
	return items[0]
}

// open returns what item it holds, opened with q's keys.
func open[T any](q *Queue[T], it *model.QueueItem) (string, error) {
	b, err := q.o.Sealer.OpenFor(q.o.Binding, it.Sealed)
	return string(b), err
}

// sink records delivered items; fail makes the next deliveries fail.
type sink struct {
	mu   sync.Mutex
	got  []string
	fail atomic.Int32
	n    atomic.Int32
}

func (s *sink) deliver(_ context.Context, it string) error {
	s.n.Add(1)
	if s.fail.Load() > 0 {
		s.fail.Add(-1)
		return errors.New("down")
	}
	s.mu.Lock()
	s.got = append(s.got, it)
	s.mu.Unlock()
	return nil
}

func (s *sink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.got) }

// keyOf is the fairness key of the test items: the first letter ("A1" is of key "A").
func keyOf(s string) string { return s[:1] }

// gate is a Deliver that holds every item until it is released, and records which are being delivered at once.
type gate struct {
	release chan struct{}
	mu      sync.Mutex
	perKey  map[string]int
	total   int
	maxKey  map[string]int
	maxAll  int
	started chan string
	done    atomic.Int32
}

func newGate() *gate {
	return &gate{release: make(chan struct{}), perKey: map[string]int{}, maxKey: map[string]int{}, started: make(chan string, 100)}
}

func (g *gate) deliver(ctx context.Context, it string) error {
	g.mu.Lock()
	g.perKey[keyOf(it)]++
	g.total++
	g.maxKey[keyOf(it)] = max(g.maxKey[keyOf(it)], g.perKey[keyOf(it)])
	g.maxAll = max(g.maxAll, g.total)
	g.mu.Unlock()
	g.started <- it
	defer func() {
		g.mu.Lock()
		g.perKey[keyOf(it)]--
		g.total--
		g.mu.Unlock()
	}()
	select {
	case <-g.release:
	case <-ctx.Done(): // the queue is closing
		return ctx.Err()
	}
	g.done.Add(1)
	return nil
}

func (g *gate) inFlight() int { g.mu.Lock(); defer g.mu.Unlock(); return g.total }

// next waits for the next delivery to begin, and returns its item.
func (g *gate) next(t *testing.T) string {
	t.Helper()
	select {
	case it := <-g.started:
		return it
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was delivered: a slow delivery holds the queue")
		return ""
	}
}

// faulty is a store that refuses, while refuse is set, the rewrites of queued items (CompareAndPut: a re-seal, a
// retry, an end) and, while blind is set, their listings: a store that fails.
type faulty struct {
	store.Store
	refuse, blind atomic.Bool
}

func (s *faulty) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if rec.Kind == model.KindQueue && expect != 0 && s.refuse.Load() {
		return fmt.Errorf("%w: refused by the test", store.ErrUnavailable)
	}
	return s.Store.CompareAndPut(ctx, rec, expect)
}

func (s *faulty) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindQueue && s.blind.Load() {
		return nil, fmt.Errorf("%w: refused by the test", store.ErrUnavailable)
	}
	return s.Store.List(ctx, kind, q)
}

// reads is a store that counts the queued items it reads (listed or got): what the scheduler costs.
type reads struct {
	store.Store
	n atomic.Int64
}

func (s *reads) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	res, err := s.Store.List(ctx, kind, q)
	if err == nil && kind == model.KindQueue {
		s.n.Add(int64(len(res.Records)))
	}
	return res, err
}

func (s *reads) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindQueue {
		s.n.Add(1)
	}
	return s.Store.Get(ctx, kind, id)
}
