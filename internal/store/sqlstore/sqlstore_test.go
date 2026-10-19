package sqlstore

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

	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

// dialects lists the databases to test. Server databases are skipped unless their DSN variable is set (see
// scripts/test-dbs.sh); each factory call creates a fresh database and drops it on cleanup.
var dialects = []struct {
	name, env string
}{
	{"sqlite", ""},
	{"postgres", "QUISORA_TEST_POSTGRES_DSN"},
	{"mysql", "QUISORA_TEST_MYSQL_DSN"},
	{"mariadb", "QUISORA_TEST_MARIADB_DSN"},
}

var dbCounter atomic.Int64

func factory(name, env string) storetest.Factory { return factoryFeed(name, env, true) }

func factoryFeed(name, env string, feed bool) storetest.Factory {
	return func(t testing.TB) store.Store {
		t.Helper()
		ctx := context.Background()
		if name == "sqlite" {
			s, err := Open(ctx, Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "quisora.db"), Feed: feed})
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		admin := os.Getenv(env)
		db := fmt.Sprintf("qsr_t_%s_%d", strings.ReplaceAll(uuid.NewString()[:8], "-", ""), dbCounter.Add(1))
		dsn := createDatabase(t, name, admin, db)
		s, err := Open(ctx, Config{Driver: name, DSN: dsn, Feed: feed})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
}

// createDatabase creates database db through the admin DSN, registers its removal and returns a DSN for it.
func createDatabase(t testing.TB, driver, admin, db string) string {
	t.Helper()
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
	t.Cleanup(func() {
		defer sdb.Close()
		q := "DROP DATABASE " + db
		if driver == "postgres" {
			q += " WITH (FORCE)"
		}
		if _, err := sdb.Exec(q); err != nil {
			t.Logf("drop %s: %v", db, err)
		}
	})
	return dsn
}

func TestConformance(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			if d.env != "" && os.Getenv(d.env) == "" {
				t.Skipf("%s not set", d.env)
			}
			storetest.Run(t, factory(d.name, d.env))
		})
		t.Run(d.name+"-nofeed", func(t *testing.T) {
			if d.env != "" && os.Getenv(d.env) == "" {
				t.Skipf("%s not set", d.env)
			}
			storetest.RunWithOptions(t, factoryFeed(d.name, d.env, false), storetest.Options{NoFeed: true})
		})
	}
}

func BenchmarkStore(b *testing.B) {
	for _, d := range dialects {
		for _, feed := range []bool{true, false} {
			name := d.name
			if !feed {
				name += "-nofeed"
			}
			b.Run(name, func(b *testing.B) {
				if d.env != "" && os.Getenv(d.env) == "" {
					b.Skipf("%s not set", d.env)
				}
				storetest.Bench(b, factoryFeed(d.name, d.env, feed))
			})
		}
	}
}

// Reopening an existing database keeps its data and feed id and does not re-run migrations.
func TestReopen(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			if d.env != "" && os.Getenv(d.env) == "" {
				t.Skipf("%s not set", d.env)
			}
			ctx := context.Background()
			var cfg Config
			if d.name == "sqlite" {
				cfg = Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "quisora.db"), Feed: true}
			} else {
				cfg = Config{Driver: d.name, DSN: createDatabase(t, d.name, os.Getenv(d.env), fmt.Sprintf("qsr_r_%d_%d", time.Now().UnixNano()%1e9, dbCounter.Add(1))), Feed: true}
			}
			s, err := Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			rec := &store.Record{Kind: "key", ID: "k1", Version: store.Clock.Now(), Origin: "x", Scope: "s", Data: []byte("d"),
				Fields: map[string]any{"alg": "ES256"}}
			if err := s.Put(ctx, rec); err != nil {
				t.Fatal(err)
			}
			feed := s.FeedID()
			s.Close()
			s, err = Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if s.FeedID() != feed {
				t.Fatal("feed id changed on reopen")
			}
			if got, err := s.Get(ctx, "key", "k1"); err != nil || string(got.Data) != "d" || got.Fields["alg"] != "ES256" {
				t.Fatalf("reopen lost data: %v %+v", err, got)
			}
			if ch, _, _ := s.Changes(ctx, 0, 0); len(ch) != 1 {
				t.Fatal("feed lost on reopen")
			}
		})
	}
}

// Two stores on one server database (as two processes would be) must agree on unique values and optimistic
// concurrency.
func TestSharedDatabase(t *testing.T) {
	for _, d := range dialects[1:] {
		for _, feed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/feed=%v", d.name, feed), func(t *testing.T) {
				if os.Getenv(d.env) == "" {
					t.Skipf("%s not set", d.env)
				}
				ctx := context.Background()
				dsn := createDatabase(t, d.name, os.Getenv(d.env), fmt.Sprintf("qsr_m_%d_%d", time.Now().UnixNano()%1e9, dbCounter.Add(1)))
				var ss [2]*Store
				for i := range ss {
					s, err := Open(ctx, Config{Driver: d.name, DSN: dsn, Feed: feed})
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					ss[i] = s
				}
				mk := func(id, email string) *store.Record {
					return &store.Record{Kind: "user", ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "o", Unique: []string{email},
						Data: []byte("x"), Fields: map[string]any{"username": id}}
				}
				var wg sync.WaitGroup
				var won, conflicts, other atomic.Int32
				for i := range 40 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						err := ss[i%2].CompareAndPut(ctx, mk(fmt.Sprintf("u%d", i), "same@example.com"), 0)
						switch {
						case err == nil:
							won.Add(1)
						case errors.Is(err, store.ErrConflict):
							conflicts.Add(1)
						default:
							other.Add(1)
							t.Error(err)
						}
					}()
				}
				wg.Wait()
				if won.Load() != 1 || conflicts.Load() != 39 {
					t.Fatalf("unique across stores: won=%d conflicts=%d other=%d", won.Load(), conflicts.Load(), other.Load())
				}
				// Optimistic concurrency across stores: one winner per version.
				base := mk("cas", "cas@example.com")
				if err := ss[0].Put(ctx, base); err != nil {
					t.Fatal(err)
				}
				var cas atomic.Int32
				for i := range 20 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err := ss[i%2].CompareAndPut(ctx, mk("cas", "cas@example.com"), base.Version); err == nil {
							cas.Add(1)
						} else if !errors.Is(err, store.ErrStale) {
							t.Error(err)
						}
					}()
				}
				wg.Wait()
				if cas.Load() != 1 {
					t.Fatalf("cas across stores: %d winners", cas.Load())
				}
			})
		}
	}
}

func TestWipe(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			if d.env != "" && os.Getenv(d.env) == "" {
				t.Skipf("%s not set", d.env)
			}
			ctx := context.Background()
			s := factory(d.name, d.env)(t).(*Store)
			defer s.Close()
			mk := func(id, email string) *store.Record {
				return &store.Record{Kind: "user", ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "o", Unique: []string{email},
					Data: []byte("x"), Fields: map[string]any{"username": id}}
			}
			for i := range 5 {
				if err := s.Put(ctx, mk(fmt.Sprint("u", i), fmt.Sprintf("e%d@x.com", i))); err != nil {
					t.Fatal(err)
				}
			}
			feed := s.FeedID()
			if err := s.Wipe(ctx); err != nil {
				t.Fatal(err)
			}
			if s.FeedID() == feed || s.FeedID() == "" {
				t.Fatal("feed id must change")
			}
			if _, err := s.Get(ctx, "user", "u0"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("get after wipe: %v", err)
			}
			if r, err := s.List(ctx, "user", store.ListQuery{}); err != nil || r.Total != 0 || len(r.Records) != 0 {
				t.Fatalf("list after wipe: %v %+v", err, r)
			}
			if n, _ := s.Count(ctx, "user", ""); n != 0 {
				t.Fatalf("count %d", n)
			}
			if ch, _, _ := s.Changes(ctx, 0, 0); len(ch) != 0 {
				t.Fatal("changes after wipe")
			}
			if err := s.Put(ctx, mk("n1", "e0@x.com")); err != nil {
				t.Fatalf("unique value must be free again: %v", err)
			}
			if ch, _, _ := s.Changes(ctx, 0, 0); len(ch) != 1 || ch[0].Seq != 1 {
				t.Fatalf("new feed starts at seq 1: %+v", ch)
			}
			// The new feed id is persisted.
			var got string
			if err := s.wdb.QueryRow("SELECT feed_id FROM " + feedTable).Scan(&got); err != nil || got != s.FeedID() {
				t.Fatalf("persisted feed id %q: %v", got, err)
			}
		})
	}
}

// Without the feed there is no write mutex or counter row: heavy concurrent writers with overlapping unique
// values, on two stores, must neither deadlock nor lose updates.
func TestNoFeedConcurrency(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			if d.env != "" && os.Getenv(d.env) == "" {
				t.Skipf("%s not set", d.env)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			var cfg Config
			if d.name == "sqlite" {
				cfg = Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "quisora.db")}
			} else {
				cfg = Config{Driver: d.name, DSN: createDatabase(t, d.name, os.Getenv(d.env), fmt.Sprintf("qsr_c_%d_%d", time.Now().UnixNano()%1e9, dbCounter.Add(1))), MaxOpenConns: 8}
			}
			var ss [2]*Store
			for i := range ss {
				s, err := Open(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				ss[i] = s
			}
			if _, _, err := ss[0].Changes(ctx, 0, 0); !errors.Is(err, ErrFeedDisabled) {
				t.Fatalf("Changes: %v", err)
			}
			mk := func(id string, uniq ...string) *store.Record {
				return &store.Record{Kind: "user", ID: id, Version: store.Clock.Now(), Origin: "n", Scope: "o", Unique: uniq,
					Data: []byte("x"), Fields: map[string]any{"username": id}}
			}
			var wg sync.WaitGroup
			var wins atomic.Int32
			const rows = 4
			for r := range rows {
				if err := ss[0].Put(ctx, mk(fmt.Sprint("r", r), fmt.Sprint("a", r), fmt.Sprint("b", r))); err != nil {
					t.Fatal(err)
				}
			}
			for g := range 64 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					s := ss[g%2]
					for i := range 20 {
						id := fmt.Sprint("r", (g+i)%rows)
						switch i % 3 {
						case 0: // crosswise unique values on shared rows, plus fresh ones
							err := s.Put(ctx, mk(fmt.Sprintf("n%d-%d", g, i), fmt.Sprint("b", i%rows), fmt.Sprint("a", i%rows), fmt.Sprintf("x%d-%d", g, i)))
							if err != nil && !errors.Is(err, store.ErrConflict) {
								t.Error(err)
							}
						case 1: // CAS on the same row
							cur, err := s.Get(ctx, "user", id)
							if err != nil {
								t.Error(err)
								return
							}
							err = s.CompareAndPut(ctx, mk(id, fmt.Sprint("a", (g+i)%rows+10*g+i), "b"+id), cur.Version)
							if err == nil {
								wins.Add(1)
							} else if !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrConflict) {
								t.Error(err)
							}
						default:
							if err := s.Put(ctx, mk(fmt.Sprintf("m%d-%d", g, i), fmt.Sprintf("m%d-%d", g, i))); err != nil {
								t.Error(err)
							}
						}
					}
				}()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("writers did not finish: deadlock")
			}
			if wins.Load() == 0 {
				t.Fatal("no CAS ever won")
			}
		})
	}
}

func TestWipeNoFeed(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			if d.env != "" && os.Getenv(d.env) == "" {
				t.Skipf("%s not set", d.env)
			}
			ctx := context.Background()
			s := factoryFeed(d.name, d.env, false)(t).(*Store)
			defer s.Close()
			r := &store.Record{Kind: "user", ID: "a", Version: store.Clock.Now(), Scope: "o", Unique: []string{"u"}, Data: []byte("x")}
			if err := s.Put(ctx, r); err != nil {
				t.Fatal(err)
			}
			feed := s.FeedID()
			if err := s.Wipe(ctx); err != nil || s.FeedID() == feed {
				t.Fatalf("wipe: %v", err)
			}
			if n, _ := s.Count(ctx, "user", ""); n != 0 {
				t.Fatal("not empty")
			}
			r2 := &store.Record{Kind: "user", ID: "b", Version: store.Clock.Now(), Scope: "o", Unique: []string{"u"}, Data: []byte("x")}
			if err := s.Put(ctx, r2); err != nil {
				t.Fatal(err)
			}
		})
	}
}
