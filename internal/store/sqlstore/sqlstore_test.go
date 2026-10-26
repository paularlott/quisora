package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) { storetest.Run(t, factory(d.name, d.env)) })
}

func BenchmarkStore(b *testing.B) {
	for _, d := range dialects {
		b.Run(d.name, func(b *testing.B) {
			if d.env != "" && os.Getenv(d.env) == "" {
				b.Skipf("%s not set", d.env)
			}
			storetest.Bench(b, factory(d.name, d.env))
		})
	}
}

// Reopening an existing database, again and again, keeps its data and identity and does not re-run migrations.
func TestReopen(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		ctx := context.Background()
		s, dsn := openTest(t, d.name, d.env, 0)
		rec := &store.Record{Kind: "key", ID: "k1", Version: store.Clock.Now(), Origin: "x", Scope: "s", Data: []byte("d"),
			Fields: map[string]any{"alg": "ES256"}}
		if err := s.Put(ctx, rec); err != nil {
			t.Fatal(err)
		}
		feed := s.FeedID()
		s.Close()
		for range 2 {
			s, err := Open(ctx, Config{Driver: d.name, DSN: dsn})
			if err != nil {
				t.Fatal(err)
			}
			if s.FeedID() != feed {
				t.Fatal("feed id changed on reopen")
			}
			if got, err := s.Get(ctx, "key", "k1"); err != nil || string(got.Data) != "d" || got.Fields["alg"] != "ES256" {
				t.Fatalf("reopen lost data: %v %+v", err, got)
			}
			s.Close()
		}
	})
}

// Two stores on one server database (as two processes would be) must agree on unique values and optimistic
// concurrency.
func TestSharedDatabase(t *testing.T) {
	forEachDialect(t, dialects[1:], func(t *testing.T, d testDialect) {
		ctx := context.Background()
		first, dsn := openTest(t, d.name, d.env, 0)
		defer first.Close()
		second, err := Open(ctx, Config{Driver: d.name, DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		ss := [2]*Store{first, second}
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

// A wiped database's new identity is written to it (storetest's Wipe checks the rest): a reopen keeps it.
func TestWipePersistsTheNewFeedID(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		ctx := context.Background()
		s, dsn := openTest(t, d.name, d.env, 0)
		defer s.Close()
		if err := s.Put(ctx, record("link", "a", time.Time{}, "t/a")); err != nil {
			t.Fatal(err)
		}
		feed := s.FeedID()
		if err := s.Wipe(ctx); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := s.wdb.QueryRow("SELECT feed_id FROM " + feedTable).Scan(&got); err != nil || got != s.FeedID() || got == feed {
			t.Fatalf("persisted store id %q (in memory %q, before %q): %v", got, s.FeedID(), feed, err)
		}
		again, err := Open(ctx, Config{Driver: d.name, DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		defer again.Close()
		if again.FeedID() != got {
			t.Fatalf("reopened with feed id %q, want %q", again.FeedID(), got)
		}
	})
}

// Nothing serialises writes in the process (no mutex, no counter row): heavy concurrent writers with overlapping unique
// values, on two stores, must neither deadlock nor lose updates.
func TestConcurrentWriters(t *testing.T) {
	forEachDialect(t, dialects, func(t *testing.T, d testDialect) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		first, dsn := openTest(t, d.name, d.env, 8)
		defer first.Close()
		second, err := Open(ctx, Config{Driver: d.name, DSN: dsn, MaxOpenConns: 8})
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		ss := [2]*Store{first, second}
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
