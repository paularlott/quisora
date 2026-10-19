package ephemeral_test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

// 200 increments of one counter at once on SQLite: none errors, and the count is exact or reports Contended (which
// is above every limit), never below the real number.
func TestSharedIncrHotSQLite(t *testing.T) {
	ctx := context.Background()
	s, err := sqlstore.Open(ctx, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "a.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := ephemeral.NewShared(s)
	var wg sync.WaitGroup
	var errs, contended atomic.Int32
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := e.Incr(ctx, "rate", "hot", 1, time.Minute)
			if err != nil {
				errs.Add(1)
				t.Log(err)
			}
			if n == ephemeral.Contended {
				contended.Add(1)
			}
		}()
	}
	wg.Wait()
	n, _ := e.Incr(ctx, "rate", "hot", 0, time.Minute)
	if errs.Load() > 0 || n+int64(contended.Load()) < 200 {
		t.Fatalf("%d errors, count %d with %d reported contended", errs.Load(), n, contended.Load())
	}
}
