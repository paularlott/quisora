package ephemeral_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

func newSharedSQLite(t *testing.T) *ephemeral.Shared {
	t.Helper()
	s, err := sqlstore.Open(context.Background(), sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "a.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return ephemeral.NewShared(s)
}

func TestSharedCRUD(t *testing.T) {
	ctx := context.Background()
	e := newSharedSQLite(t)

	id, err := e.New(ctx, "code", []byte("v"), time.Minute)
	if err != nil || id == "" {
		t.Fatalf("new: %q %v", id, err)
	}
	if v, err := e.Get(ctx, "code", id); err != nil || string(v) != "v" {
		t.Fatalf("get: %q %v", v, err)
	}
	if _, err := e.Get(ctx, "other", id); err != ephemeral.ErrNotFound {
		t.Fatalf("namespace isolation: %v", err)
	}
	if err := e.Set(ctx, "code", id, []byte("w"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.Get(ctx, "code", id); string(v) != "w" {
		t.Fatalf("set overwrites: %q", v)
	}
	if v, err := e.Take(ctx, "code", id); err != nil || string(v) != "w" {
		t.Fatalf("take: %q %v", v, err)
	}
	if _, err := e.Take(ctx, "code", id); err != ephemeral.ErrNotFound {
		t.Fatalf("take is single use: %v", err)
	}
	if _, err := e.Get(ctx, "code", id); err != ephemeral.ErrNotFound {
		t.Fatalf("taken item is gone: %v", err)
	}
}

func TestSharedDelete(t *testing.T) {
	ctx := context.Background()
	e := newSharedSQLite(t)
	if err := e.Set(ctx, "ns", "k", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.Delete(ctx, "ns", "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Get(ctx, "ns", "k"); err != ephemeral.ErrNotFound {
		t.Fatalf("deleted: %v", err)
	}
	if err := e.Delete(ctx, "ns", "never-existed"); err != nil {
		t.Fatalf("deleting a missing item: %v", err)
	}
}

func TestSharedIncr(t *testing.T) {
	ctx := context.Background()
	e := newSharedSQLite(t)
	if n, err := e.Incr(ctx, "rate", "k", 0, time.Minute); err != nil || n != 0 {
		t.Fatalf("reading a missing counter: %d %v", n, err)
	}
	for want := int64(1); want <= 3; want++ {
		if n, err := e.Incr(ctx, "rate", "k", 1, time.Minute); err != nil || n != want {
			t.Fatalf("incr: %d %v want %d", n, err, want)
		}
	}
	if n, _ := e.Incr(ctx, "rate", "k", 0, time.Minute); n != 3 {
		t.Fatalf("read: %d", n)
	}
	if n, _ := e.Incr(ctx, "rate", "other", 5, time.Minute); n != 5 {
		t.Fatalf("separate key: %d", n)
	}
}

func TestSharedIncrCanceled(t *testing.T) {
	e := newSharedSQLite(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Incr(ctx, "rate", "k", 1, time.Minute); err == nil {
		t.Fatal("a canceled context must fail")
	}
	if _, err := e.Get(ctx, "rate", "k"); err == nil {
		t.Fatal("a canceled context must fail Get")
	}
}
