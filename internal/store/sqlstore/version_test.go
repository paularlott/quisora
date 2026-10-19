package sqlstore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A database whose schema a newer build wrote is refused (no downgrade); reopening at this build's version works.
func TestNewerSchemaRefused(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "q.db")
	s, err := Open(ctx, Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.wdb.ExecContext(ctx, "UPDATE "+schemaTable+" SET version = 99"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(ctx, Config{Driver: "sqlite", DSN: path}); err == nil || !strings.Contains(err.Error(), "newer than this build") {
		t.Fatalf("a schema from a newer build: %v", err)
	}
}
