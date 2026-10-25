package sqlstore

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// openMem opens a scratch SQLite database (not a Store) for tests that need real driver errors.
func openMem(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "scratch.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}
