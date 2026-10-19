package sqlstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/paularlott/quisora/internal/model"
)

// reconcile makes the database match model.Schemas after the numbered migrations: it creates the table of any kind
// that is missing, adds every missing field column and creates missing indexes. It runs under the migration lock and
// is idempotent, so a database created by an older build gains new kinds, fields and indexes on the next Open.
//
// Existing rows get the column's zero value (every field column is NOT NULL with a zero default). Their real value
// still lives inside the record's data blob; the queryable column is populated the next time the record is written.
// Services must therefore tolerate zero values in newly added fields until a record is rewritten.
func (s *Store) reconcile(ctx context.Context, ex execer) error {
	d := s.d
	for _, k := range model.Kinds() {
		t := s.tables[k]
		have, err := s.columns(ctx, ex, "qsr_"+string(k))
		if err != nil {
			return fmt.Errorf("reconcile %s: %w", k, err)
		}
		stmts := t.ddl(d) // CREATE TABLE IF NOT EXISTS + indexes
		if len(have) > 0 && (!have["epoch"] || !have["created_v"]) {
			return fmt.Errorf("sqlstore: table %s was created by an earlier, incompatible pre-release build of Quisora "+
				"(no epoch column): there is no conversion; drop the database and start clean (restore from a backup "+
				"made by this build if needed)", t.name)
		}
		if len(have) > 0 {
			var add []string
			for _, f := range t.fields {
				if !have[strings.ToLower(f.Name)] {
					add = append(add, "ALTER TABLE "+t.name+" ADD COLUMN "+d.quote(f.Name)+" "+d.colType(f))
				}
			}
			stmts = append(add, stmts[1:]...) // table exists: skip its CREATE
		}
		for _, stmt := range stmts {
			if _, err := ex.ExecContext(ctx, stmt); err != nil && !d.ignorableDDL(err) {
				return fmt.Errorf("reconcile %s: %w\n%s", k, err, stmt)
			}
		}
	}
	return nil
}

// columns returns the lower-cased column names of a table, or an empty set when the table does not exist.
func (s *Store) columns(ctx context.Context, ex execer, table string) (map[string]bool, error) {
	d := s.d
	var q string
	var args []any
	switch {
	case d.name == "sqlite":
		q = "SELECT name FROM pragma_table_info(?)"
		args = []any{table}
	case d.isPG():
		q = "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1"
		args = []any{table}
	default:
		q = "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?"
		args = []any{table}
	}
	rows, err := ex.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[strings.ToLower(n)] = true
	}
	return out, rows.Err()
}
