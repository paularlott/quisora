package sqlstore

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// reconcile makes the database match model.Schemas after the numbered migrations: it creates the table of any kind
// that is missing, adds every missing field column and creates missing indexes. It runs under the migration lock and
// is idempotent, so a database created by an older build gains new kinds, fields and indexes on the next Open.
//
// A column added to a table that has rows is filled from each live record's data (backfill), as writing the record
// would fill it, so a filter on a new field finds the records written before it existed.
func (s *Store) reconcile(ctx context.Context, ex execer) error {
	d := s.d
	for _, stmt := range s.partitionDDL() { // the partition protocol's own tables, as for any table that is missing
		if _, err := ex.ExecContext(ctx, stmt); err != nil && !d.ignorableDDL(err) {
			return fmt.Errorf("reconcile partition state: %w\n%s", err, stmt)
		}
	}
	for _, k := range model.Kinds() {
		t := s.tables[k]
		have, err := s.columns(ctx, ex, tableName(k))
		if err != nil {
			return fmt.Errorf("reconcile %s: %w", k, err)
		}
		stmts := t.ddl(d) // CREATE TABLE IF NOT EXISTS + indexes
		if len(have) > 0 && (!have["epoch"] || !have["created_v"] || slices.ContainsFunc(partColumns(d),
			func(c struct{ name, def string }) bool { return !have[c.name] })) {
			return fmt.Errorf("sqlstore: table %s was created by an earlier, incompatible pre-release build of Quisora "+
				"(no epoch or partition columns): there is no conversion; drop the database and start clean (restore "+
				"from a backup made by this build if needed)", t.name)
		}
		var added []model.Field
		if len(have) > 0 {
			var add []string
			for _, f := range t.fields {
				if !have[strings.ToLower(f.Name)] {
					add = append(add, "ALTER TABLE "+t.name+" ADD COLUMN "+d.quote(f.Name)+" "+d.colType(f))
					added = append(added, f)
				}
			}
			stmts = append(add, stmts[1:]...) // table exists: skip its CREATE
		}
		for _, stmt := range stmts {
			if _, err := ex.ExecContext(ctx, stmt); err != nil && !d.ignorableDDL(err) {
				return fmt.Errorf("reconcile %s: %w\n%s", k, err, stmt)
			}
		}
		if len(added) > 0 {
			if err := s.backfill(ctx, ex, t, added); err != nil {
				return fmt.Errorf("reconcile %s: filling the added columns: %w", k, err)
			}
		}
	}
	return nil
}

// backfillPage is how many rows backfill reads at a time.
const backfillPage = 500

// backfill fills the columns of fields, just added to t's table, from each live record's data: the values encoding
// the record gives (store.IndexFields). A page of rows at a time, in id order; the record itself (data, version) is
// not changed. A record whose data cannot be decoded keeps the zero value, as before the column was filled: one bad
// record never stops the database from opening.
func (s *Store) backfill(ctx context.Context, ex execer, t *table, fields []model.Field) error {
	d := s.d
	sets := make([]string, len(fields))
	for i, f := range fields {
		sets[i] = d.quote(f.Name) + " = ?"
	}
	update := d.bind("UPDATE " + t.name + " SET " + strings.Join(sets, ", ") + " WHERE id = ?")
	page := d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE deleted = FALSE AND id > ? ORDER BY id LIMIT " +
		strconv.Itoa(backfillPage))
	for after := ""; ; {
		rows, err := ex.QueryContext(ctx, page, after)
		if err != nil {
			return err
		}
		var recs []*store.Record
		for rows.Next() {
			r, err := t.scan(rows)
			if err != nil {
				rows.Close()
				return err
			}
			recs = append(recs, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, r := range recs { // the page is read in full first: one connection cannot write during a read
			vals, err := store.IndexFields(r)
			if err != nil {
				continue
			}
			args := make([]any, 0, len(fields)+1)
			for _, f := range fields {
				v, err := fieldArg(f, vals[f.Name])
				if err != nil {
					return fmt.Errorf("%s: %w", r.ID, err)
				}
				args = append(args, v)
			}
			if _, err := ex.ExecContext(ctx, update, append(args, r.ID)...); err != nil {
				return err
			}
		}
		if len(recs) < backfillPage {
			return nil
		}
		after = recs[len(recs)-1].ID
	}
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
