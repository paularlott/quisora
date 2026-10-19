package sqlstore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/paularlott/quisora/internal/model"
)

// execer is satisfied by *sql.Tx and *sql.Conn.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// migrations are applied in order; the index+1 is the schema version. Never edit a released migration: append one.
func (s *Store) migrations() []func() []string {
	return []func() []string{
		func() []string { return s.initialSchema() },
	}
}

func (s *Store) initialSchema() []string {
	d := s.d
	var out []string
	for _, k := range model.Kinds() {
		out = append(out, s.tables[k].ddl(d)...)
	}
	out = append(out,
		"CREATE TABLE IF NOT EXISTS "+uniqueTable+" (\n  kind "+d.keyType(64)+" NOT NULL,\n  value "+d.keyType(512)+
			" NOT NULL,\n  id "+d.keyType(191)+" NOT NULL,\n  PRIMARY KEY (kind, value)\n)"+uniqueSuffix(d),
		"CREATE TABLE IF NOT EXISTS "+feedTable+" (\n  id INT NOT NULL PRIMARY KEY,\n  feed_id "+d.keyType(64)+
			" NOT NULL,\n  seq BIGINT NOT NULL\n)"+tableSuffix(d),
		d.insertIgnore(feedTable, "id, feed_id, seq", "1, '"+model.NewID()+"', 0"),
	)
	return out
}

func tableSuffix(d *dialect) string {
	if d.isMySQL() {
		return " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" + d.strCollate()
	}
	return ""
}

func uniqueSuffix(d *dialect) string {
	if d.name == "sqlite" {
		return " WITHOUT ROWID"
	}
	return tableSuffix(d)
}

// migrate brings the schema up to date, serialised across processes by a database lock.
func (s *Store) migrate(ctx context.Context) error {
	ms := s.migrations()
	d := s.d
	conn, err := s.wdb.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlstore: migrate: %w", err)
	}
	defer conn.Close()

	var ex execer = conn
	var finish func(ok bool) error
	switch {
	case d.isMySQL():
		var got int
		if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK('qsr_schema', 60)").Scan(&got); err != nil || got != 1 {
			return fmt.Errorf("sqlstore: migrate: schema lock: %v", err)
		}
		finish = func(bool) error {
			_, err := conn.ExecContext(context.WithoutCancel(ctx), "SELECT RELEASE_LOCK('qsr_schema')")
			return err
		}
	default: // DDL is transactional on sqlite and postgres
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
		if d.isPG() {
			if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(7274201)"); err != nil {
				tx.Rollback()
				return fmt.Errorf("sqlstore: migrate: schema lock: %w", err)
			}
		}
		ex = tx
		finish = func(ok bool) error {
			if ok {
				return tx.Commit()
			}
			return tx.Rollback()
		}
	}
	err = s.applyMigrations(ctx, ex, ms)
	if err == nil {
		err = s.reconcile(ctx, ex)
	}
	if ferr := finish(err == nil); err == nil {
		err = ferr
	}
	if err != nil {
		return fmt.Errorf("sqlstore: migrate: %w", err)
	}
	return nil
}

func (s *Store) applyMigrations(ctx context.Context, ex execer, ms []func() []string) error {
	d := s.d
	if _, err := ex.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+schemaTable+" (version INT NOT NULL)"+tableSuffix(d)); err != nil {
		return err
	}
	var cur int
	err := ex.QueryRowContext(ctx, "SELECT version FROM "+schemaTable).Scan(&cur)
	have := err == nil
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if cur > len(ms) {
		return fmt.Errorf("database schema version %d is newer than this build (%d)", cur, len(ms))
	}
	for v := cur; v < len(ms); v++ {
		for _, stmt := range ms[v]() {
			if _, err := ex.ExecContext(ctx, stmt); err != nil && !d.ignorableDDL(err) {
				return fmt.Errorf("version %d: %w\n%s", v+1, err, stmt)
			}
		}
		var err error
		if have {
			_, err = ex.ExecContext(ctx, d.bind("UPDATE "+schemaTable+" SET version = ?"), v+1)
		} else {
			_, err = ex.ExecContext(ctx, d.bind("INSERT INTO "+schemaTable+" (version) VALUES (?)"), v+1)
			have = true
		}
		if err != nil {
			return err
		}
	}
	return nil
}
