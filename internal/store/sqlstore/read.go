package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

const live = "deleted = FALSE AND (expires IS NULL OR expires > ?)"

func (s *Store) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	t, ok := s.tables[kind]
	if !ok {
		return nil, store.ErrNotFound
	}
	rec, _, err := t.scan(s.reader().queryRow(ctx, t.get, id, time.Now().UnixMicro()))
	return rec, notFound(err)
}

// Lookup returns the stored record whatever its state (store.Store).
func (s *Store) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	t, ok := s.tables[kind]
	if !ok {
		return nil, store.ErrNotFound
	}
	rec, _, err := t.scan(s.reader().queryRow(ctx, t.lookup, id))
	return rec, notFound(err)
}

func (s *Store) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	t, ok := s.tables[kind]
	if !ok {
		return nil, store.ErrNotFound
	}
	q := s.d.bind("SELECT " + qualify(t.cols, "k") + " FROM " + uniqueTable + " u JOIN " + t.name +
		" k ON k.id = u.id WHERE u.kind = ? AND u.value = ? AND k.deleted = FALSE AND (k.expires IS NULL OR k.expires > ?)")
	rec, _, err := t.scan(s.reader().queryRow(ctx, q, string(kind), value, time.Now().UnixMicro()))
	return rec, notFound(err)
}

// qualify prefixes every column of a comma-separated list with a table alias.
func qualify(cols, alias string) string {
	parts := strings.Split(cols, ", ")
	for i, p := range parts {
		parts[i] = alias + "." + p
	}
	return strings.Join(parts, ", ")
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// likeEscape escapes LIKE wildcards with '!' (used as the ESCAPE character everywhere, so no backslash rules apply).
var likeEscape = strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")

// where builds the shared WHERE clause of List and Count.
func (s *Store) where(t *table, q store.ListQuery) (string, []any, error) {
	schema := model.Schemas[t.kind]
	var b strings.Builder
	var args []any
	if q.Scope != "" {
		b.WriteString("scope = ? AND ")
		args = append(args, q.Scope)
	}
	b.WriteString(live)
	args = append(args, time.Now().UnixMicro())
	for _, f := range q.Filters {
		fld, _ := schema.Field(f.Field)
		v, err := fieldArg(fld, f.Value)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %v", store.ErrBadQuery, err)
		}
		col, op := s.d.quote(fld.Name), " = ?"
		switch f.Op {
		case store.OpPrefix:
			col, op, v = "LOWER("+col+")", " LIKE ? ESCAPE '!'", likeEscape.Replace(strings.ToLower(f.Value.(string)))+"%"
		case store.OpGTE:
			op = " >= ?"
		case store.OpLT:
			op = " < ?"
		}
		b.WriteString(" AND " + col + op)
		args = append(args, v)
	}
	if q.Search != "" {
		var terms []string
		pat := "%" + likeEscape.Replace(strings.ToLower(q.Search)) + "%"
		for _, f := range schema.Fields {
			if f.Search {
				terms = append(terms, "LOWER("+s.d.quote(f.Name)+") LIKE ? ESCAPE '!'")
				args = append(args, pat)
			}
		}
		if len(terms) == 0 {
			b.WriteString(" AND 1 = 0")
		} else {
			b.WriteString(" AND (" + strings.Join(terms, " OR ") + ")")
		}
	}
	return b.String(), args, nil
}

func (s *Store) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	return s.list(ctx, s.reader(), kind, q)
}

func (s *Store) list(ctx context.Context, rd runner, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if err := store.ValidateQuery(kind, q); err != nil {
		return nil, err
	}
	t := s.tables[kind]
	where, args, err := s.where(t, q)
	if err != nil {
		return nil, err
	}
	if q.After != "" {
		where += " AND id > ?"
		args = append(args, q.After)
		q.Offset = 0
	}
	order := "id"
	if q.Sort == "" {
		if q.Desc {
			order = "id DESC"
		}
	} else {
		f, _ := model.Schemas[kind].Field(q.Sort)
		order = s.d.sortExpr(f)
		if q.Desc {
			order += " DESC"
		}
		order += ", id"
	}
	offset, limit := max(q.Offset, 0), int64(math.MaxInt64)
	if q.Limit > 0 {
		limit = int64(q.Limit)
	}
	sel := s.d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE " + where + " ORDER BY " + order + " LIMIT ? OFFSET ?")
	rows, err := rd.query(ctx, sel, append(args[:len(args):len(args)], limit, int64(offset))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	res := &store.ListResult{Records: []*store.Record{}}
	for rows.Next() {
		rec, _, err := t.scan(rows)
		if err != nil {
			return nil, err
		}
		res.Records = append(res.Records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	switch n := len(res.Records); {
	case q.After != "":
		res.Total = n
	case q.Limit <= 0:
		res.Total = offset + n
		if n == 0 && offset > 0 {
			return res, s.count(ctx, rd, t, where, args, &res.Total)
		}
	case n < q.Limit && (n > 0 || offset == 0):
		res.Total = offset + n // a short page is the last page
	default:
		return res, s.count(ctx, rd, t, where, args, &res.Total)
	}
	return res, nil
}

func (s *Store) count(ctx context.Context, rd runner, t *table, where string, args []any, out *int) error {
	return rd.queryRow(ctx, s.d.bind("SELECT COUNT(*) FROM "+t.name+" WHERE "+where), args...).Scan(out)
}

func (s *Store) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	return s.countScope(ctx, s.reader(), kind, scope)
}

func (s *Store) countScope(ctx context.Context, rd runner, kind model.Kind, scope string) (int, error) {
	t, err := s.table(kind)
	if err != nil {
		return 0, err
	}
	where, args, _ := s.where(t, store.ListQuery{Scope: scope})
	var n int
	return n, s.count(ctx, rd, t, where, args, &n)
}

// snapshot is a read-only view of the store inside one repeatable-read transaction (Store.Snapshot).
type snapshot struct {
	s  *Store
	tx *sql.Tx
}

func (v *snapshot) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	return v.s.list(ctx, runner{c: v.s.rc, tx: v.tx}, kind, q)
}

func (v *snapshot) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	return v.s.countScope(ctx, runner{c: v.s.rc, tx: v.tx}, kind, scope)
}

func (v *snapshot) Close() error { return v.tx.Rollback() }

// Snapshot returns a read-only, point-in-time view of the whole store (store.Snapshotter): one read-only
// transaction at REPEATABLE READ on PostgreSQL, MySQL and MariaDB (a single snapshot for every statement), and a
// read transaction on SQLite (WAL: the snapshot of its first read). A backup taken through it is consistent.
func (s *Store) Snapshot(ctx context.Context) (store.Reader, error) {
	opts := &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	if s.d.name == "sqlite" {
		opts = nil // one isolation level; the reader connections are query_only already
	}
	tx, err := s.rdb.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if s.d.name == "sqlite" {
		// Fix the snapshot now: a SQLite read transaction takes it at its first read.
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+feedTable).Scan(&n); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	return &snapshot{s: s, tx: tx}, nil
}

func (s *Store) Changes(ctx context.Context, since uint64, limit int) ([]store.Change, uint64, error) {
	if !s.feed {
		return nil, 0, ErrFeedDisabled
	}
	// Every seq <= head is committed (the counter row is locked until commit), so the window (since, head] is
	// complete and a reader never skips a seq.
	var head int64
	if err := s.reader().queryRow(ctx, "SELECT seq FROM "+feedTable+" WHERE id = 1").Scan(&head); err != nil {
		return nil, 0, err
	}
	out := []store.Change{}
	if uint64(head) <= since {
		return out, since, nil
	}
	n := int64(math.MaxInt64)
	if limit > 0 {
		n = int64(limit)
	}
	for _, k := range model.Kinds() {
		t := s.tables[k]
		q := s.d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE seq > ? AND seq <= ? ORDER BY seq LIMIT ?")
		rows, err := s.reader().query(ctx, q, int64(since), head, n)
		if err != nil {
			return nil, 0, err
		}
		for rows.Next() {
			rec, seq, err := t.scan(rows)
			if err != nil {
				rows.Close()
				return nil, 0, err
			}
			out = append(out, store.Change{Seq: uint64(seq), Record: rec})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, 0, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if limit > 0 && len(out) >= limit {
		out = out[:limit]
		return out, out[limit-1].Seq, nil
	}
	return out, uint64(head), nil
}

func (s *Store) Purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
	if s.feed {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	var tombVersion int64
	if tb := tombstonesBefore.Add(999 * time.Nanosecond); tb.UnixMicro() > 1735689600000000 {
		tombVersion = int64(hlc.FromTime(tb))
	}
	exp := expiredBefore.UnixMicro()
	total := 0
	for _, k := range model.Kinds() {
		t := s.tables[k]
		n, err := s.purgeKind(ctx, t, tombVersion, exp)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (s *Store) purgeKind(ctx context.Context, t *table, tombVersion, exp int64) (int, error) {
	r := runner{c: s.wc}
	total := 0
	res, err := r.exec(ctx, s.d.bind("DELETE FROM "+t.name+" WHERE deleted = TRUE AND version < ?"), tombVersion)
	if err != nil {
		return total, err
	}
	n, _ := res.RowsAffected()
	total += int(n)
	// Expired records without unique values go in one statement; the rest release their unique values first.
	res, err = r.exec(ctx, s.d.bind("DELETE FROM "+t.name+" WHERE expires IS NOT NULL AND expires < ? AND uniq IS NULL"), exp)
	if err != nil {
		return total, err
	}
	n, _ = res.RowsAffected()
	total += int(n)
	for {
		c, err := s.purgeExpiredUnique(ctx, t, exp)
		total += c
		if err != nil || c == 0 {
			return total, err
		}
	}
}

func (s *Store) purgeExpiredUnique(ctx context.Context, t *table, exp int64) (int, error) {
	tx, err := s.wdb.BeginTx(ctx, s.txOptions())
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	r := runner{c: s.wc, tx: tx}
	rows, err := r.query(ctx, s.d.bind("SELECT id, uniq FROM "+t.name+" WHERE expires IS NOT NULL AND expires < ? AND uniq IS NOT NULL LIMIT 500"+s.d.lockClause("")), exp)
	if err != nil {
		return 0, err
	}
	type item struct {
		id   string
		uniq []string
	}
	var items []item
	for rows.Next() {
		var id string
		var u sql.NullString
		if err := rows.Scan(&id, &u); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, item{id, decodeUnique(u)})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	del := s.d.bind("DELETE FROM " + t.name + " WHERE id = ? AND expires IS NOT NULL AND expires < ?")
	n := 0
	for _, it := range items {
		res, err := r.exec(ctx, del, it.id, exp)
		if err != nil {
			return 0, err
		}
		if c, _ := res.RowsAffected(); c == 1 {
			n++
			for _, u := range it.uniq {
				if _, err := r.exec(ctx, s.releaseSQL(), string(t.kind), u, it.id); err != nil {
					return 0, err
				}
			}
		}
	}
	return n, tx.Commit()
}
