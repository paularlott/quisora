package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
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
	rec, err := t.scan(s.reader().queryRow(ctx, t.get, id, time.Now().UnixMicro()))
	return rec, notFound(err)
}

// getManyBatch bounds the ids of one GetMany query (bind parameters: SQLite takes 32766, PostgreSQL 65535).
const getManyBatch = 500

// GetMany returns the live records of kind among ids, in the order of ids, in one query per getManyBatch ids
// (store.MultiGetter): a token's groups, a page of users' sign-in records, a group's members.
func (s *Store) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	t, ok := s.tables[kind]
	if !ok || len(ids) == 0 {
		return nil, nil
	}
	byID := make(map[string]*store.Record, len(ids))
	now := time.Now().UnixMicro()
	for start := 0; start < len(ids); start += getManyBatch {
		batch := ids[start:min(start+getManyBatch, len(ids))]
		args := make([]any, 0, len(batch)+1)
		for _, id := range batch {
			args = append(args, id)
		}
		args = append(args, now)
		q := s.d.bind("SELECT " + t.cols + " FROM " + t.name + " WHERE id IN (" + strings.Repeat("?, ", len(batch)-1) +
			"?) AND deleted = FALSE AND (expires IS NULL OR expires > ?)")
		rows, err := s.reader().query(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			rec, err := t.scan(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			byID[rec.ID] = rec
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	out := make([]*store.Record, 0, len(ids))
	for _, id := range ids {
		if rec, ok := byID[id]; ok {
			out = append(out, rec)
		}
	}
	return out, nil
}

// Lookup returns the stored record whatever its state (store.Store).
func (s *Store) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	t, ok := s.tables[kind]
	if !ok {
		return nil, store.ErrNotFound
	}
	rec, err := t.scan(s.reader().queryRow(ctx, t.lookup, id))
	return rec, notFound(err)
}

func (s *Store) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	t, ok := s.tables[kind]
	if !ok {
		return nil, store.ErrNotFound
	}
	q := s.d.bind("SELECT " + qualify(t.cols, "k") + " FROM " + uniqueTable + " u JOIN " + t.name +
		" k ON k.id = u.id WHERE u.kind = ? AND u.value = ? AND k.deleted = FALSE AND (k.expires IS NULL OR k.expires > ?)")
	rec, err := t.scan(s.reader().queryRow(ctx, q, string(kind), value, time.Now().UnixMicro()))
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
		if fld.Words && f.Op == "" { // one of the space-separated words: alone, first, last or in between
			if strings.ContainsAny(v.(string), " \t\n") {
				b.WriteString(" AND 1 = 0") // not a word
				continue
			}
			low := strings.ToLower(v.(string)) // ignoring case, as on every backend
			w, lc := likeEscape.Replace(low), s.d.lower(col)
			b.WriteString(" AND (" + lc + " = ? OR " + lc + " LIKE ? ESCAPE '!' OR " + lc + " LIKE ? ESCAPE '!' OR " +
				lc + " LIKE ? ESCAPE '!')")
			args = append(args, low, w+" %", "% "+w, "% "+w+" %")
			continue
		}
		switch f.Op {
		case store.OpPrefix:
			col, op, v = s.d.lower(col), " LIKE ? ESCAPE '!'", likeEscape.Replace(strings.ToLower(f.Value.(string)))+"%"
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
		pat := likeEscape.Replace(strings.ToLower(q.Search)) + "%" // a prefix match, as on every backend
		for _, f := range schema.Fields {
			if f.Search {
				terms = append(terms, s.d.lower(s.d.quote(f.Name))+" LIKE ? ESCAPE '!'")
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
		rec, err := t.scan(rows)
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
	// Fix the snapshot now: every dialect takes it at the transaction's first read, not when it begins.
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+feedTable).Scan(&n); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return &snapshot{s: s, tx: tx}, nil
}

func (s *Store) Purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
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
		uniq, err := decodeUnique(u)
		if err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, item{id, uniq})
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
