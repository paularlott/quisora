package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
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
	return rec, unavailable(notFound(err))
}

// getManyBatch bounds the ids of one GetMany query (bind parameters: SQLite takes 32766, PostgreSQL 65535).
const getManyBatch = 500

// GetMany returns the live records of kind among ids, in the order of ids, in one query per getManyBatch ids
// (store.MultiGetter): a token's groups, a page of users' sign-in records, a group's members.
func (s *Store) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	out, err := s.getMany(ctx, kind, ids)
	return out, unavailable(err)
}

func (s *Store) getMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
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
	return rec, unavailable(notFound(err))
}

func (s *Store) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	t, ok := s.tables[kind]
	if !ok {
		return nil, store.ErrNotFound
	}
	rec, err := t.scan(s.reader().queryRow(ctx, t.byUnique, string(kind), uniqueKey(value), time.Now().UnixMicro()))
	return rec, unavailable(notFound(err))
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
	res, err := s.list(ctx, s.reader(), kind, q)
	return res, unavailable(err)
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
	cols := t.cols
	if q.IDsOnly { // the ids are wanted, not the records (store.ListQuery.IDsOnly): no data to read or decode
		cols = "id"
	}
	sel := s.d.bind("SELECT " + cols + " FROM " + t.name + " WHERE " + where + " ORDER BY " + order + " LIMIT ? OFFSET ?")
	rows, err := rd.query(ctx, sel, append(args[:len(args):len(args)], limit, int64(offset))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	res := &store.ListResult{Records: []*store.Record{}}
	for rows.Next() {
		var rec *store.Record
		if q.IDsOnly {
			rec = &store.Record{Kind: kind}
			err = rows.Scan(&rec.ID)
		} else {
			rec, err = t.scan(rows)
		}
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
			return res, s.countMax(ctx, rd, t, where, args, q.CountMax, &res.Total)
		}
	case n < q.Limit && (n > 0 || offset == 0):
		res.Total = offset + n // a short page is the last page
	default:
		most := q.CountMax
		if most > 0 {
			most = max(most, offset+n) // a page past the bound is counted to its end
		}
		return res, s.countMax(ctx, rd, t, where, args, most, &res.Total)
	}
	return res, nil
}

func (s *Store) count(ctx context.Context, rd runner, t *table, where string, args []any, out *int) error {
	return s.countMax(ctx, rd, t, where, args, 0, out)
}

// countMax counts the rows that match where, stopping at most (store.ListQuery.CountMax; 0: every one): a COUNT
// over a LIMIT reads at most that many rows, where a plain COUNT reads every match of a large table.
func (s *Store) countMax(ctx context.Context, rd runner, t *table, where string, args []any, most int, out *int) error {
	if most <= 0 {
		return rd.queryRow(ctx, s.d.bind("SELECT COUNT(*) FROM "+t.name+" WHERE "+where), args...).Scan(out)
	}
	q := s.d.bind("SELECT COUNT(*) FROM (SELECT 1 AS one FROM " + t.name + " WHERE " + where + " LIMIT ?) bounded")
	return rd.queryRow(ctx, q, append(args[:len(args):len(args)], most)...).Scan(out)
}

func (s *Store) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	n, err := s.countScope(ctx, s.reader(), kind, scope)
	return n, unavailable(err)
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
	res, err := v.s.list(ctx, runner{c: v.s.rc, tx: v.tx}, kind, q)
	return res, unavailable(err)
}

func (v *snapshot) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	n, err := v.s.countScope(ctx, runner{c: v.s.rc, tx: v.tx}, kind, scope)
	return n, unavailable(err)
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
		return nil, unavailable(err)
	}
	// Fix the snapshot now: every dialect takes it at the transaction's first read, not when it begins.
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+feedTable).Scan(&n); err != nil {
		_ = tx.Rollback()
		return nil, unavailable(err)
	}
	// A view holding a partition part-way through an import, full or not, is refused (store.Snapshotter).
	switch unfinished, err := s.anyImportUnfinished(ctx, runner{c: s.rc, tx: tx}); {
	case err != nil:
		_ = tx.Rollback()
		return nil, unavailable(err)
	case unfinished:
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: a partition is part-way through an import; try again once it has finished", store.ErrUnavailable)
	}
	return &snapshot{s: s, tx: tx}, nil
}

func (s *Store) Purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
	n, err := s.purge(ctx, tombstonesBefore, expiredBefore)
	return n, unavailable(err)
}

func (s *Store) purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
	var tombVersion int64
	if tb := tombstonesBefore.Add(999 * time.Nanosecond); tb.UnixMicro() > 1735689600000000 {
		tombVersion = int64(hlc.FromTime(tb))
	}
	exp := expiredBefore.UnixMicro()
	total := 0
	var errs []error
	for _, k := range model.Kinds() {
		n, err := s.purgeKind(ctx, s.tables[k], tombVersion, exp)
		total += n
		if err != nil {
			// One table that keeps timing out must not leave every later kind (audit, sessions, ephemeral records)
			// growing without bound: go on, and report each failure with the kind it was.
			errs = append(errs, fmt.Errorf("purge %s: %w", k, err))
			if ctx.Err() != nil { // nothing later can succeed
				break
			}
		}
	}
	return total, errors.Join(errs...)
}

func (s *Store) purgeKind(ctx context.Context, t *table, tombVersion, exp int64) (int, error) {
	total, err := s.deleteBatches(ctx, t, "deleted = TRUE AND pseq = 0 AND version < ?", tombVersion)
	if err != nil || model.ExpiryOf(t.kind) == model.NeverExpires { // none carries an expiry, and no index finds the expired ones
		return total, err
	}
	// Expired records without unique values go a batch to a statement; the rest release their unique values first.
	n, err := s.deleteBatches(ctx, t, "expires IS NOT NULL AND expires < ? AND uniq IS NULL", exp)
	total += n
	if err != nil {
		return total, err
	}
	sel := s.d.bind("SELECT id, uniq FROM " + t.name + " WHERE expires IS NOT NULL AND expires < ? AND uniq IS NOT NULL LIMIT " +
		strconv.Itoa(batchRows) + s.d.lockClause(""))
	del := s.d.bind("DELETE FROM " + t.name + " WHERE id = ? AND expires IS NOT NULL AND expires < ?")
	s.wc.get(ctx, sel)
	s.wc.get(ctx, del)
	for {
		var found int
		err := s.partitionTx(ctx, true, []*table{t}, func(r runner) error {
			var err error
			n, found, err = s.purgeExpiredUnique(ctx, r, t, sel, del, exp)
			return err
		})
		if err != nil {
			return total, err
		}
		total += n
		if found < batchRows {
			return total, nil
		}
	}
}

// deleteBatches deletes the rows of t that match where (none of which holds a unique value), batchRows to a
// transaction, until a batch deletes fewer. A batch is a short transaction of its own, run as a partition write is
// (partitionTx: run again on a deadlock, and unsynced: a purge a crash undoes is simply done again by the next one), so a
// large purge never holds SQLite's one writer (which every sign-in waits for), or a server's locks and log, for its
// whole run; and a cancelled ctx stops it between batches.
func (s *Store) deleteBatches(ctx context.Context, t *table, where string, args ...any) (int, error) {
	q := s.d.bind(s.d.deleteLimit(t.name, where, batchRows))
	s.wc.get(ctx, q) // prepared outside the transactions (runner.stmt)
	total := 0
	for {
		var n int64
		err := s.partitionTx(ctx, true, nil, func(r runner) error {
			res, err := r.exec(ctx, q, args...)
			if err == nil {
				n, err = res.RowsAffected()
			}
			return err
		})
		if err != nil {
			return total, err
		}
		total += int(n)
		if n < batchRows {
			return total, nil
		}
	}
}

// purgeExpiredUnique deletes, in the transaction of r, the expired records that sel (the next batchRows of them, locked)
// finds, each with del, releasing the unique values of those deleted. It returns how many it deleted and how many sel
// found.
func (s *Store) purgeExpiredUnique(ctx context.Context, r runner, t *table, sel, del string, exp int64) (int, int, error) {
	rows, err := r.query(ctx, sel, exp)
	if err != nil {
		return 0, 0, err
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
			return 0, 0, err
		}
		uniq, err := decodeUnique(u)
		if err != nil {
			rows.Close()
			return 0, 0, err
		}
		items = append(items, item{id, uniq})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, 0, err
	}
	n := 0
	for _, it := range items {
		res, err := r.exec(ctx, del, it.id, exp)
		if err != nil {
			return 0, 0, err
		}
		if c, _ := res.RowsAffected(); c == 1 {
			n++
			for _, u := range it.uniq {
				if err := s.release(ctx, r, t, u, it.id); err != nil {
					return 0, 0, err
				}
			}
		}
	}
	return n, len(items), nil
}
