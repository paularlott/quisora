package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

type mode int

const (
	modePut mode = iota
	modeCAS
	modeReplicated
)

const maxAttempts = 30

// stored is the metadata of an existing row.
type stored struct {
	kind    model.Kind
	version hlc.Timestamp
	epoch   hlc.Timestamp
	created hlc.Timestamp
	origin  string
	deleted bool
	expires sql.NullInt64
	uniq    []string
}

func (o *stored) head() *store.Head {
	return &store.Head{Kind: o.kind, Version: o.version, Epoch: o.epoch, Created: o.created, Deleted: o.deleted, Origin: o.origin}
}

func (o *stored) live(now int64) bool {
	return !o.deleted && (!o.expires.Valid || o.expires.Int64 > now)
}

func (s *Store) Put(ctx context.Context, rec *store.Record) error {
	_, _, err := s.apply(ctx, modePut, rec, 0)
	return err
}

func (s *Store) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	_, _, err := s.apply(ctx, modeCAS, rec, expect)
	return err
}

func (s *Store) PutReplicated(ctx context.Context, rec *store.Record) (bool, []string, error) {
	return s.apply(ctx, modeReplicated, rec, 0)
}

// apply runs one write, retrying deadlocks and lost insert races. Each write is its own transaction: grouping
// several into one (as the Badger engine does) would break the lock order below across processes.
func (s *Store) apply(ctx context.Context, m mode, rec *store.Record, expect hlc.Timestamp) (bool, []string, error) {
	t, err := s.table(rec.Kind)
	if err != nil {
		return false, nil, err
	}
	if rec.Version > math.MaxInt64 {
		return false, nil, fmt.Errorf("sqlstore: version %d out of range", rec.Version)
	}
	s.warm(ctx, t)
	if s.feed {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	for attempt := 1; ; attempt++ {
		applied, losers, err := s.applyOnce(ctx, t, m, rec, expect)
		if err == nil || attempt >= maxAttempts || !s.d.retryable(err) || ctx.Err() != nil {
			return applied, losers, err
		}
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		case <-time.After(time.Duration(1+rand.IntN(3*min(attempt, 10))) * time.Millisecond):
		}
	}
}

func (s *Store) txOptions() *sql.TxOptions {
	if s.d.name == "sqlite" {
		return nil
	}
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

func (s *Store) applyOnce(ctx context.Context, t *table, m mode, rec *store.Record, expect hlc.Timestamp) (bool, []string, error) {
	tx, err := s.wdb.BeginTx(ctx, s.txOptions())
	if err != nil {
		return false, nil, err
	}
	defer tx.Rollback()
	r := runner{c: s.wc, tx: tx}
	now := time.Now().UnixMicro()

	old, err := loadStored(ctx, r, t, rec.ID)
	if err != nil {
		return false, nil, err
	}
	switch m {
	case modePut:
		if old != nil && old.version >= rec.Version {
			return false, nil, store.ErrStale
		}
		if err := old.stamp(rec, false); err != nil {
			return false, nil, err
		}
	case modeCAS:
		live := old != nil && old.live(now)
		if expect == 0 {
			if live || (old != nil && old.version >= rec.Version) {
				return false, nil, store.ErrStale
			}
		} else {
			if !live {
				return false, nil, store.ErrNotFound
			}
			if old.version != expect || rec.Version <= expect {
				return false, nil, store.ErrStale
			}
		}
		if err := old.stamp(rec, expect == 0); err != nil {
			return false, nil, err
		}
	case modeReplicated:
		if old != nil && !rec.Head().Newer(old.head()) {
			return false, nil, nil
		}
		store.Witness(rec.Version)
	}

	var want []string
	if !rec.Deleted {
		for _, u := range rec.Unique {
			if !slices.Contains(want, u) {
				want = append(want, u)
			}
		}
	}
	// Unique values are always touched in sorted order so concurrent writers cannot lock them crosswise.
	slices.Sort(want)
	if old != nil {
		olds := slices.Clone(old.uniq)
		slices.Sort(olds)
		for _, u := range olds {
			if !slices.Contains(want, u) {
				if _, err := r.exec(ctx, s.releaseSQL(), t.kind, u, rec.ID); err != nil {
					return false, nil, err
				}
			}
		}
	}
	var losers []string
	for _, u := range want {
		loser, err := s.claim(ctx, r, t, m, rec, u, now)
		if err != nil {
			return false, nil, err
		}
		if loser != "" && !slices.Contains(losers, loser) {
			losers = append(losers, loser)
		}
	}

	var seq int64
	if s.feed {
		if seq, err = s.nextSeq(ctx, r); err != nil {
			return false, nil, err
		}
	}
	args, err := t.args(rec, seq)
	if err != nil {
		return false, nil, err
	}
	if old == nil {
		_, err = r.exec(ctx, t.insert, args...)
	} else {
		_, err = r.exec(ctx, t.update, append(args[1:], rec.ID)...)
	}
	if err != nil {
		return false, nil, err
	}
	if err := tx.Commit(); err != nil {
		return false, nil, err
	}
	return true, losers, nil
}

// stamp applies store.StampLocal for a local write of rec over o (nil: nothing stored).
func (o *stored) stamp(rec *store.Record, create bool) error {
	if o == nil {
		return store.StampLocal(rec, nil, create)
	}
	return store.StampLocal(rec, o.head(), create)
}

func loadStored(ctx context.Context, r runner, t *table, id string) (*stored, error) {
	var o stored
	var v, epoch, created int64
	var uniq sql.NullString
	err := r.queryRow(ctx, t.meta, id).Scan(&v, &o.origin, &o.deleted, &o.expires, &uniq, &epoch, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o.kind, o.version, o.epoch, o.created = t.kind, hlc.Timestamp(v), hlc.Timestamp(epoch), hlc.Timestamp(created)
	store.Witness(o.version) // a write refused as stale succeeds when retried (see table.scan)
	o.uniq = decodeUnique(uniq)
	return &o, nil
}

func (s *Store) releaseSQL() string { return s.releaseQ }

// warm prepares the statements a write to t uses, outside any transaction.
func (s *Store) warm(ctx context.Context, t *table) {
	for _, q := range []string{t.meta, t.insert, t.update, t.uInsert, t.uHolder, t.uSteal, s.releaseQ, s.seqQ, s.seqSelQ} {
		if q != "" {
			s.wc.get(ctx, q)
		}
	}
}

// claim indexes unique value u for rec. A live record of the kind already holding it is a conflict (ErrConflict
// for local writes); for replicated writes the record created first keeps it (store.KeepsUnique) and the loser's id
// is returned.
func (s *Store) claim(ctx context.Context, r runner, t *table, m mode, rec *store.Record, u string, now int64) (string, error) {
	insert, holder, steal := t.uInsert, t.uHolder, t.uSteal
	for range 5 {
		res, err := r.exec(ctx, insert, t.kind, u, rec.ID)
		if err != nil {
			return "", err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return "", nil
		}
		var hid string
		var hv, hexp, hcreated sql.NullInt64
		var horigin sql.NullString
		var hdel sql.NullBool
		err = r.queryRow(ctx, holder, t.kind, u).Scan(&hid, &hv, &horigin, &hdel, &hexp, &hcreated)
		if errors.Is(err, sql.ErrNoRows) {
			continue // released concurrently
		}
		if err != nil {
			return "", err
		}
		if hid == rec.ID {
			return "", nil
		}
		hlive := hv.Valid && !hdel.Bool && (!hexp.Valid || hexp.Int64 > now)
		loser := ""
		if hlive {
			if m != modeReplicated {
				return "", store.ErrConflict
			}
			other := &store.Head{Version: hlc.Timestamp(hv.Int64), Origin: horigin.String, Created: hlc.Timestamp(hcreated.Int64)}
			if store.KeepsUnique(other, rec.Head(), hid, rec.ID) {
				return rec.ID, nil
			}
			loser = hid
		}
		res, err = r.exec(ctx, steal, rec.ID, t.kind, u, hid)
		if err != nil {
			return "", err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return loser, nil
		}
	}
	return "", fmt.Errorf("sqlstore: unique value %q is contended", u)
}

// nextSeq bumps the feed counter inside the write transaction. The row lock it takes is held until commit, so
// sequence numbers follow commit order even across processes.
func (s *Store) nextSeq(ctx context.Context, r runner) (int64, error) {
	var seq int64
	if s.d.isMySQL() {
		if _, err := r.exec(ctx, s.seqQ); err != nil {
			return 0, err
		}
		err := r.queryRow(ctx, s.seqSelQ).Scan(&seq)
		return seq, err
	}
	err := r.queryRow(ctx, s.seqQ).Scan(&seq)
	return seq, err
}

// Wipe deletes every record and unique value and starts a new change feed (new feed id, seq back to 0), all in one
// transaction. Peers see the new feed id and restart their cursors.
func (s *Store) Wipe(ctx context.Context) error {
	if s.feed {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	tx, err := s.wdb.BeginTx(ctx, s.txOptions())
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, k := range model.Kinds() {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.tables[k].name); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+uniqueTable); err != nil {
		return err
	}
	feed := model.NewID()
	if _, err := tx.ExecContext(ctx, s.d.bind("UPDATE "+feedTable+" SET feed_id = ?, seq = 0 WHERE id = 1"), feed); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.feedID.Store(feed)
	return nil
}

// RefreshFields recomputes the field columns of the records q selects from their data (store.FieldRefresher): a
// column added by reconcile is empty on rows written before. Only the columns change; a row rewritten meanwhile (its
// version moved) is left alone.
func (s *Store) RefreshFields(ctx context.Context, kind model.Kind, q store.ListQuery) (int, error) {
	res, err := s.List(ctx, kind, q)
	if err != nil || len(res.Records) == 0 {
		return 0, err
	}
	t := s.tables[kind]
	sets := make([]string, len(t.fields))
	for i, f := range t.fields {
		sets[i] = s.d.quote(f.Name) + " = ?"
	}
	stmt := s.d.bind("UPDATE " + t.name + " SET " + strings.Join(sets, ", ") + " WHERE id = ? AND version = ?")
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range res.Records {
		fields, err := store.IndexFields(r)
		if err != nil {
			return n, err
		}
		args := make([]any, 0, len(t.fields)+2)
		for _, f := range t.fields {
			v, err := fieldArg(f, fields[f.Name])
			if err != nil {
				return n, err
			}
			args = append(args, v)
		}
		res, err := s.wdb.ExecContext(ctx, stmt, append(args, r.ID, int64(r.Version))...)
		if err != nil {
			return n, err
		}
		if c, _ := res.RowsAffected(); c > 0 {
			n++
		}
	}
	return n, nil
}
