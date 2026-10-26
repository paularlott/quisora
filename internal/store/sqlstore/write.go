package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
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
	modeApply // a write decided by a partition's owner (ApplyPartition, ImportPartition): taken as it is
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
	_, err := s.apply(ctx, modePut, rec, 0)
	return err
}

func (s *Store) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	_, err := s.apply(ctx, modeCAS, rec, expect)
	return err
}

func (s *Store) PutReplicated(ctx context.Context, rec *store.Record) (bool, error) {
	return s.apply(ctx, modeReplicated, rec, 0)
}

// apply runs one write, retrying deadlocks and lost insert races. Each write is its own transaction: grouping
// several into one (as the Badger engine does) would break the lock order below across processes.
func (s *Store) apply(ctx context.Context, m mode, rec *store.Record, expect hlc.Timestamp) (bool, error) {
	t, err := s.table(rec.Kind)
	if err != nil {
		return false, err
	}
	if rec.Version > math.MaxInt64 {
		return false, fmt.Errorf("sqlstore: version %d out of range", rec.Version)
	}
	s.warm(ctx, t)
	for attempt := 1; ; attempt++ {
		applied, err := s.applyOnce(ctx, t, m, rec, expect)
		if err == nil || attempt >= maxAttempts || !s.d.retryable(err) || ctx.Err() != nil {
			return applied, err
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
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

func (s *Store) applyOnce(ctx context.Context, t *table, m mode, rec *store.Record, expect hlc.Timestamp) (bool, error) {
	tx, err := s.wdb.BeginTx(ctx, s.txOptions())
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	r := runner{c: s.wc, tx: tx}
	now := time.Now().UnixMicro()

	old, err := loadStored(ctx, r, t, rec.ID)
	if err != nil {
		return false, err
	}
	switch m {
	case modePut:
		if old != nil && old.version >= rec.Version {
			return false, store.ErrStale
		}
		if err := old.stamp(rec, false); err != nil {
			return false, err
		}
	case modeCAS:
		live := old != nil && old.live(now)
		if expect == 0 {
			if live || (old != nil && old.version >= rec.Version) {
				return false, store.ErrStale
			}
		} else {
			if !live {
				return false, store.ErrNotFound
			}
			if old.version != expect || rec.Version <= expect {
				return false, store.ErrStale
			}
		}
		if err := old.stamp(rec, expect == 0); err != nil {
			return false, err
		}
	case modeReplicated:
		if old != nil && old.version >= rec.Version {
			return false, nil
		}
		store.Witness(rec.Version)
	}

	if err := s.writeRow(ctx, r, t, m, rec, old, pstamp{}, now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// writeRow stores rec over the stored row old (nil: none), inside the transaction of r, after the checks of its mode:
// its unique values (those it no longer lists released, the ones it lists claimed) and the row itself, stamped ps.
func (s *Store) writeRow(ctx context.Context, r runner, t *table, m mode, rec *store.Record, old *stored, ps pstamp, now int64) error {
	var err error
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
					return err
				}
			}
		}
	}
	for _, u := range want {
		if err := s.claim(ctx, r, t, m, rec, u, now); err != nil {
			return err
		}
	}
	args, err := t.args(rec, ps)
	if err != nil {
		return err
	}
	if old == nil {
		_, err = r.exec(ctx, t.insert, args...)
	} else {
		_, err = r.exec(ctx, t.update, append(args[1:], rec.ID)...)
	}
	return err
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
	if o.uniq, err = decodeUnique(uniq); err != nil {
		return nil, err
	}
	return &o, nil
}

func (s *Store) releaseSQL() string { return s.releaseQ }

// warm prepares the statements a write to t uses, outside any transaction.
func (s *Store) warm(ctx context.Context, t *table) {
	for _, q := range []string{t.meta, t.insert, t.update, t.uInsert, t.uHolder, t.uSteal, s.releaseQ} {
		s.wc.get(ctx, q)
	}
}

// claim indexes unique value u for rec. A live record of the kind already holding it is a conflict (ErrConflict), unless
// the write is a partition's owner's (modeApply): the owner decided the value is rec's, and it takes it, whoever holds it
// (that record keeps its data and loses the index entry), so every node applying the same write ends the same.
func (s *Store) claim(ctx context.Context, r runner, t *table, m mode, rec *store.Record, u string, now int64) error {
	insert, holder, steal := t.uInsert, t.uHolder, t.uSteal
	for range 5 {
		res, err := r.exec(ctx, insert, t.kind, u, rec.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
		var hid string
		var hv, hexp sql.NullInt64
		var hdel sql.NullBool
		err = r.queryRow(ctx, holder, t.kind, u).Scan(&hid, &hv, &hdel, &hexp)
		if errors.Is(err, sql.ErrNoRows) {
			continue // released concurrently
		}
		if err != nil {
			return err
		}
		if hid == rec.ID {
			return nil
		}
		if hlive := hv.Valid && !hdel.Bool && (!hexp.Valid || hexp.Int64 > now); hlive && m != modeApply {
			return store.ErrConflict
		}
		res, err = r.exec(ctx, steal, rec.ID, t.kind, u, hid)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
	}
	return fmt.Errorf("sqlstore: unique value %q is contended", u)
}

// Wipe deletes every record and unique value and gives the store a new identity (FeedID), all in one transaction.
func (s *Store) Wipe(ctx context.Context) error {
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+partTable); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+importTable); err != nil {
		return err
	}
	feed := model.NewID()
	if _, err := tx.ExecContext(ctx, s.d.bind("UPDATE "+feedTable+" SET feed_id = ? WHERE id = 1"), feed); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.feedID.Store(feed)
	return nil
}
