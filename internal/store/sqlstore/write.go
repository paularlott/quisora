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
	req     string
	deleted bool
	expires sql.NullInt64
	uniq    []string
}

// head returns the row's version metadata (nil for no row).
func (o *stored) head() *store.Head {
	if o == nil {
		return nil
	}
	return &store.Head{Kind: o.kind, Version: o.version, Epoch: o.epoch, Created: o.created, Deleted: o.deleted, Origin: o.origin,
		Req: o.req}
}

func (o *stored) live(now int64) bool {
	return !o.deleted && (!o.expires.Valid || o.expires.Int64 > now)
}

// op is one write of a transaction: Put (modePut), CompareAndPut (modeCAS, expecting expect) or PutReplicated
// (modeReplicated, always alone). old is the row the transaction found, loaded inside it.
type op struct {
	t      *table
	rec    *store.Record
	m      mode
	expect hlc.Timestamp
	old    *stored
}

func (s *Store) Put(ctx context.Context, rec *store.Record) error {
	return s.write(ctx, modePut, rec, 0)
}

func (s *Store) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	return s.write(ctx, modeCAS, rec, expect)
}

// write runs one Put or CompareAndPut: a transaction of one write.
func (s *Store) write(ctx context.Context, m mode, rec *store.Record, expect hlc.Timestamp) error {
	t, err := s.table(rec.Kind)
	if err != nil {
		return err
	}
	defer store.EnsureReq(rec)()
	_, err = s.apply(ctx, []op{{t: t, rec: rec, m: m, expect: expect}})
	return err
}

func (s *Store) PutReplicated(ctx context.Context, rec *store.Record) (bool, error) {
	t, err := s.table(rec.Kind)
	if err != nil {
		return false, err
	}
	if rec.Version > math.MaxInt64 {
		return false, fmt.Errorf("sqlstore: version %d out of range", rec.Version)
	}
	return s.apply(ctx, []op{{t: t, rec: rec, m: modeReplicated}})
}

// Tx applies ops all or nothing, in one SQL transaction (store.Store).
func (s *Store) Tx(ctx context.Context, ops []store.Op) error {
	type key struct {
		kind model.Kind
		id   string
	}
	seen := make(map[key]bool, len(ops))
	list := make([]op, len(ops))
	for i, o := range ops {
		if o.Rec == nil || seen[key{o.Rec.Kind, o.Rec.ID}] {
			return store.ErrBadTx
		}
		seen[key{o.Rec.Kind, o.Rec.ID}] = true
		t, err := s.table(o.Rec.Kind)
		if err != nil {
			return err
		}
		list[i] = op{t: t, rec: o.Rec, m: modePut}
		if o.Match {
			list[i].m, list[i].expect = modeCAS, o.Expect
		}
	}
	if len(ops) == 0 {
		return store.ErrBadTx
	}
	defer store.TxReq(ops)()
	_, err := s.apply(ctx, list)
	return err
}

// apply runs ops as one transaction, retrying deadlocks and lost insert races. On a server database each call is its own
// transaction: grouping several calls into one would break the lock order below across processes (and the server
// groups the commits itself). A failure that says the store cannot serve now is ErrUnavailable.
func (s *Store) apply(ctx context.Context, ops []op) (bool, error) {
	for _, o := range ops {
		s.warm(ctx, o.t)
	}
	for attempt := 1; ; attempt++ {
		applied, err := s.applyOnce(ctx, ops)
		if err == nil || attempt >= maxAttempts || !s.d.retryable(err) || ctx.Err() != nil {
			return applied, unavailable(err)
		}
		select {
		case <-ctx.Done():
			return false, unavailable(ctx.Err())
		case <-time.After(time.Duration(1+rand.IntN(3*min(attempt, 10))) * time.Millisecond):
		}
	}
}

// txOptions are the options of a write transaction: read committed, which MySQL and MariaDB get from their connections
// (readCommitted), where asking per transaction would cost the driver a round trip (SET TRANSACTION) before each BEGIN.
func (s *Store) txOptions() *sql.TxOptions {
	if s.d.isPG() {
		return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	return nil
}

// applyOnce runs ops in one transaction and reports whether they were all written (a replicated record that is not newer
// than the stored one is not). On SQLite the transaction is shared with the writes that arrive meanwhile (committer).
func (s *Store) applyOnce(ctx context.Context, ops []op) (bool, error) {
	if s.gc != nil {
		return s.gc.submit(ctx, ops)
	}
	tx, err := s.wdb.BeginTx(ctx, s.txOptions())
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	written, err := s.applyIn(ctx, runner{c: s.wc, tx: tx}, ops)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return s.settle(ctx, ops, err)
	}
	return written, nil
}

// applyIn stages and writes ops in the transaction of r, which the caller commits, and reports whether they were all
// written.
func (s *Store) applyIn(ctx context.Context, r runner, ops []op) (bool, error) {
	now := time.Now().UnixMicro()
	retried := false
	for i := range ops {
		o := &ops[i]
		var err error
		if o.old, err = loadStored(ctx, r, o.t, o.rec.ID); err != nil {
			return false, err
		}
		retried = retried || (o.m != modeReplicated && store.Retried(o.rec, o.old.head()))
	}
	if retried { // an earlier attempt applied this request: nothing is written, and the records take what is stored
		for _, o := range ops {
			if h := o.old.head(); h != nil && h.Req == o.rec.Req {
				store.Settle(o.rec, h)
			}
		}
		return true, nil
	}
	written := true
	for i := range ops {
		o := &ops[i]
		ok, err := o.stage(now)
		if err != nil {
			return false, err
		}
		if !ok {
			written = false
			continue
		}
		if err := s.writeRow(ctx, r, o.t, o.m, o.rec, o.old, pstamp{}, now); err != nil {
			return false, err
		}
	}
	return written, nil
}

// stage decides the write over the row o found: refused (an error), not to be made (a replicated record that is not
// newer), or stamped and ready to write. Unique values are not looked at here: writeRow claims them as the transaction
// goes, so a later write of a transaction meets the values the earlier ones left.
func (o *op) stage(now int64) (bool, error) {
	if o.m == modeReplicated {
		if o.old != nil && o.old.version >= o.rec.Version {
			return false, nil
		}
		store.Witness(o.rec.Version)
		return true, nil
	}
	create := o.m == modeCAS && o.expect == 0
	if o.m == modeCAS {
		live := o.old != nil && o.old.live(now)
		switch {
		case create && live:
			return false, store.ErrStale
		case !create && !live:
			return false, store.ErrNotFound
		case !create && o.old.version != o.expect:
			return false, store.ErrStale
		}
	}
	store.StampWrite(o.rec, o.old.head())
	return true, store.StampLocal(o.rec, o.old.head(), create)
}

// settle answers a transaction whose commit failed. When the connection was lost the commit may have landed: the records
// are read back (on another connection, the failed one being discarded) and if one carries a request of the
// transaction it was applied (ErrUnavailable is the answer when none does, or the database cannot be read: the caller
// retries, and a retry is recognised by its request id). Any other failure means nothing was committed.
func (s *Store) settle(ctx context.Context, ops []op, cause error) (bool, error) {
	if classify(cause) != failLost || ops[0].m == modeReplicated { // (a replicated record has no request to find)
		return false, cause
	}
	// The caller's context may be what ended: the answer is still wanted, within a bound of its own.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleWait)
	defer cancel()
	for {
		heads, err := s.readHeads(ctx, ops)
		if err == nil {
			applied := false
			for i, h := range heads {
				if h != nil && h.Req == ops[i].rec.Req {
					store.Settle(ops[i].rec, h)
					applied = true
				}
			}
			if applied {
				return true, nil
			}
			// (not there now; a server may still be finishing the commit the connection lost: not known either way)
			return false, fmt.Errorf("%w: %w", store.ErrUnconfirmed, cause)
		}
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("%w: %w", store.ErrUnconfirmed, cause)
		case <-time.After(settleRetry):
		}
	}
}

// How long settle tries to read the records back, and how often.
const (
	settleWait  = 3 * time.Second
	settleRetry = 100 * time.Millisecond
)

// readHeads reads the stored version metadata of the records of ops (nil for a record that is not stored).
func (s *Store) readHeads(ctx context.Context, ops []op) ([]*store.Head, error) {
	heads := make([]*store.Head, len(ops))
	for i, o := range ops {
		rec, err := o.t.scan(s.reader().queryRow(ctx, o.t.lookup, o.rec.ID))
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return nil, err
		default:
			heads[i] = rec.Head()
		}
	}
	return heads, nil
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

func loadStored(ctx context.Context, r runner, t *table, id string) (*stored, error) {
	var o stored
	var v, epoch, created int64
	var uniq sql.NullString
	err := r.queryRow(ctx, t.meta, id).Scan(&v, &o.origin, &o.deleted, &o.expires, &uniq, &epoch, &created, &o.req)
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
	return unavailable(s.wipe(ctx))
}

func (s *Store) wipe(ctx context.Context) error {
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
