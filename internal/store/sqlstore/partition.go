package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Partition replication support (store.PartitionStore).
//
// State: one row per partition in qsr_partition, in the same database as the data and written in the same
// transaction as the records an apply or import changes. Every kind table has the stamp columns pnum and pseq (the
// partition and the sequence of the write that last changed the row) with a partial index on (pnum, pseq), which is
// what ExportPartition selects on; a row is stamped only by ApplyPartition and ImportPartition.
//
// Durability, per database (ApplyPartition, ImportPartition and PurgePartition commit unsynced where the database can; the
// state writes commit synced; a synced commit makes the earlier unsynced ones durable because the log is ordered):
//
//   - SQLite (WAL): the writer connection runs with synchronous=FULL (the WAL is fsynced at every commit); a partition
//     write switches that connection to synchronous=NORMAL for its transaction (the commit appends to the WAL without an
//     fsync) and back to FULL afterwards. The WAL is one append-only file: the fsync of a later FULL commit flushes the
//     whole file, every earlier NORMAL commit's frames with it, and a checkpoint syncs the WAL before it copies pages into
//     the database file at either setting. So a FULL commit that returns means every commit before it is on disk.
//   - PostgreSQL: SET LOCAL synchronous_commit = off for the transaction. The WAL is one ordered log: a later synchronous
//     commit flushes it up to its own commit record, which includes every earlier asynchronous one.
//   - MySQL and MariaDB: always durable (the server's innodb_flush_log_at_trx_commit, left at its default of 1, flushes the
//     redo log at every commit); there is no per-transaction setting, so every partition write is simply synced.

// partTable holds each partition's protocol state.
const partTable = "qsr_partition"

func (s *Store) partitionDDL() []string {
	d := s.d
	return []string{"CREATE TABLE IF NOT EXISTS " + partTable + " (\n  part INT NOT NULL PRIMARY KEY,\n" +
		"  promised_c BIGINT NOT NULL DEFAULT 0,\n  promised_n " + d.blobType() + " NULL,\n" +
		"  committed_c BIGINT NOT NULL DEFAULT 0,\n  committed_n " + d.blobType() + " NULL,\n" +
		"  committed_seq BIGINT NOT NULL DEFAULT 0,\n  pending_seq BIGINT NOT NULL DEFAULT 0,\n" +
		"  pending " + d.blobType() + " NULL,\n  purged BIGINT NOT NULL DEFAULT 0\n)" + tableSuffix(d),
		"CREATE TABLE IF NOT EXISTS " + importTable + " (\n  part INT NOT NULL,\n  kind " + d.keyType(64) + " NOT NULL,\n  id " +
			d.keyType(191) + " NOT NULL,\n  PRIMARY KEY (part, kind, id)\n)" + tableSuffix(d)}
}

// importTable says that a full import is in progress: a row with the kind importActive is the marker, written by the
// First call (in the transaction that checks the position, before anything is removed) and deleted in the transaction
// that commits the final position. The reset that starts an import deletes rows in transactions of their own, before the
// position moves, so without it a crash between them leaves no row above the committed position, and an export would
// advertise a position the data no longer matches. (The table has kind and id columns from when a full import marked each
// record it brought; only the marker row is used now, and the table is kept as it is to spare databases that have it a
// migration.)
const (
	importTable  = "qsr_import"
	importActive = "" // the kind of the marker row (no record kind is empty)
)

const stateCols = "promised_c, promised_n, committed_c, committed_n, committed_seq, pending_seq, pending, purged"

func (s *Store) stateSelect() string {
	return "SELECT " + stateCols + " FROM " + partTable + " WHERE part = ?"
}

// readState reads a partition's state row (the zero state if there is none).
func (s *Store) readState(ctx context.Context, r runner, p int, lock bool) (store.PartitionState, error) {
	q := s.stateSelect()
	if lock {
		q += s.d.lockClause("")
	}
	var st store.PartitionState
	var pc, cc, cs, ps, pu int64
	var pn, cn, pending []byte
	err := r.queryRow(ctx, s.d.bind(q), p).Scan(&pc, &pn, &cc, &cn, &cs, &ps, &pending, &pu)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Promised.Counter, st.Committed.Epoch.Counter, st.Committed.Seq = uint64(pc), uint64(cc), uint64(cs)
	copy(st.Promised.Node[:], pn)
	copy(st.Committed.Epoch.Node[:], cn)
	st.Pending, st.PendingSeq, st.Purged = bytes.Clone(pending), uint64(ps), uint64(pu)
	return st, nil
}

// lockState makes sure the partition's state row exists and returns it, locked until the transaction ends.
func (s *Store) lockState(ctx context.Context, r runner, p int) (store.PartitionState, error) {
	if _, err := r.exec(ctx, s.d.bind(s.d.insertIgnore(partTable, "part", "?")), p); err != nil {
		return store.PartitionState{}, err
	}
	return s.readState(ctx, r, p, true)
}

func (s *Store) saveState(ctx context.Context, r runner, p int, st *store.PartitionState) error {
	var pending any
	if st.Pending != nil {
		pending = st.Pending
	}
	_, err := r.exec(ctx, s.d.bind("UPDATE "+partTable+" SET promised_c = ?, promised_n = ?, committed_c = ?, committed_n = ?, "+
		"committed_seq = ?, pending_seq = ?, pending = ?, purged = ? WHERE part = ?"),
		int64(st.Promised.Counter), st.Promised.Node[:], int64(st.Committed.Epoch.Counter), st.Committed.Epoch.Node[:],
		int64(st.Committed.Seq), int64(st.PendingSeq), pending, int64(st.Purged), p)
	return err
}

func (s *Store) PartitionState(ctx context.Context, p int) (store.PartitionState, error) {
	r := s.reader()
	// The marker first: an import that ends in between shows as still importing (the safe side), never the reverse.
	rows, err := r.query(ctx, s.d.bind("SELECT 1 FROM "+importTable+" WHERE part = ? AND kind = ?"), p, importActive)
	if err != nil {
		return store.PartitionState{}, err
	}
	active := rows.Next()
	rows.Close()
	if err := rows.Err(); err != nil {
		return store.PartitionState{}, err
	}
	st, err := s.readState(ctx, r, p, false)
	if st.PendingSeq <= st.Committed.Seq { // a pending write the commit has passed is not shown
		st.Pending, st.PendingSeq = nil, 0
	}
	st.Importing = active
	return st, err
}

// beginWrite starts a write transaction. unsynced asks for a commit that need not be on disk when it returns (see the
// top of this file); finish must run after the transaction has ended, commit or rollback.
func (s *Store) beginWrite(ctx context.Context, unsynced bool) (tx *sql.Tx, finish func(), err error) {
	switch {
	case unsynced && s.d.name == "sqlite":
		conn, err := s.wdb.Conn(ctx)
		if err != nil {
			return nil, nil, err
		}
		if _, err := conn.ExecContext(ctx, "PRAGMA synchronous = NORMAL"); err != nil {
			conn.Close()
			return nil, nil, err
		}
		finish = func() {
			// The connection must never go back to the pool unsynced: if FULL cannot be restored, discard it.
			if _, err := conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA synchronous = FULL"); err != nil {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
			conn.Close()
		}
		if tx, err = conn.BeginTx(ctx, nil); err != nil {
			finish()
			return nil, nil, err
		}
		return tx, finish, nil
	case unsynced && s.d.isPG():
		tx, err = s.wdb.BeginTx(ctx, s.txOptions())
		if err != nil {
			return nil, nil, err
		}
		if _, err := tx.ExecContext(ctx, "SET LOCAL synchronous_commit = off"); err != nil {
			tx.Rollback()
			return nil, nil, err
		}
	default:
		if tx, err = s.wdb.BeginTx(ctx, s.txOptions()); err != nil {
			return nil, nil, err
		}
	}
	return tx, func() {}, nil
}

// partitionTxHook, when set (tests), is called inside every partition write transaction before its work, with whether the
// transaction commits unsynced.
var partitionTxHook func(ctx context.Context, tx *sql.Tx, unsynced bool)

// partitionTx runs fn in one write transaction and commits it, running it again on a deadlock or a lost race as apply
// does. tables are the kinds fn writes (their statements are prepared before the transaction begins).
func (s *Store) partitionTx(ctx context.Context, unsynced bool, tables []*table, fn func(r runner) error) error {
	for _, t := range tables {
		s.warm(ctx, t)
	}
	for attempt := 1; ; attempt++ {
		err := func() error {
			tx, finish, err := s.beginWrite(ctx, unsynced)
			if err != nil {
				return err
			}
			defer finish()
			defer tx.Rollback()
			if partitionTxHook != nil {
				partitionTxHook(ctx, tx, unsynced)
			}
			if err := fn(runner{c: s.wc, tx: tx}); err != nil {
				return err
			}
			return tx.Commit()
		}()
		if err == nil || attempt >= maxAttempts || !s.d.retryable(err) || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(1+rand.IntN(3*min(attempt, 10))) * time.Millisecond):
		}
	}
}

func (s *Store) SetPartitionPromised(ctx context.Context, p int, e store.PartitionEpoch) error {
	return s.partitionTx(ctx, false, nil, func(r runner) error {
		st, err := s.lockState(ctx, r, p)
		if err != nil {
			return err
		}
		if e.Compare(st.Promised) < 0 {
			return store.ErrPartitionRegress
		}
		st.Promised = e
		return s.saveState(ctx, r, p, &st)
	})
}

func (s *Store) SetPartitionPending(ctx context.Context, p int, seq uint64, pending []byte) error {
	if seq > store.MaxPartitionSeq {
		return fmt.Errorf("store: partition %d: write sequence %d out of range", p, seq)
	}
	return s.partitionTx(ctx, false, nil, func(r runner) error {
		st, err := s.lockState(ctx, r, p)
		if err != nil {
			return err
		}
		st.Pending, st.PendingSeq = pending, seq
		if pending == nil {
			st.PendingSeq = 0
		}
		return s.saveState(ctx, r, p, &st)
	})
}

// commitState sets the committed position and clears the pending write it has passed.
func (s *Store) commitState(ctx context.Context, r runner, p int, st *store.PartitionState, committed store.PartitionPos) error {
	st.Committed = committed
	if st.PendingSeq <= committed.Seq {
		st.Pending, st.PendingSeq = nil, 0
	}
	return s.saveState(ctx, r, p, st)
}

// putPartition stores rec as given, stamped (p, seq), in the transaction of r.
func (s *Store) putPartition(ctx context.Context, r runner, rec *store.Record, p int, seq uint64, now int64) error {
	t, err := s.table(rec.Kind)
	if err != nil {
		return err
	}
	if rec.Version > math.MaxInt64 {
		return fmt.Errorf("sqlstore: version %d out of range", rec.Version)
	}
	store.Witness(rec.Version)
	old, err := loadStored(ctx, r, t, rec.ID)
	if err != nil {
		return err
	}
	return s.writeRow(ctx, r, t, modeApply, rec, old, pstamp{num: p, pseq: int64(seq)}, now)
}

// tablesOf returns the tables of the given kinds, each once.
func (s *Store) tablesOf(kinds []model.Kind) ([]*table, error) {
	var out []*table
	seen := map[model.Kind]bool{}
	for _, k := range kinds {
		if seen[k] {
			continue
		}
		seen[k] = true
		t, err := s.table(k)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (s *Store) ApplyPartition(ctx context.Context, p int, recs []*store.Record, committed store.PartitionPos) error {
	if err := store.CheckApply(p, committed); err != nil {
		return err
	}
	kinds := make([]model.Kind, len(recs))
	for i, r := range recs {
		kinds[i] = r.Kind
	}
	tables, err := s.tablesOf(kinds)
	if err != nil {
		return err
	}
	return s.partitionTx(ctx, true, tables, func(r runner) error {
		st, err := s.lockState(ctx, r, p)
		if err != nil {
			return err
		}
		if committed.Seq <= st.Committed.Seq {
			return store.ErrPartitionBehind
		}
		now := time.Now().UnixMicro()
		for _, rec := range recs {
			if err := s.putPartition(ctx, r, rec, p, committed.Seq, now); err != nil {
				return err
			}
		}
		return s.commitState(ctx, r, p, &st, committed)
	})
}

// rowPlus scans a row of a kind table's columns and one more, the partition sequence.
type rowPlus struct {
	rows *sql.Rows
	seq  int64
}

func (r *rowPlus) Scan(dest ...any) error { return r.rows.Scan(append(dest, &r.seq)...) }

func (s *Store) ExportPartition(ctx context.Context, p int, afterSeq uint64, start func(store.PartitionPos) error,
	fn func(store.PartitionRecord) error) error {
	if afterSeq > store.MaxPartitionSeq {
		return fmt.Errorf("store: sequence %d out of range", afterSeq)
	}
	opts := &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	if s.d.name == "sqlite" {
		opts = nil
	}
	tx, err := s.rdb.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r := runner{c: s.rc, tx: tx}
	// The state is the first read, which fixes the snapshot everywhere (SQLite takes it at the first read): the data below is
	// exactly the committed position read here, because an apply writes both in one transaction.
	st, err := s.readState(ctx, r, p, false)
	if err != nil {
		return err
	}
	if !store.ExportAllowed(st.Purged, afterSeq) {
		return store.ErrPartitionPurged
	}
	// A row above the committed position is an import that did not finish: the rows below may lack what it overwrote.
	for _, k := range model.Kinds() {
		rows, err := r.query(ctx, s.tables[k].aboveSQL, p, int64(st.Committed.Seq))
		if err != nil {
			return err
		}
		above := rows.Next()
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if above {
			return store.ErrImportUnfinished
		}
	}
	// So is a full import's marker: its reset removes rows before the position moves, leaving nothing above it.
	rows, err := r.query(ctx, s.d.bind("SELECT 1 FROM "+importTable+" WHERE part = ? AND kind = ?"), p, importActive)
	if err != nil {
		return err
	}
	active := rows.Next()
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if active {
		return store.ErrImportUnfinished
	}
	if err := start(st.Committed); err != nil {
		return err
	}
	for _, k := range model.Kinds() {
		t := s.tables[k]
		rows, err := r.query(ctx, t.exportSQL, p, int64(afterSeq), int64(st.Committed.Seq))
		if err != nil {
			return err
		}
		for rows.Next() {
			rp := &rowPlus{rows: rows}
			rec, err := t.scan(rp)
			if err == nil {
				err = fn(store.PartitionRecord{Record: rec, Seq: uint64(rp.seq)})
			}
			if err != nil {
				rows.Close()
				return err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteRow removes a row and releases its unique values.
func (s *Store) deleteRow(ctx context.Context, r runner, t *table, id string) error {
	old, err := loadStored(ctx, r, t, id)
	if err != nil || old == nil {
		return err
	}
	for _, u := range old.uniq {
		if _, err := r.exec(ctx, s.releaseSQL(), t.kind, u, id); err != nil {
			return err
		}
	}
	_, err = r.exec(ctx, s.d.bind("DELETE FROM "+t.name+" WHERE id = ?"), id)
	return err
}

func (s *Store) ImportPartition(ctx context.Context, p int, recs []store.PartitionRecord, upTo store.PartitionPos, step store.ImportStep) error {
	if err := store.CheckImport(p, recs, upTo); err != nil {
		return err
	}
	if step.Full && step.First {
		if err := s.resetPartition(ctx, p, upTo, step.Removed); err != nil {
			return err
		}
	}
	kinds := make([]model.Kind, len(recs))
	for i, r := range recs {
		kinds[i] = r.Kind
	}
	tables, err := s.tablesOf(kinds)
	if err != nil {
		return err
	}
	// The batch and, with the Final one, the committed position (a full import also raises the purge point and ends).
	return s.partitionTx(ctx, true, tables, func(r runner) error {
		st, err := s.lockState(ctx, r, p)
		if err != nil {
			return err
		}
		if upTo.Seq <= st.Committed.Seq {
			return store.ErrPartitionBehind
		}
		now := time.Now().UnixMicro()
		for _, rec := range recs {
			if err := s.putPartition(ctx, r, rec.Record, p, rec.Seq, now); err != nil {
				return err
			}
		}
		if !step.Final {
			return nil
		}
		if step.Full {
			if _, err := r.exec(ctx, s.d.bind("DELETE FROM "+importTable+" WHERE part = ?"), p); err != nil {
				return err
			}
			st.Purged = max(st.Purged, upTo.Seq)
		}
		return s.commitState(ctx, r, p, &st, upTo)
	})
}

// resetPageSize is how many rows one transaction of the reset that starts a full import removes.
const resetPageSize = 500

// resetPartition starts a full import: it sets the import marker (refusing, changing nothing, if upTo is not above the
// committed position), then removes every row of partition p, a page to a transaction, and reports each after its
// transaction is committed. A reset an earlier import left unfinished is simply done again.
func (s *Store) resetPartition(ctx context.Context, p int, upTo store.PartitionPos, removed func(model.Kind, string)) error {
	err := s.partitionTx(ctx, true, nil, func(r runner) error {
		st, err := s.lockState(ctx, r, p)
		if err != nil {
			return err
		}
		if upTo.Seq <= st.Committed.Seq {
			return store.ErrPartitionBehind
		}
		_, err = r.exec(ctx, s.d.bind(s.d.insertIgnore(importTable, "part, kind, id", "?, ?, ?")), p, importActive, "")
		return err
	})
	if err != nil {
		return err
	}
	for _, k := range model.Kinds() {
		t := s.tables[k]
		q := s.d.bind("SELECT id FROM " + t.name + " WHERE pnum = ? AND pseq > 0 ORDER BY id LIMIT " + strconv.Itoa(resetPageSize))
		for {
			var ids []string
			err := s.partitionTx(ctx, true, []*table{t}, func(r runner) error {
				ids = ids[:0]
				rows, err := r.query(ctx, q, p)
				if err != nil {
					return err
				}
				for rows.Next() {
					var id string
					if err := rows.Scan(&id); err != nil {
						rows.Close()
						return err
					}
					ids = append(ids, id)
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return err
				}
				for _, id := range ids {
					if err := s.deleteRow(ctx, r, t, id); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			if removed != nil {
				for _, id := range ids {
					removed(k, id)
				}
			}
			if len(ids) < resetPageSize {
				break
			}
		}
	}
	return nil
}

func (s *Store) PurgePartition(ctx context.Context, p int, beforeSeq uint64) (int, error) {
	if p < 0 {
		return 0, fmt.Errorf("store: partition %d out of range", p)
	}
	if beforeSeq > store.MaxPartitionSeq {
		return 0, fmt.Errorf("store: purge point %d out of range", beforeSeq)
	}
	var tables []*table
	for _, k := range model.Kinds() {
		tables = append(tables, s.tables[k])
	}
	removed := 0
	err := s.partitionTx(ctx, true, tables, func(r runner) error {
		removed = 0
		st, err := s.lockState(ctx, r, p)
		if err != nil {
			return err
		}
		if pt := store.PurgePoint(beforeSeq); pt > st.Purged {
			st.Purged = pt
			if err := s.saveState(ctx, r, p, &st); err != nil {
				return err
			}
		}
		for _, t := range tables { // tombstones carry no unique values: a plain delete
			res, err := r.exec(ctx, s.d.bind("DELETE FROM "+t.name+" WHERE pnum = ? AND pseq > 0 AND pseq < ? AND deleted = TRUE"),
				p, int64(beforeSeq))
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			removed += int(n)
		}
		return nil
	})
	return removed, err
}

func (s *Store) PartitionTombstones(ctx context.Context, p int, afterSeq, upTo uint64, fn func(uint64, hlc.Timestamp) error) error {
	if afterSeq > store.MaxPartitionSeq || upTo > store.MaxPartitionSeq {
		return fmt.Errorf("store: sequence out of range")
	}
	for _, k := range model.Kinds() {
		t := s.tables[k]
		rows, err := s.reader().query(ctx, t.tombSQL, p, int64(afterSeq), int64(upTo))
		if err != nil {
			return err
		}
		for rows.Next() {
			var version, seq int64
			if err = rows.Scan(&version, &seq); err == nil {
				err = fn(uint64(seq), hlc.Timestamp(version))
			}
			if err != nil {
				rows.Close()
				return err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

var _ store.PartitionStore = (*Store)(nil)
