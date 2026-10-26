package kvstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/shamaton/msgpack/v3"
)

// Partition replication support (store.PartitionStore).
//
// State: one key per partition, pstate/<p>, in the same database as the data, written in the same transaction as the
// records an apply or import changes (so the data and the committed position never disagree).
//
// Sequence index: every record written by ApplyPartition or ImportPartition is a member of the ordered set ps/<p>,
// "<20-digit sequence>/<kind>/<id>", maintained with the record's other index entries (indexEntries), so ExportPartition
// is a range scan from the caller's sequence and PurgePartition and a full import reach the partition's records without
// reading the others.
//
// Durability: Badger fsyncs every commit (BadgerOptions.NoSync off, the default, which a gossip node requires), so every
// write is durable and the ordering the protocol asks for (a durable state write makes the earlier applies durable)
// holds trivially. Applies, imports and purges are synced like the rest. (An option to commit them unsynced and sync only
// the state writes was built and removed: nothing enabled it, and it left a gap around a memtable rotation, where a
// power cut could lose an apply and keep a later state write.)

func pstateKey(p int) string { return "pstate/" + strconv.Itoa(p) }

// wireState is the stored form of a partition's state (array encoded).
type wireState struct {
	PromisedC  uint64
	PromisedN  []byte
	CommittedC uint64
	CommittedN []byte
	Seq        uint64
	PendingSeq uint64
	Pending    []byte
	Purged     uint64
}

func encodeState(st *store.PartitionState) ([]byte, error) {
	return msgpack.MarshalAsArray(&wireState{
		PromisedC: st.Promised.Counter, PromisedN: st.Promised.Node[:],
		CommittedC: st.Committed.Epoch.Counter, CommittedN: st.Committed.Epoch.Node[:], Seq: st.Committed.Seq,
		PendingSeq: st.PendingSeq, Pending: st.Pending, Purged: st.Purged,
	})
}

func decodeState(b []byte) (store.PartitionState, error) {
	var st store.PartitionState
	if b == nil {
		return st, nil
	}
	var w wireState
	if err := msgpack.UnmarshalAsArray(b, &w); err != nil {
		return st, fmt.Errorf("kvstore: decode partition state: %w", err)
	}
	st.Promised.Counter, st.Committed.Epoch.Counter, st.Committed.Seq = w.PromisedC, w.CommittedC, w.Seq
	copy(st.Promised.Node[:], w.PromisedN)
	copy(st.Committed.Epoch.Node[:], w.CommittedN)
	st.Pending, st.PendingSeq, st.Purged = w.Pending, w.PendingSeq, w.Purged
	return st, nil
}

// view hides a pending write the commit has passed.
func view(st store.PartitionState) store.PartitionState {
	if st.PendingSeq <= st.Committed.Seq {
		st.Pending, st.PendingSeq = nil, 0
	}
	return st
}

func loadState(tx txn, p int) (store.PartitionState, error) {
	b, err := tx.Get(pstateKey(p))
	if err != nil {
		return store.PartitionState{}, err
	}
	return decodeState(b)
}

func saveState(tx txn, p int, st *store.PartitionState) error {
	b, err := encodeState(st)
	if err != nil {
		return err
	}
	tx.Set(pstateKey(p), b)
	return nil
}

func (s *Store) PartitionState(ctx context.Context, p int) (store.PartitionState, error) {
	b, err := s.eng.Get(ctx, pstateKey(p))
	if err != nil {
		return store.PartitionState{}, err
	}
	st, err := decodeState(b)
	return view(st), err
}

// lockPartition holds partition p's state lock (Store.plocks) until the returned function is called.
func (s *Store) lockPartition(p int) func() {
	m, _ := s.plocks.LoadOrStore(p, new(sync.Mutex))
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (s *Store) SetPartitionPromised(ctx context.Context, p int, e store.PartitionEpoch) error {
	defer s.lockPartition(p)()
	return s.eng.Update(ctx, func(tx txn) error {
		st, err := loadState(tx, p)
		if err != nil {
			return err
		}
		if e.Compare(st.Promised) < 0 {
			return store.ErrPartitionRegress
		}
		st.Promised = e
		return saveState(tx, p, &st)
	})
}

func (s *Store) SetPartitionPending(ctx context.Context, p int, seq uint64, pending []byte) error {
	defer s.lockPartition(p)()
	return s.eng.Update(ctx, func(tx txn) error {
		st, err := loadState(tx, p)
		if err != nil {
			return err
		}
		st.Pending, st.PendingSeq = pending, seq
		if pending == nil {
			st.PendingSeq = 0
		}
		return saveState(tx, p, &st)
	})
}

// putPartition stores rec as given, stamped (p, seq), inside tx. A unique value rec lists is indexed under it whoever
// held it before (that record keeps its data and loses the index entry, as with a replicated clash); one it no longer
// lists is released (apply).
func putPartition(tx txn, rec *store.Record, p int, seq uint64) error {
	store.Witness(rec.Version)
	old, err := loadRec(tx, rec.Kind, rec.ID)
	if err != nil {
		return err
	}
	var index []string
	if !rec.Deleted {
		for _, u := range rec.Unique {
			if !slices.Contains(index, u) {
				index = append(index, u)
			}
		}
	}
	return apply(tx, old, rec, index, nil, pstamp{num: uint32(p), seq: seq})
}

func (s *Store) ApplyPartition(ctx context.Context, p int, recs []*store.Record, committed store.PartitionPos) error {
	if err := store.CheckApply(p, committed); err != nil {
		return err
	}
	defer s.lockPartition(p)()
	return s.eng.Update(ctx, func(tx txn) error {
		st, err := loadState(tx, p)
		if err != nil {
			return err
		}
		if committed.Seq <= st.Committed.Seq {
			return store.ErrPartitionBehind
		}
		for _, r := range recs {
			if err := putPartition(tx, r, p, committed.Seq); err != nil {
				return err
			}
		}
		return commitState(tx, p, &st, committed)
	})
}

// commitState sets the committed position and clears the pending write it has passed.
func commitState(tx txn, p int, st *store.PartitionState, committed store.PartitionPos) error {
	st.Committed = committed
	if st.PendingSeq <= committed.Seq {
		st.Pending, st.PendingSeq = nil, 0
	}
	return saveState(tx, p, st)
}

// readView returns an engine that reads one consistent snapshot, and releases it.
func (s *Store) readView() (engine, func()) {
	if e, ok := s.eng.(*badgerEngine); ok {
		t := e.db.NewTransaction(false)
		return &badgerSnapshot{t: t}, t.Discard
	}
	return s.eng, func() {}
}

// psMember parses a member of the partition sequence index.
func psMember(m string) (seq uint64, kind model.Kind, id string, err error) {
	parts := strings.SplitN(m, "/", 3)
	if len(parts) == 3 {
		if seq, err = strconv.ParseUint(parts[0], 10, 64); err == nil {
			return seq, model.Kind(parts[1]), parts[2], nil
		}
	}
	return 0, "", "", fmt.Errorf("kvstore: corrupt partition index entry %q", m)
}

// psFrom is the first member of the sequence index after seq.
func psFrom(seq uint64) string { return string(appendPadded(nil, seq+1, 20)) }

func (s *Store) ExportPartition(ctx context.Context, p int, afterSeq uint64, start func(store.PartitionPos) error,
	fn func(store.PartitionRecord) error) error {
	eng, done := s.readView()
	defer done()
	b, err := eng.Get(ctx, pstateKey(p))
	if err != nil {
		return err
	}
	st, err := decodeState(b)
	if err != nil {
		return err
	}
	if !store.ExportAllowed(st.Purged, afterSeq) {
		return store.ErrPartitionPurged
	}
	bucket := psBucket(uint32(p))
	// A record above the committed position (the index is in sequence order, so the first member from there tells) is an
	// import that did not finish: the records below may lack what it overwrote.
	if above, err := eng.Range(ctx, bucket, psFrom(st.Committed.Seq), "\xff", 1); err != nil {
		return err
	} else if len(above) > 0 {
		return store.ErrImportUnfinished
	}
	if err := start(st.Committed); err != nil {
		return err
	}
	// Up to the committed position (nothing is above it: see above).
	to := string(appendPadded(nil, st.Committed.Seq, 20)) + "/\xff"
	for from := psFrom(afterSeq); ; {
		members, err := eng.Range(ctx, bucket, from, to, 512)
		if err != nil {
			return err
		}
		if len(members) == 0 {
			return nil
		}
		keys := make([]string, len(members))
		seqs := make([]uint64, len(members))
		for i, m := range members {
			seq, kind, id, err := psMember(m)
			if err != nil {
				return err
			}
			seqs[i], keys[i] = seq, recKey(kind, id)
		}
		vals, err := eng.MGet(ctx, keys)
		if err != nil {
			return err
		}
		for i, v := range vals {
			if v == nil {
				return fmt.Errorf("kvstore: partition index entry %q has no record", members[i])
			}
			rec, err := decodeRecord(v)
			if err != nil {
				return err
			}
			if err := fn(store.PartitionRecord{Record: rec.rec, Seq: seqs[i]}); err != nil {
				return err
			}
		}
		from = members[len(members)-1] + "\x00"
	}
}

// importFallbacks counts batches that did not fit one transaction (tests).
var importFallbacks atomic.Int64

// importMark is the key of the mark a full import puts on a record it brought: its value names the import (its
// position), so that a mark an unfinished import left means nothing to a later one.
func importMark(p int, kind model.Kind, id string) string {
	return "pimp/" + strconv.Itoa(p) + "/" + string(kind) + "/" + id
}

func importGen(upTo store.PartitionPos) []byte {
	b := binary.BigEndian.AppendUint64(make([]byte, 0, 32), upTo.Epoch.Counter)
	b = append(b, upTo.Epoch.Node[:]...)
	return binary.BigEndian.AppendUint64(b, upTo.Seq)
}

func (s *Store) ImportPartition(ctx context.Context, p int, recs []store.PartitionRecord, upTo store.PartitionPos, step store.ImportStep) error {
	if err := store.CheckImport(p, recs, upTo); err != nil {
		return err
	}
	defer s.lockPartition(p)() // (the whole import: its state writes are the partition's, as Commit's)
	gen := importGen(upTo)
	if step.Full && step.First {
		// A new import: the marks an earlier one left (it did not finish) mean nothing to it, whatever its position.
		if err := s.clearImportMarks(ctx, p); err != nil {
			return err
		}
	}
	// put stores recs (a full import marks them) and, with setState, moves the position.
	put := func(tx txn, recs []store.PartitionRecord, setState bool) error {
		st, err := loadState(tx, p)
		if err != nil {
			return err
		}
		if upTo.Seq <= st.Committed.Seq {
			return store.ErrPartitionBehind
		}
		for _, r := range recs {
			if err := putPartition(tx, r.Record, p, r.Seq); err != nil {
				return err
			}
			if step.Full {
				tx.Set(importMark(p, r.Kind, r.ID), gen)
			}
		}
		if !setState {
			return nil
		}
		if step.Full {
			st.Purged = max(st.Purged, upTo.Seq)
		}
		return commitState(tx, p, &st, upTo)
	}
	// The position goes with the records unless a sweep of what the import did not bring has to come first.
	together := step.Final && !step.Full
	err := s.eng.Update(ctx, func(tx txn) error { return put(tx, recs, together) })
	if isTxnTooBig(err) {
		// Too big for one Badger transaction: the records in as many as it takes, the position after them (so a crash
		// leaves the old position, and repeating the import completes it).
		importFallbacks.Add(1)
		for size := batchGroup; ; {
			err = s.importChunks(ctx, size, recs, put)
			if !isTxnTooBig(err) || size == 1 {
				break
			}
			size /= 2
		}
		if err == nil && together {
			err = s.eng.Update(ctx, func(tx txn) error { return put(tx, nil, true) })
		}
	}
	if err != nil || !step.Final || !step.Full {
		return err
	}
	if err := s.sweepImport(ctx, p, gen, step.Removed); err != nil {
		return err
	}
	return s.eng.Update(ctx, func(tx txn) error { return put(tx, nil, true) })
}

// importChunks stores recs, size to a transaction.
func (s *Store) importChunks(ctx context.Context, size int, recs []store.PartitionRecord,
	put func(tx txn, recs []store.PartitionRecord, setState bool) error) error {
	for len(recs) > 0 {
		n := min(size, len(recs))
		if err := s.eng.Update(ctx, func(tx txn) error { return put(tx, recs[:n], false) }); err != nil {
			return err
		}
		recs = recs[n:]
	}
	return nil
}

// sweepImport ends a full import: it removes the records of p that the import's batches did not mark (and reports each
// after its removal is committed), and clears the marks. It walks the partition's sequence index a page at a time.
func (s *Store) sweepImport(ctx context.Context, p int, gen []byte, removed func(model.Kind, string)) error {
	bucket := psBucket(uint32(p))
	page := batchGroup
	for from := ""; ; {
		members, err := s.eng.Range(ctx, bucket, from, "", page)
		if err != nil {
			return err
		}
		if len(members) == 0 {
			return nil
		}
		var gone []goneRecord
		err = s.eng.Update(ctx, func(tx txn) error {
			gone = gone[:0]
			for _, m := range members {
				seq, kind, id, err := psMember(m)
				if err != nil {
					return err
				}
				mk := importMark(p, kind, id)
				mark, err := tx.Get(mk)
				if err != nil {
					return err
				}
				if mark != nil {
					tx.Delete(mk)
				}
				if bytes.Equal(mark, gen) {
					continue
				}
				old, err := loadRec(tx, kind, id)
				if err != nil {
					return err
				}
				if old != nil && old.ps.seq == seq && int(old.ps.num) == p {
					if err := remove(tx, old); err != nil {
						return err
					}
					gone = append(gone, goneRecord{kind, id})
				}
			}
			return nil
		})
		if isTxnTooBig(err) && page > 1 {
			page /= 2
			continue
		}
		if err != nil {
			return err
		}
		if removed != nil {
			for _, g := range gone {
				removed(g.kind, g.id)
			}
		}
		from = members[len(members)-1] + "\x00"
	}
}

// clearImportMarks removes the marks an import of p left on the records of the partition (they are found through its
// sequence index: a full import marks only records it stores there), a page to a transaction.
func (s *Store) clearImportMarks(ctx context.Context, p int) error {
	bucket := psBucket(uint32(p))
	page := batchGroup
	for from := ""; ; {
		members, err := s.eng.Range(ctx, bucket, from, "", page)
		if err != nil {
			return err
		}
		if len(members) == 0 {
			return nil
		}
		err = s.eng.Update(ctx, func(tx txn) error {
			for _, m := range members {
				_, kind, id, err := psMember(m)
				if err != nil {
					return err
				}
				mk := importMark(p, kind, id)
				if mark, err := tx.Get(mk); err != nil {
					return err
				} else if mark != nil {
					tx.Delete(mk)
				}
			}
			return nil
		})
		if isTxnTooBig(err) && page > 1 {
			page /= 2
			continue
		}
		if err != nil {
			return err
		}
		from = members[len(members)-1] + "\x00"
	}
}

// goneRecord names a record a full import removed.
type goneRecord struct {
	kind model.Kind
	id   string
}

func (s *Store) PurgePartition(ctx context.Context, p int, beforeSeq uint64) (int, error) {
	if p < 0 {
		return 0, fmt.Errorf("store: partition %d out of range", p)
	}
	if beforeSeq > store.MaxPartitionSeq {
		return 0, fmt.Errorf("store: purge point %d out of range", beforeSeq)
	}
	// The purge point first: a crash part-way must never leave tombstones missing below a lower point.
	unlock := s.lockPartition(p)
	err := s.eng.Update(ctx, func(tx txn) error {
		st, err := loadState(tx, p)
		if err != nil {
			return err
		}
		if pt := store.PurgePoint(beforeSeq); pt > st.Purged {
			st.Purged = pt
			return saveState(tx, p, &st)
		}
		return nil
	})
	unlock()
	if err != nil || beforeSeq <= 1 {
		return 0, err
	}
	removed := 0
	to := string(appendPadded(nil, beforeSeq-1, 20)) + "/\xff" // every member with a sequence below beforeSeq
	for from := ""; ; {
		members, err := s.eng.Range(ctx, ptBucket(uint32(p)), from, to, purgeBatch)
		if err != nil {
			return removed, err
		}
		if len(members) == 0 {
			return removed, nil
		}
		from = members[len(members)-1] + "\x00"
		var n int
		err = s.eng.Update(ctx, func(tx txn) error {
			n = 0
			for _, m := range members {
				seq, kind, id, err := psMember(m)
				if err != nil {
					return err
				}
				st, err := loadRec(tx, kind, id)
				if err != nil {
					return err
				}
				if st == nil || !st.rec.Deleted || st.ps.seq != seq || int(st.ps.num) != p {
					continue
				}
				if err := remove(tx, st); err != nil {
					return err
				}
				n++
			}
			return nil
		})
		if err != nil {
			return removed, err
		}
		removed += n
	}
}

func (s *Store) PartitionTombstones(ctx context.Context, p int, afterSeq, upTo uint64, fn func(uint64, hlc.Timestamp) error) error {
	if p < 0 {
		return fmt.Errorf("store: partition %d out of range", p)
	}
	eng, done := s.readView()
	defer done()
	to := string(appendPadded(nil, upTo, 20)) + "/\xff"
	for from := psFrom(afterSeq); ; {
		members, err := eng.Range(ctx, ptBucket(uint32(p)), from, to, 512)
		if err != nil {
			return err
		}
		if len(members) == 0 {
			return nil
		}
		keys := make([]string, len(members))
		seqs := make([]uint64, len(members))
		for i, m := range members {
			seq, kind, id, err := psMember(m)
			if err != nil {
				return err
			}
			seqs[i], keys[i] = seq, recKey(kind, id)
		}
		vals, err := eng.MGet(ctx, keys)
		if err != nil {
			return err
		}
		for i, v := range vals {
			if v == nil {
				return fmt.Errorf("kvstore: tombstone index entry %q has no record", members[i])
			}
			rec, err := decodeRecord(v)
			if err != nil {
				return err
			}
			if err := fn(seqs[i], rec.rec.Version); err != nil {
				return err
			}
		}
		from = members[len(members)-1] + "\x00"
	}
}

var _ store.PartitionStore = (*Store)(nil)
