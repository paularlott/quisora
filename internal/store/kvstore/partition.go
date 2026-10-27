package kvstore

import (
	"context"
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
// is a range scan from the caller's sequence and PurgePartition and the reset that starts a full import reach the partition's records without
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
	// The marker first: an import that ends in between shows as still importing (the safe side), never the reverse.
	active, err := s.eng.Get(ctx, importActiveKey(p))
	if err != nil {
		return store.PartitionState{}, err
	}
	b, err := s.eng.Get(ctx, pstateKey(p))
	if err != nil {
		return store.PartitionState{}, err
	}
	st, err := decodeState(b)
	out := view(st)
	out.Importing = active != nil
	return out, err
}

// partitionLock returns partition p's lock (Store.plocks) read-locked, and lockPartition holds it exclusively until the
// returned function is called: an import or a purge of the partition is not interleaved with its protocol writes, which
// share it among themselves.
func (s *Store) partitionLock(p int) *sync.RWMutex {
	m, _ := s.plocks.LoadOrStore(p, new(sync.RWMutex))
	mu := m.(*sync.RWMutex)
	mu.RLock()
	return mu
}

func (s *Store) lockPartition(p int) func() {
	m, _ := s.plocks.LoadOrStore(p, new(sync.RWMutex))
	mu := m.(*sync.RWMutex)
	mu.Lock()
	return mu.Unlock
}

// writePartition runs fn as a write of partition p's state and records: through the engine's group commit when it has one,
// so that the protocol's writes (the next write's pending while the last one commits, applies of many partitions, each moving
// the counters of the kinds it adds to) are applied one after another by the committer, in the order they were queued, and
// never conflict with each other.
func (s *Store) writePartition(ctx context.Context, p int, fn func(tx txn) error) error {
	defer s.partitionLock(p).RUnlock()
	if g, ok := s.eng.(grouper); ok {
		return g.Group(ctx, "pstate", strconv.Itoa(p), fn)
	}
	return s.eng.Update(ctx, fn)
}

func (s *Store) SetPartitionPromised(ctx context.Context, p int, e store.PartitionEpoch) error {
	return s.writePartition(ctx, p, func(tx txn) error {
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
	return s.writePartition(ctx, p, func(tx txn) error {
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
	return s.writePartition(ctx, p, func(tx txn) error {
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
	// So is a full import's marker: its reset removes records before the position moves, leaving nothing above it.
	if active, err := eng.Get(ctx, importActiveKey(p)); err != nil {
		return err
	} else if active != nil {
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

// importActiveKey is the key of the marker that a full import of p is in progress: the First call sets it, in the
// transaction that checks the position, before anything is removed, and the transaction that commits the final position
// deletes it. The reset that starts an import removes records in transactions of their own, before the position moves, so
// without the marker a crash between them leaves nothing above the committed position, and an export would advertise a
// position the data no longer matches.
func importActiveKey(p int) string { return importActivePrefix + strconv.Itoa(p) }

const importActivePrefix = "pimp-active/"

func (s *Store) ImportPartition(ctx context.Context, p int, recs []store.PartitionRecord, upTo store.PartitionPos, step store.ImportStep) error {
	if err := store.CheckImport(p, recs, upTo); err != nil {
		return err
	}
	defer s.lockPartition(p)() // (the whole import: its state writes are the partition's, as Commit's)
	if step.Full && step.First {
		if err := s.resetPartition(ctx, p, upTo, step.Removed); err != nil {
			return err
		}
	}
	// put stores recs and, with setState, moves the position (and a full import ends).
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
		}
		if !setState {
			return nil
		}
		if step.Full {
			tx.Delete(importActiveKey(p)) // with the position
		}
		return commitState(tx, p, &st, upTo)
	}
	err := s.eng.Update(ctx, func(tx txn) error { return put(tx, recs, step.Final) })
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
		if err == nil && step.Final {
			err = s.eng.Update(ctx, func(tx txn) error { return put(tx, nil, true) })
		}
	}
	return err
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

// resetPartition starts a full import: it sets the import marker (refusing, changing nothing, if upTo is not above the
// committed position), then removes every record of p, a page to a transaction (and reports each after its removal is
// committed). It walks the partition's sequence index a page at a time. A reset an earlier import left unfinished is
// simply done again.
func (s *Store) resetPartition(ctx context.Context, p int, upTo store.PartitionPos, removed func(model.Kind, string)) error {
	err := s.eng.Update(ctx, func(tx txn) error {
		st, err := loadState(tx, p)
		if err != nil {
			return err
		}
		if upTo.Seq <= st.Committed.Seq {
			return store.ErrPartitionBehind
		}
		tx.Set(importActiveKey(p), []byte{1})
		return nil
	})
	if err != nil {
		return err
	}
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
