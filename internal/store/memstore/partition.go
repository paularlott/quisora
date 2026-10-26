package memstore

import (
	"bytes"
	"cmp"
	"context"
	"slices"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/store"
)

// partState is one partition's protocol state.
type partState struct {
	promised   store.PartitionEpoch
	committed  store.PartitionPos
	pending    []byte
	pendingSeq uint64
	purged     uint64
	brought    map[key]bool // a full import's records so far (what the sweep at its end keeps)
}

func (s *Store) part(p int) *partState {
	st := s.parts[p]
	if st == nil {
		st = &partState{}
		s.parts[p] = st
	}
	return st
}

// view is the state as PartitionState reports it: a pending write the commit has passed is not shown.
func (st *partState) view() store.PartitionState {
	out := store.PartitionState{Promised: st.promised, Committed: st.committed, Purged: st.purged}
	if st.pending != nil && st.pendingSeq > st.committed.Seq {
		out.Pending, out.PendingSeq = bytes.Clone(st.pending), st.pendingSeq
	}
	return out
}

func (s *Store) PartitionState(_ context.Context, p int) (store.PartitionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st := s.parts[p]; st != nil {
		return st.view(), nil
	}
	return store.PartitionState{}, nil
}

func (s *Store) SetPartitionPromised(_ context.Context, p int, e store.PartitionEpoch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.part(p)
	if e.Compare(st.promised) < 0 {
		return store.ErrPartitionRegress
	}
	st.promised = e
	return nil
}

func (s *Store) SetPartitionPending(_ context.Context, p int, seq uint64, pending []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.part(p)
	if pending == nil {
		st.pending, st.pendingSeq = nil, 0
		return nil
	}
	st.pending, st.pendingSeq = bytes.Clone(pending), seq
	return nil
}

// putPartition stores rec as given, stamped (p, seq); the lock must be held. A unique value rec lists is indexed under
// it whoever held it before (that record keeps its data and loses the index entry).
func (s *Store) putPartition(rec *store.Record, p int, seq uint64) {
	store.Witness(rec.Version)
	var index []string
	if !rec.Deleted {
		for _, u := range rec.Unique {
			if slices.Contains(index, u) {
				continue
			}
			if hid, ok := s.unique[key{rec.Kind, u}]; ok && hid != rec.ID {
				if h := s.records[key{rec.Kind, hid}]; h != nil {
					delete(h.indexed, u)
				}
				delete(s.unique, key{rec.Kind, u})
			}
			index = append(index, u)
		}
	}
	s.write(rec, index)
	e := s.records[key{rec.Kind, rec.ID}]
	e.pnum, e.pseq = p, seq
}

func (s *Store) ApplyPartition(_ context.Context, p int, recs []*store.Record, committed store.PartitionPos) error {
	if err := store.CheckApply(p, committed); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.part(p)
	if committed.Seq <= st.committed.Seq {
		return store.ErrPartitionBehind
	}
	for _, r := range recs {
		s.putPartition(r, p, committed.Seq)
	}
	st.committed = committed
	return nil
}

func (s *Store) ExportPartition(_ context.Context, p int, afterSeq uint64, start func(store.PartitionPos) error,
	fn func(store.PartitionRecord) error) error {
	s.mu.RLock()
	var pos store.PartitionPos
	var out []store.PartitionRecord
	st := s.parts[p]
	if st != nil {
		pos = st.committed
		if !store.ExportAllowed(st.purged, afterSeq) {
			s.mu.RUnlock()
			return store.ErrPartitionPurged
		}
	}
	for _, e := range s.records {
		if e.pseq > afterSeq && e.pseq <= pos.Seq && e.pnum == p { // (a record above the position: an import not finished)
			out = append(out, store.PartitionRecord{Record: clone(e.rec), Seq: e.pseq})
		}
	}
	s.mu.RUnlock()
	slices.SortFunc(out, func(a, b store.PartitionRecord) int { return cmp.Compare(a.Seq, b.Seq) })
	if err := start(pos); err != nil {
		return err
	}
	for _, r := range out {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ImportPartition(_ context.Context, p int, recs []store.PartitionRecord, upTo store.PartitionPos, step store.ImportStep) error {
	if err := store.CheckImport(p, recs, upTo); err != nil {
		return err
	}
	var gone []key
	err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		st := s.part(p)
		if upTo.Seq <= st.committed.Seq {
			return store.ErrPartitionBehind
		}
		if step.Full && step.First {
			st.brought = map[key]bool{}
		}
		for _, r := range recs {
			s.putPartition(r.Record, p, r.Seq)
			if step.Full {
				if st.brought == nil {
					st.brought = map[key]bool{}
				}
				st.brought[key{r.Kind, r.ID}] = true
			}
		}
		if !step.Final {
			return nil
		}
		if step.Full {
			for k, e := range s.records {
				if e.pseq > 0 && e.pnum == p && !st.brought[k] {
					s.remove(k, e)
					gone = append(gone, k)
				}
			}
			st.brought = nil
			st.purged = max(st.purged, upTo.Seq)
		}
		st.committed = upTo
		return nil
	}()
	if err == nil && step.Removed != nil { // outside the lock: the callback may read the store
		for _, k := range gone {
			step.Removed(k.kind, k.id)
		}
	}
	return err
}

func (s *Store) PurgePartition(_ context.Context, p int, beforeSeq uint64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, e := range s.records {
		if e.pseq > 0 && e.pseq < beforeSeq && e.pnum == p && e.rec.Deleted {
			s.remove(k, e)
			n++
		}
	}
	st := s.part(p)
	st.purged = max(st.purged, store.PurgePoint(beforeSeq))
	return n, nil
}

func (s *Store) PartitionTombstones(_ context.Context, p int, afterSeq, upTo uint64, fn func(uint64, hlc.Timestamp) error) error {
	type tomb struct {
		seq     uint64
		version hlc.Timestamp
	}
	var out []tomb
	s.mu.RLock()
	for _, e := range s.records {
		if e.rec.Deleted && e.pnum == p && e.pseq > afterSeq && e.pseq <= upTo {
			out = append(out, tomb{e.pseq, e.rec.Version})
		}
	}
	s.mu.RUnlock()
	for _, t := range out {
		if err := fn(t.seq, t.version); err != nil {
			return err
		}
	}
	return nil
}

// remove deletes a record and its index entries; the lock must be held.
func (s *Store) remove(k key, e *entry) {
	for u := range e.indexed {
		if s.unique[key{k.kind, u}] == k.id {
			delete(s.unique, key{k.kind, u})
		}
	}
	delete(s.records, k)
}
