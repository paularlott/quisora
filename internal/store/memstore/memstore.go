// Package memstore is an in-memory Store: the reference implementation of the contract, used by tests.
package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

type key struct {
	kind model.Kind
	id   string
}

type entry struct {
	rec     *store.Record
	seq     uint64
	indexed map[string]bool // unique values this record is indexed under
}

// Store is an in-memory store.
type Store struct {
	mu      sync.RWMutex
	feedID  string
	records map[key]*entry
	unique  map[key]string // (kind, unique value) -> id
	seq     uint64
	log     map[uint64]key // seq -> record (latest change of each record only)
}

// New returns an empty store.
func New() *Store {
	return &Store{feedID: model.NewID(), records: map[key]*entry{}, unique: map[key]string{}, log: map[uint64]key{}}
}

// clone copies a record handed to a reader; like every backend, a read moves the clock past the record's version.
func clone(r *store.Record) *store.Record {
	store.Witness(r.Version)
	c := *r
	return &c
}

func live(e *entry) bool { return e != nil && e.rec.Live(time.Now()) }

func (s *Store) FeedID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.feedID
}

func (s *Store) Get(_ context.Context, kind model.Kind, id string) (*store.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.records[key{kind, id}]
	if !live(e) {
		return nil, store.ErrNotFound
	}
	return clone(e.rec), nil
}

func (s *Store) GetByUnique(_ context.Context, kind model.Kind, value string) (*store.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.unique[key{kind, value}]
	if !ok {
		return nil, store.ErrNotFound
	}
	e := s.records[key{kind, id}]
	if !live(e) {
		return nil, store.ErrNotFound
	}
	return clone(e.rec), nil
}

// write stores rec indexed under the given unique values; the lock must be held and checks done.
func (s *Store) write(rec *store.Record, index []string) {
	k := key{rec.Kind, rec.ID}
	if old := s.records[k]; old != nil {
		for u := range old.indexed {
			if s.unique[key{rec.Kind, u}] == rec.ID {
				delete(s.unique, key{rec.Kind, u})
			}
		}
		delete(s.log, old.seq)
	}
	rec = clone(rec)
	if rec.Deleted {
		rec.Data, rec.Fields, rec.Unique, rec.Scope, rec.Expires, rec.Epoch, rec.Created = nil, nil, nil, "", time.Time{}, 0, 0
		index = nil
	}
	e := &entry{rec: rec, indexed: map[string]bool{}}
	for _, u := range index {
		s.unique[key{rec.Kind, u}] = rec.ID
		e.indexed[u] = true
	}
	s.seq++
	e.seq = s.seq
	s.records[k] = e
	s.log[s.seq] = k
}

// holder returns the live record (other than id) indexed under the unique value.
func (s *Store) holder(kind model.Kind, u, id string) *entry {
	hid, ok := s.unique[key{kind, u}]
	if !ok || hid == id {
		return nil
	}
	if e := s.records[key{kind, hid}]; live(e) {
		return e
	}
	return nil
}

func (s *Store) conflict(rec *store.Record) bool {
	if rec.Deleted {
		return false
	}
	for _, u := range rec.Unique {
		if s.holder(rec.Kind, u, rec.ID) != nil {
			return true
		}
	}
	return false
}

func (s *Store) Put(_ context.Context, rec *store.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.records[key{rec.Kind, rec.ID}]
	if old != nil && old.rec.Version >= rec.Version {
		return store.ErrStale
	}
	if err := store.StampLocal(rec, headOf(old), false); err != nil {
		return err
	}
	if s.conflict(rec) {
		return store.ErrConflict
	}
	s.write(rec, rec.Unique)
	return nil
}

func headOf(e *entry) *store.Head {
	if e == nil {
		return nil
	}
	return e.rec.Head()
}

// Lookup returns the stored record whatever its state (store.Store).
func (s *Store) Lookup(_ context.Context, kind model.Kind, id string) (*store.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.records[key{kind, id}]
	if e == nil {
		return nil, store.ErrNotFound
	}
	return clone(e.rec), nil
}

func (s *Store) PutReplicated(_ context.Context, rec *store.Record) (bool, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	applied, losers := s.putReplicated(rec)
	return applied, losers, nil
}

// PutReplicatedBatch applies recs under one lock acquisition (store.BatchReplicator).
func (s *Store) PutReplicatedBatch(_ context.Context, recs []*store.Record) ([]bool, [][]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	applied := make([]bool, len(recs))
	losers := make([][]string, len(recs))
	for i, rec := range recs {
		applied[i], losers[i] = s.putReplicated(rec)
	}
	return applied, losers, nil
}

// putReplicated applies rec; the lock must be held.
func (s *Store) putReplicated(rec *store.Record) (bool, []string) {
	if old := s.records[key{rec.Kind, rec.ID}]; old != nil && !store.Newer(rec, old.rec) {
		return false, nil
	}
	store.Witness(rec.Version)
	var losers []string
	index := make([]string, 0, len(rec.Unique))
	if !rec.Deleted {
		for _, u := range rec.Unique {
			other := s.holder(rec.Kind, u, rec.ID)
			switch {
			case other == nil:
				index = append(index, u)
			case store.KeepsUnique(other.rec.Head(), rec.Head(), other.rec.ID, rec.ID):
				losers = appendOnce(losers, rec.ID)
			default:
				delete(s.unique, key{rec.Kind, u})
				delete(other.indexed, u)
				losers = appendOnce(losers, other.rec.ID)
				index = append(index, u)
			}
		}
	}
	s.write(rec, index)
	return true, losers
}

func appendOnce(list []string, id string) []string {
	for _, v := range list {
		if v == id {
			return list
		}
	}
	return append(list, id)
}

func (s *Store) CompareAndPut(_ context.Context, rec *store.Record, expect hlc.Timestamp) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.records[key{rec.Kind, rec.ID}]
	if expect == 0 {
		if live(old) {
			return store.ErrStale
		}
		if old != nil && old.rec.Version >= rec.Version {
			return store.ErrStale
		}
	} else {
		if !live(old) {
			return store.ErrNotFound
		}
		if old.rec.Version != expect || rec.Version <= expect {
			return store.ErrStale
		}
	}
	if err := store.StampLocal(rec, headOf(old), expect == 0); err != nil {
		return err
	}
	if s.conflict(rec) {
		return store.ErrConflict
	}
	s.write(rec, rec.Unique)
	return nil
}

func (s *Store) List(_ context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if err := store.ValidateQuery(kind, q); err != nil {
		return nil, err
	}
	s.mu.RLock()
	recs := make([]*store.Record, 0)
	now := time.Now()
	for k, e := range s.records {
		if k.kind == kind && e.rec.Live(now) && (q.Scope == "" || e.rec.Scope == q.Scope) {
			recs = append(recs, clone(e.rec))
		}
	}
	s.mu.RUnlock()
	return store.ApplyQuery(kind, recs, q)
}

func (s *Store) Count(_ context.Context, kind model.Kind, scope string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	now := time.Now()
	for k, e := range s.records {
		if k.kind == kind && e.rec.Live(now) && (scope == "" || e.rec.Scope == scope) {
			n++
		}
	}
	return n, nil
}

func (s *Store) Changes(_ context.Context, since uint64, limit int) ([]store.Change, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []store.Change{}
	next := since
	for seq := since + 1; seq <= s.seq; seq++ {
		next = seq
		k, ok := s.log[seq]
		if !ok {
			continue
		}
		out = append(out, store.Change{Seq: seq, Record: clone(s.records[k].rec)})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, next, nil
}

func (s *Store) Purge(_ context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, e := range s.records {
		r := e.rec
		if (r.Deleted && r.Version.Time().Before(tombstonesBefore)) ||
			(!r.Deleted && !r.Expires.IsZero() && r.Expires.Before(expiredBefore)) {
			for u := range e.indexed {
				if s.unique[key{k.kind, u}] == r.ID {
					delete(s.unique, key{k.kind, u})
				}
			}
			delete(s.log, e.seq)
			delete(s.records, k)
			n++
		}
	}
	return n, nil
}

func (s *Store) Close() error { return nil }

// Wipe discards everything and starts a new change feed (tests clear a database with it).
func (s *Store) Wipe(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records, s.unique, s.log = map[key]*entry{}, map[key]string{}, map[uint64]key{}
	s.feedID = model.NewID()
	return nil
}

// RefreshFields recomputes the index fields of the records q selects from their data (store.FieldRefresher).
func (s *Store) RefreshFields(ctx context.Context, kind model.Kind, q store.ListQuery) (int, error) {
	res, err := s.List(ctx, kind, q)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range res.Records {
		e := s.records[key{kind, r.ID}]
		if e == nil || e.rec.Version != r.Version {
			continue
		}
		fields, err := store.IndexFields(e.rec)
		if err != nil {
			return n, err
		}
		rec := clone(e.rec)
		rec.Fields = fields
		e.rec = rec
		n++
	}
	return n, nil
}
