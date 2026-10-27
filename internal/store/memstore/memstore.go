// Package memstore is an in-memory Store: the reference implementation of the contract, used by tests.
package memstore

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
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
	indexed map[string]bool // unique values this record is indexed under
	// pnum and pseq stamp a record written by ApplyPartition or ImportPartition: the partition and the sequence number
	// of the write that last changed it (pseq 0: no stamp).
	pnum int
	pseq uint64
}

// Store is an in-memory store.
type Store struct {
	mu      sync.RWMutex
	feedID  string
	records map[key]*entry
	unique  map[key]string // (kind, unique value) -> id
	parts   map[int]*partState
	closed  atomic.Bool
}

// open refuses every call once the store is closed (store.Store: ErrUnavailable).
func (s *Store) open() error {
	if s.closed.Load() {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, store.ErrClosed)
	}
	return nil
}

// New returns an empty store.
func New() *Store {
	return &Store{feedID: model.NewID(), records: map[key]*entry{}, unique: map[key]string{}, parts: map[int]*partState{}}
}

// clone copies a record handed to a reader; like every backend, a read moves the clock past the record's version.
func clone(r *store.Record) *store.Record {
	store.Witness(r.Version)
	c := *r
	if !c.Expires.IsZero() {
		c.Expires = c.Expires.UTC().Truncate(time.Microsecond) // (store.Record: to the microsecond, in UTC)
	}
	return &c
}

func live(e *entry) bool { return e != nil && e.rec.Live(time.Now()) }

func (s *Store) FeedID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.feedID
}

func (s *Store) Get(_ context.Context, kind model.Kind, id string) (*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.records[key{kind, id}]
	if !live(e) {
		return nil, store.ErrNotFound
	}
	return clone(e.rec), nil
}

func (s *Store) GetByUnique(_ context.Context, kind model.Kind, value string) (*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
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
	}
	rec = clone(rec)
	if rec.Deleted {
		rec.Data, rec.Fields, rec.Unique, rec.Scope, rec.Expires, rec.Created = nil, nil, nil, "", time.Time{}, 0 // Epoch and Partition kept
		index = nil
	}
	e := &entry{rec: rec, indexed: map[string]bool{}}
	for _, u := range index {
		s.unique[key{rec.Kind, u}] = rec.ID
		e.indexed[u] = true
	}
	s.records[k] = e
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

// apply is one write, Put (match false) or CompareAndPut(rec, expect) (match true); the lock must be held. A retry
// (the stored record carries rec's request id) is answered as done whatever the expectation; the store stamps the
// version, so the caller's is neither compared nor used.
func (s *Store) apply(rec *store.Record, match bool, expect hlc.Timestamp) error {
	old := s.records[key{rec.Kind, rec.ID}]
	if store.Retried(rec, headOf(old)) {
		store.Settle(rec, old.rec.Head())
		return nil
	}
	if match {
		if expect == 0 && live(old) {
			return store.ErrStale
		}
		if expect != 0 {
			if !live(old) {
				return store.ErrNotFound
			}
			if old.rec.Version != expect {
				return store.ErrStale
			}
		}
	}
	if rec.Deleted && !live(old) {
		return nil // nothing to delete: nothing is written (store.Store.Put)
	}
	if old != nil {
		if err := store.CheckMove(rec, true, old.rec.Partition); err != nil {
			return err
		}
	}
	store.StampWrite(rec, headOf(old))
	if err := store.StampLocal(rec, headOf(old), match && expect == 0); err != nil {
		return err
	}
	if s.conflict(rec) {
		return store.ErrConflict
	}
	s.write(rec, rec.Unique)
	return nil
}

func (s *Store) Put(ctx context.Context, rec *store.Record) (err error) {
	if err := s.open(); err != nil {
		return err
	}
	if err := store.Ended(ctx); err != nil {
		return err
	}
	if err := store.CheckRecord(rec); err != nil {
		return err
	}
	defer store.EnsureReq(rec, &err)()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apply(rec, false, 0)
}

// Tx applies ops all or nothing under one lock: each as apply does, in order, so a later op sees what the earlier ones
// leave (a unique value one releases another may claim). A refusal puts back every record and unique entry the ops
// touched.
func (s *Store) Tx(ctx context.Context, ops []store.Op) (err error) {
	if err := s.open(); err != nil {
		return err
	}
	if err := store.Ended(ctx); err != nil {
		return err
	}
	if len(ops) == 0 {
		return store.ErrBadTx
	}
	if err := store.CheckTx(ops); err != nil {
		return err
	}
	seen := map[key]bool{}
	for _, op := range ops {
		k := key{op.Rec.Kind, op.Rec.ID}
		if seen[k] {
			return store.ErrBadTx
		}
		seen[k] = true
	}
	defer store.TxReq(ops, &err)()
	s.mu.Lock()
	defer s.mu.Unlock()
	retried := false
	for _, op := range ops {
		retried = retried || store.Retried(op.Rec, headOf(s.records[key{op.Rec.Kind, op.Rec.ID}]))
	}
	if retried { // the whole transaction was applied: every record it wrote takes its stored version
		for _, op := range ops {
			if h := headOf(s.records[key{op.Rec.Kind, op.Rec.ID}]); h != nil && h.Req == op.Rec.Req {
				store.Settle(op.Rec, h)
			}
		}
		return nil
	}
	// What a refusal must put back: the entries the ops replace, and the unique index under every value they touch.
	oldRecs := map[key]*entry{}
	oldUnique := map[key]*string{}
	save := func(k key) {
		if _, ok := oldUnique[k]; ok {
			return
		}
		if id, ok := s.unique[k]; ok {
			oldUnique[k] = &id
		} else {
			oldUnique[k] = nil
		}
	}
	for _, op := range ops {
		k := key{op.Rec.Kind, op.Rec.ID}
		oldRecs[k] = s.records[k]
		if e := s.records[k]; e != nil {
			for u := range e.indexed {
				save(key{k.kind, u})
			}
		}
		for _, u := range op.Rec.Unique {
			save(key{k.kind, u})
		}
	}
	for _, op := range ops {
		if err := s.apply(op.Rec, op.Match, op.Expect); err != nil {
			for k, e := range oldRecs {
				if e == nil {
					delete(s.records, k)
				} else {
					s.records[k] = e
				}
			}
			for k, id := range oldUnique {
				if id == nil {
					delete(s.unique, k)
				} else {
					s.unique[k] = *id
				}
			}
			return err
		}
	}
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
	if err := s.open(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.records[key{kind, id}]
	if e == nil {
		return nil, store.ErrNotFound
	}
	return clone(e.rec), nil
}

func (s *Store) PutReplicated(ctx context.Context, rec *store.Record) (bool, error) {
	if err := s.open(); err != nil {
		return false, err
	}
	if err := store.Ended(ctx); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putReplicated(rec)
}

// PutReplicatedBatch applies recs under one lock acquisition (store.BatchReplicator); a record refused with an error
// stops the batch (the ones before it stay applied here; the caller gives up on an error).
func (s *Store) PutReplicatedBatch(ctx context.Context, recs []*store.Record) ([]bool, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	if err := store.Ended(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	applied := make([]bool, len(recs))
	for i, rec := range recs {
		var err error
		if applied[i], err = s.putReplicated(rec); err != nil {
			return nil, err
		}
	}
	return applied, nil
}

// putReplicated applies rec; the lock must be held.
func (s *Store) putReplicated(rec *store.Record) (bool, error) {
	if old := s.records[key{rec.Kind, rec.ID}]; old != nil && old.rec.Version >= rec.Version {
		return false, nil
	}
	if s.conflict(rec) {
		return false, store.ErrConflict
	}
	store.Witness(rec.Version)
	s.write(rec, rec.Unique)
	return true, nil
}

func (s *Store) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) (err error) {
	if err := s.open(); err != nil {
		return err
	}
	if err := store.Ended(ctx); err != nil {
		return err
	}
	if err := store.CheckRecord(rec); err != nil {
		return err
	}
	defer store.EnsureReq(rec, &err)()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apply(rec, true, expect)
}

func (s *Store) List(_ context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
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
	if err := s.open(); err != nil {
		return 0, err
	}
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

func (s *Store) Purge(_ context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
	if err := s.open(); err != nil {
		return 0, err
	}
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
			delete(s.records, k)
			n++
		}
	}
	return n, nil
}

func (s *Store) Close() error {
	s.closed.Store(true)
	return nil
}

var _ store.PartitionStore = (*Store)(nil)

// Wipe discards everything and gives the store a new identity (FeedID); tests clear a database with it.
func (s *Store) Wipe(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records, s.unique, s.parts = map[key]*entry{}, map[key]string{}, map[int]*partState{}
	s.feedID = model.NewID()
	return nil
}
