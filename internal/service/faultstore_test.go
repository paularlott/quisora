package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
)

var errInjected = errors.New("injected store failure")

// faultStore wraps a store to fail or pause one call. A before hook runs ahead of the call it names: an error it
// returns ends the call with that error and nothing is done, and a hook that blocks (see gate) stalls the call. An
// after hook runs once the call has returned its result. Calls without a hook go straight to the store.
type faultStore struct {
	store.Store
	beforeGet         func(kind model.Kind, id string) error
	beforeGetByUnique func(kind model.Kind, value string) error
	beforePut         func(r *store.Record) error
	beforeCAS         func(r *store.Record, expect hlc.Timestamp) error
	beforeTx          func(ops []store.Op) error
	afterCAS          func(r *store.Record, err error)
	beforeList        func(kind model.Kind, q store.ListQuery) error
	afterList         func(kind model.Kind)
	afterGetMany      func(kind model.Kind)
}

func (f *faultStore) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if f.beforeGet != nil {
		if err := f.beforeGet(kind, id); err != nil {
			return nil, err
		}
	}
	return f.Store.Get(ctx, kind, id)
}

func (f *faultStore) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	if f.beforeGetByUnique != nil {
		if err := f.beforeGetByUnique(kind, value); err != nil {
			return nil, err
		}
	}
	return f.Store.GetByUnique(ctx, kind, value)
}

// GetMany reads one record at a time through Get, so the hooks of Get apply to each.
func (f *faultStore) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	var out []*store.Record
	for _, id := range ids {
		r, err := f.Get(ctx, kind, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if f.afterGetMany != nil {
		f.afterGetMany(kind)
	}
	return out, nil
}

func (f *faultStore) Put(ctx context.Context, r *store.Record) error {
	if f.beforePut != nil {
		if err := f.beforePut(r); err != nil {
			return err
		}
	}
	return f.Store.Put(ctx, r)
}

func (f *faultStore) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if f.beforeCAS != nil {
		if err := f.beforeCAS(r, expect); err != nil {
			return err
		}
	}
	err := f.Store.CompareAndPut(ctx, r, expect)
	if f.afterCAS != nil {
		f.afterCAS(r, err)
	}
	return err
}

// Tx runs beforeTx, then the hooks of each of its writes as they would run for it alone (beforeCAS for a
// compare-and-put, beforePut for a put), before any is made; then the transaction, and afterCAS for each compare-and-put.
func (f *faultStore) Tx(ctx context.Context, ops []store.Op) error {
	if f.beforeTx != nil {
		if err := f.beforeTx(ops); err != nil {
			return err
		}
	}
	for _, op := range ops {
		var err error
		switch {
		case op.Match && f.beforeCAS != nil:
			err = f.beforeCAS(op.Rec, op.Expect)
		case !op.Match && f.beforePut != nil:
			err = f.beforePut(op.Rec)
		}
		if err != nil {
			return err
		}
	}
	err := f.Store.Tx(ctx, ops)
	if f.afterCAS != nil {
		for _, op := range ops {
			if op.Match {
				f.afterCAS(op.Rec, err)
			}
		}
	}
	return err
}

func (f *faultStore) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if f.beforeList != nil {
		if err := f.beforeList(kind, q); err != nil {
			return nil, err
		}
	}
	res, err := f.Store.List(ctx, kind, q)
	if f.afterList != nil {
		f.afterList(kind)
	}
	return res, err
}

// failingCAS is a store whose compare-and-swap of the records match selects fails.
func failingCAS(inner store.Store, match func(*store.Record) bool) *faultStore {
	return &faultStore{Store: inner, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
		if match(r) {
			return errInjected
		}
		return nil
	}}
}

// failingReads is a store whose reads of one kind (by id or by unique value) fail.
func failingReads(inner store.Store, kind model.Kind) *faultStore {
	return &faultStore{
		Store:             inner,
		beforeGet:         func(k model.Kind, _ string) error { return failKind(k, kind) },
		beforeGetByUnique: func(k model.Kind, _ string) error { return failKind(k, kind) },
	}
}

func failKind(got, want model.Kind) error {
	if got == want {
		return errInjected
	}
	return nil
}

// gate pauses one call of a faultStore until the test releases it, so that the test can act while the call is
// part way through.
type gate struct {
	entered, resume chan struct{}
	enter, free     sync.Once
}

// newGate is a gate that is released when the test ends, so a failing test leaves nothing blocked.
func newGate(t testing.TB) *gate {
	g := &gate{entered: make(chan struct{}), resume: make(chan struct{})}
	t.Cleanup(g.release)
	return g
}

// hold pauses the caller until release.
func (g *gate) hold() { <-g.resume }

// stall pauses the first caller until release and lets any later caller through.
func (g *gate) stall() {
	first := false
	g.enter.Do(func() { first = true; close(g.entered) })
	if first {
		g.hold()
	}
}

// waitEntered returns once a caller is paused, and fails the test if none is within five seconds (the code under test
// no longer reaches the point the test needs).
func (g *gate) waitEntered(t testing.TB, what string) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s was not reached", what)
	}
}

func (g *gate) release() { g.free.Do(func() { close(g.resume) }) }

// failingDelete is a store that cannot delete (tombstone) the record id.
func failingDelete(inner store.Store, id string) *faultStore {
	return &faultStore{Store: inner, beforePut: func(r *store.Record) error {
		if r.Deleted && r.ID == id {
			return errInjected
		}
		return nil
	}}
}

// noUserScan fails any query that would read every user (a filtered list of the whole kind): on a key-value store
// that decodes all of them.
type noUserScan struct{ *kvstore.Store }

func (s noUserScan) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindUser && q.Scope == "" && len(q.Filters) > 0 {
		return nil, errors.New("read every user")
	}
	return s.Store.List(ctx, kind, q)
}
