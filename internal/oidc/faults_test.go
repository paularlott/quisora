package oidc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

var errFault = errors.New("fault: store operation failed")

// faultStore wraps a record store and fails what its fields select; a zero field lets the operation through.
type faultStore struct {
	store.Store
	getKind    model.Kind                       // Get of a record of this kind fails
	listKind   model.Kind                       // List of this kind fails
	deleteKind model.Kind                       // deleting (a tombstone Put) a record of this kind fails
	cas        func(r *store.Record) error      // CompareAndPut of a record answers cas(r) when it is not nil
	afterGet   func(kind model.Kind, id string) // runs after every Get, as the store answers
	gets       atomic.Int64
	lists      atomic.Int64
}

// failReads fails every Get of one kind (an access entry, a grant, a session, an organization ...).
func failReads(s store.Store, kind model.Kind) *faultStore {
	return &faultStore{Store: s, getKind: kind}
}

// failLists fails every List of one kind (a user's memberships).
func failLists(s store.Store, kind model.Kind) *faultStore {
	return &faultStore{Store: s, listKind: kind}
}

// failDeletes fails every deletion of one kind.
func failDeletes(s store.Store, kind model.Kind) *faultStore {
	return &faultStore{Store: s, deleteKind: kind}
}

// failCAS answers every compare-and-put of a live record of one kind with err() (nil lets the write through).
func failCAS(s store.Store, kind model.Kind, err func() error) *faultStore {
	return &faultStore{Store: s, cas: func(r *store.Record) error {
		if r.Kind == kind && !r.Deleted {
			return err()
		}
		return nil
	}}
}

func (s *faultStore) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == s.getKind {
		return nil, errFault
	}
	r, err := s.Store.Get(ctx, kind, id)
	s.gets.Add(1)
	if s.afterGet != nil {
		s.afterGet(kind, id)
	}
	return r, err
}

func (s *faultStore) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	s.lists.Add(1)
	if kind == s.listKind {
		return nil, errFault
	}
	return s.Store.List(ctx, kind, q)
}

func (s *faultStore) Put(ctx context.Context, r *store.Record) error {
	if r.Deleted && r.Kind == s.deleteKind {
		return errFault
	}
	return s.Store.Put(ctx, r)
}

func (s *faultStore) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if s.cas != nil {
		if err := s.cas(r); err != nil {
			return err
		}
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func expectUnavailable(t testing.TB, what string, r tokResp) {
	t.Helper()
	if r.status != http.StatusServiceUnavailable || r.str("error") != "temporarily_unavailable" {
		t.Fatalf("%s: %d %v, want 503 temporarily_unavailable", what, r.status, r.m)
	}
}

func isUnavailable(err error) bool {
	return err != nil && strings.Contains(err.Error(), service.ErrUnavailable.Error())
}

// faultEph wraps the ephemeral store. before answers an error to fail an operation ("new", "get", "take", "set"), or
// pauses it; after runs once an operation has succeeded; answer replaces the result of a Get.
type faultEph struct {
	ephemeral.Store
	before func(op, ns string) error
	after  func(op, ns string)
	answer func(ns, id string) []byte
}

func (e faultEph) fail(op, ns string) error {
	if e.before == nil {
		return nil
	}
	return e.before(op, ns)
}

func (e faultEph) done(op, ns string) {
	if e.after != nil {
		e.after(op, ns)
	}
}

func (e faultEph) New(ctx context.Context, ns string, v []byte, ttl time.Duration) (string, error) {
	if err := e.fail("new", ns); err != nil {
		return "", err
	}
	id, err := e.Store.New(ctx, ns, v, ttl)
	if err == nil {
		e.done("new", ns)
	}
	return id, err
}

func (e faultEph) Get(ctx context.Context, ns, id string) ([]byte, error) {
	if err := e.fail("get", ns); err != nil {
		return nil, err
	}
	if e.answer != nil {
		if b := e.answer(ns, id); b != nil {
			return b, nil
		}
	}
	b, err := e.Store.Get(ctx, ns, id)
	if err == nil {
		e.done("get", ns)
	}
	return b, err
}

func (e faultEph) Take(ctx context.Context, ns, id string) ([]byte, error) {
	if err := e.fail("take", ns); err != nil {
		return nil, err
	}
	b, err := e.Store.Take(ctx, ns, id)
	if err == nil {
		e.done("take", ns)
	}
	return b, err
}

func (e faultEph) Set(ctx context.Context, ns, id string, v []byte, ttl time.Duration) error {
	if err := e.fail("set", ns); err != nil {
		return err
	}
	err := e.Store.Set(ctx, ns, id, v, ttl)
	if err == nil {
		e.done("set", ns)
	}
	return err
}

// useEph swaps the server's ephemeral store for one failing the operations fail answers an error for, and restores
// the original when the test ends. Calling it again replaces the failures.
func (h *harness) useEph(fail func(op, ns string) error) { h.useEphFaults(faultEph{before: fail}) }

func (h *harness) useEphFaults(f faultEph) {
	h.t.Helper()
	orig := h.env.Server.Eph
	good := orig
	if c, ok := good.(faultEph); ok {
		good = c.Store
	}
	f.Store = good
	h.env.Server.Eph = f
	h.t.Cleanup(func() { h.env.Server.Eph = orig })
}

// gate holds the code that reaches it until the test releases it, so a test can run other work in that window. Every
// wait is bounded: a path that no longer reaches the gate fails the test instead of hanging it.
type gate struct {
	entered chan struct{}
	resume  chan struct{}
	enter   sync.Once
	release sync.Once
}

func newGate(t testing.TB) *gate {
	g := &gate{entered: make(chan struct{}), resume: make(chan struct{})}
	t.Cleanup(g.open)
	return g
}

// hold is called by the code under test: the first caller announces itself and waits to be released.
func (g *gate) hold() {
	first := false
	g.enter.Do(func() { first = true; close(g.entered) })
	if first {
		<-g.resume
	}
}

func (g *gate) waitHeld(t testing.TB) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the code under test never reached the gate")
	}
}

func (g *gate) open() { g.release.Do(func() { close(g.resume) }) }

// membersOnlyLogin signs the user in to a client of a members-only tenant they have access to.
func (h *harness) membersOnlyLogin(name string) (*model.Client, string, tokResp) {
	h.t.Helper()
	tn := h.tenant(name, membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	tokens, _ := h.login(cl, secret, orgScope)
	if tokens.status != 200 || tokens.str("access_token") == "" || tokens.str("refresh_token") == "" {
		h.t.Fatalf("login: %d %v", tokens.status, tokens.m)
	}
	return cl, secret, tokens
}
