package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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
	deleteKind model.Kind                       // deleting (a tombstone, put or compared) a record of this kind fails
	cas        func(r *store.Record) error      // a compared write (CompareAndPut, or one in a Tx) of a record answers cas(r) when it is not nil
	afterGet   func(kind model.Kind, id string) // runs after every Get, as the store answers
	gets       atomic.Int64
	lists      atomic.Int64
	// healed lets every operation through again, for a test that ends the fault while other goroutines still use the
	// store (swapping the store back would race with them).
	healed atomic.Bool
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
	if kind == s.getKind && !s.healed.Load() {
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
	if r.Deleted && r.Kind == s.deleteKind {
		return errFault
	}
	if s.cas != nil {
		if err := s.cas(r); err != nil {
			return err
		}
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func (s *faultStore) Tx(ctx context.Context, ops []store.Op) error {
	for _, op := range ops {
		if op.Rec.Deleted && op.Rec.Kind == s.deleteKind {
			return errFault
		}
		if s.cas != nil && op.Match {
			if err := s.cas(op.Rec); err != nil {
				return err
			}
		}
	}
	return s.Store.Tx(ctx, ops)
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

// faultEph wraps the ephemeral store. before answers an error to fail an operation ("new", "get", "take", "set",
// "incr"), or pauses it; after runs once an operation has succeeded; answer replaces the result of a Get.
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

func (e faultEph) Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	if err := e.fail("incr", ns); err != nil {
		return 0, err
	}
	return e.Store.Incr(ctx, ns, key, delta, window)
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

// A token names its client's tenant: a tenant that cannot be read when it is issued issues nothing (503), rather than
// a token that silently lacks it, whether for a user (a code exchange) or for the client itself.
func TestMintFailsClosedOnTenantReadFailure(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	good := h.env.Svc.Tenants.S
	h.env.Svc.Tenants.S = failReads(good, model.KindTenant)
	h.p.InvalidateTenant(cl.TenantID)
	expectUnavailable(t, "code exchange with an unreadable tenant", h.exchangeCode(cl, secret, code, v))
	expectUnavailable(t, "client_credentials with an unreadable tenant", h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret))
	h.env.Svc.Tenants.S = good
	if r := h.exchangeCode(cl, secret, code, v); r.status != 200 || claimsOf(t, r.str("access_token"))["tenant"] != cl.TenantID {
		t.Fatalf("the code kept for the retry: %d %v", r.status, r.m)
	}
}

// A sign-in whose flow, client or tenant cannot be read is not a bad or expired request: the browser is told to try
// again (503), or the application is sent server_error, never a 400 that has the user start over for nothing.
func TestAuthorizeAnswersUnavailableOnReadFailures(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	c, csrf := h.session(h.user)
	_, ch := pkce()
	flow := h.authorize(c, authzQuery(cl, ch, nil)).Query().Get("flow")
	if flow == "" {
		t.Fatal("no consent flow")
	}
	resume, cancel, consent := h.orgBase+"/oauth/authorize/resume?flow="+flow, h.orgBase+"/oauth/authorize/cancel?flow="+flow,
		h.orgBase+"/oauth/consent?flow="+flow
	status := func(path string) int {
		resp := h.get(c, path)
		body(resp)
		return resp.StatusCode
	}

	// the flow cannot be read
	h.useEph(func(op, ns string) error {
		if op == "get" && ns == nsFlow {
			return errFault
		}
		return nil
	})
	for _, path := range []string{resume, cancel, consent} {
		if st := status(path); st != http.StatusServiceUnavailable {
			t.Errorf("flow unreadable, %s: %d", path, st)
		}
	}
	if st, _ := h.decideConsent(c, csrf, flow, true); st != http.StatusServiceUnavailable {
		t.Errorf("flow unreadable, consent decision: %d", st)
	}
	h.useEph(func(string, string) error { return nil })

	// its client cannot be read
	clients := h.env.Svc.Clients.S
	h.env.Svc.Clients.S = failReads(clients, model.KindClient)
	h.p.InvalidateClient(cl.ID)
	for _, path := range []string{resume, consent} {
		if st := status(path); st != http.StatusServiceUnavailable {
			t.Errorf("client unreadable, %s: %d", path, st)
		}
	}
	if st, _ := h.decideConsent(c, csrf, flow, true); st != http.StatusServiceUnavailable {
		t.Errorf("client unreadable, consent decision: %d", st)
	}
	// nor whether a metadata document's application is stored
	meta := url.Values{"client_id": {"https://app.example/client.json"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}}
	if st := status(h.orgBase + "/oauth/authorize?" + meta.Encode()); st != http.StatusServiceUnavailable {
		t.Errorf("client unreadable, metadata document application: %d", st)
	}
	h.env.Svc.Clients.S = clients

	// its tenant cannot be read, once the user is signed in: the application is told, as server_error
	tenants := h.env.Svc.Tenants.S
	h.env.Svc.Tenants.S = failReads(tenants, model.KindTenant)
	h.p.InvalidateTenant(cl.TenantID)
	resp := h.get(c, resume)
	body(resp)
	if resp.StatusCode != http.StatusFound || loc(t, resp).Query().Get("error") != "server_error" {
		t.Errorf("tenant unreadable: %d", resp.StatusCode)
	}
	h.env.Svc.Tenants.S = tenants
}
