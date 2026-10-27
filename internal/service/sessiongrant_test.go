package service_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// beforeSessionDelete runs before, once, just before the first deletion of a session: an exchange's grant
// committed after a revocation listed the session's grants and before it deleted the session.
type beforeSessionDelete struct {
	store.Store
	before func()
	done   atomic.Bool
}

func (f *beforeSessionDelete) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindSession && r.Deleted && f.before != nil && f.done.CompareAndSwap(false, true) {
		f.before()
	}
	return f.Store.CompareAndPut(ctx, r, expect)
}

func (f *beforeSessionDelete) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindSession && r.Deleted && f.before != nil && f.done.CompareAndSwap(false, true) {
		f.before()
	}
	return f.Store.Put(ctx, r)
}

func offlineGrant(u *model.User, sess *model.Session) *model.Grant {
	return &model.Grant{Meta: model.Meta{ID: model.NewID()}, UserID: u.ID, OrgID: u.OrgID, ClientID: "c1",
		SessionID: sess.ID, Scopes: []string{"openid", "offline_access"}, Expires: time.Now().Add(time.Hour),
		Epoch: sess.Epoch, Stamp: sess.Stamp}
}

// A grant an exchange makes after a revocation of its session listed the session's grants, and before the revocation
// deleted the session, is ended by that revocation: it changed the session, so the deletion lists the grants again.
func TestRevocationEndsAGrantMadeWhileItRuns(t *testing.T) {
	f := &beforeSessionDelete{Store: memstore.New()}
	e := newEnvOn(t, f)
	org := e.org("acme")
	u := e.user(org.ID, "u", model.RoleUser)
	sess := e.session(u)
	checked := *sess // the exchange's copy, read and found usable before the revocation began
	g := offlineGrant(u, sess)
	f.before = func() {
		if err := e.svc.CreateSessionGrant(e.ctx, g, &checked); err != nil {
			t.Errorf("the exchange's grant: %v", err)
		}
	}
	revoking := *sess
	if _, err := e.svc.EndSession(e.ctx, &revoking); err != nil {
		t.Fatal(err)
	}
	if !f.done.Load() {
		t.Fatal("test set-up: the session was never deleted")
	}
	if _, err := e.svc.Grants.Get(e.ctx, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a grant made while its session was revoked outlived the revocation: %v", err)
	}
	if _, err := e.svc.Sessions.Get(e.ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the revoked session: %v", err)
	}
}

// An exchange that checked its session before a revocation of it, and writes its grant after the revocation finished,
// makes no grant.
func TestGrantOfASessionRevokedMeanwhileIsNotMade(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	u := e.user(org.ID, "u", model.RoleUser)
	sess := e.session(u)
	checked := *sess
	if _, err := e.svc.EndSession(e.ctx, sess); err != nil {
		t.Fatal(err)
	}
	g := offlineGrant(u, &checked)
	if err := e.svc.CreateSessionGrant(e.ctx, g, &checked); !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a grant of a revoked session: %v, want refused", err)
	}
	if _, err := e.svc.Grants.Get(e.ctx, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a grant of a revoked session was made: %v", err)
	}
}

// beforeSessionTx runs before, once, just before the first transaction that deletes a session: a grant committed after a
// passkey's removal listed its sessions' grants and before the removal's transaction.
type beforeSessionTx struct {
	store.Store
	before func()
	done   atomic.Bool
}

func (f *beforeSessionTx) Tx(ctx context.Context, ops []store.Op) error {
	for _, op := range ops {
		if op.Rec.Kind == model.KindSession && op.Rec.Deleted && f.before != nil && f.done.CompareAndSwap(false, true) {
			f.before()
			break
		}
	}
	return f.Store.Tx(ctx, ops)
}

// Removing a passkey ends the sessions it signed in with their grants, and a grant an exchange makes on one of them
// while the removal runs too: the removal's transaction finds the session changed and is decided again.
func TestPasskeyRemovalEndsAGrantMadeWhileItRuns(t *testing.T) {
	f := &beforeSessionTx{Store: memstore.New()}
	e := newEnvOn(t, f)
	org := e.org("acme")
	admin, u := e.user(org.ID, "admin", model.RoleAdmin), e.user(org.ID, "pk", model.RoleUser)
	pk := e.passkey(u, "lost")
	sess := e.session(u)
	sess.Passkey = pk.ID
	if err := e.svc.Sessions.Update(e.ctx, sess); err != nil {
		t.Fatal(err)
	}
	checked := *sess // the exchange's copy, read and found usable before the removal began
	g := offlineGrant(u, sess)
	f.before = func() {
		if err := e.svc.CreateSessionGrant(e.ctx, g, &checked); err != nil {
			t.Errorf("the exchange's grant: %v", err)
		}
	}
	if _, err := e.svc.RemovePasskey(e.ctx, actor(admin), u.ID, pk.ID, ""); err != nil {
		t.Fatal(err)
	}
	if !f.done.Load() {
		t.Fatal("test set-up: no transaction deleted the session")
	}
	if _, err := e.svc.Grants.Get(e.ctx, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a grant made while the passkey was removed outlived the removal: %v", err)
	}
}

// countGrantLists counts the listings of refresh grants.
type countGrantLists struct {
	store.Store
	n atomic.Int64
}

func (c *countGrantLists) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindGrant {
		c.n.Add(1)
	}
	return c.Store.List(ctx, kind, q)
}

// Ending the many sessions a compromised passkey signed in lists the user's grants once, not once a session.
func TestEndPasskeySessionsListsGrantsOnce(t *testing.T) {
	c := &countGrantLists{Store: memstore.New()}
	e := newEnvOn(t, c)
	org := e.org("acme")
	u := e.user(org.ID, "pk", model.RoleUser)
	pk := e.passkey(u, "copied")
	for range 20 {
		sess := e.session(u)
		sess.Passkey = pk.ID
		if err := e.svc.Sessions.Update(e.ctx, sess); err != nil {
			t.Fatal(err)
		}
		for range 5 {
			if err := e.svc.Grants.Create(e.ctx, offlineGrant(u, sess)); err != nil {
				t.Fatal(err)
			}
		}
	}
	c.n.Store(0)
	n, err := e.svc.EndPasskeySessions(e.ctx, u.ID, pk.ID, "")
	if err != nil || n != 20 {
		t.Fatalf("ended %d: %v", n, err)
	}
	if got := c.n.Load(); got > 2 { // (Table.All may page: a listing is a call or two)
		t.Fatalf("the grants were listed %d times for 20 sessions", got)
	}
	if left, _ := e.svc.Grants.All(e.ctx, u.ID); len(left) != 0 {
		t.Fatalf("%d grants left", len(left))
	}
}
