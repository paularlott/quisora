package service_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// afterSessionList runs after, once, just after the first listing of sessions: a sign-in that finished after a
// revocation listed the user's sessions.
type afterSessionList struct {
	store.Store
	after func()
	done  atomic.Bool
}

func (f *afterSessionList) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	res, err := f.Store.List(ctx, kind, q)
	if kind == model.KindSession && f.after != nil && f.done.CompareAndSwap(false, true) {
		f.after()
	}
	return res, err
}

// Signing a user out everywhere ends the session a sign-in made after the revocation listed the sessions (it was made
// in the epoch the revocation moved the account on from, so it counts for nothing), not only those the listing found.
func TestRevokeSessionsEndsASessionMadeAfterTheListing(t *testing.T) {
	f := &afterSessionList{Store: memstore.New()}
	e := newEnvOn(t, f)
	org := e.org("acme")
	admin, u := e.user(org.ID, "admin", model.RoleAdmin), e.user(org.ID, "u", model.RoleUser)
	listed := e.session(u)
	var late *model.Session
	f.after = func() { late = e.session(u) } // a sign-in that read the account before the revocation
	if err := e.svc.RevokeSessions(e.ctx, actor(admin), u.ID); err != nil {
		t.Fatal(err)
	}
	if late == nil {
		t.Fatal("test set-up: no session was listed")
	}
	if e.sessionCounts(listed, u.ID) {
		t.Error("a session the revocation listed still counts")
	}
	if e.sessionCounts(late, u.ID) {
		t.Error("a session made after the revocation listed the sessions still counts")
	}
}

// Signing out the other sessions keeps the current session and its refresh grants working, ends every other session
// and grant, and ends a session made while it ran.
func TestRevokeOtherSessionsKeepsTheCurrentOneAndEndsAnInFlightSignIn(t *testing.T) {
	f := &afterSessionList{Store: memstore.New()}
	e := newEnvOn(t, f)
	org := e.org("acme")
	u := e.user(org.ID, "u", model.RoleUser)
	current, other := e.session(u), e.session(u)
	keptGrant, otherGrant := e.grant(u, current.ID), e.grant(u, other.ID)
	var late *model.Session
	f.after = func() { late = e.session(u) }
	n, err := e.svc.RevokeOtherSessions(e.ctx, u.ID, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if late == nil {
		t.Fatal("test set-up: no session was listed")
	}
	if n != 1 { // the other session: the one made after the listing is not counted
		t.Errorf("ended %d sessions, want the one other session", n)
	}
	if !e.sessionCounts(current, u.ID) {
		t.Error("the current session was ended")
	}
	cur := e.fresh(u)
	if g, err := e.svc.Grants.Get(e.ctx, keptGrant.ID); err != nil || !cur.SessionHolds(g.Epoch) {
		t.Errorf("the current session's refresh grant was ended: %v", err)
	}
	if e.sessionCounts(other, u.ID) {
		t.Error("another session still counts")
	}
	if e.sessionCounts(late, u.ID) {
		t.Error("a session made while the revocation ran still counts")
	}
	if _, err := e.svc.Grants.Get(e.ctx, otherGrant.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another session's refresh grant is left: %v", err)
	}
}

// A user who becomes a manager or administrator loses every session and refresh grant they held: some may have met
// their second factor only through rules for plain users (a provider trusted for it, or a code mailed to them), which
// do not hold for a privileged account and are not looked at again when a session is used. A change between
// privileged roles, and any change that is not a promotion, ends nothing.
func TestPromotionEndsTheSessionsOfTheUser(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	for _, to := range []model.Role{model.RoleManager, model.RoleAdmin} {
		u := e.user(org.ID, "p-"+string(to), model.RoleUser)
		sess := e.session(u)
		g := e.grant(u, sess.ID)
		if !e.sessionCounts(sess, u.ID) {
			t.Fatal("test set-up: the session does not count")
		}
		if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: &to}); err != nil {
			t.Fatal(err)
		}
		if e.sessionCounts(sess, u.ID) {
			t.Errorf("a session made before the promotion to %s still counts", to)
		}
		if got, err := e.svc.Grants.Get(e.ctx, g.ID); err == nil && e.fresh(u).SessionHolds(got.Epoch) {
			t.Errorf("a refresh grant made before the promotion to %s still counts", to)
		}
		if _, err := e.svc.Sessions.Get(e.ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the session record of the promoted user is left: %v", err)
		}
	}
	// no promotion: a privileged user changed to another privileged role keeps their sessions
	m := e.user(org.ID, "m", model.RoleManager)
	sess := e.session(m)
	admin := model.RoleAdmin
	if _, err := e.svc.UpdateUser(e.ctx, service.System, m.ID, service.UserInput{Role: &admin}); err != nil {
		t.Fatal(err)
	}
	if !e.sessionCounts(sess, m.ID) {
		t.Error("a manager made an administrator lost their sessions")
	}
}
