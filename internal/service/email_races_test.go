package service_test

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// beforeUserWrite runs before, once, just before the first write of a user record: a change committed after the
// caller read the user and before the write that decides on that read.
type beforeUserWrite struct {
	store.Store
	before func()
	done   atomic.Bool
}

func (f *beforeUserWrite) fire(r *store.Record) {
	if r.Kind == model.KindUser && !r.Deleted && f.before != nil && f.done.CompareAndSwap(false, true) {
		f.before()
	}
}

func (f *beforeUserWrite) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	f.fire(r)
	return f.Store.CompareAndPut(ctx, r, expect)
}

func (f *beforeUserWrite) Put(ctx context.Context, r *store.Record) error {
	f.fire(r)
	return f.Store.Put(ctx, r)
}

func (f *beforeUserWrite) Tx(ctx context.Context, ops []store.Op) error {
	for _, op := range ops {
		f.fire(op.Rec)
	}
	return f.Store.Tx(ctx, ops)
}

// promote makes user id hold role in the store, as a promotion committed by someone else would.
func (e *env) promote(id string, role model.Role) {
	e.t.Helper()
	u := e.fresh(&model.User{Meta: model.Meta{ID: id}})
	u.Role = role
	if err := e.svc.Users.Update(e.ctx, u); err != nil {
		e.t.Errorf("promote: %v", err)
	}
}

// What an actor may do to a user's email addresses is judged on the copy being written, not on the one the caller
// read first: a user promoted between the read and the write is refused for an actor who may not manage them (or may
// not reset their sign-in), and nothing changes. (A manager made a verified address primary on a plain user who became
// an administrator, and could then reset the administrator's password.)
func TestEmailOperationsJudgeRankOnTheCopyBeingWritten(t *testing.T) {
	ops := map[string]struct {
		resets bool                      // a sign-in reset for an established privileged account (a manager's or above)
		setup  func(c *cast, uid string) // runs before the race is armed
		do     func(c *cast, a *model.User, uid string) error
	}{
		"add verified": {
			resets: true,
			do: func(c *cast, a *model.User, uid string) error {
				_, err := c.svc.AddLinkedEmail(c.ctx, actor(a), uid, "new@example.org", true)
				return err
			},
		},
		"add unverified": {
			do: func(c *cast, a *model.User, uid string) error {
				_, err := c.svc.AddLinkedEmail(c.ctx, actor(a), uid, "new@example.org", false)
				return err
			},
		},
		"remove": {
			setup: func(c *cast, uid string) {
				if _, err := c.svc.AddLinkedEmail(c.ctx, service.System, uid, "alt@example.org", true); err != nil {
					t.Fatal(err)
				}
			},
			do: func(c *cast, a *model.User, uid string) error {
				_, err := c.svc.RemoveLinkedEmail(c.ctx, actor(a), uid, "alt@example.org")
				return err
			},
		},
		"make primary": {
			resets: true,
			setup: func(c *cast, uid string) {
				if _, err := c.svc.AddLinkedEmail(c.ctx, service.System, uid, "alt@example.org", true); err != nil {
					t.Fatal(err)
				}
			},
			do: func(c *cast, a *model.User, uid string) error {
				_, err := c.svc.MakePrimary(c.ctx, actor(a), uid, "alt@example.org")
				return err
			},
		},
		"mark verified": {
			resets: true,
			setup: func(c *cast, uid string) {
				if _, err := c.svc.AddLinkedEmail(c.ctx, service.System, uid, "alt@example.org", false); err != nil {
					t.Fatal(err)
				}
			},
			do: func(c *cast, a *model.User, uid string) error {
				_, err := c.svc.MarkEmailVerified(c.ctx, actor(a), uid, "alt@example.org")
				return err
			},
		},
	}
	// to: the role the user is promoted to; by: who acts; want: how the write must end.
	for _, promo := range []struct {
		name   string
		to     model.Role
		by     func(c *cast) *model.User
		want   string
		resets bool // only the operations that reset a sign-in are refused
	}{
		// a manager cannot manage an administrator at all
		{"manager acts, user becomes admin", model.RoleAdmin, func(c *cast) *model.User { return c.aManager }, "denied", false},
		// an administrator cannot reset the sign-in of an established manager (and a password makes one established)
		{"admin acts, user becomes an established manager", model.RoleManager, func(c *cast) *model.User { return c.aAdmin }, "invalid", true},
	} {
		for name, op := range ops {
			if promo.resets && !op.resets {
				continue // not a sign-in reset: an administrator may whatever the user's role
			}
			t.Run(promo.name+"/"+name, func(t *testing.T) {
				f := &beforeUserWrite{Store: memstore.New()}
				c := &cast{env: newEnvOn(t, f)}
				c.a = c.org("org-a")
				c.aAdmin = c.user(c.a.ID, "aadmin", model.RoleAdmin)
				c.aManager = c.user(c.a.ID, "amanager", model.RoleManager)
				u := c.user(c.a.ID, "plain", model.RoleUser)
				c.establish(u)
				if op.setup != nil {
					op.setup(c, u.ID)
				}
				before := c.fresh(u)
				f.before = func() { c.promote(u.ID, promo.to) }
				err := op.do(c, promo.by(c), u.ID)
				if !f.done.Load() {
					t.Fatal("test set-up: the user was never written")
				}
				c.check(t, "the change on a user promoted meanwhile", err, promo.want)
				got := c.fresh(u)
				if got.Email != before.Email || got.EmailVerified != before.EmailVerified ||
					!reflect.DeepEqual(got.LinkedEmails, before.LinkedEmails) {
					t.Errorf("the addresses changed: %q %v %+v, were %q %v %+v", got.Email, got.EmailVerified, got.LinkedEmails,
						before.Email, before.EmailVerified, before.LinkedEmails)
				}
				if got.Role != promo.to {
					t.Errorf("test set-up: role %v", got.Role)
				}
			})
		}
	}
}
