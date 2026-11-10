package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// What ending a session ends, by how it is ended:
//
//	                                    own sign-out       revoked (another session, an administrator)  everywhere / lock-out
//	the session                         ends               ends                                          ends
//	grants without offline_access       end                end                                           end
//	grants with offline_access          go on              end                                           end
//	SSH certificates of that sign-in    go on (to expiry)  revoked                                       revoked
func TestSignOutAndRevocationEnd(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	now := time.Now().UTC()

	type signIn struct {
		u                              *model.User
		sess                           *model.Session
		online, offline                string // grant ids
		viaSess, viaOnline, viaOffline *service.SSHIssued
	}
	var keepUser *model.User
	start := func(name string) signIn {
		var u *model.User
		if name == "other" { // a second session of the user of "keep"
			u = w.fresh(keepUser)
		} else {
			u = w.fresh(w.env.user(w.org.ID, name, model.RoleUser))
		}
		if name == "keep" {
			keepUser = u
		}
		sess := &model.Session{Meta: model.Meta{ID: "sess-" + name}, UserID: u.ID, OrgID: u.OrgID, AuthTime: now, LastSeen: now,
			Expires: now.Add(time.Hour), Epoch: u.SessionEpoch, Stamp: w.stamp(u.OrgID)}
		if err := w.svc.Sessions.Create(w.ctx, sess); err != nil {
			t.Fatal(err)
		}
		grant := func(id string, scopes ...string) string {
			g := &model.Grant{Meta: model.Meta{ID: id}, UserID: u.ID, OrgID: u.OrgID, ClientID: "app", SessionID: sess.ID,
				Epoch: u.SessionEpoch, Stamp: sess.Stamp, Scopes: scopes, Expires: now.Add(time.Hour)}
			if err := w.svc.Grants.Create(w.ctx, g); err != nil {
				t.Fatal(err)
			}
			return id
		}
		s := signIn{u: u, sess: sess, online: grant("on-"+name, "openid"), offline: grant("off-"+name, "openid", "offline_access")}
		from := func(id string) func(*service.SSHUserRequest) {
			return func(r *service.SSHUserRequest) { r.SignIn = id }
		}
		s.viaSess, s.viaOnline, s.viaOffline = w.mustSign(u, from(sess.ID)), w.mustSign(u, from(s.online)), w.mustSign(u, from(s.offline))
		return s
	}
	sessionGone := func(s signIn) bool {
		_, err := w.svc.Sessions.Get(w.ctx, s.sess.ID)
		return errors.Is(err, store.ErrNotFound)
	}
	// a grant counts while its record is there and the user's session epoch is the one it was made in
	grantLive := func(s signIn, id string) bool {
		g, err := w.svc.Grants.Get(w.ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		u := w.fresh(s.u)
		return u.SessionHolds(g.Epoch) && u.Enabled(time.Now())
	}
	certs := func(s signIn) []string {
		return []string{w.reasonOf(s.viaSess), w.reasonOf(s.viaOnline), w.reasonOf(s.viaOffline)}
	}
	check := func(what string, s signIn, offlineLives bool, certReason string) {
		t.Helper()
		if !sessionGone(s) {
			t.Errorf("%s: the session goes on", what)
		}
		if grantLive(s, s.online) {
			t.Errorf("%s: the grant without offline_access goes on", what)
		}
		if got := grantLive(s, s.offline); got != offlineLives {
			t.Errorf("%s: the offline grant goes on: %v, want %v", what, got, offlineLives)
		}
		for i, got := range certs(s) {
			if got != certReason {
				t.Errorf("%s: certificate %d: reason %q, want %q", what, i, got, certReason)
			}
		}
	}

	own := start("own")
	if _, err := w.svc.SignOutSession(w.ctx, own.sess); err != nil {
		t.Fatal(err)
	}
	check("own sign-out", own, true, "")

	revoked := start("revoked")
	if _, err := w.svc.EndSession(w.ctx, revoked.sess); err != nil {
		t.Fatal(err)
	}
	check("revoked", revoked, false, service.SSHReasonSignInEnded)

	// "sign out my other sessions": the others are revoked; the one asking, its grants and its certificates go on
	keep, other := start("keep"), start("other")
	if _, err := w.svc.RevokeOtherSessions(w.ctx, keep.u.ID, keep.sess.ID); err != nil {
		t.Fatal(err)
	}
	if sessionGone(keep) || !grantLive(keep, keep.online) || !grantLive(keep, keep.offline) {
		t.Error("revoking the other sessions ended the one kept, or a grant of it")
	}
	for i, got := range certs(keep) {
		if got != "" {
			t.Errorf("revoking the other sessions revoked certificate %d of the one kept: %q", i, got)
		}
	}

	check("another session, signed out from the one kept", other, false, service.SSHReasonSessionsEnded)

	everywhere := start("everywhere")
	if err := w.svc.RevokeSessions(w.ctx, actor(w.admin), everywhere.u.ID); err != nil {
		t.Fatal(err)
	}
	check("signed out everywhere", everywhere, false, service.SSHReasonSessionsEnded)

	locked := start("locked")
	if _, err := w.svc.LockOutUser(w.ctx, actor(w.admin), locked.u.ID, "test"); err != nil {
		t.Fatal(err)
	}
	check("locked out", locked, false, service.SSHReasonUserDisabled)
}
