package service_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Pulling an organization's lever ends its sessions, refresh grants and (when asked) API tokens at once, keeps the
// session it was pulled from, and leaves other organizations alone; the sweep then deletes what it ended and tells
// applications, but not what was made since.
func TestSignOutOrg(t *testing.T) {
	e := newEnv(t)
	acme, globex := e.org("acme"), e.org("globex")
	admin, alan := e.user(acme.ID, "admin", model.RoleAdmin), e.user(acme.ID, "alan", model.RoleUser)
	gary := e.user(globex.ID, "gary", model.RoleUser)

	adminSess, alanSess, garySess := e.session(admin), e.session(alan), e.session(gary)
	alanGrant, garyGrant := e.grant(alan, alanSess.ID), e.grant(gary, garySess.ID)
	alanTok, garyTok := e.apiToken(alan), e.apiToken(gary)

	// who may pull it, and a reason is required (no longer than MaxSignOutReason)
	mgr := e.user(acme.ID, "mgr", model.RoleManager)
	for _, c := range []struct {
		name   string
		a      *service.Actor
		org    string
		reason string
		want   string
	}{
		{"user", actor(alan), acme.ID, "x", "forbidden"},
		{"manager", actor(mgr), acme.ID, "x", "forbidden"},
		{"other org's admin", actor(e.user(globex.ID, "gadmin", model.RoleAdmin)), acme.ID, "x", "forbidden"},
		{"primary org's admin, on the primary org", actor(e.user(e.primary.ID, "padmin", model.RoleAdmin)), e.primary.ID, "x", "forbidden"},
		{"blank reason", actor(admin), acme.ID, "  ", "invalid"},
		{"no reason", actor(admin), acme.ID, "", "invalid"},
		{"reason too long", actor(admin), acme.ID, strings.Repeat("r", model.MaxSignOutReason+1), "invalid"},
		{"unknown organization", actor(e.super), "missing", "x", "notfound"},
	} {
		if _, err := e.svc.SignOutOrg(e.ctx, c.a, c.org, service.SignOutOptions{Reason: c.reason}); outcome(err) != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
	}
	if !e.sessionLive(alanSess) {
		t.Fatal("a refused pull ended sessions")
	}

	ev, err := e.svc.SignOutOrg(e.ctx, actor(admin), acme.ID, service.SignOutOptions{Reason: "laptop stolen", KeepSession: adminSess.ID})
	if err != nil {
		t.Fatal(err)
	}
	if ev.By != "admin" || ev.Reason != "laptop stolen" || ev.APITokens {
		t.Errorf("event: %+v", ev)
	}
	if e.sessionLive(alanSess) || e.grantLive(alanGrant) {
		t.Error("acme's session or grant still works")
	}
	if !e.sessionLive(adminSess) {
		t.Error("the session the lever was pulled from was ended")
	}
	if !e.sessionLive(garySess) || !e.grantLive(garyGrant) || !e.tokenLive(garyTok) {
		t.Error("another organization was signed out")
	}
	if !e.tokenLive(alanTok) {
		t.Error("API tokens ended without being asked to")
	}
	if o, _ := e.svc.Orgs.Get(e.ctx, acme.ID); o.LastSignOut == nil || o.LastSignOut.Reason != "laptop stolen" {
		t.Errorf("last sign-out not recorded: %+v", o.LastSignOut)
	}
	if n := len(e.audited(acme.ID, "org.signout")); n != 1 {
		t.Errorf("%d sign-outs audited, want 1", n)
	}

	// signing in again works at once
	again := e.session(alan)
	if !e.sessionLive(again) {
		t.Fatal("a session made after the pull does not work")
	}

	// with API tokens
	if _, err := e.svc.SignOutOrg(e.ctx, actor(admin), acme.ID, service.SignOutOptions{Reason: "token leak",
		APITokens: true, KeepSession: adminSess.ID}); err != nil {
		t.Fatal(err)
	}
	if e.tokenLive(alanTok) {
		t.Error("API token still works")
	}
	if !e.tokenLive(garyTok) {
		t.Error("another organization's API token ended")
	}
	newTok := e.apiToken(alan)
	if !e.tokenLive(newTok) {
		t.Error("an API token made after the pull does not work")
	}
	again2 := e.session(alan)

	// the sweep deletes what was ended, tells applications, and keeps what is current
	var mu sync.Mutex
	told := map[string][]string{}
	e.svc.OnSessionsEnding = func(_ context.Context, userID string, ids []string) {
		mu.Lock()
		told[userID] = append(told[userID], ids...)
		mu.Unlock()
	}
	n, err := e.svc.SweepSignOut(e.ctx, actor(admin), acme.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if n.Sessions != 2 || n.Grants != 1 || n.APITokens != 1 { // alan's first two sessions, his grant, his first token
		t.Errorf("sweep: %+v", n)
	}
	for _, s := range []*model.Session{alanSess, again} {
		if _, err := e.svc.Sessions.Get(e.ctx, s.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ended session %s not deleted: %v", s.ID, err)
		}
	}
	if len(told[alan.ID]) != 2 || len(told[admin.ID]) != 0 {
		t.Errorf("back-channel logout: %v", told)
	}
	if !e.sessionLive(adminSess) || !e.sessionLive(again2) || !e.tokenLive(newTok) {
		t.Error("the sweep removed current credentials")
	}
	if !e.sessionLive(garySess) {
		t.Error("the sweep touched another organization")
	}
	if len(e.audited(acme.ID, "signout.sweep")) != 1 {
		t.Error("the sweep was not audited")
	}
	// a super admin pulls the lever of the primary organization, which holds the super admins
	if _, err := e.svc.SignOutOrg(e.ctx, actor(e.super), e.primary.ID, service.SignOutOptions{Reason: "test", APITokens: true}); err != nil {
		t.Fatalf("a super admin could not sign out the primary organization: %v", err)
	}
}

// The server's lever ends every organization's sessions (super admins only), and moving the primary organization
// keeps them ended.
func TestSignOutServer(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	admin, alan := e.user(acme.ID, "admin", model.RoleAdmin), e.user(acme.ID, "alan", model.RoleUser)
	superSess, alanSess, adminSess := e.session(e.super), e.session(alan), e.session(admin)
	alanTok := e.apiToken(alan)

	for name, u := range map[string]*model.User{"organization admin": admin, "primary organization admin": e.user(e.primary.ID, "padmin", model.RoleAdmin),
		"manager": e.user(acme.ID, "mgr", model.RoleManager)} {
		if _, err := e.svc.SignOutServer(e.ctx, actor(u), service.SignOutOptions{Reason: "x"}); outcome(err) != "forbidden" {
			t.Fatalf("a %s pulled the server's lever: %v", name, err)
		}
	}
	if _, err := e.svc.SignOutServer(e.ctx, actor(e.super), service.SignOutOptions{Reason: "breach", APITokens: true,
		KeepSession: superSess.ID}); err != nil {
		t.Fatal(err)
	}
	if e.sessionLive(alanSess) || e.sessionLive(adminSess) || e.tokenLive(alanTok) {
		t.Error("a credential survived the server's sign-out")
	}
	if !e.sessionLive(superSess) {
		t.Error("the super admin's own session was ended")
	}
	if p, _ := e.svc.PrimaryOrg(e.ctx); p.LastServerSignOut == nil || p.LastServerSignOut.Reason != "breach" {
		t.Errorf("last server sign-out not recorded: %+v", p.LastServerSignOut)
	}
	if len(e.audited(e.primary.ID, "server.signout")) != 1 {
		t.Error("the server sign-out was not audited in the primary organization")
	}

	// another organization made primary: what the server's lever ended stays ended
	if _, _, err := e.svc.SetPrimaryOrg(e.ctx, acme.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if e.sessionLive(alanSess) || e.tokenLive(alanTok) {
		t.Error("moving the primary organization brought signed-out credentials back")
	}
	if !e.sessionLive(e.session(alan)) {
		t.Error("a session made after the move does not work")
	}
	if p, _ := e.svc.PrimaryOrg(e.ctx); p.LastServerSignOut == nil {
		t.Error("the last server sign-out did not move with the primary organization")
	}

	n, err := e.svc.SweepSignOut(e.ctx, actor(e.super), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if n.Sessions != 2 || n.APITokens != 1 { // alan's and admin's sessions, alan's token; the super admin's kept
		t.Errorf("sweep: %+v", n)
	}
}

// Another node sees a pull at once when told the organization changed, and within the cache bound otherwise.
func TestSignOutOtherNode(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	admin, alan := e.user(acme.ID, "admin", model.RoleAdmin), e.user(acme.ID, "alan", model.RoleUser)
	s := e.session(alan)
	other := service.New(e.svc.Cfg, e.svc.Store, e.svc.Sealer) // a second node over the same data
	if !other.SessionCurrent(e.ctx, s.OrgID, s.Stamp) {
		t.Fatal("not current before the pull")
	}
	if _, err := e.svc.SignOutOrg(e.ctx, actor(admin), acme.ID, service.SignOutOptions{Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	other.InvalidateSignOut() // what the cluster's change notice does
	if other.SessionCurrent(e.ctx, s.OrgID, s.Stamp) {
		t.Error("the other node still accepts the session")
	}
}

func TestSessionUsableVerdicts(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	u := e.user(org.ID, "alan", model.RoleUser)
	sess := e.session(u)
	if ok, err := e.svc.SessionUsable(e.ctx, sess, u); err != nil || !ok {
		t.Fatalf("fresh: %v %v", ok, err)
	}
	other := e.user(org.ID, "bea", model.RoleUser)
	if ok, _ := e.svc.SessionUsable(e.ctx, sess, other); ok {
		t.Error("session usable for another user")
	}
	exp := *sess
	exp.Expires = time.Now().Add(-time.Minute)
	if ok, _ := e.svc.SessionUsable(e.ctx, &exp, u); ok {
		t.Error("expired session usable")
	}
	stale := *sess
	stale.Epoch = 12345
	if ok, _ := e.svc.SessionUsable(e.ctx, &stale, u); ok {
		t.Error("session of another epoch usable")
	}
	off := *u
	off.Active = false
	if ok, err := e.svc.SessionUsable(e.ctx, sess, &off); ok || err != nil {
		t.Errorf("disabled user: %v %v", ok, err)
	}
	ghost := *u
	ghost.OrgID = "gone"
	if ok, err := e.svc.UserUsable(e.ctx, &ghost); ok || err != nil {
		t.Errorf("user of a missing org: %v %v", ok, err)
	}
	// after an emergency sign-out of the org, the old session is ended
	if _, err := e.svc.SignOutOrg(e.ctx, service.System, org.ID, service.SignOutOptions{Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.svc.SessionUsable(e.ctx, sess, u); ok || err != nil {
		t.Errorf("after sign-out: %v %v", ok, err)
	}
	want, err := e.svc.SessionStamp(e.ctx, org.ID)
	if err != nil || service.SessionUsableAt(sess, u, want) {
		t.Errorf("SessionUsableAt after sign-out: %v", err)
	}
}

// A sign-out that ends sessions tells the hook who and which sessions, so the connections held open for them can close.
func TestSessionsEndingHookReceivesTheUserAndSessions(t *testing.T) {
	e := newEnv(t)
	var got []string
	e.svc.OnSessionsEnding = func(_ context.Context, user string, ids []string) { got = append(got, user+":"+strings.Join(ids, ",")) }
	e.svc.SessionsEnding(e.ctx, "u1", "s1", "s2")
	if len(got) != 1 || got[0] != "u1:s1,s2" {
		t.Errorf("hook calls %v", got)
	}
}

// Signing out everywhere ends the user's sessions and refresh grants, tells the hook once, and is audited; someone who
// may not manage the user changes nothing.
func TestRevokeSessionsEndsSessionsAndGrants(t *testing.T) {
	c := newCast(t)
	victim := c.aUser
	sess := c.session(victim)
	g := c.grant(victim, sess.ID)
	for name, u := range map[string]*model.User{"foreign admin": c.bAdmin, "peer": c.e2(c.a.ID)} {
		if err := c.svc.RevokeSessions(c.ctx, actor(u), victim.ID); err == nil {
			t.Errorf("%s revoked another user's sessions", name)
		}
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess.ID); err != nil {
		t.Fatal("session gone after denied revocations")
	}
	if err := c.svc.RevokeSessions(c.ctx, actor(c.aAdmin), "nobody"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	var ended []string
	c.svc.OnSessionsEnding = func(_ context.Context, user string, ids []string) { ended = append(ended, user) }
	if err := c.svc.RevokeSessions(c.ctx, actor(victim), victim.ID); err != nil { // sign out everywhere, by themselves
		t.Fatal(err)
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess.ID); err == nil {
		t.Error("session survived")
	}
	if _, err := c.svc.Grants.Get(c.ctx, g.ID); err == nil {
		t.Error("grant survived")
	}
	if len(ended) != 1 || ended[0] != victim.ID {
		t.Errorf("hook %v", ended)
	}
	if len(c.audited(c.a.ID, "user.sessions.revoke")) != 1 {
		t.Error("revocation not audited")
	}
}
