package service_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// session makes a stamped browser session for u, as the web layer does.
func (e *env) session(u *model.User) *model.Session {
	e.t.Helper()
	st, err := e.svc.SessionStamp(e.ctx, u.OrgID)
	if err != nil {
		e.t.Fatal(err)
	}
	s := &model.Session{UserID: u.ID, OrgID: u.OrgID, Expires: time.Now().Add(time.Hour), LastSeen: time.Now(), Stamp: st}
	if err := e.svc.Sessions.Create(e.ctx, s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

// grant makes a stamped refresh grant for u, as the OIDC provider does.
func (e *env) grant(u *model.User, sessionID string) *model.Grant {
	e.t.Helper()
	st, err := e.svc.SessionStamp(e.ctx, u.OrgID)
	if err != nil {
		e.t.Fatal(err)
	}
	g := &model.Grant{UserID: u.ID, OrgID: u.OrgID, ClientID: "c1", SessionID: sessionID, Expires: time.Now().Add(time.Hour), Stamp: st}
	if err := e.svc.Grants.Create(e.ctx, g); err != nil {
		e.t.Fatal(err)
	}
	return g
}

// apiToken makes a personal API token for u through the service; it returns the presented form.
func (e *env) apiToken(u *model.User) string {
	e.t.Helper()
	_, plain, err := e.svc.CreateAPIToken(e.ctx, actor(u), service.APITokenInput{Name: e.next("t"), Scopes: []string{service.ScopeAPI}})
	if err != nil {
		e.t.Fatal(err)
	}
	return plain
}

func (e *env) sessionLive(s *model.Session) bool {
	got, err := e.svc.Sessions.Get(e.ctx, s.ID)
	return err == nil && e.svc.SessionCurrent(e.ctx, got.OrgID, got.Stamp)
}

func (e *env) grantLive(g *model.Grant) bool {
	got, err := e.svc.Grants.Get(e.ctx, g.ID)
	return err == nil && e.svc.SessionCurrent(e.ctx, got.OrgID, got.Stamp)
}

func (e *env) tokenLive(plain string) bool {
	_, _, err := e.svc.ValidateAPIToken(e.ctx, plain)
	return err == nil
}

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

	// who may pull it, and a reason is required
	for _, c := range []struct {
		name string
		a    *service.Actor
		opt  service.SignOutOptions
		want string
	}{
		{"user", actor(alan), service.SignOutOptions{Reason: "x"}, "forbidden"},
		{"manager", actor(e.user(acme.ID, "mgr", model.RoleManager)), service.SignOutOptions{Reason: "x"}, "forbidden"},
		{"other org's admin", actor(e.user(globex.ID, "gadmin", model.RoleAdmin)), service.SignOutOptions{Reason: "x"}, "forbidden"},
		{"no reason", actor(admin), service.SignOutOptions{Reason: "  "}, "invalid"},
	} {
		if _, err := e.svc.SignOutOrg(e.ctx, c.a, acme.ID, c.opt); outcome(err) != c.want {
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
		if _, err := e.svc.Sessions.Get(e.ctx, s.ID); !isErr(err, store.ErrNotFound) {
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
}

// The server's lever ends every organization's sessions (super admins only), and moving the primary organization
// keeps them ended.
func TestSignOutServer(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	admin, alan := e.user(acme.ID, "admin", model.RoleAdmin), e.user(acme.ID, "alan", model.RoleUser)
	superSess, alanSess, adminSess := e.session(e.super), e.session(alan), e.session(admin)
	alanTok := e.apiToken(alan)

	if _, err := e.svc.SignOutServer(e.ctx, actor(admin), service.SignOutOptions{Reason: "x"}); outcome(err) != "forbidden" {
		t.Fatalf("an organization's admin pulled the server's lever: %v", err)
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
