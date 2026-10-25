package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestSignOutAuthorizationAndReasons(t *testing.T) {
	c := newCast(t)
	opt := service.SignOutOptions{Reason: "incident"}
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{{"manager", c.aManager, "forbidden"}, {"user", c.aUser, "forbidden"}, {"foreign admin", c.bAdmin, "forbidden"}, {"admin", c.aAdmin, "ok"}, {"super", c.super, "ok"}} {
		_, err := c.svc.SignOutOrg(c.ctx, actor(tc.u), c.a.ID, opt)
		c.check(t, tc.name+" org", err, tc.want)
	}
	for name, u := range map[string]*model.User{"primary admin": c.pAdmin, "org admin": c.aAdmin, "manager": c.aManager} {
		if _, err := c.svc.SignOutServer(c.ctx, actor(u), opt); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("%s server sign-out: %v", name, err)
		}
	}
	for _, reason := range []string{"", "   ", strings.Repeat("r", model.MaxSignOutReason+1)} {
		if _, err := c.svc.SignOutOrg(c.ctx, actor(c.aAdmin), c.a.ID, service.SignOutOptions{Reason: reason}); !isInvalid(err) {
			t.Errorf("reason %d chars: %v", len(reason), err)
		}
	}
	if _, err := c.svc.SignOutOrg(c.ctx, actor(c.super), "missing", opt); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown org: %v", err)
	}
	// only the orgs asked for are affected
	sa, sb := c.session(c.aUser), c.session(c.bAdmin)
	if _, err := c.svc.SignOutOrg(c.ctx, actor(c.aAdmin), c.a.ID, opt); err != nil {
		t.Fatal(err)
	}
	if c.sessionLive(sa) || !c.sessionLive(sb) {
		t.Errorf("sign-out of org a: a live %v, b live %v", c.sessionLive(sa), c.sessionLive(sb))
	}
	if n := len(c.audited(c.a.ID, "org.signout")); n != 3 {
		t.Errorf("org.signout events %d (aadmin, super and the earlier ok)", n)
	}
	// SweepSignOut is audited and leaves other orgs' sessions
	if _, err := c.svc.SweepSignOut(c.ctx, actor(c.aAdmin), c.a.ID, true); err != nil {
		t.Fatal(err)
	}
	if !c.sessionLive(sb) {
		t.Error("sweep ended another org's live session")
	}
	if len(c.audited(c.a.ID, "signout.sweep")) != 1 {
		t.Error("sweep not audited")
	}
	// the server-wide one ends everything, and its audit event is the primary's
	if _, err := c.svc.SignOutServer(c.ctx, actor(c.super), service.SignOutOptions{Reason: "all", KeepSession: "no-such-session"}); err != nil {
		t.Fatal(err)
	}
	if c.sessionLive(sb) {
		t.Error("server sign-out left a session")
	}
	if len(c.audited(c.primary.ID, "server.signout")) != 1 {
		t.Error("server sign-out not audited in the primary org")
	}
}

func TestRevokeSessionsAndFindUserByEmail(t *testing.T) {
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
	if got, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, "  "+strings.ToUpper(victim.Email)+" "); err != nil || got.ID != victim.ID {
		t.Errorf("find by email: %v", err)
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.b.ID, victim.Email); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("same address in another org: %v", err)
	}
	// a linked address never finds the user for sign-in or reset
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), victim.ID, "alias@example.com", true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, "alias@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("linked address found a user: %v", err)
	}
}

// Deleting a user leaves its records to the orphan sweep: they stop counting at once and the sweep removes them,
// and only them.
func TestSweepRemovesOrphansOnly(t *testing.T) {
	c := newCast(t)
	gone, keep := c.user(c.a.ID, "leaver", model.RoleUser), c.aUser
	for _, u := range []*model.User{gone, keep} {
		c.session(u)
		c.passkey(u, "pk-"+u.Username)
		c.apiToken(u)
	}
	ten, _ := c.svc.CreateTenant(c.ctx, service.System, c.a.ID, service.TenantInput{Name: ptr("staff")})
	if _, err := c.svc.AddAccess(c.ctx, service.System, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: gone.ID}); err != nil {
		t.Fatal(err)
	}
	grp, _ := c.svc.CreateGroup(c.ctx, service.System, c.a.ID, service.GroupInput{DisplayName: ptr("Ops")})
	if err := c.svc.SetMembership(c.ctx, service.System, grp.ID, gone.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.SetMembership(c.ctx, service.System, grp.ID, keep.ID, true); err != nil {
		t.Fatal(err)
	}
	// a long-expired lock goes; a live one stays
	if err := c.svc.Locks.Create(c.ctx, &model.Lock{Meta: model.Meta{ID: "dead-lock"}, Holder: "x", Until: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.Locks.Create(c.ctx, &model.Lock{Meta: model.Meta{ID: "live-lock"}, Holder: "x", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.Users.Delete(c.ctx, gone.ID); err != nil {
		t.Fatal(err)
	}
	// a normal run judges only records old enough: nothing of this test is an hour old
	var sw service.Sweep
	total := 0
	for i := 0; i < 30; i++ {
		n, err := c.svc.SweepOrphans(c.ctx, &sw, 1000)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	if total != 1 { // only the lock, whose age is its lease's
		t.Errorf("a young orphan removed by a normal sweep: %d", total)
	}
	n, err := c.svc.SweepAll(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 {
		t.Errorf("SweepAll removed %d (session, passkey, token, access, membership)", n)
	}
	count := func(k model.Kind, scope string) int {
		got, err := c.svc.Store.Count(c.ctx, k, scope)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, k := range []model.Kind{model.KindSession, model.KindPasskey, model.KindAPIToken} {
		if count(k, gone.ID) != 0 {
			t.Errorf("%v of the deleted user remain", k)
		}
		if count(k, keep.ID) != 1 {
			t.Errorf("%v of the kept user: %d", k, count(k, keep.ID))
		}
	}
	if l, _, _ := c.svc.ListAccess(c.ctx, service.System, ten.ID, store.ListQuery{}); len(l) != 0 {
		t.Errorf("access entries %d", len(l))
	}
	if _, err := c.svc.Locks.Get(c.ctx, "live-lock"); err != nil {
		t.Error("a live lock was swept")
	}
	if _, err := c.svc.Locks.Get(c.ctx, "dead-lock"); err == nil {
		t.Error("a long-dead lock was kept")
	}
	if again, _ := c.svc.SweepAll(c.ctx); again != 0 {
		t.Errorf("second sweep removed %d", again)
	}
}
